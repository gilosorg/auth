package middleware

import (
	"context"
	"fmt"
	"gilosauth/database"
	"gilosauth/utils"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Scopes defines all available OAuth scopes in the system.
// This is the single source of truth for scopes used in the backend and templates.
// Standard OIDC scopes (openid, profile, email, phone) are listed first,
// followed by platform-specific fine-grained scopes.
var Scopes = []string{
	// Standard OIDC scopes (RFC 6749 / OIDC Core §5.4 / §11)
	"openid",
	"profile",
	"email",
	"phone",
	"offline_access",
	// Platform-specific scopes
	"user_sessions",
	"user_totps",
	"user_manage_account",
}

// IsValidScope checks if a given scope string is valid.
func IsValidScope(scope string) bool {
	return slices.Contains(Scopes, scope)
}

func writeBearerError(w http.ResponseWriter, status int, errCode, desc string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, errCode, desc))
	utils.WriteJSONResponse(w, status, map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}

// RequireAccessToken ensures a valid access token is provided for API requests
func RequireAccessToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeBearerError(w, http.StatusUnauthorized, "invalid_request", "missing Authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
			writeBearerError(w, http.StatusUnauthorized, "invalid_request", "invalid Authorization header format")
			return
		}
		token := strings.TrimSpace(parts[1])

		// Hash the token before DB lookup (tokens are stored as SHA-256 hashes)
		hashedToken := utils.HashToken(token)

		// Retrieve session using hashed token
		var session database.Session
		now := time.Now()
		if err := database.DB.Where("access_token = ? AND type = ? AND expires_at > ? AND access_token_expires_at > ?", hashedToken, "client", now, now).First(&session).Error; err != nil {
			writeBearerError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
			return
		}
		metadataChanged := database.SM.UpdateMetadata(&session, r)
		if metadataChanged || time.Since(session.LastSeenAt) >= time.Minute {
			session.LastSeenAt = now
			database.DB.Model(&session).Updates(map[string]interface{}{
				"last_seen_at": session.LastSeenAt,
				"device_info":  session.DeviceInfo,
				"ip_address":   session.IPAddress,
			})
		}

		// Verify user exists and is active
		if session.UserID == nil {
			writeBearerError(w, http.StatusUnauthorized, "invalid_token", "no user associated with token")
			return
		}

		var user database.User
		if err := database.DB.First(&user, *session.UserID).Error; err != nil {
			writeBearerError(w, http.StatusUnauthorized, "invalid_token", "user not found")
			return
		}
		if user.Status != "active" {
			writeBearerError(w, http.StatusForbidden, "access_denied", "account is suspended")
			return
		}

		// Verify client exists
		if session.ClientID == nil {
			writeBearerError(w, http.StatusUnauthorized, "invalid_token", "no client associated with token")
			return
		}

		var client database.Client
		if err := database.DB.First(&client, *session.ClientID).Error; err != nil {
			writeBearerError(w, http.StatusUnauthorized, "invalid_token", "client not found")
			return
		}

		// Add session, user ID, and client ID to context
		ctx := context.WithValue(r.Context(), database.SessionContextKey, &session)
		ctx = context.WithValue(ctx, userIDKey, *session.UserID)
		ctx = context.WithValue(ctx, clientIDKey, *session.ClientID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetClientID retrieves the client ID from the context
func GetClientID(r *http.Request) (uint64, error) {
	clientID, ok := r.Context().Value(clientIDKey).(uint64)
	if !ok {
		return 0, fmt.Errorf("client ID not found in context")
	}
	return clientID, nil
}

// RequireScope ensures the session has the required OAuth scope.
func RequireScope(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
		if !ok || session == nil {
			writeBearerError(w, http.StatusUnauthorized, "invalid_token", "session not found")
			return
		}

		if session.Scopes == nil {
			writeBearerError(w, http.StatusForbidden, "insufficient_scope", "no scopes authorized for this token")
			return
		}

		authorized := false
		scopes := strings.Fields(strings.ReplaceAll(*session.Scopes, ",", " "))
		for _, s := range scopes {
			if strings.TrimSpace(s) == scope {
				authorized = true
				break
			}
		}

		if !authorized {
			writeBearerError(w, http.StatusForbidden, "insufficient_scope", fmt.Sprintf("insufficient scope: %s required", scope))
			return
		}

		next.ServeHTTP(w, r)
	}
}
