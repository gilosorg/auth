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
	// Standard OIDC scopes (RFC 6749 / OIDC Core §5.4)
	"openid",
	"profile",
	"email",
	"phone",
	// Platform-specific scopes
	"user_sessions",
	"user_totps",
	"user_manage_account",
}

// IsValidScope checks if a given scope string is valid.
func IsValidScope(scope string) bool {
	return slices.Contains(Scopes, scope)
}

// RequireAccessToken ensures a valid access token is provided for API requests
func RequireAccessToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "missing Authorization header"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, `{"error": "invalid Authorization header format"}`, http.StatusUnauthorized)
			return
		}
		token := parts[1]

		// C5: Hash the token before DB lookup (tokens are stored as SHA-256 hashes)
		hashedToken := utils.HashToken(token)

		// Retrieve session using hashed token
		var session database.Session
		if err := database.DB.Where("access_token = ? AND type = ? AND expires_at > ? AND access_token_expires_at > ?", hashedToken, "client", time.Now(), time.Now()).First(&session).Error; err != nil {
			http.Error(w, `{"error": "invalid or expired access token"}`, http.StatusUnauthorized)
			return
		}
		database.SM.UpdateMetadata(&session, r)
		database.DB.Save(&session)

		// Verify user exists
		if session.UserID == nil {
			http.Error(w, `{"error": "no user associated with token"}`, http.StatusUnauthorized)
			return
		}

		var user database.User
		if err := database.DB.First(&user, *session.UserID).Error; err != nil {
			http.Error(w, `{"error": "user not found"}`, http.StatusUnauthorized)
			return
		}

		// Verify client exists
		if session.ClientID == nil {
			http.Error(w, `{"error": "no client associated with token"}`, http.StatusUnauthorized)
			return
		}

		var client database.Client
		if err := database.DB.First(&client, *session.ClientID).Error; err != nil {
			http.Error(w, `{"error": "client not found"}`, http.StatusUnauthorized)
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
			http.Error(w, `{"error": "session not found"}`, http.StatusUnauthorized)
			return
		}

		if session.Scopes == nil {
			http.Error(w, `{"error": "no scopes authorized for this token"}`, http.StatusForbidden)
			return
		}

		authorized := false
		scopes := strings.Fields(*session.Scopes)
		for _, s := range scopes {
			if strings.TrimSpace(s) == scope {
				authorized = true
				break
			}
		}

		if !authorized {
			http.Error(w, fmt.Sprintf(`{"error": "insufficient scope: %s required"}`, scope), http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}
