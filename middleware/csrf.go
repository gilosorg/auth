package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"gilosauth/database"
	"gilosauth/utils"
	"net/http"
	"strings"
)

const csrfTokenKey = "csrf_token"
const csrfHeaderName = "X-CSRF-Token"
const csrfFormFieldName = "csrf_token"

// CSRFMiddleware validates CSRF tokens on state-changing requests.
// It skips:
//   - Safe methods (GET, HEAD, OPTIONS)
//   - API endpoints that use Bearer token authentication (/api/*)
//   - The OAuth token endpoint (/o/token) which authenticates via client_secret
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe methods don't need CSRF protection
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path

		// Skip CSRF for API endpoints (protected by Bearer tokens)
		if strings.HasPrefix(path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF for pre-authentication endpoints (no session/CSRF token exists yet)
		if strings.HasPrefix(path, "/auth/") {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF for OAuth token endpoint family (protected by client_secret, not cookies)
		if path == "/o/token" || path == "/o/introspect" || path == "/o/revoke" {
			next.ServeHTTP(w, r)
			return
		}

		// Skip health check
		if path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Get session to retrieve stored CSRF token
		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value == "" {
			// No session — most POST endpoints require a session anyway,
			// so let the downstream handler deal with auth
			next.ServeHTTP(w, r)
			return
		}

		sess, err := database.SM.Get(cookie.Value, "native")
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Get stored CSRF token from session
		storedToken, exists := database.SM.GetData(sess, csrfTokenKey)
		if !exists {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "CSRF token missing from session"})
			return
		}

		// Get submitted CSRF token (from header or form field)
		submittedToken := r.Header.Get(csrfHeaderName)
		if submittedToken == "" {
			// Try form field (for HTML form submissions)
			if err := r.ParseForm(); err == nil {
				submittedToken = r.FormValue(csrfFormFieldName)
			}
		}

		if submittedToken == "" {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "CSRF token required"})
			return
		}

		// Constant-time comparison
		if !utils.ConstantTimeOTPCompare(fmt.Sprint(storedToken), submittedToken) {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GenerateCSRFToken creates a cryptographically secure CSRF token.
func GenerateCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// EnsureCSRFToken generates and stores a CSRF token in the session if one doesn't exist.
// Returns the token for inclusion in forms/responses.
func EnsureCSRFToken(sess *database.Session) (string, error) {
	if existing, exists := database.SM.GetData(sess, csrfTokenKey); exists {
		return fmt.Sprint(existing), nil
	}

	token, err := GenerateCSRFToken()
	if err != nil {
		return "", err
	}

	if err := database.SM.SetData(sess, csrfTokenKey, token); err != nil {
		return "", fmt.Errorf("failed to store CSRF token: %w", err)
	}

	return token, nil
}
