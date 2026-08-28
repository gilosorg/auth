package middleware

import (
	"context"
	"fmt"
	"gilosauth/config"
	"gilosauth/database"
	"net/http"
	"net/url"
	"time"
)

// contextKey is a custom type to avoid collisions when using context.WithValue
type contextKey string

// Context keys for storing values in the request context
const (
	userIDKey   contextKey = "UserID"
	clientIDKey contextKey = "ClientID"
)

// RequireCookieToken ensures a user is logged in
func RequireCookieToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session from cookie
		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value == "" {
			// Encode the original RequestURI safely to preserve path + query params
			target := url.QueryEscape(r.RequestURI)
			http.Redirect(w, r, "/?target="+target, http.StatusSeeOther)
			return
		}

		// Retrieve session
		sess, err := database.SM.Get(cookie.Value, "native")
		if err != nil {
			// Clear the session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    "",
				Path:     "/",
				HttpOnly: true,
				Secure:   config.SecureCookies,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(-1 * time.Hour), // Expire immediately
			})
			// Encode target on invalid session
			target := url.QueryEscape(r.RequestURI)
			http.Redirect(w, r, "/?target="+target, http.StatusSeeOther)
			return
		}

		// Verify user exists
		if sess.UserID == nil {
			target := url.QueryEscape(r.RequestURI)
			http.Redirect(w, r, "/?target="+target, http.StatusSeeOther)
			return
		}

		var user database.User
		if err := database.DB.First(&user, *sess.UserID).Error; err != nil {
			// Clear the session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    "",
				Path:     "/",
				HttpOnly: true,
				Secure:   config.SecureCookies,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(-1 * time.Hour),
			})
			target := url.QueryEscape(r.RequestURI)
			http.Redirect(w, r, "/?target="+target, http.StatusSeeOther)
			return
		}

		// Add session and user ID to context
		ctx := context.WithValue(r.Context(), database.SessionContextKey, sess)
		ctx = context.WithValue(ctx, userIDKey, *sess.UserID)
		if sess.ClientID != nil {
			ctx = context.WithValue(ctx, clientIDKey, *sess.ClientID)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetUserID retrieves the user ID from the context
func GetUserID(r *http.Request) (uint64, error) {
	userID, ok := r.Context().Value(userIDKey).(uint64)
	if !ok {
		return 0, fmt.Errorf("user ID not found in context")
	}
	return userID, nil
}

// GetSession retrieves the session from the context
func GetSession(r *http.Request) (*database.Session, error) {
	sess, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok {
		return nil, fmt.Errorf("session not found in context")
	}
	return sess, nil
}
