package middleware

import (
	"context"
	"fmt"
	"gilosauth/database"
	"gilosauth/utils"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// contextKey is a custom type to avoid collisions when using context.WithValue
type contextKey string

// Context keys for storing values in the request context
const (
	userIDKey   contextKey = "UserID"
	clientIDKey contextKey = "ClientID"
)

func isAPIOrAjaxRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	if r.Header.Get("X-CSRF-Token") != "" || r.Header.Get("X-Current-Password") != "" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

func rejectUnauthenticatedCookie(w http.ResponseWriter, r *http.Request, clearCookie bool) {
	if clearCookie {
		database.SetSessionCookieHelper(w, "", time.Now().Add(-1*time.Hour))
	}
	if isAPIOrAjaxRequest(r) {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	target := url.QueryEscape(r.RequestURI)
	http.Redirect(w, r, "/?target="+target, http.StatusSeeOther)
}

// RequireCookieToken ensures a user is logged in and active.
func RequireCookieToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session from cookie
		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value == "" {
			rejectUnauthenticatedCookie(w, r, false)
			return
		}

		// Retrieve session
		sess, err := database.SM.Get(cookie.Value, "native", r)
		if err != nil {
			rejectUnauthenticatedCookie(w, r, true)
			return
		}

		// Verify user exists
		if sess.UserID == nil {
			rejectUnauthenticatedCookie(w, r, false)
			return
		}

		var user database.User
		if err := database.DB.First(&user, *sess.UserID).Error; err != nil {
			_ = database.SM.Destroy(sess)
			rejectUnauthenticatedCookie(w, r, true)
			return
		}

		if user.Status == "suspended" {
			_ = database.SM.Destroy(sess)
			database.SetSessionCookieHelper(w, "", time.Now().Add(-1*time.Hour))
			if isAPIOrAjaxRequest(r) {
				utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
				return
			}
			http.Redirect(w, r, "/?error=suspended", http.StatusSeeOther)
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
