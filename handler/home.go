package handler

import (
	"bytes"
	"gilosauth/database"
	"gilosauth/i18n"
	"gilosauth/middleware"
	"html/template"
	"log"
	"net/http"
)

// HomeHandler handles rendering the home page.
func HomeHandler(tmpls *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// UserID verified by middleware
		userID, err := middleware.GetUserID(r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Fetch full user data
		var user database.User
		if err := database.DB.First(&user, userID).Error; err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Get current session ID
		var currentSessionID uint64
		cookie, err := r.Cookie("session_token")
		if err == nil {
			var sess database.Session
			if err := database.DB.Where("cookie_token = ?", cookie.Value).First(&sess).Error; err == nil {
				currentSessionID = sess.ID
			}
		}

		// Generate CSRF token for the session
		var csrfToken string
		sess, err := middleware.GetSession(r)
		if err == nil {
			csrfToken, err = middleware.EnsureCSRFToken(sess)
			if err != nil {
				log.Printf("Failed to generate CSRF token: %v", err)
			}
		}

		// Get language preference
		lang := "en"
		if langCookie, err := r.Cookie("lang"); err == nil {
			lang = i18n.NormalizeCode(langCookie.Value)
		}

		tr := i18n.New(lang)

		// Render home page with full User and current session ID
		data := map[string]interface{}{
			"User":             user,
			"CurrentSessionID": currentSessionID,
			"ValidScopes":      middleware.Scopes,
			"Lang":             lang,
			"CurrentLanguage":  tr.Current(),
			"Languages":        tr.All(),
			"T":                i18n.GetTranslations(lang),
			"CSRFToken":        csrfToken,
		}

		// Buffer template execution to prevent partial writes on error
		var buf bytes.Buffer
		if err := tmpls.ExecuteTemplate(&buf, "home.html", data); err != nil {
			http.Error(w, "Could not render template", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		buf.WriteTo(w)
	}
}
