package handler

import (
	"bytes"
	"gilosauth/database"
	"gilosauth/i18n"
	"html/template"
	"net/http"
	"time"
)

// DocsHandler handles rendering the documentation page with interactive features.
// The page is accessible to everyone but provides enhanced features for logged-in users.
func DocsHandler(tmpls *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get language preference or default to en
		lang := "en"
		if langCookie, err := r.Cookie("lang"); err == nil {
			lang = i18n.NormalizeCode(langCookie.Value)
		}

		tr := i18n.New(lang)
		data := map[string]interface{}{
			"Year":            time.Now().Year(),
			"Lang":            lang,
			"CurrentLanguage": tr.Current(),
			"Languages":       tr.All(),
			"T":               i18n.GetTranslations(lang),
			"IsLoggedIn":      false,
			"AppVersion":      config.Version,
			"User":            nil,
			"Clients":         []database.Client{},
		}

		// Try to get session from cookie (without requiring login)
		cookie, err := r.Cookie("session_token")
		if err == nil && cookie.Value != "" {
			if sess, err := database.SM.Get(cookie.Value, "native"); err == nil && sess.UserID != nil {
				// User is logged in
				var user database.User
				if err := database.DB.First(&user, *sess.UserID).Error; err == nil {
					data["IsLoggedIn"] = true
					data["User"] = user

					// Fetch user's OAuth clients — create safe DTOs that exclude the hashed secret
					var clients []database.Client
					database.DB.Where("user_id = ?", *sess.UserID).Find(&clients)

					// Build safe client list for template (only expose SecretPrefix, never the hash)
					type SafeClient struct {
						ID             uint64
						Name           string
						Type           string
						SecretPrefix   string
						RedirectURIs   string
						Scopes         string
						RequiredScopes string
					}
					safeClients := make([]SafeClient, len(clients))
					for i, c := range clients {
						safeClients[i] = SafeClient{
							ID:             c.ID,
							Name:           c.Name,
							Type:           c.Type,
							SecretPrefix:   c.SecretPrefix,
							RedirectURIs:   c.RedirectURIs,
							Scopes:         c.Scopes,
							RequiredScopes: c.RequiredScopes,
						}
					}
					data["Clients"] = safeClients
				}
			}
		}

		// Buffer template execution to prevent partial writes
		var buf bytes.Buffer
		if err := tmpls.ExecuteTemplate(&buf, "docs.html", data); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Write buffer to response
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		buf.WriteTo(w)
	}
}
