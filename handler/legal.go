package handler

import (
	"bytes"
	"gilosauth/config"
	"gilosauth/i18n"
	"html/template"
	"net/http"
	"time"
)

func renderLegalPage(tmpls *template.Template, pageType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			"AppVersion":      config.Version,
			"AppName":         config.AppName,
			"AppIDLabel":      config.AppIDLabel,
			"IssuerURL":       config.IssuerURL,
			"PageType":        pageType,
		}

		var buf bytes.Buffer
		if err := tmpls.ExecuteTemplate(&buf, "legal.html", data); err != nil {
			http.Error(w, "Template Error", http.StatusInternalServerError)
			return
		}
		buf.WriteTo(w)
	}
}

// TermsHandler serves the Terms of Service page.
func TermsHandler(tmpls *template.Template) http.HandlerFunc {
	return renderLegalPage(tmpls, "terms")
}

// PrivacyHandler serves the Privacy Policy page.
func PrivacyHandler(tmpls *template.Template) http.HandlerFunc {
	return renderLegalPage(tmpls, "privacy")
}

