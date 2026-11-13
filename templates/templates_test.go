package templates

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"gilosauth/database"
	"gilosauth/i18n"
)

func TestParseAndExecuteTemplates(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(".."); err != nil {
		t.Fatalf("Chdir repo root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	if err := i18n.Init(); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}

	tmpls, err := ParseTemplates()
	if err != nil {
		t.Fatalf("ParseTemplates failed: %v", err)
	}

	tr := i18n.New("en")
	translations := i18n.GetTranslations("en")

	user := &database.User{
		ID:            42,
		Username:      "alice123",
		Email:         "alice@example.com",
		EmailVerified: true,
		Phone:         998901234567,
		FirstName:     "Alice",
		LastName:      "Smith",
		Status:        "active",
	}

	client := database.Client{
		ID:           7,
		Name:         "Sample App",
		Type:         "public",
		RedirectURIs: "https://app.example.com/callback",
		Scopes:       "openid,profile,email",
	}

	type scopeDetail struct {
		ID          string
		Description string
		MaskedValue string
		IsRequired  bool
		IsMissing   bool
	}

	cases := []struct {
		name string
		data map[string]interface{}
	}{
		{
			name: "auth.html",
			data: map[string]interface{}{
				"Year":            2026,
				"Lang":            "en",
				"CurrentLanguage": tr.Current(),
				"Languages":       tr.All(),
				"T":               translations,
				"AppVersion":      "v1.0.0",
				"AppName":         "Gilos Auth",
				"AppIDLabel":      "Gilos ID",
				"AuthError":       "Your account has been suspended",
			},
		},
		{
			name: "home.html",
			data: map[string]interface{}{
				"Year":             2026,
				"User":             user,
				"CurrentSessionID": uint64(1),
				"ValidScopes":      []string{"openid", "profile", "email", "phone"},
				"Lang":             "en",
				"CurrentLanguage":  tr.Current(),
				"Languages":        tr.All(),
				"T":                translations,
				"CSRFToken":        "csrf-test-token",
				"AppVersion":       "v1.0.0",
				"AppName":          "Gilos Auth",
			},
		},
		{
			name: "oauth.html",
			data: map[string]interface{}{
				"Year":               2026,
				"Client":             client,
				"ScopeDetails":       []scopeDetail{{ID: "profile", Description: "View profile", MaskedValue: "Alice", IsRequired: true}},
				"RedirectURI":        "https://app.example.com/callback",
				"State":              "xyzstate",
				"ValidScopes":        []string{"openid", "profile", "email"},
				"Lang":               "en",
				"CurrentLanguage":    tr.Current(),
				"Languages":          tr.All(),
				"T":                  translations,
				"AppVersion":         "v1.0.0",
				"AppName":            "Gilos Auth",
				"Error":              "",
				"User":               user,
				"HasMissingRequired": false,
				"MissingFields":      []string{},
				"CSRFToken":          "csrf-test-token",
			},
		},
		{
			name: "docs.html",
			data: map[string]interface{}{
				"Year":            2026,
				"Lang":            "en",
				"CurrentLanguage": tr.Current(),
				"Languages":       tr.All(),
				"T":               translations,
				"IsLoggedIn":      true,
				"AppVersion":      "v1.0.0",
				"AppName":         "Gilos Auth",
				"AppIDLabel":      "Gilos ID",
				"IssuerURL":       "https://auth.example.com",
				"User":            user,
				"Clients":         []database.Client{client},
			},
		},
		{
			name: "legal.html",
			data: map[string]interface{}{
				"Year":            2026,
				"Lang":            "en",
				"CurrentLanguage": tr.Current(),
				"Languages":       tr.All(),
				"T":               translations,
				"AppVersion":      "v1.0.0",
				"AppName":         "Gilos Auth",
				"AppIDLabel":      "Gilos ID",
				"IssuerURL":       "https://auth.example.com",
				"PageType":        "terms",
			},
		},
		{
			name: "legal.html",
			data: map[string]interface{}{
				"Year":            2026,
				"Lang":            "uz",
				"CurrentLanguage": i18n.New("uz").Current(),
				"Languages":       i18n.New("uz").All(),
				"T":               i18n.GetTranslations("uz"),
				"AppVersion":      "v1.0.0",
				"AppName":         "Gilos Auth",
				"AppIDLabel":      "Gilos ID",
				"IssuerURL":       "https://auth.example.com",
				"PageType":        "privacy",
			},
		},
	}

	for _, tc := range cases {
		var buf bytes.Buffer
		if err := tmpls.ExecuteTemplate(&buf, tc.name, tc.data); err != nil {
			t.Errorf("ExecuteTemplate(%q) failed: %v", tc.name, err)
			continue
		}
		out := buf.String()
		if strings.Contains(out, "<no value>") {
			t.Errorf("template %q rendered '<no value>'", tc.name)
		}
		if len(out) == 0 {
			t.Errorf("template %q rendered empty output", tc.name)
		}
	}
}

