package templates

import (
	"bytes"
	"gilosauth/database"
	"gilosauth/i18n"
	"gilosauth/middleware"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTemplateVariantsAndMissingPlaceholders(t *testing.T) {
	origWD, err := os.Getwd()
	if err == nil {
		if _, statErr := os.Stat("templates"); statErr != nil {
			if chErr := os.Chdir(".."); chErr == nil {
				t.Cleanup(func() { _ = os.Chdir(origWD) })
			}
		}
	}

	if err := i18n.Init(); err != nil {
		t.Fatalf("i18n.Init: %v", err)
	}
	tmpls, err := ParseTemplates()
	if err != nil {
		t.Fatalf("ParseTemplates: %v", err)
	}

	tr := i18n.New("en")
	trans := i18n.GetTranslations("en")

	// 1. home.html with pending_deletion user and AppIDLabel: "Gilos Username"
	homeUser := database.User{
		ID:              1,
		Username:        "pendinguser",
		FirstName:       "Pending",
		LastName:        "User",
		Email:           "pending@example.com",
		Phone:           998901234567,
		Status:          "pending_deletion",
		MFAEmailEnabled: true,
	}
	homeData := map[string]interface{}{
		"Year":             time.Now().Year(),
		"User":             homeUser,
		"CurrentSessionID": uint64(1),
		"ValidScopes":      middleware.Scopes,
		"Lang":             "en",
		"CurrentLanguage":  tr.Current(),
		"Languages":        tr.All(),
		"T":                trans,
		"CSRFToken":        "csrf-token-value",
		"AppVersion":       "v1.0.0",
		"AppName":          "Gilos Auth",
		"AppIDLabel":       "Gilos Username",
	}
	var homeBuf bytes.Buffer
	if err := tmpls.ExecuteTemplate(&homeBuf, "home.html", homeData); err != nil {
		t.Fatalf("ExecuteTemplate(home.html): %v", err)
	}
	homeOut := homeBuf.String()
	if strings.Contains(homeOut, "<no value>") {
		t.Errorf("home.html rendered <no value>")
	}
	if !strings.Contains(homeOut, "Gilos Username") {
		t.Errorf("home.html output missing AppIDLabel 'Gilos Username'")
	}
	if !strings.Contains(homeOut, "global-deletion-banner") {
		t.Errorf("home.html output missing global-deletion-banner")
	}

	// 2. legal.html with IsLoggedIn=true vs IsLoggedIn=false
	for _, loggedIn := range []bool{true, false} {
		legalData := map[string]interface{}{
			"Year":            time.Now().Year(),
			"Lang":            "en",
			"CurrentLanguage": tr.Current(),
			"Languages":       tr.All(),
			"T":               trans,
			"AppVersion":      "v1.0.0",
			"AppName":         "Gilos Auth",
			"AppIDLabel":      "Gilos Username",
			"IssuerURL":       "https://auth.example.com",
			"PageType":        "terms",
			"IsLoggedIn":      loggedIn,
		}
		var legalBuf bytes.Buffer
		if err := tmpls.ExecuteTemplate(&legalBuf, "legal.html", legalData); err != nil {
			t.Fatalf("ExecuteTemplate(legal.html IsLoggedIn=%v): %v", loggedIn, err)
		}
		legalOut := legalBuf.String()
		if strings.Contains(legalOut, "<no value>") {
			t.Errorf("legal.html (IsLoggedIn=%v) rendered <no value>", loggedIn)
		}
		if loggedIn {
			if !strings.Contains(legalOut, `href="/home" class="legal-nav-link"`) {
				t.Errorf("legal.html (IsLoggedIn=true) missing /home nav link")
			}
			if strings.Contains(legalOut, `href="/" class="legal-nav-link"`) {
				t.Errorf("legal.html (IsLoggedIn=true) unexpectedly rendered / nav link")
			}
		} else {
			if !strings.Contains(legalOut, `href="/" class="legal-nav-link"`) {
				t.Errorf("legal.html (IsLoggedIn=false) missing / nav link")
			}
			if strings.Contains(legalOut, `href="/home" class="legal-nav-link"`) {
				t.Errorf("legal.html (IsLoggedIn=false) unexpectedly rendered /home nav link")
			}
		}
	}

	// 3. docs.html with IsLoggedIn=false
	docsData := map[string]interface{}{
		"Year":            time.Now().Year(),
		"Lang":            "en",
		"CurrentLanguage": tr.Current(),
		"Languages":       tr.All(),
		"T":               trans,
		"IsLoggedIn":      true,
		"AppVersion":      "v1.0.0",
		"AppName":         "Gilos Auth",
		"AppIDLabel":      "Gilos Username",
		"IssuerURL":       "https://auth.example.com",
		"User":            database.User{ID: 1, Username: "alice", FirstName: "Alice"},
		"Clients": []database.Client{
			{ID: 1, Type: "confidential", Name: "Sample App", RedirectURIs: "https://app.example.com/cb", Scopes: "openid,profile"},
		},
	}
	var docsBuf bytes.Buffer
	if err := tmpls.ExecuteTemplate(&docsBuf, "docs.html", docsData); err != nil {
		t.Fatalf("ExecuteTemplate(docs.html): %v", err)
	}
	docsOut := docsBuf.String()
	if strings.Contains(docsOut, "<no value>") {
		t.Errorf("docs.html rendered <no value>")
	}
	if !strings.Contains(docsOut, "/media/user/icon/avatar.png") {
		t.Errorf("docs.html missing /media/user/icon/avatar.png example URL")
	}
	if !strings.Contains(docsOut, "error_description") {
		t.Errorf("docs.html missing error_description field in error response example")
	}
	if !strings.Contains(docsOut, "docsFilterClearBtn") || !strings.Contains(docsOut, "clearRedirectUrlBtn") {
		t.Errorf("docs.html missing filter/redirect clear controls")
	}
}

func TestRenderedHTMLHeadStructureAndOAuthAvatar(t *testing.T) {
	origWD, err := os.Getwd()
	if err == nil {
		if _, statErr := os.Stat("templates"); statErr != nil {
			if chErr := os.Chdir(".."); chErr == nil {
				t.Cleanup(func() { _ = os.Chdir(origWD) })
			}
		}
	}

	if err := i18n.Init(); err != nil {
		t.Fatalf("i18n.Init: %v", err)
	}
	tmpls, err := ParseTemplates()
	if err != nil {
		t.Fatalf("ParseTemplates: %v", err)
	}

	tr := i18n.New("en")
	trans := i18n.GetTranslations("en")
	mockUser := database.User{
		ID:        42,
		Username:  "alice",
		FirstName: "Alice",
		Icon:      "/media/user/icon/42_sample.jpg",
	}

	baseData := func() map[string]interface{} {
		return map[string]interface{}{
			"Year":               time.Now().Year(),
			"Lang":               "en",
			"CurrentLanguage":    tr.Current(),
			"Languages":          tr.All(),
			"T":                  trans,
			"AppVersion":         "v1.0.0",
			"AppName":            "Gilos Auth",
			"AppIDLabel":         "Gilos Username",
			"IssuerURL":          "https://auth.example.com",
			"User":               mockUser,
			"CurrentSessionID":   uint64(1),
			"ValidScopes":        middleware.Scopes,
			"CSRFToken":          "csrf-test",
			"Client":             database.Client{ID: 1, Name: "Test App"},
			"ScopeDetails":       []map[string]interface{}{},
			"RedirectURI":        "https://app.example.com/callback",
			"State":              "xyz",
			"Error":              "",
			"HasMissingRequired": false,
			"MissingFields":      []string{},
			"AuthError":          "",
			"PageType":           "terms",
			"IsLoggedIn":         true,
			"Clients":            []database.Client{},
		}
	}

	for _, name := range []string{"auth.html", "home.html", "oauth.html", "docs.html", "legal.html"} {
		var buf bytes.Buffer
		if err := tmpls.ExecuteTemplate(&buf, name, baseData()); err != nil {
			t.Fatalf("ExecuteTemplate(%s): %v", name, err)
		}
		out := buf.String()
		if cnt := strings.Count(out, "<head>"); cnt != 1 {
			t.Errorf("%s expected exactly 1 <head>, got %d", name, cnt)
		}
		if cnt := strings.Count(out, "</head>"); cnt != 1 {
			t.Errorf("%s expected exactly 1 </head>, got %d", name, cnt)
		}
		headEnd := strings.Index(out, "</head>")
		bodyStart := strings.Index(out, "<body>")
		if headEnd == -1 || bodyStart == -1 || headEnd > bodyStart {
			t.Errorf("%s invalid </head> before <body> placement (headEnd=%d, bodyStart=%d)", name, headEnd, bodyStart)
		}
		firstStyle := strings.Index(out, "<style>")
		if firstStyle != -1 && firstStyle > headEnd {
			t.Errorf("%s page <style> appeared after </head>", name)
		}
		if strings.Contains(out, "<no value>") {
			t.Errorf("%s rendered <no value>", name)
		}
		if name == "auth.html" && strings.Contains(out, "auth-logo-frame") {
			t.Errorf("auth.html unexpectedly rendered auth-logo-frame")
		}
		if name == "oauth.html" && strings.Contains(out, "oauth-logo-frame") {
			t.Errorf("oauth.html unexpectedly rendered oauth-logo-frame")
		}
		if name == "auth.html" && !strings.Contains(out, "@media (max-width: 560px)") {
			t.Errorf("auth.html missing mobile cardless breakpoint")
		}
		if name == "oauth.html" && !strings.Contains(out, "@media (max-width: 560px)") {
			t.Errorf("oauth.html missing mobile cardless breakpoint")
		}
		if name == "oauth.html" && !strings.Contains(out, `data-icon="/media/user/icon/42_sample.jpg"`) {
			t.Errorf("oauth.html did not preserve User.Icon on #oauth-user-avatar")
		}
		if (name == "auth.html" || name == "home.html") && strings.Contains(out, `<span class="gilos-input-addon" aria-hidden="true">@</span>`) {
			t.Errorf("%s unexpectedly rendered raw @ username addon instead of Fluent UI icon", name)
		}
		if (name == "auth.html" || name == "home.html") && !strings.Contains(out, `gilos-input-addon--icon`) {
			t.Errorf("%s missing Fluent UI icon addon class gilos-input-addon--icon", name)
		}
		if name == "home.html" {
			if !strings.Contains(out, "renderPaginationFooter") || !strings.Contains(out, "session-active-state") {
				t.Errorf("home.html missing aligned pagination footer or session-active-state styling")
			}
			if !strings.Contains(out, `showing_of_total`) || !strings.Contains(out, `active_now`) {
				t.Errorf("home.html missing pagination/active status translation keys")
			}
		}
	}
}
