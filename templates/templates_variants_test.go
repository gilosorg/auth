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
		"IsLoggedIn":      false,
		"AppVersion":      "v1.0.0",
		"AppName":         "Gilos Auth",
		"AppIDLabel":      "Gilos Username",
		"IssuerURL":       "https://auth.example.com",
		"User":            nil,
		"Clients":         []database.Client{},
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
}

