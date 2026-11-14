package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"gilosauth/database"
	"gilosauth/middleware"
	"gilosauth/utils"

	"github.com/pquerna/otp/totp"
)

func TestTOTPFailureRemainingCountdown(t *testing.T) {
	env := setupHandlerTestEnv(t)

	totpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Gilos Auth",
		AccountName: "totpuser1",
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	encryptedSecret, err := utils.EncryptTOTPSecret(totpKey.Secret())
	if err != nil {
		t.Fatalf("EncryptTOTPSecret: %v", err)
	}

	user := createTestUser(t, "totpuser1", "ValidPass123!", "active")
	if err := database.DB.Model(&user).Updates(map[string]interface{}{
		"mfatotp_enabled": true,
		"totp_secret":     encryptedSecret,
	}).Error; err != nil {
		t.Fatalf("enable TOTP: %v", err)
	}

	wantMessages := []string{
		"4 attempts left",
		"3 attempts left",
		"2 attempts left",
		"1 attempt left",
	}

	for i, want := range wantMessages {
		body := strings.NewReader(`{"username":"totpuser1","password":"ValidPass123!","two_step_code":"000000"}`)
		req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		env.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d, want 400: %s", i+1, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("attempt %d error = %q, want substring %q", i+1, rec.Body.String(), want)
		}
	}

	// 5th failed TOTP attempt triggers security block (429)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"totpuser1","password":"ValidPass123!","two_step_code":"000000"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("5th attempt status = %d, want 429: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuthCommaScopesIssuesIDTokenNameClaimAndAuditsDenial(t *testing.T) {
	env := setupHandlerTestEnv(t)
	owner := createTestUser(t, "devowner1", "ValidPass123!", "active")
	endUser := createTestUser(t, "enduser1", "ValidPass123!", "active")
	cookie, csrfToken, _ := createNativeSessionCookie(t, endUser.ID)

	client := database.Client{
		UserID:       owner.ID,
		Name:         "Comma Scope App",
		Type:         "public",
		Scopes:       "openid,profile,email",
		RedirectURIs: "https://client.example.com/callback",
	}
	if err := database.DB.Create(&client).Error; err != nil {
		t.Fatalf("Create client: %v", err)
	}

	verifier := "test-pkce-verifier-with-sufficient-entropy-0123456789abcdef"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{
		"client_id":             {strconv.FormatUint(client.ID, 10)},
		"redirect_uri":          {"https://client.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid,profile"},
		"state":                 {"state-xyz-123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"nonce":                 {"nonce-abc-123"},
	}

	// 1. Test denial emits AuditOAuthDenied
	denyForm := url.Values{
		"approve":    {"false"},
		"csrf_token": {csrfToken},
	}
	denyReq := httptest.NewRequest(http.MethodPost, "/o/authorize?"+q.Encode(), strings.NewReader(denyForm.Encode()))
	denyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	denyReq.AddCookie(cookie)
	denyRec := httptest.NewRecorder()
	env.mux.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusFound {
		t.Fatalf("deny status = %d, want 302: %s", denyRec.Code, denyRec.Body.String())
	}

	var deniedCount int64
	database.DB.Model(&database.AuditLog{}).Where("user_id = ? AND event_type = ?", endUser.ID, database.AuditOAuthDenied).Count(&deniedCount)
	if deniedCount != 1 {
		t.Fatalf("AuditOAuthDenied count = %d, want 1", deniedCount)
	}

	// 2. Test approval with comma-separated scopes normalizes scopes & issues id_token
	approveForm := url.Values{
		"approve":    {"true"},
		"csrf_token": {csrfToken},
	}
	appReq := httptest.NewRequest(http.MethodPost, "/o/authorize?"+q.Encode(), strings.NewReader(approveForm.Encode()))
	appReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	appReq.AddCookie(cookie)
	appRec := httptest.NewRecorder()
	env.mux.ServeHTTP(appRec, appReq)
	if appRec.Code != http.StatusFound {
		t.Fatalf("approve status = %d, want 302: %s", appRec.Code, appRec.Body.String())
	}

	loc, err := url.Parse(appRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("expected auth code in redirect: %s", loc.String())
	}

	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example.com/callback"},
		"client_id":     {strconv.FormatUint(client.ID, 10)},
		"code_verifier": {verifier},
	}
	tokReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(tokForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	env.mux.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("POST /o/token = %d, want 200: %s", tokRec.Code, tokRec.Body.String())
	}

	var tokResp map[string]interface{}
	if err := json.Unmarshal(tokRec.Body.Bytes(), &tokResp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	if tokResp["id_token"] == "" || tokResp["id_token"] == nil {
		t.Fatalf("expected id_token for comma-separated openid,profile request; resp=%v", tokResp)
	}
	if tokResp["scope"] != "openid profile" {
		t.Fatalf("normalized scope = %q, want %q", tokResp["scope"], "openid profile")
	}

	// Verify /api/userinfo includes standard OIDC "name" claim under profile scope
	accessToken, _ := tokResp["access_token"].(string)
	uiReq := httptest.NewRequest(http.MethodGet, "/api/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+accessToken)
	uiRec := httptest.NewRecorder()
	env.mux.ServeHTTP(uiRec, uiReq)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("GET /api/userinfo = %d, want 200: %s", uiRec.Code, uiRec.Body.String())
	}
	var uiResp map[string]interface{}
	if err := json.Unmarshal(uiRec.Body.Bytes(), &uiResp); err != nil {
		t.Fatalf("unmarshal userinfo: %v", err)
	}
	if uiResp["name"] != "Test User" {
		t.Fatalf("userinfo name = %v, want %q", uiResp["name"], "Test User")
	}
}

func TestClientAuditMethodChecksAndSessionFiltering(t *testing.T) {
	env := setupHandlerTestEnv(t)
	user := createTestUser(t, "audituser1", "ValidPass123!", "active")
	cookie, csrfToken, _ := createNativeSessionCookie(t, user.ID)

	// 1. POST /clients should emit AuditClientCreated
	form := url.Values{
		"name":          {"Audited Client"},
		"type":          {"public"},
		"redirect_uris": {"https://audited.example.com/cb"},
		"openid":        {"on"},
	}
	cReq := httptest.NewRequest(http.MethodPost, "/clients", strings.NewReader(form.Encode()))
	cReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cReq.Header.Set("X-CSRF-Token", csrfToken)
	cReq.AddCookie(cookie)
	cRec := httptest.NewRecorder()
	env.mux.ServeHTTP(cRec, cReq)
	if cRec.Code != http.StatusOK {
		t.Fatalf("POST /clients = %d: %s", cRec.Code, cRec.Body.String())
	}

	var clientAudit int64
	database.DB.Model(&database.AuditLog{}).Where("user_id = ? AND event_type = ?", user.ID, database.AuditClientCreated).Count(&clientAudit)
	if clientAudit != 1 {
		t.Fatalf("AuditClientCreated count = %d, want 1", clientAudit)
	}

	// 2. OAuth token endpoints must reject GET requests
	for _, path := range []string{"/o/token", "/o/introspect", "/o/revoke"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		switch path {
		case "/o/token":
			OAuthTokenHandler(rec, req)
		case "/o/introspect":
			OAuthIntrospectHandler(rec, req)
		case "/o/revoke":
			OAuthRevokeHandler(rec, req)
		}
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s status = %d, want 405", path, rec.Code)
		}
	}

	// 3. SessionsHandler excludes expired sessions and clamps TotalPages >= 1
	expiredSess := database.Session{
		UserID:     &user.ID,
		Type:       "client",
		LastSeenAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	}
	if err := database.DB.Create(&expiredSess).Error; err != nil {
		t.Fatalf("create expired session: %v", err)
	}

	sMux := http.NewServeMux()
	sMux.HandleFunc("GET /sessions", middleware.RequireCookieToken(SessionsHandler))
	sMux.HandleFunc("POST /profile/username", middleware.RequireCookieToken(UsernameUpdateHandler))

	sReq := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	sReq.AddCookie(cookie)
	sRec := httptest.NewRecorder()
	sMux.ServeHTTP(sRec, sReq)
	if sRec.Code != http.StatusOK {
		t.Fatalf("GET /sessions = %d: %s", sRec.Code, sRec.Body.String())
	}
	var sResp struct {
		Data       []database.SessionResponse `json:"data"`
		Pagination Pagination                 `json:"pagination"`
	}
	if err := json.Unmarshal(sRec.Body.Bytes(), &sResp); err != nil {
		t.Fatalf("unmarshal sessions response: %v", err)
	}
	if sResp.Pagination.Total != 1 || sResp.Pagination.TotalPages != 1 {
		t.Fatalf("sessions pagination = %+v, want total=1, total_pages=1", sResp.Pagination)
	}

	// 4. POST /profile/username logs AuditUsernameChanged
	uReq := httptest.NewRequest(http.MethodPost, "/profile/username", strings.NewReader(`{"username":"audituser1new"}`))
	uReq.Header.Set("Content-Type", "application/json")
	uReq.Header.Set("X-Current-Password", "ValidPass123!")
	uReq.Header.Set("X-CSRF-Token", csrfToken)
	uReq.AddCookie(cookie)
	uRec := httptest.NewRecorder()
	sMux.ServeHTTP(uRec, uReq)
	if uRec.Code != http.StatusOK {
		t.Fatalf("POST /profile/username = %d: %s", uRec.Code, uRec.Body.String())
	}

	var unameAudit int64
	database.DB.Model(&database.AuditLog{}).Where("user_id = ? AND event_type = ?", user.ID, database.AuditUsernameChanged).Count(&unameAudit)
	if unameAudit != 1 {
		t.Fatalf("AuditUsernameChanged count = %d, want 1", unameAudit)
	}
}
