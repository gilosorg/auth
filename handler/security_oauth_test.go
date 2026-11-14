package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gilosauth/config"
	"gilosauth/database"
	"gilosauth/i18n"
	"gilosauth/middleware"
	"gilosauth/templates"
	"gilosauth/utils"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type testEnv struct {
	mux   http.Handler
	tmpls *template.Template
}

func setupHandlerTestEnv(t *testing.T) *testEnv {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(".."); err != nil {
		t.Fatalf("Chdir repo root: %v", err)
	}

	origDBPath := config.DBPath
	origDB := database.DB
	origSM := database.SM
	origEncKey := config.EncryptionKey
	origBcrypt := config.BcryptCost
	origIssuer := config.IssuerURL
	origAppName := config.AppName
	origAppIDLabel := config.AppIDLabel
	origSecure := config.SecureCookies
	origRSA := utils.RSAPrivateKey
	origJWK := utils.JWK

	config.DBPath = filepath.Join(t.TempDir(), "handler_test.db")
	config.EncryptionKey = strings.Repeat("1a", 32)
	config.BcryptCost = bcrypt.MinCost
	config.IssuerURL = "https://auth.example.com"
	config.AppName = "Gilos Auth"
	config.AppIDLabel = "Gilos Username"
	config.SecureCookies = false
	config.Version = "v1.0.0-test"

	if err := i18n.Init(); err != nil {
		t.Fatalf("i18n.Init: %v", err)
	}

	database.InitDatabase()
	if err := database.MigrateDatabase(); err != nil {
		t.Fatalf("MigrateDatabase: %v", err)
	}
	database.InitSessionManager()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	utils.RSAPrivateKey = privKey
	pubKey := privKey.Public().(*rsa.PublicKey)
	utils.JWK = map[string]interface{}{
		"kty": "RSA",
		"kid": utils.KeyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}

	tmpls, err := templates.ParseTemplates()
	if err != nil {
		t.Fatalf("ParseTemplates: %v", err)
	}

	t.Cleanup(func() {
		if database.DB != nil {
			if sqlDB, err := database.DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}
		config.DBPath = origDBPath
		database.DB = origDB
		database.SM = origSM
		config.EncryptionKey = origEncKey
		config.BcryptCost = origBcrypt
		config.IssuerURL = origIssuer
		config.AppName = origAppName
		config.AppIDLabel = origAppIDLabel
		config.SecureCookies = origSecure
		utils.RSAPrivateKey = origRSA
		utils.JWK = origJWK
		_ = os.Chdir(wd)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /terms", TermsHandler(tmpls))
	mux.HandleFunc("GET /privacy", PrivacyHandler(tmpls))
	mux.HandleFunc("GET /home", middleware.RequireCookieToken(HomeHandler(tmpls)))
	mux.HandleFunc("GET /profile", middleware.RequireCookieToken(ProfileHandler))
	mux.HandleFunc("GET /profile/contact/pending", middleware.RequireCookieToken(ProfileContactPendingHandler))
	mux.HandleFunc("GET /profile/delete/status", middleware.RequireCookieToken(DeletionStatusHandler))
	mux.HandleFunc("GET /auth/check-user", CheckUserHandler)
	mux.HandleFunc("POST /auth/login", LoginHandler)
	mux.HandleFunc("GET /auth/state", AuthStateHandler)
	mux.HandleFunc("POST /auth/state", AuthStateHandler)
	mux.HandleFunc("POST /auth/logout", LogoutHandler)
	mux.HandleFunc("GET /clients", middleware.RequireCookieToken(ClientsHandler))
	mux.HandleFunc("POST /clients", middleware.RequireCookieToken(ClientsHandler))
	mux.HandleFunc("GET /o/authorize", middleware.RequireCookieToken(OAuthAuthorizeHandler(tmpls)))
	mux.HandleFunc("POST /o/authorize", middleware.RequireCookieToken(OAuthAuthorizeHandler(tmpls)))
	mux.HandleFunc("POST /o/token", OAuthTokenHandler)
	mux.HandleFunc("POST /o/introspect", OAuthIntrospectHandler)
	mux.HandleFunc("POST /o/revoke", OAuthRevokeHandler)
	mux.HandleFunc("GET /api/userinfo", middleware.RequireAccessToken(UserInfoHandler))
	mux.HandleFunc("POST /api/userinfo", middleware.RequireAccessToken(UserInfoHandler))

	return &testEnv{
		mux:   middleware.CSRFMiddleware(mux),
		tmpls: tmpls,
	}
}

func createTestUser(t *testing.T, username, password, status string) database.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	user := database.User{
		Username:      username,
		Email:         username + "@example.com",
		EmailVerified: true,
		Password:      string(hash),
		FirstName:     "Test",
		LastName:      "User",
		Icon:          "/uploads/icons/" + username + ".png",
		Status:        status,
	}
	if err := database.DB.Create(&user).Error; err != nil {
		t.Fatalf("Create user %s: %v", username, err)
	}
	return user
}

func createNativeSessionCookie(t *testing.T, userID uint64) (*http.Cookie, string, *database.Session) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, err := database.SM.Start(req.Context(), rec, req, nil)
	if err != nil {
		t.Fatalf("SM.Start: %v", err)
	}
	if err := database.SM.SetUser(sess, userID); err != nil {
		t.Fatalf("SM.SetUser: %v", err)
	}
	csrfToken, err := middleware.EnsureCSRFToken(sess)
	if err != nil {
		t.Fatalf("EnsureCSRFToken: %v", err)
	}
	return &http.Cookie{Name: "session_token", Value: *sess.CookieToken}, csrfToken, sess
}

func pkcePair(verifier string) (string, string) {
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestLegalPagesRender(t *testing.T) {
	env := setupHandlerTestEnv(t)

	for _, tc := range []struct {
		path    string
		snippet string
	}{
		{"/terms", "Terms of Service"},
		{"/privacy", "Privacy Policy"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		env.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", tc.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), tc.snippet) {
			t.Errorf("GET %s body missing %q", tc.path, tc.snippet)
		}
	}
}

func TestLogoutDeletesSessionAndEnforcesCSRF(t *testing.T) {
	env := setupHandlerTestEnv(t)
	user := createTestUser(t, "logoutuser1", "ValidPass123!", "active")
	cookie, csrfToken, sess := createNativeSessionCookie(t, user.ID)

	// Cookie POST /auth/logout without CSRF token must be blocked
	reqNoCSRF := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	reqNoCSRF.AddCookie(cookie)
	recNoCSRF := httptest.NewRecorder()
	env.mux.ServeHTTP(recNoCSRF, reqNoCSRF)
	if recNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("POST /auth/logout without CSRF = %d, want 403", recNoCSRF.Code)
	}

	// Session must still exist in DB
	var count int64
	database.DB.Model(&database.Session{}).Where("id = ?", sess.ID).Count(&count)
	if count != 1 {
		t.Fatalf("expected session to remain after rejected logout, count=%d", count)
	}

	// Cookie POST /auth/logout with valid CSRF token must delete session
	reqOK := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	reqOK.AddCookie(cookie)
	reqOK.Header.Set("X-CSRF-Token", csrfToken)
	recOK := httptest.NewRecorder()
	env.mux.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("POST /auth/logout with CSRF = %d, want 200: %s", recOK.Code, recOK.Body.String())
	}

	database.DB.Model(&database.Session{}).Where("id = ?", sess.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected session to be deleted on logout, count=%d", count)
	}
}

func TestBruteForceTrackingAndBlocking(t *testing.T) {
	env := setupHandlerTestEnv(t)
	_ = createTestUser(t, "bruteforce1", "CorrectPass123!", "active")

	for i := 0; i < 5; i++ {
		body := strings.NewReader(`{"username":"bruteforce1","password":"WrongPassword1"}`)
		req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		env.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, rec.Code)
		}
	}

	// 6th attempt should be blocked even with correct password
	body := strings.NewReader(`{"username":"bruteforce1","password":"CorrectPass123!"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt status = %d, want 429: %s", rec.Code, rec.Body.String())
	}
}

func TestClientRegistrationRedirectURIValidation(t *testing.T) {
	env := setupHandlerTestEnv(t)
	user := createTestUser(t, "devuser1", "ValidPass123!", "active")
	cookie, csrfToken, _ := createNativeSessionCookie(t, user.ID)

	badURIs := []string{
		"http://app.example.com/cb",
		"https://app.example.com/cb#fragment",
		"javascript:alert(1)",
	}
	for _, uri := range badURIs {
		form := url.Values{
			"name":          {"Bad Client"},
			"type":          {"public"},
			"redirect_uris": {uri},
			"profile":       {"on"},
		}
		req := httptest.NewRequest(http.MethodPost, "/clients", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		env.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST /clients with bad URI %q = %d, want 400", uri, rec.Code)
		}
	}

	goodForm := url.Values{
		"name":          {"Good Client"},
		"type":          {"public"},
		"redirect_uris": {"https://app.example.com/callback"},
		"openid":        {"on"},
		"profile":       {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/clients", strings.NewReader(goodForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("POST /clients with valid URI = %d, want 200/201: %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth21PKCEOIDCAndBearerErrors(t *testing.T) {
	env := setupHandlerTestEnv(t)
	user := createTestUser(t, "oauthuser1", "ValidPass123!", "active")
	cookie, csrfToken, _ := createNativeSessionCookie(t, user.ID)

	// Confidential client with secret
	clientSecret := "super-secret-value-123"
	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	secretStr := string(secretHash)
	client := database.Client{
		Name:         "Confidential OIDC Client",
		Secret:       &secretStr,
		SecretPrefix: clientSecret[:8],
		UserID:       user.ID,
		Type:         "confidential",
		RedirectURIs: "https://client.example.com/cb",
		Scopes:       "openid,profile,email",
	}
	if err := database.DB.Create(&client).Error; err != nil {
		t.Fatalf("Create client: %v", err)
	}

	verifier, challenge := pkcePair("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	redirectURI := "https://client.example.com/cb"

	// 1. /o/authorize rejects missing PKCE or non-S256
	reqNoPKCE := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/o/authorize?client_id=%d&redirect_uri=%s&response_type=code&scope=openid+profile+email&state=st1",
			client.ID, url.QueryEscape(redirectURI)), nil)
	reqNoPKCE.AddCookie(cookie)
	recNoPKCE := httptest.NewRecorder()
	env.mux.ServeHTTP(recNoPKCE, reqNoPKCE)
	if recNoPKCE.Code != http.StatusBadRequest {
		t.Fatalf("/o/authorize without PKCE = %d, want 400", recNoPKCE.Code)
	}

	reqPlainPKCE := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/o/authorize?client_id=%d&redirect_uri=%s&response_type=code&scope=openid+profile+email&state=st1&code_challenge=%s&code_challenge_method=plain",
			client.ID, url.QueryEscape(redirectURI), url.QueryEscape(challenge)), nil)
	reqPlainPKCE.AddCookie(cookie)
	recPlainPKCE := httptest.NewRecorder()
	env.mux.ServeHTTP(recPlainPKCE, reqPlainPKCE)
	if recPlainPKCE.Code != http.StatusBadRequest {
		t.Fatalf("/o/authorize with plain PKCE = %d, want 400", recPlainPKCE.Code)
	}

	// 2. Approve authorization request
	authPath := fmt.Sprintf("/o/authorize?client_id=%d&redirect_uri=%s&response_type=code&scope=%s&state=csrfstate123&nonce=nonce456&code_challenge=%s&code_challenge_method=S256",
		client.ID, url.QueryEscape(redirectURI), url.QueryEscape("openid profile email"), url.QueryEscape(challenge))
	form := url.Values{
		"approve":    {"true"},
		"csrf_token": {csrfToken},
	}
	reqApprove := httptest.NewRequest(http.MethodPost, authPath, strings.NewReader(form.Encode()))
	reqApprove.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqApprove.AddCookie(cookie)
	recApprove := httptest.NewRecorder()
	env.mux.ServeHTTP(recApprove, reqApprove)
	if recApprove.Code != http.StatusFound && recApprove.Code != http.StatusSeeOther {
		t.Fatalf("POST /o/authorize approve = %d, want 302/303: %s", recApprove.Code, recApprove.Body.String())
	}

	loc, err := url.Parse(recApprove.Header().Get("Location"))
	if err != nil {
		t.Fatalf("invalid redirect Location: %v", err)
	}
	if loc.Query().Get("state") != "csrfstate123" {
		t.Fatalf("redirect state = %q, want csrfstate123", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("expected non-empty authorization code in Location %q", loc.String())
	}

	// 3. Invalid Basic Auth returns 401 with WWW-Authenticate: Basic challenge (RFC 6749 §5.2)
	badBasicReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}.Encode()))
	badBasicReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badBasicReq.SetBasicAuth(fmt.Sprint(client.ID), "wrong-secret")
	badBasicRec := httptest.NewRecorder()
	env.mux.ServeHTTP(badBasicRec, badBasicReq)
	if badBasicRec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid Basic auth status = %d, want 401", badBasicRec.Code)
	}
	if !strings.HasPrefix(badBasicRec.Header().Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("expected WWW-Authenticate: Basic header, got %q", badBasicRec.Header().Get("WWW-Authenticate"))
	}

	// 4. Wrong PKCE code_verifier is rejected
	wrongPKCEReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {strings.Repeat("x", 43)},
	}.Encode()))
	wrongPKCEReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongPKCEReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	wrongPKCERec := httptest.NewRecorder()
	env.mux.ServeHTTP(wrongPKCERec, wrongPKCEReq)
	if wrongPKCERec.Code != http.StatusBadRequest {
		t.Fatalf("wrong code_verifier status = %d, want 400", wrongPKCERec.Code)
	}

	// 5. Valid exchange returns access_token, refresh_token, id_token
	tokenReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	tokenRec := httptest.NewRecorder()
	env.mux.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("POST /o/token = %d, want 200: %s", tokenRec.Code, tokenRec.Body.String())
	}

	var tokResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokResp.AccessToken == "" || tokResp.RefreshToken == "" || tokResp.IDToken == "" {
		t.Fatalf("incomplete token response: %+v", tokResp)
	}

	// Verify ID token claims (nonce, preferred_username, picture single slash, email_verified)
	parsedID, err := jwt.Parse(tokResp.IDToken, func(token *jwt.Token) (interface{}, error) {
		return &utils.RSAPrivateKey.PublicKey, nil
	})
	if err != nil || !parsedID.Valid {
		t.Fatalf("invalid id_token: %v", err)
	}
	claims := parsedID.Claims.(jwt.MapClaims)
	if claims["nonce"] != "nonce456" {
		t.Errorf("id_token nonce = %v, want nonce456", claims["nonce"])
	}
	if claims["preferred_username"] != "oauthuser1" {
		t.Errorf("id_token preferred_username = %v, want oauthuser1", claims["preferred_username"])
	}
	if claims["picture"] != "https://auth.example.com/uploads/icons/oauthuser1.png" {
		t.Errorf("id_token picture = %v (double slash check)", claims["picture"])
	}
	if claims["email_verified"] != true {
		t.Errorf("id_token email_verified = %v, want true", claims["email_verified"])
	}

	// 6. Auth code replay MUST fail (atomic single-use guarantee)
	replayReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}.Encode()))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	replayRec := httptest.NewRecorder()
	env.mux.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusBadRequest {
		t.Fatalf("auth code replay status = %d, want 400", replayRec.Code)
	}

	// 7. UserInfo works via both GET and POST and returns single-slash picture
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		uiReq := httptest.NewRequest(method, "/api/userinfo", nil)
		uiReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
		uiRec := httptest.NewRecorder()
		env.mux.ServeHTTP(uiRec, uiReq)
		if uiRec.Code != http.StatusOK {
			t.Fatalf("%s /api/userinfo = %d, want 200: %s", method, uiRec.Code, uiRec.Body.String())
		}
		var uiData map[string]interface{}
		if err := json.Unmarshal(uiRec.Body.Bytes(), &uiData); err != nil {
			t.Fatalf("decode userinfo: %v", err)
		}
		if uiData["picture"] != "https://auth.example.com/uploads/icons/oauthuser1.png" {
			t.Errorf("%s userinfo picture = %v", method, uiData["picture"])
		}
	}

	// 8. Missing/invalid Bearer token returns RFC 6750 401 JSON with WWW-Authenticate
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/userinfo", nil)
	unauthRec := httptest.NewRecorder()
	env.mux.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("missing Bearer status = %d, want 401", unauthRec.Code)
	}
	if !strings.HasPrefix(unauthRec.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("expected WWW-Authenticate: Bearer, got %q", unauthRec.Header().Get("WWW-Authenticate"))
	}

	// 9. Refresh token rotation: succeeds once, replaying old refresh_token fails
	refReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokResp.RefreshToken},
	}.Encode()))
	refReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	refRec := httptest.NewRecorder()
	env.mux.ServeHTTP(refRec, refReq)
	if refRec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200: %s", refRec.Code, refRec.Body.String())
	}

	var rotatedResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(refRec.Body.Bytes(), &rotatedResp); err != nil {
		t.Fatalf("decode rotated token: %v", err)
	}
	if rotatedResp.RefreshToken == "" || rotatedResp.RefreshToken == tokResp.RefreshToken {
		t.Fatalf("expected rotated refresh_token to differ from previous token")
	}

	oldRefReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokResp.RefreshToken},
	}.Encode()))
	oldRefReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	oldRefReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	oldRefRec := httptest.NewRecorder()
	env.mux.ServeHTTP(oldRefRec, oldRefReq)
	if oldRefRec.Code != http.StatusBadRequest {
		t.Fatalf("replaying old refresh_token status = %d, want 400", oldRefRec.Code)
	}

	// 10. Suspending user blocks API Bearer, cookie endpoints, OAuth authorize, and introspect
	if err := database.DB.Model(&database.User{}).Where("id = ?", user.ID).Update("status", "suspended").Error; err != nil {
		t.Fatalf("suspend user: %v", err)
	}

	// Suspended UserInfo request fails cleanly with Bearer Forbidden/Unauthorized
	suspUIReq := httptest.NewRequest(http.MethodGet, "/api/userinfo", nil)
	suspUIReq.Header.Set("Authorization", "Bearer "+rotatedResp.AccessToken)
	suspUIRec := httptest.NewRecorder()
	env.mux.ServeHTTP(suspUIRec, suspUIReq)
	if suspUIRec.Code != http.StatusForbidden && suspUIRec.Code != http.StatusUnauthorized {
		t.Fatalf("suspended userinfo status = %d, want 401/403", suspUIRec.Code)
	}

	// Suspended Introspect reports active: false
	introReq := httptest.NewRequest(http.MethodPost, "/o/introspect", strings.NewReader(url.Values{
		"token": {rotatedResp.AccessToken},
	}.Encode()))
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	introRec := httptest.NewRecorder()
	env.mux.ServeHTTP(introRec, introReq)
	if introRec.Code != http.StatusOK {
		t.Fatalf("introspect status = %d, want 200", introRec.Code)
	}
	var introResp struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(introRec.Body.Bytes(), &introResp); err != nil {
		t.Fatalf("decode introspect: %v", err)
	}
	if introResp.Active {
		t.Fatalf("expected introspect active=false for suspended user")
	}

	// Suspended cookie endpoint returns 403 JSON when Accept: application/json
	suspCookieReq := httptest.NewRequest(http.MethodGet, "/clients", nil)
	suspCookieReq.Header.Set("Accept", "application/json")
	suspCookieReq.AddCookie(cookie)
	suspCookieRec := httptest.NewRecorder()
	env.mux.ServeHTTP(suspCookieRec, suspCookieReq)
	if suspCookieRec.Code != http.StatusForbidden {
		t.Fatalf("suspended GET /clients status = %d, want 403", suspCookieRec.Code)
	}
}

func TestHomeAndProfileEndpoints(t *testing.T) {
	env := setupHandlerTestEnv(t)
	user := createTestUser(t, "homeuser1", "ValidPass123!", "active")
	cookie, _, _ := createNativeSessionCookie(t, user.ID)

	homeReq := httptest.NewRequest(http.MethodGet, "/home", nil)
	homeReq.AddCookie(cookie)
	homeRec := httptest.NewRecorder()
	env.mux.ServeHTTP(homeRec, homeReq)
	if homeRec.Code != http.StatusOK {
		t.Fatalf("GET /home status = %d, want 200", homeRec.Code)
	}
	if !strings.Contains(homeRec.Body.String(), "function initHomePasswordToggles()") {
		t.Errorf("GET /home response missing top-level initHomePasswordToggles declaration")
	}

	profReq := httptest.NewRequest(http.MethodGet, "/profile", nil)
	profReq.AddCookie(cookie)
	profRec := httptest.NewRecorder()
	env.mux.ServeHTTP(profRec, profReq)
	if profRec.Code != http.StatusOK {
		t.Fatalf("GET /profile status = %d, want 200: %s", profRec.Code, profRec.Body.String())
	}
	var profData map[string]interface{}
	if err := json.Unmarshal(profRec.Body.Bytes(), &profData); err != nil {
		t.Fatalf("decode /profile JSON: %v", err)
	}
	if profData["email_verified"] != true {
		t.Errorf("GET /profile email_verified = %v, want true", profData["email_verified"])
	}
	if _, ok := profData["phone_verified"]; !ok {
		t.Errorf("GET /profile missing phone_verified key")
	}

	pendReq := httptest.NewRequest(http.MethodGet, "/profile/contact/pending", nil)
	pendReq.AddCookie(cookie)
	pendRec := httptest.NewRecorder()
	env.mux.ServeHTTP(pendRec, pendReq)
	if pendRec.Code != http.StatusOK {
		t.Fatalf("GET /profile/contact/pending status = %d, want 200", pendRec.Code)
	}

	delReq := httptest.NewRequest(http.MethodGet, "/profile/delete/status", nil)
	delReq.AddCookie(cookie)
	delRec := httptest.NewRecorder()
	env.mux.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("GET /profile/delete/status status = %d, want 200", delRec.Code)
	}
}
