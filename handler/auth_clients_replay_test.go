package handler

import (
	"encoding/json"
	"fmt"
	"gilosauth/config"
	"gilosauth/database"
	"gilosauth/middleware"
	"gilosauth/templates"
	"gilosauth/utils"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func setupExtendedMux(t *testing.T) http.Handler {
	t.Helper()
	_ = setupHandlerTestEnv(t)

	tmpls, err := templates.ParseTemplates()
	if err != nil {
		t.Fatalf("ParseTemplates: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /home", middleware.RequireCookieToken(HomeHandler(tmpls)))
	mux.HandleFunc("POST /auth/login", LoginHandler)
	mux.HandleFunc("POST /auth/reset-password", ResetPasswordHandler)
	mux.HandleFunc("POST /auth/otp/send", SendOTPHandler)
	mux.HandleFunc("POST /auth/otp/verify", VerifyOTPHandler)
	mux.HandleFunc("POST /auth/logout", LogoutHandler)

	mux.HandleFunc("POST /clients", middleware.RequireCookieToken(ClientsHandler))
	mux.HandleFunc("POST /clients/edit", middleware.RequireCookieToken(EditClientHandler))
	mux.HandleFunc("POST /clients/delete", middleware.RequireCookieToken(DeleteClientHandler))
	mux.HandleFunc("POST /clients/regenerate-secret", middleware.RequireCookieToken(RegenerateSecretHandler))

	mux.HandleFunc("GET /profile/contact/pending", middleware.RequireCookieToken(ProfileContactPendingHandler))

	mux.HandleFunc("GET /o/authorize", middleware.RequireCookieToken(OAuthAuthorizeHandler(tmpls)))
	mux.HandleFunc("POST /o/authorize", middleware.RequireCookieToken(OAuthAuthorizeHandler(tmpls)))
	mux.HandleFunc("POST /o/token", OAuthTokenHandler)
	mux.HandleFunc("POST /o/introspect", OAuthIntrospectHandler)

	mux.HandleFunc("GET /api/userinfo", middleware.RequireAccessToken(UserInfoHandler))

	return middleware.CSRFMiddleware(mux)
}

func issueAuthorizationCodeTokens(t *testing.T, h http.Handler, cookie *http.Cookie, csrfToken string, client database.Client, clientSecret, redirectURI, scope string) (accessToken, refreshToken string) {
	t.Helper()
	verifier, challenge := pkcePair("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	authPath := fmt.Sprintf("/o/authorize?client_id=%d&redirect_uri=%s&response_type=code&scope=%s&state=st123&nonce=nc123&code_challenge=%s&code_challenge_method=S256",
		client.ID, url.QueryEscape(redirectURI), url.QueryEscape(scope), url.QueryEscape(challenge))

	form := url.Values{"approve": {"true"}, "csrf_token": {csrfToken}}
	req := httptest.NewRequest(http.MethodPost, authPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound && rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /o/authorize = %d, want redirect: %s", rec.Code, rec.Body.String())
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("missing authorization code in %q", loc.String())
	}

	tokReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	tokRec := httptest.NewRecorder()
	h.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("POST /o/token = %d: %s", tokRec.Code, tokRec.Body.String())
	}

	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tokRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp.AccessToken, resp.RefreshToken
}

func TestOAuthRefreshTokenReplayRevokesFamily(t *testing.T) {
	h := setupExtendedMux(t)
	user := createTestUser(t, "replayuser1", "ValidPass123!", "active")
	cookie, csrfToken, _ := createNativeSessionCookie(t, user.ID)

	clientSecret := "replay-client-secret-123"
	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), config.BcryptCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	secretStr := string(secretHash)
	redirectURI := "https://replay.example.com/cb"
	client := database.Client{
		Name:         "Replay Test Client",
		Secret:       &secretStr,
		SecretPrefix: clientSecret[:8],
		UserID:       user.ID,
		Type:         "confidential",
		RedirectURIs: redirectURI,
		Scopes:       "openid,profile,email",
	}
	if err := database.DB.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, refresh1 := issueAuthorizationCodeTokens(t, h, cookie, csrfToken, client, clientSecret, redirectURI, "openid profile email")

	// Rotate refresh1 -> (access2, refresh2)
	rotReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh1},
	}.Encode()))
	rotReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rotReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	rotRec := httptest.NewRecorder()
	h.ServeHTTP(rotRec, rotReq)
	if rotRec.Code != http.StatusOK {
		t.Fatalf("refresh rotation = %d: %s", rotRec.Code, rotRec.Body.String())
	}
	var rotResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rotRec.Body.Bytes(), &rotResp); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if rotResp.RefreshToken == "" || rotResp.RefreshToken == refresh1 {
		t.Fatalf("expected rotated refresh token")
	}

	// Replay refresh1 -> must fail and revoke the whole session family
	replayReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh1},
	}.Encode()))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	replayRec := httptest.NewRecorder()
	h.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400: %s", replayRec.Code, replayRec.Body.String())
	}

	// Newer rotated refresh2 must now also be invalid because the family was revoked
	useNewReq := httptest.NewRequest(http.MethodPost, "/o/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotResp.RefreshToken},
	}.Encode()))
	useNewReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	useNewReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	useNewRec := httptest.NewRecorder()
	h.ServeHTTP(useNewRec, useNewReq)
	if useNewRec.Code != http.StatusBadRequest {
		t.Fatalf("refresh2 after replay status = %d, want 400", useNewRec.Code)
	}

	// Introspect access2 must report active: false
	introReq := httptest.NewRequest(http.MethodPost, "/o/introspect", strings.NewReader(url.Values{
		"token": {rotResp.AccessToken},
	}.Encode()))
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.SetBasicAuth(fmt.Sprint(client.ID), clientSecret)
	introRec := httptest.NewRecorder()
	h.ServeHTTP(introRec, introReq)
	if introRec.Code != http.StatusOK {
		t.Fatalf("introspect status = %d", introRec.Code)
	}
	var introResp map[string]interface{}
	if err := json.Unmarshal(introRec.Body.Bytes(), &introResp); err != nil {
		t.Fatalf("decode introspect: %v", err)
	}
	if active, _ := introResp["active"].(bool); active {
		t.Fatalf("expected introspect active=false after replay revocation, got %+v", introResp)
	}

	var count int64
	database.DB.Model(&database.Session{}).Where("client_id = ? AND type = ?", client.ID, "client").Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 remaining client sessions, got %d", count)
	}
}

func TestPendingDeletionUserAllowedOnHomeAuthorizeUserinfo(t *testing.T) {
	h := setupExtendedMux(t)
	user := createTestUser(t, "penddel1", "ValidPass123!", "pending_deletion")
	cookie, csrfToken, _ := createNativeSessionCookie(t, user.ID)

	// /home remains accessible during deletion grace period
	homeReq := httptest.NewRequest(http.MethodGet, "/home", nil)
	homeReq.AddCookie(cookie)
	homeRec := httptest.NewRecorder()
	h.ServeHTTP(homeRec, homeReq)
	if homeRec.Code != http.StatusOK {
		t.Fatalf("GET /home for pending_deletion user = %d, want 200", homeRec.Code)
	}

	clientSecret := "pending-del-secret-123"
	secretHash, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), config.BcryptCost)
	secretStr := string(secretHash)
	redirectURI := "https://pending.example.com/cb"
	client := database.Client{
		Name:         "Pending Deletion App",
		Secret:       &secretStr,
		SecretPrefix: clientSecret[:8],
		UserID:       user.ID,
		Type:         "confidential",
		RedirectURIs: redirectURI,
		Scopes:       "openid,profile,email",
	}
	if err := database.DB.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	accessToken, _ := issueAuthorizationCodeTokens(t, h, cookie, csrfToken, client, clientSecret, redirectURI, "openid profile email")

	uiReq := httptest.NewRequest(http.MethodGet, "/api/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+accessToken)
	uiRec := httptest.NewRecorder()
	h.ServeHTTP(uiRec, uiReq)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("GET /api/userinfo for pending_deletion user = %d, want 200: %s", uiRec.Code, uiRec.Body.String())
	}
}

func TestAuthOTPSessionUsernameBindingAndPasswordReset(t *testing.T) {
	h := setupExtendedMux(t)
	alice := createTestUser(t, "aliceuser1", "OldValidPass123!", "active")
	_ = createTestUser(t, "bobuser1", "OtherValidPass123!", "active")

	// Existing other web session that must be revoked on password reset
	_, _, otherSess := createNativeSessionCookie(t, alice.ID)

	// Active auth-flow session for alice
	resetCookie, _, resetSess := createNativeSessionCookie(t, alice.ID)
	_ = database.SM.SetData(resetSess, "username", alice.Username)
	_ = database.SM.SetData(resetSess, "step", "otp")
	_ = database.SM.SetData(resetSess, "contact", alice.Email)
	_ = database.SM.SetData(resetSess, "contact_type", "email")
	_ = database.SM.SetData(resetSess, "otp", utils.HashToken("654321"))
	_ = database.SM.SetData(resetSess, "otp_sent_at", time.Now().Format(time.RFC3339))

	// SendOTP must enforce session username binding
	sendMismatchReq := httptest.NewRequest(http.MethodPost, "/auth/otp/send", strings.NewReader(`{"username":"bobuser1","contact":"totp"}`))
	sendMismatchReq.Header.Set("Content-Type", "application/json")
	sendMismatchReq.AddCookie(resetCookie)
	sendMismatchRec := httptest.NewRecorder()
	h.ServeHTTP(sendMismatchRec, sendMismatchReq)
	if sendMismatchRec.Code != http.StatusBadRequest {
		t.Fatalf("SendOTP username mismatch status = %d, want 400: %s", sendMismatchRec.Code, sendMismatchRec.Body.String())
	}

	// VerifyOTP must enforce session username binding
	verifyMismatchReq := httptest.NewRequest(http.MethodPost, "/auth/otp/verify", strings.NewReader(`{"username":"bobuser1","otp":"654321"}`))
	verifyMismatchReq.Header.Set("Content-Type", "application/json")
	verifyMismatchReq.AddCookie(resetCookie)
	verifyMismatchRec := httptest.NewRecorder()
	h.ServeHTTP(verifyMismatchRec, verifyMismatchReq)
	if verifyMismatchRec.Code != http.StatusBadRequest {
		t.Fatalf("VerifyOTP username mismatch status = %d, want 400: %s", verifyMismatchRec.Code, verifyMismatchRec.Body.String())
	}

	// ResetPassword before OTP verification must be rejected
	resetEarlyReq := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(fmt.Sprintf(`{"username":"%s","password":"NewValidPass456!","contact":"%s"}`, alice.Username, alice.Email)))
	resetEarlyReq.Header.Set("Content-Type", "application/json")
	resetEarlyReq.AddCookie(resetCookie)
	resetEarlyRec := httptest.NewRecorder()
	h.ServeHTTP(resetEarlyRec, resetEarlyReq)
	if resetEarlyRec.Code != http.StatusBadRequest {
		t.Fatalf("ResetPassword before OTP verification = %d, want 400", resetEarlyRec.Code)
	}

	// Verify OTP -> transitions step to reset-password and sets password_reset_verified
	verifyOKReq := httptest.NewRequest(http.MethodPost, "/auth/otp/verify", strings.NewReader(fmt.Sprintf(`{"username":"%s","otp":"654321"}`, alice.Username)))
	verifyOKReq.Header.Set("Content-Type", "application/json")
	verifyOKReq.AddCookie(resetCookie)
	verifyOKRec := httptest.NewRecorder()
	h.ServeHTTP(verifyOKRec, verifyOKReq)
	if verifyOKRec.Code != http.StatusOK {
		t.Fatalf("VerifyOTP failed = %d: %s", verifyOKRec.Code, verifyOKRec.Body.String())
	}

	// Perform ResetPassword -> rotates current session, sets new password, revokes other native sessions
	resetOKReq := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(fmt.Sprintf(`{"username":"%s","password":"NewValidPass456!","contact":"%s"}`, alice.Username, alice.Email)))
	resetOKReq.Header.Set("Content-Type", "application/json")
	resetOKReq.AddCookie(resetCookie)
	resetOKRec := httptest.NewRecorder()
	h.ServeHTTP(resetOKRec, resetOKReq)
	if resetOKRec.Code != http.StatusOK {
		t.Fatalf("ResetPassword failed = %d: %s", resetOKRec.Code, resetOKRec.Body.String())
	}

	var rotatedToken string
	for _, c := range resetOKRec.Result().Cookies() {
		if c.Name == "session_token" {
			rotatedToken = c.Value
			break
		}
	}
	if rotatedToken == "" || rotatedToken == resetCookie.Value {
		t.Fatalf("expected rotated session_token cookie after password reset")
	}

	var oldResetCount, otherCount, activeNativeCount int64
	database.DB.Model(&database.Session{}).Where("id = ?", resetSess.ID).Count(&oldResetCount)
	database.DB.Model(&database.Session{}).Where("id = ?", otherSess.ID).Count(&otherCount)
	database.DB.Model(&database.Session{}).Where("user_id = ? AND type = ?", alice.ID, "native").Count(&activeNativeCount)
	if oldResetCount != 0 || otherCount != 0 || activeNativeCount != 1 {
		t.Fatalf("unexpected session state after password reset: oldReset=%d other=%d totalNative=%d", oldResetCount, otherCount, activeNativeCount)
	}

	var reloadedAlice database.User
	if err := database.DB.First(&reloadedAlice, alice.ID).Error; err != nil {
		t.Fatalf("reload alice: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(reloadedAlice.Password), []byte("NewValidPass456!")); err != nil {
		t.Fatalf("updated password does not match hash: %v", err)
	}
}

func TestTokenLogoutBypassPreservesWebSession(t *testing.T) {
	h := setupExtendedMux(t)
	user := createTestUser(t, "toklogout1", "ValidPass123!", "active")
	webCookie, _, webSess := createNativeSessionCookie(t, user.ID)

	client := database.Client{
		Name:         "Logout Token Client",
		UserID:       user.ID,
		Type:         "public",
		RedirectURIs: "https://app.example.com/cb",
		Scopes:       "openid,profile",
	}
	if err := database.DB.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	rawAccess := "bearer-token-to-revoke-123"
	hashedAccess := utils.HashToken(rawAccess)
	clientSess := database.Session{
		UserID:      &user.ID,
		ClientID:    &client.ID,
		Type:        "client",
		AccessToken: &hashedAccess,
		LastSeenAt:  time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := database.DB.Create(&clientSess).Error; err != nil {
		t.Fatalf("create client session: %v", err)
	}

	// Token logout with Authorization: Bearer must bypass CSRF without revoking the browser cookie session
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(webCookie)
	req.Header.Set("Authorization", "Bearer "+rawAccess)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token logout status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var clientCount, webCount int64
	database.DB.Model(&database.Session{}).Where("id = ?", clientSess.ID).Count(&clientCount)
	database.DB.Model(&database.Session{}).Where("id = ?", webSess.ID).Count(&webCount)
	if clientCount != 0 {
		t.Fatalf("expected bearer token client session to be deleted, count=%d", clientCount)
	}
	if webCount != 1 {
		t.Fatalf("expected browser web session to remain intact, count=%d", webCount)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session_token" && c.Value == "" {
			t.Fatalf("expected token logout bypass not to clear session_token cookie")
		}
	}
}

func TestClientEditSecretRotationAndDeleteRevokeGrants(t *testing.T) {
	h := setupExtendedMux(t)
	user := createTestUser(t, "clientowner1", "ValidPass123!", "active")
	cookie, csrfToken, _ := createNativeSessionCookie(t, user.ID)

	client := database.Client{
		Name:         "Mutable Client",
		UserID:       user.ID,
		Type:         "public",
		RedirectURIs: "https://app.example.com/cb",
		Scopes:       "openid,profile,email",
	}
	if err := database.DB.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	createGrant := func(tag string) uint64 {
		tok := utils.HashToken("grant-" + tag)
		s := database.Session{
			UserID:      &user.ID,
			ClientID:    &client.ID,
			Type:        "client",
			AccessToken: &tok,
			LastSeenAt:  time.Now(),
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		if err := database.DB.Create(&s).Error; err != nil {
			t.Fatalf("create grant session: %v", err)
		}
		return s.ID
	}

	_ = createGrant("edit")

	// 1. EditClientHandler: upgrade public -> confidential & narrow scopes -> returns secret once and revokes client sessions
	editForm := url.Values{
		"name":          {"Mutable Client Updated"},
		"type":          {"confidential"},
		"redirect_uris": {"https://app.example.com/cb2"},
		"openid":        {"on"},
		"profile":       {"on"},
	}
	editReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/clients/edit?id=%d", client.ID), strings.NewReader(editForm.Encode()))
	editReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	editReq.Header.Set("X-CSRF-Token", csrfToken)
	editReq.AddCookie(cookie)
	editRec := httptest.NewRecorder()
	h.ServeHTTP(editRec, editReq)
	if editRec.Code != http.StatusOK {
		t.Fatalf("POST /clients/edit = %d: %s", editRec.Code, editRec.Body.String())
	}
	var editResp map[string]interface{}
	if err := json.Unmarshal(editRec.Body.Bytes(), &editResp); err != nil {
		t.Fatalf("decode edit response: %v", err)
	}
	if secret, _ := editResp["client_secret"].(string); secret == "" {
		t.Fatalf("expected client_secret on public -> confidential upgrade, got %+v", editResp)
	}
	var grantCount int64
	database.DB.Model(&database.Session{}).Where("client_id = ? AND type = ?", client.ID, "client").Count(&grantCount)
	if grantCount != 0 {
		t.Fatalf("expected edit security change to revoke client grants, count=%d", grantCount)
	}

	// 2. RegenerateSecretHandler: rotates secret and revokes active client sessions
	_ = createGrant("regen")
	regenForm := url.Values{"client_id": {strconv.FormatUint(client.ID, 10)}}
	regenReq := httptest.NewRequest(http.MethodPost, "/clients/regenerate-secret", strings.NewReader(regenForm.Encode()))
	regenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	regenReq.Header.Set("X-CSRF-Token", csrfToken)
	regenReq.AddCookie(cookie)
	regenRec := httptest.NewRecorder()
	h.ServeHTTP(regenRec, regenReq)
	if regenRec.Code != http.StatusOK {
		t.Fatalf("POST /clients/regenerate-secret = %d: %s", regenRec.Code, regenRec.Body.String())
	}
	var regenResp map[string]interface{}
	if err := json.Unmarshal(regenRec.Body.Bytes(), &regenResp); err != nil {
		t.Fatalf("decode regenerate response: %v", err)
	}
	if secret, _ := regenResp["client_secret"].(string); secret == "" {
		t.Fatalf("expected client_secret on regenerate-secret, got %+v", regenResp)
	}
	database.DB.Model(&database.Session{}).Where("client_id = ? AND type = ?", client.ID, "client").Count(&grantCount)
	if grantCount != 0 {
		t.Fatalf("expected secret rotation to revoke client grants, count=%d", grantCount)
	}

	// 3. DeleteClientHandler: removes client and all its grants inside transaction
	_ = createGrant("delete")
	delForm := url.Values{"client_id": {strconv.FormatUint(client.ID, 10)}}
	delReq := httptest.NewRequest(http.MethodPost, "/clients/delete", strings.NewReader(delForm.Encode()))
	delReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	delReq.Header.Set("X-CSRF-Token", csrfToken)
	delReq.AddCookie(cookie)
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("POST /clients/delete = %d: %s", delRec.Code, delRec.Body.String())
	}
	var clientCount int64
	database.DB.Model(&database.Client{}).Where("id = ?", client.ID).Count(&clientCount)
	database.DB.Model(&database.Session{}).Where("client_id = ?", client.ID).Count(&grantCount)
	if clientCount != 0 || grantCount != 0 {
		t.Fatalf("expected client and grants deleted, clientCount=%d grantCount=%d", clientCount, grantCount)
	}
}

func TestProfileContactPendingNormalizedPhoneBlockAndTimers(t *testing.T) {
	h := setupExtendedMux(t)
	user := createTestUser(t, "pendingphone1", "ValidPass123!", "active")
	cookie, _, sess := createNativeSessionCookie(t, user.ID)

	// Simulate float64 JSON round-tripped phone number + attempts/resends on session
	_ = database.SM.SetData(sess, "profile_pending_phone", float64(998901234567))
	_ = database.SM.SetData(sess, "profile_otp_sent_at_phone", time.Now().Add(-20*time.Second).Format(time.RFC3339))
	_ = database.SM.SetData(sess, "profile_attempts_phone", float64(2))
	_ = database.SM.SetData(sess, "profile_resends_phone", float64(1))

	// Apply block only on the normalized contact identifier so /profile/contact/pending still returns 200 with blocks.phone
	phoneKey := utils.NormalizePendingBlockKey("phone", float64(998901234567))
	if err := database.SM.ApplyBlock(phoneKey, nil, time.Hour, "security"); err != nil {
		t.Fatalf("ApplyBlock failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/profile/contact/pending", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /profile/contact/pending = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Pending           []string               `json:"pending"`
		Masked            map[string]string      `json:"masked"`
		Attempts          map[string]int         `json:"attempts"`
		Resends           map[string]int         `json:"resends"`
		TimeRemaining     map[string]int         `json:"time_remaining"`
		ResendAvailableIn map[string]int         `json:"resend_available_in"`
		Blocks            map[string]interface{} `json:"blocks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode pending response: %v", err)
	}
	if len(resp.Pending) != 1 || resp.Pending[0] != "phone" {
		t.Fatalf("pending = %v, want [phone]", resp.Pending)
	}
	if resp.Masked["phone"] != "+998******567" {
		t.Fatalf("masked.phone = %q, want +998******567", resp.Masked["phone"])
	}
	if resp.Attempts["phone"] != 2 || resp.Resends["phone"] != 1 {
		t.Fatalf("attempts/resends = %+v / %+v, want 2 / 1", resp.Attempts, resp.Resends)
	}
	if resp.TimeRemaining["phone"] < 200 || resp.ResendAvailableIn["phone"] <= 0 {
		t.Fatalf("unexpected timers: time_remaining=%+v resend_available_in=%+v", resp.TimeRemaining, resp.ResendAvailableIn)
	}
	phoneBlock, ok := resp.Blocks["phone"].(map[string]interface{})
	if !ok || phoneBlock["is_blocked"] != true {
		t.Fatalf("expected blocks.phone.is_blocked=true, got %+v", resp.Blocks)
	}
}

