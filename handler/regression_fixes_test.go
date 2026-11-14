package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gilosauth/config"
	"gilosauth/database"
	"gilosauth/handler/client"
	"gilosauth/middleware"
	"gilosauth/utils"
)

func TestRegressionLegalContentTypeAndOTPGeneration(t *testing.T) {
	env := setupHandlerTestEnv(t)

	for _, path := range []string{"/privacy", "/terms"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		env.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("GET %s Content-Type = %q, want text/html prefix", path, ct)
		}
	}

	otp, err := utils.GenerateOTP()
	if err != nil {
		t.Fatalf("GenerateOTP unexpected error: %v", err)
	}
	if len(otp) != 6 {
		t.Fatalf("GenerateOTP length = %d, want 6", len(otp))
	}
}

func TestRegressionLoginMultiMFATOTPError(t *testing.T) {
	env := setupHandlerTestEnv(t)
	user := createTestUser(t, "multimfa1", "ValidPass123!", "active")

	encSecret, err := utils.EncryptTOTPSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("EncryptTOTPSecret: %v", err)
	}
	user.Email = "multimfa@example.com"
	user.EmailVerified = true
	user.MFAEmailEnabled = true
	user.MFATOTPEnabled = true
	user.TOTPSecret = encSecret
	if err := database.DB.Save(&user).Error; err != nil {
		t.Fatalf("update user MFA: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"multimfa1","password":"ValidPass123!","two_step_code":"000000"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("multi-MFA wrong TOTP status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "4 attempts left") {
		t.Fatalf("multi-MFA error = %q, expected TOTP countdown instead of missing session OTP", rec.Body.String())
	}
}

func TestRegressionVerifyOTPThirdAttemptAndBlock(t *testing.T) {
	h := setupExtendedMux(t)
	user := createTestUser(t, "otpuser1", "ValidPass123!", "active")
	user.Email = "otpuser1@example.com"
	user.EmailVerified = true
	user.MFAEmailEnabled = true
	if err := database.DB.Save(&user).Error; err != nil {
		t.Fatalf("update user: %v", err)
	}

	startSessionWithOTP := func(plainOTP string) *http.Cookie {
		req := httptest.NewRequest(http.MethodGet, "/auth/state", nil)
		rec := httptest.NewRecorder()
		sess, err := database.SM.Start(req.Context(), rec, req, nil)
		if err != nil {
			t.Fatalf("SM.Start: %v", err)
		}
		if err := database.SM.SetData(sess, "username", "otpuser1"); err != nil {
			t.Fatalf("SetData username: %v", err)
		}
		_ = database.SM.SetData(sess, "step", "otp")
		_ = database.SM.SetData(sess, "contact_type", "email")
		_ = database.SM.SetData(sess, "contact", "otpuser1@example.com")
		_ = database.SM.SetData(sess, "otp", utils.HashToken(plainOTP))
		_ = database.SM.SetData(sess, "otp_sent_at", time.Now().Format(time.RFC3339))
		_ = database.SM.SetData(sess, "attempts", 0)
		_ = database.SM.SetData(sess, "password_verified", true)
		return rec.Result().Cookies()[0]
	}

	// Valid OTP on the 3rd attempt (after 2 failed tries) must succeed
	c1 := startSessionWithOTP("654321")
	for i, wantMsg := range []string{"2 attempts left", "1 attempt left"} {
		req := httptest.NewRequest(http.MethodPost, "/auth/otp/verify", strings.NewReader(`{"username":"otpuser1","otp":"000000"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(c1)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), wantMsg) {
			t.Fatalf("attempt %d status=%d body=%q, want 400 with %q", i+1, rec.Code, rec.Body.String(), wantMsg)
		}
	}

	reqPass := httptest.NewRequest(http.MethodPost, "/auth/otp/verify", strings.NewReader(`{"username":"otpuser1","otp":"654321"}`))
	reqPass.Header.Set("Content-Type", "application/json")
	reqPass.AddCookie(c1)
	recPass := httptest.NewRecorder()
	h.ServeHTTP(recPass, reqPass)
	if recPass.Code != http.StatusOK {
		t.Fatalf("3rd attempt with valid OTP = %d, want 200: %s", recPass.Code, recPass.Body.String())
	}

	// 3rd wrong attempt blocks immediately with 429 (never "0 attempts left")
	c2 := startSessionWithOTP("111222")
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/otp/verify", strings.NewReader(`{"username":"otpuser1","otp":"000000"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(c2)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("wrong try %d = %d, want 400", i+1, rec.Code)
		}
	}
	reqBlock := httptest.NewRequest(http.MethodPost, "/auth/otp/verify", strings.NewReader(`{"username":"otpuser1","otp":"000000"}`))
	reqBlock.Header.Set("Content-Type", "application/json")
	reqBlock.AddCookie(c2)
	recBlock := httptest.NewRecorder()
	h.ServeHTTP(recBlock, reqBlock)
	if recBlock.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd wrong OTP attempt = %d, want 429: %s", recBlock.Code, recBlock.Body.String())
	}
}

func TestRegressionUsernameCooldownDoesNotBlockContactAndPasswordUpdateRejectsEmpty(t *testing.T) {
	env := setupHandlerTestEnv(t)
	user := createTestUser(t, "cooluser1", "ValidPass123!", "active")
	cookie, csrfToken, sess := createNativeSessionCookie(t, user.ID)

	// Simulate active 30-day username cooldown block
	if err := database.SM.ApplyBlock(fmt.Sprintf("user:%d:username", user.ID), sess, 30*24*time.Hour, "username"); err != nil {
		t.Fatalf("ApplyBlock username: %v", err)
	}

	// Contact pending endpoint must NOT be blocked by username cooldown
	reqPending := httptest.NewRequest(http.MethodGet, "/profile/contact/pending", nil)
	reqPending.AddCookie(cookie)
	recPending := httptest.NewRecorder()
	env.mux.ServeHTTP(recPending, reqPending)
	if recPending.Code != http.StatusOK {
		t.Fatalf("GET /profile/contact/pending with username cooldown = %d, want 200: %s", recPending.Code, recPending.Body.String())
	}

	// Empty password update must fail closed with 400 instead of silently succeeding
	mux := http.NewServeMux()
	mux.HandleFunc("POST /profile/password", middleware.RequireCookieToken(PasswordUpdateHandler))
	wrapped := middleware.CSRFMiddleware(mux)

	form := url.Values{"password": {""}, "confirm_password": {""}}
	reqPw := httptest.NewRequest(http.MethodPost, "/profile/password", strings.NewReader(form.Encode()))
	reqPw.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqPw.Header.Set("X-CSRF-Token", csrfToken)
	reqPw.AddCookie(cookie)
	recPw := httptest.NewRecorder()
	wrapped.ServeHTTP(recPw, reqPw)
	if recPw.Code != http.StatusBadRequest {
		t.Fatalf("POST /profile/password empty = %d, want 400: %s", recPw.Code, recPw.Body.String())
	}
}

func TestRegressionClientAPIPasswordJSONTerminateAndTOTPFailClosed(t *testing.T) {
	h := setupExtendedMux(t)
	user := createTestUser(t, "clientsec1", "ValidPass123!", "active")
	cookie, csrfToken, _ := createNativeSessionCookie(t, user.ID)

	// Create confidential client and mint real OAuth access token
	c := database.Client{
		Name:         "Regression OAuth Client",
		UserID:       user.ID,
		Type:         "public",
		RedirectURIs: "https://client.example.com/cb",
		Scopes:       "openid,profile",
	}
	if err := database.DB.Create(&c).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	accessToken, _ := issueAuthorizationCodeTokens(t, h, cookie, csrfToken, c, "", "https://client.example.com/cb", "openid profile")

	// Mount client API endpoints behind RequireAccessToken
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("POST /api/sessions/terminate", middleware.RequireAccessToken(client.TerminateSessionHandler))
	apiMux.HandleFunc("POST /api/profile/password", middleware.RequireAccessToken(client.PasswordUpdateHandler))
	apiMux.HandleFunc("POST /api/profile/delete", middleware.RequireAccessToken(client.DeleteAccountHandler))
	apiMux.HandleFunc("POST /api/profile/totp/disable", middleware.RequireAccessToken(client.TOTPDisableHandler))
	apiMux.HandleFunc("GET /api/totp/list", middleware.RequireAccessToken(client.ListTOTPsHandler))

	// 1. Missing X-Current-Password rejected on sensitive client profile endpoints
	for _, tc := range []struct {
		path string
		body string
	}{
		{"/api/profile/password", `{"password":"NewPass123!","confirm_password":"NewPass123!"}`},
		{"/api/profile/delete", `{"reason":"privacy"}`},
		{"/api/profile/totp/disable", `{}`},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		apiMux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "password_required") {
			t.Fatalf("%s without X-Current-Password = %d %q, want 400 password_required", tc.path, rec.Code, rec.Body.String())
		}
	}

	// 2. JSON body session termination succeeds on client API
	_, _, targetSess := createNativeSessionCookie(t, user.ID)
	termReq := httptest.NewRequest(http.MethodPost, "/api/sessions/terminate", strings.NewReader(fmt.Sprintf(`{"session_id": %d}`, targetSess.ID)))
	termReq.Header.Set("Authorization", "Bearer "+accessToken)
	termReq.Header.Set("Content-Type", "application/json")
	termRec := httptest.NewRecorder()
	apiMux.ServeHTTP(termRec, termReq)
	if termRec.Code != http.StatusOK {
		t.Fatalf("POST /api/sessions/terminate JSON = %d, want 200: %s", termRec.Code, termRec.Body.String())
	}

	// 3. ListTOTPsHandler fails closed with 500 when secret cannot be decrypted
	if err := database.DB.Create(&database.TOTPSecret{
		UserID:    user.ID,
		UUID:      "11111111-1111-4111-8111-111111111111",
		Secret:    "corrupted-non-aes-ciphertext",
		Label:     "Broken",
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
	}).Error; err != nil {
		t.Fatalf("create corrupt totp: %v", err)
	}
	listReq := httptest.NewRequest(http.MethodGet, "/api/totp/list", nil)
	listReq.Header.Set("Authorization", "Bearer "+accessToken)
	listRec := httptest.NewRecorder()
	apiMux.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusInternalServerError {
		t.Fatalf("GET /api/totp/list corrupt ciphertext = %d, want 500: %s", listRec.Code, listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), "corrupted-non-aes-ciphertext") {
		t.Fatalf("GET /api/totp/list leaked ciphertext in response")
	}

	_ = config.AppName
}
