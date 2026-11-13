package handler

import (
	"encoding/json"
	"gilosauth/database"
	"gilosauth/middleware"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProfileActivityHandler(t *testing.T) {
	_ = setupHandlerTestEnv(t)

	alice := database.User{
		Username: "alice123",
		Password: "hashedpassword",
		Status:   "active",
	}
	if err := database.DB.Create(&alice).Error; err != nil {
		t.Fatalf("create alice: %v", err)
	}
	bob := database.User{
		Username: "bob4567",
		Password: "hashedpassword",
		Status:   "active",
	}
	if err := database.DB.Create(&bob).Error; err != nil {
		t.Fatalf("create bob: %v", err)
	}

	aliceID := alice.ID
	bobID := bob.ID
	logs := []database.AuditLog{
		{UserID: &aliceID, EventType: database.AuditLoginSuccess, IPAddress: "203.0.113.10", UserAgent: "Mozilla/5.0", Details: "logged in via gilos id", CreatedAt: time.Now().Add(-10 * time.Minute)},
		{UserID: &bobID, EventType: database.AuditPasswordChanged, IPAddress: "198.51.100.2", UserAgent: "curl/8.0", Details: "bob event", CreatedAt: time.Now().Add(-5 * time.Minute)},
		{UserID: &aliceID, EventType: database.AuditMFATOTPEnabled, IPAddress: "203.0.113.11", UserAgent: "Chrome/120.0", Details: "totp enabled", CreatedAt: time.Now().Add(-1 * time.Minute)},
	}
	for i := range logs {
		if err := database.DB.Create(&logs[i]).Error; err != nil {
			t.Fatalf("create log %d: %v", i, err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /profile/activity", middleware.RequireCookieToken(ProfileActivityHandler))

	unauthReq := httptest.NewRequest(http.MethodGet, "/profile/activity", nil)
	unauthReq.Header.Set("Accept", "application/json")
	unauthRec := httptest.NewRecorder()
	mux.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when unauthenticated, got %d", unauthRec.Code)
	}

	cookie, _, _ := createNativeSessionCookie(t, alice.ID)
	req := httptest.NewRequest(http.MethodGet, "/profile/activity?page=1&limit=10", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Data       []ActivityLogItem `json:"data"`
		Pagination Pagination        `json:"pagination"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Pagination.Total != 2 || len(resp.Data) != 2 {
		t.Fatalf("expected 2 logs for alice, got total=%d len=%d", resp.Pagination.Total, len(resp.Data))
	}
	if resp.Data[0].EventType != database.AuditMFATOTPEnabled || resp.Data[1].EventType != database.AuditLoginSuccess {
		t.Fatalf("unexpected ordering or leakage: %+v", resp.Data)
	}

	reqPage := httptest.NewRequest(http.MethodGet, "/profile/activity?page=2&limit=1", nil)
	reqPage.AddCookie(cookie)
	recPage := httptest.NewRecorder()
	mux.ServeHTTP(recPage, reqPage)
	if recPage.Code != http.StatusOK {
		t.Fatalf("expected 200 on page 2, got %d", recPage.Code)
	}
	var respPage struct {
		Data       []ActivityLogItem `json:"data"`
		Pagination Pagination        `json:"pagination"`
	}
	if err := json.Unmarshal(recPage.Body.Bytes(), &respPage); err != nil {
		t.Fatalf("decode page 2: %v", err)
	}
	if respPage.Pagination.TotalPages != 2 || len(respPage.Data) != 1 || respPage.Data[0].EventType != database.AuditLoginSuccess {
		t.Fatalf("unexpected page 2 data: %+v", respPage)
	}
}