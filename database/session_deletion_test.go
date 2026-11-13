package database

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"gilosauth/config"
)

func setupTestDB(t *testing.T) {
	t.Helper()

	origDBPath := config.DBPath
	origDB := DB
	origSM := SM

	config.DBPath = filepath.Join(t.TempDir(), "test.db")
	config.SecureCookies = false
	config.CookieDomain = ""

	InitDatabase()
	if err := MigrateDatabase(); err != nil {
		t.Fatalf("MigrateDatabase failed: %v", err)
	}
	InitSessionManager()

	t.Cleanup(func() {
		if DB != nil {
			if sqlDB, err := DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}
		config.DBPath = origDBPath
		DB = origDB
		SM = origSM
	})
}

func TestSessionStartExpiryAndThrottling(t *testing.T) {
	setupTestDB(t)

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0 TestAgent")
	req1.RemoteAddr = "127.0.0.1:12345"

	sess1, err := SM.Start(context.Background(), rec1, req1, nil)
	if err != nil {
		t.Fatalf("initial SM.Start failed: %v", err)
	}
	if sess1.CookieToken == nil || *sess1.CookieToken == "" {
		t.Fatalf("expected non-empty cookie token")
	}

	var cookie *http.Cookie
	for _, c := range rec1.Result().Cookies() {
		if c.Name == "session_token" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatalf("expected session_token Set-Cookie header")
	}

	// Second immediate call with identical metadata should reuse session without DB write
	origLastSeen := sess1.LastSeenAt
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 TestAgent")
	req2.RemoteAddr = "127.0.0.1:12345"
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()

	sess2, err := SM.Start(context.Background(), rec2, req2, nil)
	if err != nil {
		t.Fatalf("second SM.Start failed: %v", err)
	}
	if sess2.ID != sess1.ID {
		t.Fatalf("expected reused session ID %d, got %d", sess1.ID, sess2.ID)
	}
	if !sess2.LastSeenAt.Equal(origLastSeen) {
		t.Fatalf("expected LastSeenAt to stay throttled within 1 minute")
	}

	// When LastSeenAt is older than 1 minute, LastSeenAt refreshes on reuse
	staleTime := time.Now().Add(-2 * time.Minute)
	if err := DB.Model(&Session{}).Where("id = ?", sess1.ID).Update("last_seen_at", staleTime).Error; err != nil {
		t.Fatalf("failed to age LastSeenAt: %v", err)
	}
	rec3 := httptest.NewRecorder()
	sess3, err := SM.Start(context.Background(), rec3, req2, nil)
	if err != nil {
		t.Fatalf("third SM.Start failed: %v", err)
	}
	if !sess3.LastSeenAt.After(staleTime) {
		t.Fatalf("expected LastSeenAt to refresh when older than 1 minute")
	}

	// Expired session cookie must not be reused
	if err := DB.Model(&Session{}).Where("id = ?", sess1.ID).Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("failed to expire session: %v", err)
	}
	rec4 := httptest.NewRecorder()
	sess4, err := SM.Start(context.Background(), rec4, req2, nil)
	if err != nil {
		t.Fatalf("fourth SM.Start failed: %v", err)
	}
	if sess4.ID == sess1.ID {
		t.Fatalf("expired session ID %d was unexpectedly reused", sess1.ID)
	}
}

func TestPurgeUserDataForeignKeyOrder(t *testing.T) {
	setupTestDB(t)

	target := User{
		Username:  "purgeuser",
		Email:     "purge@example.com",
		Phone:     998901111111,
		Password:  "hashed",
		FirstName: "Purge",
		LastName:  "Target",
		Status:    "active",
	}
	other := User{
		Username:  "otheruser",
		Email:     "other@example.com",
		Phone:     998902222222,
		Password:  "hashed",
		FirstName: "Other",
		LastName:  "User",
		Status:    "active",
	}
	if err := DB.Create(&target).Error; err != nil {
		t.Fatalf("failed creating target user: %v", err)
	}
	if err := DB.Create(&other).Error; err != nil {
		t.Fatalf("failed creating other user: %v", err)
	}

	client := Client{
		Name:         "Target App",
		UserID:       target.ID,
		Type:         "public",
		RedirectURIs: "https://app.example.com/cb",
		Scopes:       "openid profile",
	}
	if err := DB.Create(&client).Error; err != nil {
		t.Fatalf("failed creating client: %v", err)
	}

	userSess := Session{
		UserID:     &target.ID,
		Type:       "native",
		LastSeenAt: time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	clientSess := Session{
		UserID:     &other.ID,
		ClientID:   &client.ID,
		Type:       "client",
		LastSeenAt: time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	otherUserSess := Session{
		UserID:     &other.ID,
		Type:       "native",
		LastSeenAt: time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if err := DB.Create(&userSess).Error; err != nil {
		t.Fatalf("failed creating user session: %v", err)
	}
	if err := DB.Create(&clientSess).Error; err != nil {
		t.Fatalf("failed creating client session: %v", err)
	}
	if err := DB.Create(&otherUserSess).Error; err != nil {
		t.Fatalf("failed creating other user session: %v", err)
	}

	totp := TOTPSecret{
		UUID:      "11111111-1111-1111-1111-111111111111",
		UserID:    target.ID,
		Secret:    "JBSWY3DPEHPK3PXP",
		Label:     "test",
		Issuer:    "Gilos",
		UpdatedAt: time.Now().UnixMilli(),
	}
	if err := DB.Create(&totp).Error; err != nil {
		t.Fatalf("failed creating TOTP secret: %v", err)
	}

	changeLog := UsernameChangeLog{
		UserID:      target.ID,
		OldUsername: "oldname1",
		NewUsername: "purgeuser",
	}
	if err := DB.Create(&changeLog).Error; err != nil {
		t.Fatalf("failed creating username change log: %v", err)
	}

	if _, err := CreateDeletionRequest(target.ID, "privacy", ""); err != nil {
		t.Fatalf("failed creating deletion request: %v", err)
	}

	audit := AuditLog{
		UserID:    &target.ID,
		EventType: AuditLoginSuccess,
	}
	if err := DB.Create(&audit).Error; err != nil {
		t.Fatalf("failed creating audit log: %v", err)
	}

	if err := PurgeUserData(DB, target.ID); err != nil {
		t.Fatalf("PurgeUserData failed: %v", err)
	}

	var count int64
	DB.Model(&User{}).Where("id = ?", target.ID).Count(&count)
	if count != 0 {
		t.Errorf("expected target user to be deleted, count=%d", count)
	}
	DB.Model(&Client{}).Where("user_id = ?", target.ID).Count(&count)
	if count != 0 {
		t.Errorf("expected target clients to be deleted, count=%d", count)
	}
	DB.Model(&Session{}).Where("user_id = ? OR client_id = ?", target.ID, client.ID).Count(&count)
	if count != 0 {
		t.Errorf("expected target and client sessions to be deleted, count=%d", count)
	}
	DB.Model(&TOTPSecret{}).Where("user_id = ?", target.ID).Count(&count)
	if count != 0 {
		t.Errorf("expected TOTP secrets to be deleted, count=%d", count)
	}
	DB.Model(&UsernameChangeLog{}).Where("user_id = ?", target.ID).Count(&count)
	if count != 0 {
		t.Errorf("expected username change logs to be deleted, count=%d", count)
	}
	DB.Model(&AccountDeletionRequest{}).Where("user_id = ?", target.ID).Count(&count)
	if count != 0 {
		t.Errorf("expected deletion requests to be deleted, count=%d", count)
	}

	var preservedAudit AuditLog
	if err := DB.First(&preservedAudit, audit.ID).Error; err != nil {
		t.Fatalf("expected audit log to be preserved: %v", err)
	}
	if preservedAudit.UserID != nil {
		t.Errorf("expected preserved audit log UserID=nil, got %v", *preservedAudit.UserID)
	}

	var otherCount int64
	DB.Model(&User{}).Where("id = ?", other.ID).Count(&otherCount)
	if otherCount != 1 {
		t.Errorf("expected unrelated user to remain, count=%d", otherCount)
	}
	DB.Model(&Session{}).Where("id = ?", otherUserSess.ID).Count(&otherCount)
	if otherCount != 1 {
		t.Errorf("expected unrelated user's session to remain, count=%d", otherCount)
	}
}
