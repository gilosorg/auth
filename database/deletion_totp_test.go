package database

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeletionRequestTransactionalLifecycle(t *testing.T) {
	setupTestDB(t)

	user := User{
		Username:  "deltransuser",
		Email:     "deltrans@example.com",
		Phone:     998905551122,
		Password:  "hashed",
		FirstName: "Del",
		LastName:  "Trans",
		Status:    "active",
	}
	if err := DB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	req, err := CreateDeletionRequest(user.ID, DeletionReasonPrivacy, "cleaning up")
	if err != nil {
		t.Fatalf("CreateDeletionRequest failed: %v", err)
	}
	if req.Status != DeletionStatusPending {
		t.Fatalf("req.Status = %q, want %q", req.Status, DeletionStatusPending)
	}

	var reloaded User
	if err := DB.First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.Status != "pending_deletion" {
		t.Fatalf("user.Status = %q, want pending_deletion", reloaded.Status)
	}

	if _, err := CreateDeletionRequest(user.ID, DeletionReasonOther, "dup"); err == nil || !strings.Contains(err.Error(), "deletion_already_pending") {
		t.Fatalf("duplicate CreateDeletionRequest err = %v, want deletion_already_pending", err)
	}

	if err := CancelDeletionRequest(user.ID); err != nil {
		t.Fatalf("CancelDeletionRequest failed: %v", err)
	}

	if err := DB.First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("reload user after cancel: %v", err)
	}
	if reloaded.Status != "active" {
		t.Fatalf("user.Status after cancel = %q, want active", reloaded.Status)
	}

	var storedReq AccountDeletionRequest
	if err := DB.First(&storedReq, req.ID).Error; err != nil {
		t.Fatalf("reload deletion request: %v", err)
	}
	if storedReq.Status != DeletionStatusCancelled {
		t.Fatalf("storedReq.Status = %q, want %q", storedReq.Status, DeletionStatusCancelled)
	}

	if err := CancelDeletionRequest(user.ID); err == nil || !strings.Contains(err.Error(), "no_pending_deletion") {
		t.Fatalf("second CancelDeletionRequest err = %v, want no_pending_deletion", err)
	}
}

func TestRotateSessionAndTOTPFailures(t *testing.T) {
	setupTestDB(t)

	u1 := User{
		Username:  "totprotate1",
		Email:     "totprotate1@example.com",
		Phone:     998905553301,
		Password:  "hashed",
		FirstName: "TOTP",
		LastName:  "One",
		Status:    "active",
	}
	u2 := User{
		Username:  "totprotate2",
		Email:     "totprotate2@example.com",
		Phone:     998905553302,
		Password:  "hashed",
		FirstName: "TOTP",
		LastName:  "Two",
		Status:    "active",
	}
	if err := DB.Create(&u1).Error; err != nil {
		t.Fatalf("create u1: %v", err)
	}
	if err := DB.Create(&u2).Error; err != nil {
		t.Fatalf("create u2: %v", err)
	}

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	oldSess, err := SM.Start(context.Background(), rec1, req1, nil)
	if err != nil {
		t.Fatalf("SM.Start failed: %v", err)
	}
	if err := SM.SetUser(oldSess, u1.ID); err != nil {
		t.Fatalf("SM.SetUser failed: %v", err)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	newSess, err := SM.RotateSession(rec2, req2, oldSess)
	if err != nil {
		t.Fatalf("SM.RotateSession failed: %v", err)
	}
	if newSess.ID == oldSess.ID {
		t.Fatalf("expected rotated session ID to differ from %d", oldSess.ID)
	}
	if newSess.UserID == nil || *newSess.UserID != u1.ID {
		t.Fatalf("rotated session UserID = %v, want %d", newSess.UserID, u1.ID)
	}

	var oldCount int64
	DB.Model(&Session{}).Where("id = ?", oldSess.ID).Count(&oldCount)
	if oldCount != 0 {
		t.Fatalf("expected old session %d to be deleted, count=%d", oldSess.ID, oldCount)
	}

	var rotatedCookie string
	for _, c := range rec2.Result().Cookies() {
		if c.Name == "session_token" {
			rotatedCookie = c.Value
			break
		}
	}
	if newSess.CookieToken == nil || rotatedCookie != *newSess.CookieToken {
		t.Fatalf("expected session_token cookie %q to match rotated session token", rotatedCookie)
	}

	// Verify TOTP failures count 1..4 without blocking, and ClearTOTPFailures resets the counter
	for i := 1; i <= 4; i++ {
		blocked, until, count := SM.RecordTOTPFailure(u1.ID, newSess)
		if blocked || !until.IsZero() {
			t.Fatalf("failure %d unexpectedly blocked (until=%v)", i, until)
		}
		if count != int64(i) {
			t.Fatalf("failure %d count = %d, want %d", i, count, i)
		}
	}
	SM.ClearTOTPFailures(u1.ID)

	blockedAfterClear, _, countAfterClear := SM.RecordTOTPFailure(u1.ID, newSess)
	if blockedAfterClear || countAfterClear != 1 {
		t.Fatalf("after ClearTOTPFailures got blocked=%v count=%d, want false, 1", blockedAfterClear, countAfterClear)
	}

	// Verify 5th consecutive failure triggers a 24h security block for the user
	u2Sess := &Session{
		UserID:     &u2.ID,
		Type:       "native",
		LastSeenAt: time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if err := DB.Create(u2Sess).Error; err != nil {
		t.Fatalf("create u2 session: %v", err)
	}
	for i := 1; i <= 4; i++ {
		blocked, _, count := SM.RecordTOTPFailure(u2.ID, u2Sess)
		if blocked || count != int64(i) {
			t.Fatalf("u2 failure %d got blocked=%v count=%d", i, blocked, count)
		}
	}
	blocked, until, count := SM.RecordTOTPFailure(u2.ID, u2Sess)
	if !blocked || until.IsZero() || count != 5 {
		t.Fatalf("5th TOTP failure got blocked=%v until=%v count=%d, want true, non-zero, 5", blocked, until, count)
	}
	if isBlocked, _ := SM.IsBlocked(fmt.Sprintf("user:%d:security", u2.ID)); !isBlocked {
		t.Fatalf("expected user:%d:security to be blocked after 5 TOTP failures", u2.ID)
	}
}

func TestPartialUniqueIndexesAndTOTPScope(t *testing.T) {
	setupTestDB(t)

	// Multiple users with empty email and zero phone must be allowed
	u1 := User{Username: "emptycontact1", Email: "", Phone: 0, Password: "h", FirstName: "A", LastName: "One", Status: "active"}
	u2 := User{Username: "emptycontact2", Email: "", Phone: 0, Password: "h", FirstName: "B", LastName: "Two", Status: "active"}
	if err := DB.Create(&u1).Error; err != nil {
		t.Fatalf("create u1 with empty contact: %v", err)
	}
	if err := DB.Create(&u2).Error; err != nil {
		t.Fatalf("create u2 with empty contact: %v", err)
	}

	// Non-empty email and non-zero phone must enforce uniqueness
	u3 := User{Username: "uniqueuser1", Email: "unique@example.com", Phone: 998907778899, Password: "h", FirstName: "C", LastName: "Three", Status: "active"}
	if err := DB.Create(&u3).Error; err != nil {
		t.Fatalf("create u3: %v", err)
	}
	dupEmail := User{Username: "uniqueuser2", Email: "unique@example.com", Phone: 0, Password: "h", FirstName: "D", LastName: "Four", Status: "active"}
	if err := DB.Create(&dupEmail).Error; err == nil {
		t.Fatalf("expected duplicate non-empty email insert to fail")
	}
	dupPhone := User{Username: "uniqueuser3", Email: "", Phone: 998907778899, Password: "h", FirstName: "E", LastName: "Five", Status: "active"}
	if err := DB.Create(&dupPhone).Error; err == nil {
		t.Fatalf("expected duplicate non-zero phone insert to fail")
	}

	// Same TOTP UUID allowed across different users, rejected within the same user
	t1 := TOTPSecret{UUID: "shared-totp-uuid", UserID: u1.ID, Secret: "enc1", Label: "Work", Issuer: "Gilos", UpdatedAt: 1000}
	t2 := TOTPSecret{UUID: "shared-totp-uuid", UserID: u2.ID, Secret: "enc2", Label: "Work", Issuer: "Gilos", UpdatedAt: 1000}
	if err := DB.Create(&t1).Error; err != nil {
		t.Fatalf("create TOTPSecret for u1: %v", err)
	}
	if err := DB.Create(&t2).Error; err != nil {
		t.Fatalf("create TOTPSecret with same UUID for u2: %v", err)
	}
	dupSameUser := TOTPSecret{UUID: "shared-totp-uuid", UserID: u1.ID, Secret: "enc3", Label: "Dup", Issuer: "Gilos", UpdatedAt: 2000}
	if err := DB.Create(&dupSameUser).Error; err == nil {
		t.Fatalf("expected duplicate (user_id, uuid) TOTPSecret insert to fail")
	}
}

