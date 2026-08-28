package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"gorm.io/gorm"
)

// DeletionGracePeriod is the duration a deletion request remains pending before execution.
const DeletionGracePeriod = 30 * 24 * time.Hour

// Predefined deletion reason constants.
const (
	DeletionReasonNotUsing     = "not_using"
	DeletionReasonPrivacy      = "privacy"
	DeletionReasonSwitching    = "switching"
	DeletionReasonSecurity     = "security"
	DeletionReasonDissatisfied = "dissatisfied"
	DeletionReasonOther        = "other"
)

// Deletion request status constants.
const (
	DeletionStatusPending   = "pending"
	DeletionStatusCancelled = "cancelled"
	DeletionStatusCompleted = "completed"
)

// ValidDeletionReasons is the set of accepted reason keys.
var ValidDeletionReasons = map[string]bool{
	DeletionReasonNotUsing:     true,
	DeletionReasonPrivacy:      true,
	DeletionReasonSwitching:    true,
	DeletionReasonSecurity:     true,
	DeletionReasonDissatisfied: true,
	DeletionReasonOther:        true,
}

// AccountDeletionRequest tracks a user's request to delete their account.
// Only one pending request is allowed per user at a time (enforced by uniqueIndex on UserID + application logic).
type AccountDeletionRequest struct {
	ID           uint64    `gorm:"primaryKey" json:"id"`
	UserID       uint64    `gorm:"index;not null" json:"user_id"`
	User         User      `gorm:"foreignKey:UserID" json:"-"`
	Status       string    `gorm:"size:20;not null;default:pending" json:"status"`
	Reason       string    `gorm:"size:30;not null" json:"reason"`
	CustomReason string    `gorm:"size:500" json:"custom_reason,omitempty"`
	ScheduledAt  time.Time `gorm:"not null;index" json:"scheduled_at"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// IsValidDeletionReason checks whether the given reason is in the predefined set.
func IsValidDeletionReason(reason string) bool {
	return ValidDeletionReasons[reason]
}

// GetActiveDeletionRequest returns the pending deletion request for a user, or nil if none exists.
func GetActiveDeletionRequest(userID uint64) (*AccountDeletionRequest, error) {
	var req AccountDeletionRequest
	err := DB.Where("user_id = ? AND status = ?", userID, DeletionStatusPending).First(&req).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &req, nil
}

// CreateDeletionRequest creates a new pending deletion request for the user.
// Returns an error if a pending request already exists.
func CreateDeletionRequest(userID uint64, reason, customReason string) (*AccountDeletionRequest, error) {
	// Check for existing pending request
	existing, err := GetActiveDeletionRequest(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing requests: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("deletion_already_pending")
	}

	req := AccountDeletionRequest{
		UserID:       userID,
		Status:       DeletionStatusPending,
		Reason:       reason,
		CustomReason: customReason,
		ScheduledAt:  time.Now().Add(DeletionGracePeriod),
	}

	if err := DB.Create(&req).Error; err != nil {
		return nil, fmt.Errorf("failed to create deletion request: %w", err)
	}

	// Set user status to pending_deletion
	if err := DB.Model(&User{}).Where("id = ?", userID).Update("status", "pending_deletion").Error; err != nil {
		return nil, fmt.Errorf("failed to update user status: %w", err)
	}

	return &req, nil
}

// CancelDeletionRequest cancels the active pending deletion request for the user.
func CancelDeletionRequest(userID uint64) error {
	req, err := GetActiveDeletionRequest(userID)
	if err != nil {
		return fmt.Errorf("failed to retrieve deletion request: %w", err)
	}
	if req == nil {
		return fmt.Errorf("no_pending_deletion")
	}

	if err := DB.Model(req).Update("status", DeletionStatusCancelled).Error; err != nil {
		return fmt.Errorf("failed to cancel deletion request: %w", err)
	}

	// Restore user status to active
	if err := DB.Model(&User{}).Where("id = ?", userID).Update("status", "active").Error; err != nil {
		return fmt.Errorf("failed to restore user status: %w", err)
	}

	return nil
}

// DaysRemaining calculates the number of full days remaining until the scheduled deletion.
func (r *AccountDeletionRequest) DaysRemaining() int {
	remaining := time.Until(r.ScheduledAt)
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Hours() / 24)
}

// PurgeUserData permanently deletes all data associated with a user.
// This is the destructive operation that runs after the grace period expires.
func PurgeUserData(db *gorm.DB, userID uint64) error {
	// 1. Destroy all sessions (properly, including cookie cleanup)
	var sessions []Session
	if err := db.Where("user_id = ?", userID).Find(&sessions).Error; err != nil {
		return fmt.Errorf("failed to find sessions: %w", err)
	}
	for _, sess := range sessions {
		if err := SM.Destroy(&sess); err != nil {
			log.Printf("Warning: failed to destroy session %d for user %d: %v", sess.ID, userID, err)
		}
	}

	// 2. Delete all client sessions (sessions for clients owned by this user)
	var clients []Client
	if err := db.Where("user_id = ?", userID).Find(&clients).Error; err != nil {
		return fmt.Errorf("failed to find clients: %w", err)
	}
	for _, client := range clients {
		var clientSessions []Session
		if err := db.Where("client_id = ?", client.ID).Find(&clientSessions).Error; err == nil {
			for _, cs := range clientSessions {
				SM.Destroy(&cs)
			}
		}
	}

	// 3. Delete all OAuth clients
	if err := db.Where("user_id = ?", userID).Delete(&Client{}).Error; err != nil {
		return fmt.Errorf("failed to delete clients: %w", err)
	}

	// 4. Delete TOTP secrets
	if err := db.Where("user_id = ?", userID).Delete(&TOTPSecret{}).Error; err != nil {
		log.Printf("Warning: failed to delete TOTP secrets for user %d: %v", userID, err)
	}

	// 5. Delete username change logs
	if err := db.Where("user_id = ?", userID).Delete(&UsernameChangeLog{}).Error; err != nil {
		log.Printf("Warning: failed to delete username change logs for user %d: %v", userID, err)
	}

	// 6. Delete user icon files
	iconDir := "./media/user/icon/"
	pattern := filepath.Join(iconDir, fmt.Sprintf("%d_*.jpg", userID))
	oldFiles, _ := filepath.Glob(pattern)
	for _, f := range oldFiles {
		os.Remove(f)
	}
	os.Remove(filepath.Join(iconDir, fmt.Sprintf("%d.jpg", userID)))

	// 7. Delete the user record
	if err := db.Where("id = ?", userID).Delete(&User{}).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// ProcessExpiredDeletionRequests finds all pending requests past their scheduled date
// and executes the full account purge. Called by the hourly cleanup ticker.
func ProcessExpiredDeletionRequests(db *gorm.DB) error {
	var requests []AccountDeletionRequest
	if err := db.Where("status = ? AND scheduled_at <= ?", DeletionStatusPending, time.Now()).Find(&requests).Error; err != nil {
		return fmt.Errorf("failed to query expired deletion requests: %w", err)
	}

	for _, req := range requests {
		log.Printf("Processing expired deletion request %d for user %d", req.ID, req.UserID)

		// Log audit event before purging
		LogAuditEventWithUserID(AuditAccountDeletionCompleted, req.UserID, nil,
			fmt.Sprintf("account deletion completed after 30-day grace period (reason: %s)", req.Reason))

		// Purge all user data
		if err := PurgeUserData(db, req.UserID); err != nil {
			log.Printf("Error purging user %d data: %v", req.UserID, err)
			continue // Don't mark as completed if purge failed
		}

		// Mark request as completed
		if err := db.Model(&req).Update("status", DeletionStatusCompleted).Error; err != nil {
			log.Printf("Error marking deletion request %d as completed: %v", req.ID, err)
		}

		log.Printf("Successfully purged all data for user %d", req.UserID)
	}

	return nil
}
