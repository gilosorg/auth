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

// PurgeUserData permanently deletes all data associated with a user inside a transaction.
// This is the destructive operation that runs after the grace period expires.
func PurgeUserData(db *gorm.DB, userID uint64) error {
	err := db.Transaction(func(tx *gorm.DB) error {
		// 1. Delete all sessions belonging to this user
		if err := tx.Where("user_id = ?", userID).Delete(&Session{}).Error; err != nil {
			return fmt.Errorf("failed to delete user sessions: %w", err)
		}

		// 2. Delete all client sessions for OAuth clients owned by this user
		var clientIDs []uint64
		if err := tx.Model(&Client{}).Where("user_id = ?", userID).Pluck("id", &clientIDs).Error; err != nil {
			return fmt.Errorf("failed to find clients: %w", err)
		}
		if len(clientIDs) > 0 {
			if err := tx.Where("client_id IN ?", clientIDs).Delete(&Session{}).Error; err != nil {
				return fmt.Errorf("failed to delete client sessions: %w", err)
			}
		}

		// 3. Delete all OAuth clients owned by the user
		if err := tx.Where("user_id = ?", userID).Delete(&Client{}).Error; err != nil {
			return fmt.Errorf("failed to delete clients: %w", err)
		}

		// 4. Delete TOTP secrets
		if err := tx.Where("user_id = ?", userID).Delete(&TOTPSecret{}).Error; err != nil {
			return fmt.Errorf("failed to delete TOTP secrets: %w", err)
		}

		// 5. Delete username change logs
		if err := tx.Where("user_id = ?", userID).Delete(&UsernameChangeLog{}).Error; err != nil {
			return fmt.Errorf("failed to delete username change logs: %w", err)
		}

		// 6. Delete account deletion requests (must precede User deletion due to FK constraint)
		if err := tx.Where("user_id = ?", userID).Delete(&AccountDeletionRequest{}).Error; err != nil {
			return fmt.Errorf("failed to delete deletion requests: %w", err)
		}

		// 7. Anonymize audit log entries referencing this user
		if err := tx.Model(&AuditLog{}).Where("user_id = ?", userID).Update("user_id", nil).Error; err != nil {
			log.Printf("Warning: failed to anonymize audit logs for user %d: %v", userID, err)
		}

		// 8. Delete the user record
		if err := tx.Where("id = ?", userID).Delete(&User{}).Error; err != nil {
			return fmt.Errorf("failed to delete user: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Clean up user icon files on disk after database purge commits
	iconDir := "./media/user/icon/"
	pattern := filepath.Join(iconDir, fmt.Sprintf("%d_*.jpg", userID))
	oldFiles, _ := filepath.Glob(pattern)
	for _, f := range oldFiles {
		os.Remove(f)
	}
	os.Remove(filepath.Join(iconDir, fmt.Sprintf("%d.jpg", userID)))

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

		// Purge all user data (also removes AccountDeletionRequest FK rows)
		if err := PurgeUserData(db, req.UserID); err != nil {
			log.Printf("Error purging user %d data: %v", req.UserID, err)
			continue
		}

		log.Printf("Successfully purged all data for user %d", req.UserID)
	}

	return nil
}
