package database

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// IsBlocked checks if an identifier (email, phone, or username) is currently blocked.
func (sm *SessionManager) IsBlocked(identifier string) (bool, *time.Time) {
	if identifier == "" {
		return false, nil
	}
	var block SecurityBlock
	err := sm.db.Where("identifier = ? AND blocked_until > ?", identifier, time.Now()).
		Order("blocked_until DESC").First(&block).Error
	if err == nil {
		return true, &block.BlockedUntil
	}
	return false, nil
}

// ApplyBlock creates a persistent security block for an identifier and updates the session if provided.
// Duration specifies how long the block should last.
// blockType is appended to the UserID-based identifier (e.g., "security", "username").
// If sess is provided and has a UserID, it also blocks by UserID.
func (sm *SessionManager) ApplyBlock(identifier string, sess *Session, duration time.Duration, blockType string) error {
	blockedUntil := time.Now().Add(duration)

	if blockType == "" {
		blockType = "security"
	}

	// Create persistent block record for the identifier
	block := SecurityBlock{
		Identifier:   identifier,
		BlockedUntil: blockedUntil,
	}
	if err := sm.db.Create(&block).Error; err != nil {
		return err
	}

	// Also block by UserID if available in session (avoid inserting a duplicate row)
	if sess != nil && sess.UserID != nil {
		userIdentifier := fmt.Sprintf("user:%d:%s", *sess.UserID, blockType)
		if userIdentifier != identifier {
			userBlock := SecurityBlock{
				Identifier:   userIdentifier,
				BlockedUntil: blockedUntil,
			}
			_ = sm.db.Create(&userBlock).Error
		}
	}

	// Only propagate general security blocks onto pre-auth / active session metadata;
	// username change cooldowns must never mark a session blocked or extend its expiry.
	if sess != nil && blockType != "username" {
		if sess.RawData == nil {
			sess.RawData = make(JSONData)
		}
		sess.RawData["is_blocked"] = true
		sess.RawData["blocked_until"] = blockedUntil.Format(time.RFC3339)

		updates := map[string]interface{}{
			"raw_data": sess.RawData,
		}
		// Only extend ephemeral unauthenticated pre-auth sessions so /auth/state preserves the notice
		if sess.UserID == nil && sess.ExpiresAt.Before(blockedUntil) {
			sess.ExpiresAt = blockedUntil.Add(1 * time.Hour)
			updates["expires_at"] = sess.ExpiresAt
		}

		if err := sm.db.Model(sess).Updates(updates).Error; err != nil {
			return err
		}
	}

	return nil
}

// RecordTOTPFailure records a failed TOTP verification for userID across sessions and blocks at 5 failures.
func (sm *SessionManager) RecordTOTPFailure(userID uint64, sess *Session) (bool, time.Time, int64) {
	failKey := fmt.Sprintf("totp_fail:%d", userID)
	now := time.Now()
	var failCount int64
	if err := sm.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&SecurityBlock{}).Where("identifier = ? AND blocked_until > ?", failKey, now).Count(&failCount).Error; err != nil {
			return err
		}
		if err := tx.Create(&SecurityBlock{
			Identifier:   failKey,
			BlockedUntil: now.Add(1 * time.Hour),
		}).Error; err != nil {
			return err
		}
		failCount++
		return nil
	}); err != nil {
		return false, time.Time{}, failCount
	}
	if failCount >= 5 {
		until := now.Add(24 * time.Hour)
		_ = sm.ApplyBlock(fmt.Sprintf("user:%d:security", userID), sess, 24*time.Hour, "security")
		return true, until, failCount
	}
	return false, time.Time{}, failCount
}

// ClearTOTPFailures clears accumulated per-user TOTP failure markers after successful verification.
func (sm *SessionManager) ClearTOTPFailures(userID uint64) {
	sm.db.Where("identifier = ?", fmt.Sprintf("totp_fail:%d", userID)).Delete(&SecurityBlock{})
}
