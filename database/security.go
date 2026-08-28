package database

import (
	"fmt"
	"time"
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

	// Also block by UserID if available in session
	if sess != nil && sess.UserID != nil {
		userBlock := SecurityBlock{
			Identifier:   fmt.Sprintf("user:%d:%s", *sess.UserID, blockType),
			BlockedUntil: blockedUntil,
		}
		sm.db.Create(&userBlock) // Ignore error if already blocked or so
	}

	// If a session is provided, update it to reflect the block
	if sess != nil {
		if sess.RawData == nil {
			sess.RawData = make(JSONData)
		}
		sess.RawData["is_blocked"] = true
		sess.RawData["blocked_until"] = blockedUntil.Format(time.RFC3339)
		
		// Extend session expiration to cover the block period
		if sess.ExpiresAt.Before(blockedUntil) {
			sess.ExpiresAt = blockedUntil.Add(1 * time.Hour)
		}
		
		if err := sm.db.Save(sess).Error; err != nil {
			return err
		}
	}

	return nil
}
