package database

import (
	"log"
	"net/http"
	"time"

	"gilosauth/utils"
)

// AuditLog records security-critical events for compliance and incident response.
type AuditLog struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	UserID    *uint64   `gorm:"index" json:"user_id"`
	EventType string    `gorm:"size:50;not null;index" json:"event_type"`
	IPAddress string    `gorm:"size:45" json:"ip_address"`
	UserAgent string    `gorm:"size:500" json:"user_agent"`
	Details   string    `gorm:"size:2000" json:"details"`
	CreatedAt time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

// Audit event type constants
const (
	AuditLoginSuccess       = "login_success"
	AuditLoginFailed        = "login_failed"
	AuditPasswordChanged    = "password_changed"
	AuditPasswordReset      = "password_reset"
	AuditMFAChanged         = "mfa_changed"
	AuditMFATOTPEnabled     = "mfa_totp_enabled"
	AuditMFATOTPDisabled    = "mfa_totp_disabled"
	AuditAccountDeleted     = "account_deleted"
	AuditAccountCreated     = "account_created"
	AuditOAuthAuthorized    = "oauth_authorized"
	AuditOAuthDenied        = "oauth_denied"
	AuditOAuthTokenIssued   = "oauth_token_issued"
	AuditSessionTerminated  = "session_terminated"
	AuditSessionsTerminated = "sessions_terminated_bulk"
	AuditUsernameChanged    = "username_changed"
	AuditContactChanged     = "contact_changed"
	AuditSecurityBlocked    = "security_blocked"
	AuditBruteForceBlocked  = "brute_force_blocked"
	AuditAccountDeletionRequested = "account_deletion_requested"
	AuditAccountDeletionCancelled = "account_deletion_cancelled"
	AuditAccountDeletionCompleted = "account_deletion_completed"
)

// LogAuditEvent records a security event in the audit log.
func LogAuditEvent(eventType string, userID *uint64, r *http.Request, details string) {
	ip := ""
	userAgent := ""
	if r != nil {
		ip = utils.GetClientIP(r)
		userAgent = r.UserAgent()
		// Truncate user agent to prevent storage abuse
		if len(userAgent) > 500 {
			userAgent = userAgent[:500]
		}
	}

	entry := AuditLog{
		UserID:    userID,
		EventType: eventType,
		IPAddress: ip,
		UserAgent: userAgent,
		Details:   details,
	}

	if err := DB.Create(&entry).Error; err != nil {
		log.Printf("Failed to write audit log (event=%s): %v", eventType, err)
	}
}

// LogAuditEventWithUserID is a convenience wrapper that accepts a non-pointer userID.
func LogAuditEventWithUserID(eventType string, userID uint64, r *http.Request, details string) {
	LogAuditEvent(eventType, &userID, r, details)
}
