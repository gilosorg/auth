package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"gilosauth/config"
	"gilosauth/utils"

	"gorm.io/gorm"
)

// Manager is the global session manager instance
var SM *SessionManager

// SessionManager handles session operations
type SessionManager struct {
	db *gorm.DB
}

// ContextKey is used to store the session in the request context
type ContextKey string

const SessionContextKey ContextKey = "session"

// InitSessionManager initializes the global session manager and cleans expired sessions
func InitSessionManager() {
	SM = &SessionManager{db: DB}
	if err := CleanExpiredSessions(DB); err != nil {
		log.Printf("Failed to clean expired sessions: %v", err)
	}
}

var cleanupStopMu sync.Mutex
var cleanupStopCh chan struct{}

// StartCleanupTicker starts a background goroutine that cleans expired sessions periodically.
func StartCleanupTicker(interval time.Duration) {
	cleanupStopMu.Lock()
	if cleanupStopCh != nil {
		close(cleanupStopCh)
	}
	stopCh := make(chan struct{})
	cleanupStopCh = stopCh
	cleanupStopMu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if err := CleanExpiredSessions(DB); err != nil {
					log.Printf("Periodic session cleanup error: %v", err)
				}
			}
		}
	}()
}

// StopCleanupTicker stops the background cleanup goroutine if running.
func StopCleanupTicker() {
	cleanupStopMu.Lock()
	defer cleanupStopMu.Unlock()
	if cleanupStopCh != nil {
		close(cleanupStopCh)
		cleanupStopCh = nil
	}
}

// generateCookieToken creates a secure random cookie token
func generateCookieToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate cookie token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// setSessionCookie sets a session cookie on the response with correct flags.
func setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		Domain:   config.CookieDomain,
		HttpOnly: true,
		Secure:   config.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

// lookupNativeSession fetches an active native session by its SHA-256 token hash,
// falling back once to legacy plaintext tokens and upgrading them in place.
func lookupNativeSession(db *gorm.DB, rawToken string) (Session, error) {
	var session Session
	now := time.Now()
	hashed := utils.HashToken(rawToken)
	err := db.Where("cookie_token = ? AND type = ? AND expires_at > ?", hashed, "native", now).
		First(&session).Error
	if err == nil {
		session.RawCookieToken = rawToken
		return session, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) || rawToken == "" {
		return session, err
	}

	// Legacy plaintext session upgrade for active live cookies
	if legacyErr := db.Where("cookie_token = ? AND type = ? AND expires_at > ?", rawToken, "native", now).
		First(&session).Error; legacyErr != nil {
		return session, legacyErr
	}
	_ = db.Model(&Session{}).
		Where("id = ? AND cookie_token = ?", session.ID, rawToken).
		Update("cookie_token", hashed).Error
	session.CookieToken = &hashed
	session.RawCookieToken = rawToken
	return session, nil
}

// SetSessionCookieHelper is the exported version of setSessionCookie for use by handler packages.
func SetSessionCookieHelper(w http.ResponseWriter, token string, expires time.Time) {
	setSessionCookie(w, token, expires)
}

// Start retrieves or creates a session
func (sm *SessionManager) Start(ctx context.Context, w http.ResponseWriter, r *http.Request, clientID *uint64) (*Session, error) {
	var session Session
	var sessionType string

	// Determine session type: native (browser) or client (OAuth API)
	if clientID != nil {
		sessionType = "client"
	} else {
		sessionType = "native"
	}

	if sessionType == "native" {
		// Check for existing session cookie
		cookie, err := r.Cookie("session_token")
		if err == nil && cookie.Value != "" {
			// Try to find active, unexpired session by hashed (or legacy raw) cookie token
			if found, err := lookupNativeSession(sm.db, cookie.Value); err == nil {
				session = found
				metadataChanged := sm.UpdateMetadata(&session, r)
				shouldTouch := metadataChanged || time.Since(session.LastSeenAt) >= time.Minute
				if shouldTouch {
					session.LastSeenAt = time.Now()
					updates := map[string]interface{}{
						"last_seen_at": session.LastSeenAt,
						"device_info":  session.DeviceInfo,
						"ip_address":   session.IPAddress,
					}
					if session.UserID == nil {
						// Non-user-bound session: refresh 1-hour expiration
						session.ExpiresAt = time.Now().Add(1 * time.Hour)
						updates["expires_at"] = session.ExpiresAt
					}
					if err := sm.db.Model(&session).Updates(updates).Error; err != nil {
						return nil, fmt.Errorf("failed to update session: %w", err)
					}
				}
				// Keep browser cookie aligned with current expiration using plaintext token
				if shouldTouch || session.UserID == nil {
					setSessionCookie(w, cookie.Value, session.ExpiresAt)
				}
				return &session, nil
			}
		}
	}

	// Create new session
	var rawToken string
	var cookieToken *string
	var expiresAt time.Time
	if sessionType == "native" {
		token, err := generateCookieToken()
		if err != nil {
			return nil, err
		}
		rawToken = token
		hashed := utils.HashToken(token)
		cookieToken = &hashed
		expiresAt = time.Now().Add(1 * time.Hour) // Default 1-hour expiration for non-user-bound
	} else {
		expiresAt = time.Now().Add(30 * 24 * time.Hour) // API sessions
	}

	session = Session{
		CookieToken:    cookieToken,
		RawCookieToken: rawToken,
		Type:           sessionType,
		RawData:        make(JSONData),
		LastSeenAt:     time.Now(),
		ExpiresAt:      expiresAt,
	}
	sm.UpdateMetadata(&session, r)

	if clientID != nil {
		session.ClientID = clientID
	}

	if err := sm.db.Create(&session).Error; err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Set session cookie for web sessions with plaintext token
	if sessionType == "native" && rawToken != "" {
		setSessionCookie(w, rawToken, session.ExpiresAt)
	}

	return &session, nil
}

// Get retrieves a session by cookie token (for web) or ID (for API).
// When r is provided, session metadata (IP address, device info) is updated
// on every access so users always see the most recent IP for each session.
func (sm *SessionManager) Get(identifier string, sessionType string, r ...*http.Request) (*Session, error) {
	var session Session
	var err error

	if sessionType == "native" {
		session, err = lookupNativeSession(sm.db, identifier)
	} else {
		var id uint64
		if _, err := fmt.Sscanf(identifier, "%d", &id); err != nil {
			return nil, fmt.Errorf("invalid session ID for API: %w", err)
		}
		err = sm.db.Where("id = ? AND type = ? AND expires_at > ?", id, "client", time.Now()).First(&session).Error
	}

	if err != nil {
		return nil, fmt.Errorf("session not found or expired: %w", err)
	}

	// Update metadata immediately when IP/UA changes; throttle idle LastSeenAt writes
	metadataChanged := false
	if len(r) > 0 && r[0] != nil {
		metadataChanged = sm.UpdateMetadata(&session, r[0])
	}

	if metadataChanged || time.Since(session.LastSeenAt) >= time.Minute {
		session.LastSeenAt = time.Now()
		updates := map[string]interface{}{
			"last_seen_at": session.LastSeenAt,
			"device_info":  session.DeviceInfo,
			"ip_address":   session.IPAddress,
		}
		if session.UserID == nil {
			// Non-user-bound session: refresh 1-hour expiration
			session.ExpiresAt = time.Now().Add(1 * time.Hour)
			updates["expires_at"] = session.ExpiresAt
		}
		if err := sm.db.Model(&session).Updates(updates).Error; err != nil {
			return nil, fmt.Errorf("failed to update session: %w", err)
		}
	}

	return &session, nil
}

// GetFromRequest retrieves a session from the request for web sessions.
// Passes the request through so metadata (IP, device) is updated on every access.
func (sm *SessionManager) GetFromRequest(r *http.Request, sessionType string) (*Session, error) {
	if sessionType != "native" {
		return nil, fmt.Errorf("GetFromRequest only supports native sessions")
	}

	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	return sm.Get(cookie.Value, "native", r)
}

// SetData sets a key-value pair in the session data
func (sm *SessionManager) SetData(session *Session, key string, value interface{}) error {
	if session.RawData == nil {
		session.RawData = make(JSONData)
	}
	session.RawData[key] = value
	if err := sm.db.Model(&Session{}).Where("id = ?", session.ID).Update("raw_data", session.RawData).Error; err != nil {
		return fmt.Errorf("failed to save session data: %w", err)
	}
	return nil
}

// GetData retrieves a value from the session data
func (sm *SessionManager) GetData(session *Session, key string) (interface{}, bool) {
	if session.RawData == nil {
		return nil, false
	}
	value, exists := session.RawData[key]
	return value, exists
}

// DeleteData removes a key from the session data
func (sm *SessionManager) DeleteData(session *Session, key string) error {
	if session.RawData == nil {
		return nil
	}
	delete(session.RawData, key)
	if err := sm.db.Model(&Session{}).Where("id = ?", session.ID).Update("raw_data", session.RawData).Error; err != nil {
		return fmt.Errorf("failed to delete session data: %w", err)
	}
	return nil
}

// ClearAllData removes all data from the session
func (sm *SessionManager) ClearAllData(session *Session) error {
	session.RawData = make(JSONData)
	if err := sm.db.Model(&Session{}).Where("id = ?", session.ID).Update("raw_data", session.RawData).Error; err != nil {
		return fmt.Errorf("failed to clear session data: %w", err)
	}
	return nil
}

// Destroy deletes a session
func (sm *SessionManager) Destroy(session *Session) error {
	if err := sm.db.Delete(session).Error; err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// SetUser associates a user with the session and sets long expiration.
// Clears all session data and persists in a single DB write.
func (sm *SessionManager) SetUser(session *Session, userID uint64) error {
	session.UserID = &userID
	session.LastSeenAt = time.Now()
	// User-bound sessions have 1-year expiration
	session.ExpiresAt = time.Now().Add(365 * 24 * time.Hour)
	// Clear all session data when binding user
	session.RawData = make(JSONData)
	if err := sm.db.Save(session).Error; err != nil {
		return fmt.Errorf("failed to set user in session: %w", err)
	}
	return nil
}

// RotateSession prevents session fixation by creating a new session with a fresh
// cookie token after authentication, copying the user binding from the old session.
// The old session is deleted atomically before inserting the new one to prevent double rotation.
func (sm *SessionManager) RotateSession(w http.ResponseWriter, r *http.Request, oldSession *Session) (*Session, error) {
	if oldSession.Type != "native" {
		return oldSession, nil // Only rotate web sessions
	}

	// Generate new plaintext cookie token and mint a fresh CSRF token
	newToken, err := generateCookieToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new cookie token: %w", err)
	}
	freshCSRF, err := generateCookieToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate fresh CSRF token: %w", err)
	}
	hashedToken := utils.HashToken(newToken)

	// Create new session with the same user binding
	newSession := Session{
		UserID:         oldSession.UserID,
		ClientID:       oldSession.ClientID,
		Type:           oldSession.Type,
		CookieToken:    &hashedToken,
		RawCookieToken: newToken,
		RawData:        JSONData{"csrf_token": freshCSRF},
		LastSeenAt:     time.Now(),
		ExpiresAt:      oldSession.ExpiresAt,
	}
	sm.UpdateMetadata(&newSession, r)

	if err := sm.db.Transaction(func(tx *gorm.DB) error {
		delRes := tx.Where("id = ?", oldSession.ID).Delete(&Session{})
		if delRes.Error != nil {
			return fmt.Errorf("failed to remove old session: %w", delRes.Error)
		}
		if delRes.RowsAffected != 1 {
			return fmt.Errorf("old session no longer active")
		}
		if err := tx.Create(&newSession).Error; err != nil {
			return fmt.Errorf("failed to create rotated session: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Set new cookie only after the transaction commits
	setSessionCookie(w, newToken, newSession.ExpiresAt)

	return &newSession, nil
}

// ClearUser removes the user association from the session
func (sm *SessionManager) ClearUser(session *Session) error {
	session.UserID = nil
	session.LastSeenAt = time.Now()
	session.ExpiresAt = time.Now().Add(1 * time.Hour) // Revert to 1-hour expiration
	if err := sm.db.Save(session).Error; err != nil {
		return fmt.Errorf("failed to clear user from session: %w", err)
	}
	return nil
}

// UpdateMetadata updates the session's IP address and device info from the request.
// Returns true if either field changed.
func (sm *SessionManager) UpdateMetadata(session *Session, r *http.Request) bool {
	if r == nil {
		return false
	}
	changed := false
	userAgent := r.UserAgent()
	if len(userAgent) > 255 {
		userAgent = userAgent[:255]
	}
	if userAgent != "" && (session.DeviceInfo == nil || *session.DeviceInfo != userAgent) {
		session.DeviceInfo = &userAgent
		changed = true
	}
	clientIP := utils.GetClientIP(r)
	if len(clientIP) > 45 {
		clientIP = clientIP[:45]
	}
	if clientIP != "" && (session.IPAddress == nil || *session.IPAddress != clientIP) {
		session.IPAddress = &clientIP
		changed = true
	}
	return changed
}

// CleanExpiredSessions removes all expired sessions and security blocks from the database.
func CleanExpiredSessions(db *gorm.DB) error {
	result := db.Where("expires_at < ?", time.Now()).Delete(&Session{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		log.Printf("Cleaned %d expired sessions", result.RowsAffected)
	}

	// Also clean expired security blocks
	blockResult := db.Where("blocked_until < ?", time.Now()).Delete(&SecurityBlock{})
	if blockResult.Error != nil {
		return blockResult.Error
	}
	if blockResult.RowsAffected > 0 {
		log.Printf("Cleaned %d expired security blocks", blockResult.RowsAffected)
	}

	// Clean old audit logs (keep 90 days)
	auditResult := db.Where("created_at < ?", time.Now().Add(-90*24*time.Hour)).Delete(&AuditLog{})
	if auditResult.Error != nil {
		return auditResult.Error
	}
	if auditResult.RowsAffected > 0 {
		log.Printf("Cleaned %d old audit log entries", auditResult.RowsAffected)
	}

	// Process expired account deletion requests (30-day grace period)
	if err := ProcessExpiredDeletionRequests(db); err != nil {
		log.Printf("Error processing expired deletion requests: %v", err)
	}

	// Run WAL checkpoint and incremental vacuum to maintain database health
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.Exec("PRAGMA wal_checkpoint(PASSIVE)")
		sqlDB.Exec("PRAGMA incremental_vacuum(100)")
	}

	return nil
}

