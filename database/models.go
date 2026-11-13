package database

import (
	"database/sql/driver"
	"net/url"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// User represents a user in the system.
type User struct {
	ID              uint64    `gorm:"primaryKey" json:"id"`
	Username        string    `gorm:"size:30;uniqueIndex;not null" json:"username"`
	Email           string    `gorm:"size:100;index" json:"email"`
	Phone           uint64    `gorm:"index" json:"phone"`
	Password        string    `gorm:"size:255;not null" json:"-"`       // Hashed password (bcrypt)
	Status          string    `gorm:"size:20;not null;default:active" json:"status"` // active, suspended, pending_deletion
	MFAEmailEnabled bool      `gorm:"not null;default:false" json:"mfa_email_enabled"`
	MFAPhoneEnabled bool      `gorm:"not null;default:false" json:"mfa_phone_enabled"`
	MFATOTPEnabled  bool      `gorm:"not null;default:false" json:"mfa_totp_enabled"`
	EmailVerified   bool      `gorm:"not null;default:false" json:"email_verified"`
	PhoneVerified   bool      `gorm:"not null;default:false" json:"phone_verified"`
	FirstName       string    `gorm:"size:50" json:"first_name"`
	LastName        string    `gorm:"size:50" json:"last_name"`
	MiddleName      string    `gorm:"size:50" json:"middle_name"`
	Nickname        string    `gorm:"size:50" json:"nickname"`
	Icon            string    `gorm:"size:255" json:"icon"` // Path to user profile picture
	TOTPSecret      string    `gorm:"size:255" json:"-"`    // TOTP secret for MFA (AES-256-GCM encrypted)
	CreatedAt       time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt       time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// Client represents an OAuth client.
// Type determines the authentication method:
//   - "confidential": Server-side apps that can securely store a secret. Authenticate with client_secret.
//   - "public": Native/mobile/SPA apps that cannot store a secret. Authenticate with PKCE (RFC 7636).
type Client struct {
	ID              uint64     `gorm:"primaryKey"`
	Secret          *string    `gorm:"size:64" json:"-"`                       // Bcrypt hash — only set for confidential clients
	SecretPrefix    string     `gorm:"size:8" json:"secret_prefix,omitempty"`  // First 8 chars of plaintext secret for identification
	SecretCreatedAt *time.Time `json:"secret_created_at,omitempty"`            // When the current secret was generated
	UserID          uint64     `gorm:"index;not null"`
	User            User       `gorm:"foreignKey:UserID" json:"-"`
	Type            string     `gorm:"size:15;not null"`                       // "public" or "confidential"
	RedirectURIs    string     `gorm:"column:redirect_uris;size:2048;not null;default:''"` // Comma-separated redirect URIs
	Scopes          string     `gorm:"size:255"`                               // Comma-separated scopes
	RequiredScopes  string     `gorm:"size:255"`                               // Comma-separated scopes that require user data
	Name            string     `gorm:"size:100"`                               // Client name
	CreatedAt       time.Time  `gorm:"autoCreateTime"`
	UpdatedAt       time.Time  `gorm:"autoUpdateTime"`
}

// IsPublic returns true if this client is a public client (native/mobile/SPA).
func (c *Client) IsPublic() bool {
	return c.Type == "public"
}

// IsConfidential returns true if this client is a confidential client (server-side).
func (c *Client) IsConfidential() bool {
	return c.Type == "confidential"
}

// HasSecret returns true if the client has a secret set.
func (c *Client) HasSecret() bool {
	return c.Secret != nil && *c.Secret != ""
}

// HasRedirectURI checks whether the given URI is in this client's registered redirect URIs.
// Per RFC 8252 Section 7.3, loopback redirects (http://localhost, http://127.0.0.1, http://[::1])
// match regardless of port number, allowing desktop apps to use ephemeral ports while strictly
// matching scheme, host, and path.
func (c *Client) HasRedirectURI(uri string) bool {
	for _, registered := range c.RedirectURIList() {
		if registered == uri {
			return true
		}
		// RFC 8252: allow any port for loopback redirects
		if matchesLoopbackRedirect(registered, uri) {
			return true
		}
	}
	return false
}

// matchesLoopbackRedirect checks if requestedURI matches registeredURI per RFC 8252 §7.3.
// Loopback redirects (http://localhost, http://127.0.0.1, http://[::1]) match
// regardless of port number, allowing desktop apps to use ephemeral ports,
// while strictly requiring scheme, loopback host, and path to match.
func matchesLoopbackRedirect(registeredURI, requestedURI string) bool {
	uReg, err1 := url.Parse(registeredURI)
	uReq, err2 := url.Parse(requestedURI)
	if err1 != nil || err2 != nil || uReg.User != nil || uReq.User != nil {
		return false
	}

	// Must both use http scheme
	if !strings.EqualFold(uReg.Scheme, "http") || !strings.EqualFold(uReq.Scheme, "http") {
		return false
	}

	regHost := uReg.Hostname()
	reqHost := uReq.Hostname()

	// Both must be loopback hosts
	if !isLoopbackHost(regHost) || !isLoopbackHost(reqHost) {
		return false
	}

	// Hostname must match (e.g. localhost with localhost, 127.0.0.1 with 127.0.0.1)
	if !strings.EqualFold(regHost, reqHost) {
		return false
	}

	// Path and query string must match exactly (normalize empty path to "/")
	regPath := uReg.Path
	if regPath == "" {
		regPath = "/"
	}
	reqPath := uReq.Path
	if reqPath == "" {
		reqPath = "/"
	}

	return regPath == reqPath && uReg.RawQuery == uReq.RawQuery
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"
}

// RedirectURIList returns the registered redirect URIs as a slice.
func (c *Client) RedirectURIList() []string {
	if c.RedirectURIs == "" {
		return nil
	}
	parts := strings.Split(c.RedirectURIs, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// Session represents a user session (web or API-based).
type Session struct {
	ID                   uint64     `gorm:"primaryKey"`
	UserID               *uint64    `gorm:"index"` // Nullable UserID
	User                 *User      `gorm:"foreignKey:UserID"`
	ClientID             *uint64    `gorm:"index"` // Nullable ClientID
	Client               *Client    `gorm:"foreignKey:ClientID"`
	Scopes               *string    `gorm:"size:255"`
	Type                 string     `gorm:"size:15;not null;index:idx_type_expires"` // "native" or "client"
	RawData              JSONData   `gorm:"type:text;not null;default:'{}'" json:"-"` // JSON key-value pairs — never expose in API
	CookieToken          *string    `gorm:"size:64;uniqueIndex" json:"-"`    // Nullable cookie token for web sessions
	AccessToken          *string    `gorm:"size:64;index" json:"-"`          // SHA-256 hex (always 64 chars)
	RefreshToken         *string    `gorm:"size:64;index" json:"-"`          // SHA-256 hex (always 64 chars)
	PreviousRefreshToken *string    `gorm:"size:64;index" json:"-"`          // Previous rotated refresh token hash for reuse detection
	DeviceInfo           *string    `gorm:"size:255"`                        // e.g., "Chrome on Windows"
	IPAddress            *string    `gorm:"size:45"`                         // Supports IPv4 and IPv6
	LastSeenAt           time.Time  `gorm:"not null"`                        // Last session access time
	ExpiresAt            time.Time  `gorm:"not null;index:idx_type_expires"` // Session expiration time
	AccessTokenExpiresAt *time.Time `gorm:""`                                // Access token expiration time
	CreatedAt            time.Time  `gorm:"autoCreateTime"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime"`
}

// ClientSummary exposes non-sensitive client metadata on session DTOs.
type ClientSummary struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// SessionResponse is a safe DTO for API responses that excludes sensitive token data.
type SessionResponse struct {
	ID         uint64         `json:"id"`
	UserID     *uint64        `json:"user_id"`
	ClientID   *uint64        `json:"client_id"`
	Client     *ClientSummary `json:"client,omitempty"`
	Scopes     *string        `json:"scopes,omitempty"`
	Type       string         `json:"type"`
	DeviceInfo *string        `json:"device_info"`
	IPAddress  *string        `json:"ip_address"`
	LastSeenAt time.Time      `json:"last_seen_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// ToResponse converts a Session to a safe SessionResponse DTO.
func (s *Session) ToResponse() SessionResponse {
	var clientSummary *ClientSummary
	if s.Client != nil {
		clientSummary = &ClientSummary{
			ID:   s.Client.ID,
			Name: s.Client.Name,
			Type: s.Client.Type,
		}
	}
	resp := SessionResponse{
		ID:         s.ID,
		UserID:     s.UserID,
		ClientID:   s.ClientID,
		Client:     clientSummary,
		Scopes:     s.Scopes,
		Type:       s.Type,
		DeviceInfo: s.DeviceInfo,
		IPAddress:  s.IPAddress,
		LastSeenAt: s.LastSeenAt,
		ExpiresAt:  s.ExpiresAt,
		CreatedAt:  s.CreatedAt,
		UpdatedAt:  s.UpdatedAt,
	}
	return resp
}

// JSONData is a custom type for JSON data stored as TEXT in SQLite.
type JSONData map[string]interface{}

// Value implements the driver.Valuer interface for JSONData.
func (j JSONData) Value() (driver.Value, error) {
	if j == nil {
		return "{}", nil
	}
	bytes, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}
	return string(bytes), nil
}

// Scan implements the sql.Scanner interface for JSONData.
func (j *JSONData) Scan(value interface{}) error {
	if value == nil {
		*j = make(map[string]interface{})
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("failed to scan JSONData: expected []byte or string, got %T", value)
	}
	return json.Unmarshal(bytes, j)
}

// TOTPSecret represents a TOTP secret stored for a user.
type TOTPSecret struct {
	ID        uint64    `gorm:"primaryKey"`
	UUID      string    `gorm:"size:36;uniqueIndex:idx_totp_user_uuid;not null"`
	UserID    uint64    `gorm:"uniqueIndex:idx_totp_user_uuid;index;not null"`
	User      User      `gorm:"foreignKey:UserID"`
	Secret    string    `gorm:"not null"`
	Label     string    `gorm:"not null"`
	Issuer    string    `gorm:"not null"`
	Algorithm string    `gorm:"size:20;not null;default:sha1"`
	Digits    int       `gorm:"not null;default:6"`
	Period    int       `gorm:"not null;default:30"`
	UpdatedAt int64     `gorm:"not null"` // ms since epoch (provided by app)
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

// SecurityBlock represents a 24-hour block for an identifier (email, phone, or username)
type SecurityBlock struct {
	ID           uint64    `gorm:"primaryKey" json:"id"`
	Identifier   string    `gorm:"size:100;index:idx_block_lookup;not null" json:"identifier"`
	BlockedUntil time.Time `gorm:"not null;index:idx_block_lookup" json:"blocked_until"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// UsernameChangeLog tracks history of username changes.
type UsernameChangeLog struct {
	ID          uint64    `gorm:"primaryKey" json:"id"`
	UserID      uint64    `gorm:"index;not null" json:"user_id"`
	OldUsername string    `gorm:"size:30;not null" json:"old_username"`
	NewUsername string    `gorm:"size:30;not null" json:"new_username"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
}
