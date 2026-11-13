package utils

import (
	"fmt"
	"gilosauth/config"
	"net/url"
	"regexp"
	"strings"
)

// Pre-compiled regex patterns for validation
var (
	usernameRegex      = regexp.MustCompile(`^[a-z0-9]+$`)
	emailRegex         = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	phoneRegex         = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	pkceVerifierRegex  = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)
	pkceChallengeRegex = regexp.MustCompile(`^[A-Za-z0-9\-_]{43}$`)
	customSchemeRegex  = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)
)

// ValidateUsername ensures the username contains only a-z, 0-9, is lowercase,
// and meets the length constraints (5-30 characters).
func ValidateUsername(username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if len(username) < 5 {
		return "", fmt.Errorf("%s must be at least 5 characters", config.AppIDLabel)
	}
	if len(username) > 30 {
		return "", fmt.Errorf("%s must be at most 30 characters", config.AppIDLabel)
	}
	if !usernameRegex.MatchString(username) {
		return "", fmt.Errorf("%s can only contain lowercase letters and numbers", config.AppIDLabel)
	}
	return username, nil
}

// ValidateContact validates and identifies email or phone.
func ValidateContact(contact string) (string, string, error) {
	contact = strings.TrimSpace(contact)
	if contact == "" {
		return "", "", fmt.Errorf("contact is required")
	}

	if emailRegex.MatchString(contact) {
		return strings.ToLower(contact), "email", nil
	}
	if phoneRegex.MatchString(contact) {
		return contact, "phone", nil
	}
	return "", "", fmt.Errorf("invalid email or phone number")
}

// MaskEmail masks an email address for display (e.g., "te****@gmail.com").
// For short local parts (≤2 chars), shows "*****@domain" to avoid revealing the full username.
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}
	local := parts[0]
	if len(local) <= 2 {
		return "*****@" + parts[1]
	}
	return local[:2] + strings.Repeat("*", len(local)-2) + "@" + parts[1]
}

// Pluralize returns "s" if count is not 1, otherwise returns "".
func Pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

// ValidatePassword enforces password complexity requirements.
// Returns nil if the password meets all requirements, or an error describing the violation.
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 72 {
		return fmt.Errorf("password must be at most 72 characters")
	}
	return nil
}

// ValidateRedirectURI validates an OAuth 2.1 redirect URI.
// Allows HTTPS URLs, HTTP loopback URLs (RFC 8252 §7.3), and custom app URI schemes.
// Rejects fragments, commas (storage delimiter), whitespace, and dangerous schemes.
func ValidateRedirectURI(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("redirect URI cannot be empty")
	}
	if strings.ContainsAny(raw, ", \t\r\n") {
		return fmt.Errorf("redirect URI contains invalid characters")
	}
	if strings.Contains(raw, "#") {
		return fmt.Errorf("redirect URI must not contain a fragment identifier")
	}

	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() {
		return fmt.Errorf("redirect URI must be a valid absolute URI")
	}
	if parsed.User != nil {
		return fmt.Errorf("redirect URI must not contain userinfo")
	}

	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "javascript", "data", "vbscript", "file", "blob", "about":
		return fmt.Errorf("redirect URI scheme %q is not allowed", scheme)
	case "https":
		if parsed.Hostname() == "" {
			return fmt.Errorf("https redirect URI must include a host")
		}
	case "http":
		host := strings.ToLower(parsed.Hostname())
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("plain http redirect URIs are only permitted for loopback addresses (localhost, 127.0.0.1, ::1)")
		}
	default:
		if !customSchemeRegex.MatchString(scheme) {
			return fmt.Errorf("invalid redirect URI scheme %q", scheme)
		}
	}

	return nil
}

// ValidatePKCECodeVerifier validates code_verifier format per RFC 7636 §4.1.
func ValidatePKCECodeVerifier(verifier string) bool {
	return pkceVerifierRegex.MatchString(verifier)
}

// ValidatePKCECodeChallenge validates an S256 code_challenge per RFC 7636 §4.2.
func ValidatePKCECodeChallenge(challenge string) bool {
	return pkceChallengeRegex.MatchString(challenge)
}

// SanitizeRelativeTarget validates an internal post-auth redirect target and falls back to defaultPath on unsafe input.
// Blocks protocol-relative ("//evil.com"), backslash ("/\evil.com"), absolute external URLs, and control characters.
func SanitizeRelativeTarget(target string, defaultPath string) string {
	target = strings.TrimSpace(target)
	if target == "" || !strings.HasPrefix(target, "/") {
		return defaultPath
	}
	if strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") || strings.ContainsAny(target, "\r\n\x00") {
		return defaultPath
	}
	if u, err := url.Parse(target); err != nil || u.Scheme != "" || u.Host != "" {
		return defaultPath
	}
	return target
}
