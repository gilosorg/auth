package utils

import (
	"fmt"
	"gilosauth/config"
	"regexp"
	"strings"
)

// Pre-compiled regex patterns for validation
var (
	usernameRegex = regexp.MustCompile(`^[a-z0-9]+$`)
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	phoneRegex    = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
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
		return contact, "email", nil
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
