package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"gilosauth/config"
)

func TestTOTPSecretEncryptionAndLegacyFallback(t *testing.T) {
	origKey := config.EncryptionKey
	t.Cleanup(func() { config.EncryptionKey = origKey })

	config.EncryptionKey = strings.Repeat("ab", 32) // 64 hex chars = 32 bytes
	secret := "JBSWY3DPEHPK3PXP"

	encrypted, err := EncryptTOTPSecret(secret)
	if err != nil {
		t.Fatalf("EncryptTOTPSecret unexpected error: %v", err)
	}
	if encrypted == secret {
		t.Fatalf("expected encrypted secret to differ from plaintext")
	}

	plain, needsMigration, err := DecryptTOTPSecret(encrypted)
	if err != nil {
		t.Fatalf("DecryptTOTPSecret unexpected error: %v", err)
	}
	if plain != secret {
		t.Fatalf("got decrypted %q, want %q", plain, secret)
	}
	if needsMigration {
		t.Fatalf("expected needsMigration=false for encrypted secret")
	}

	// Legacy plaintext base32 secret should still decrypt with migration flag set
	legacyPlain, legacyMig, err := DecryptTOTPSecret(secret)
	if err != nil {
		t.Fatalf("DecryptTOTPSecret legacy unexpected error: %v", err)
	}
	if legacyPlain != secret || !legacyMig {
		t.Fatalf("got (%q, mig=%v), want (%q, mig=true)", legacyPlain, legacyMig, secret)
	}

	// Corrupted or wrong-key ciphertext should fail
	config.EncryptionKey = strings.Repeat("cd", 32)
	if _, _, err := DecryptTOTPSecret(encrypted); err == nil {
		t.Fatalf("expected decryption error with wrong encryption key")
	}
}

func TestValidateRedirectURI(t *testing.T) {
	valid := []string{
		"https://app.example.com/callback",
		"https://sub.domain.org:8443/oauth/cb?foo=bar",
		"http://localhost:3000/callback",
		"http://127.0.0.1:8080/cb",
		"http://[::1]:5173/callback",
		"myapp://auth/callback",
	}
	for _, uri := range valid {
		if err := ValidateRedirectURI(uri); err != nil {
			t.Errorf("ValidateRedirectURI(%q) rejected valid URI: %v", uri, err)
		}
	}

	invalid := []string{
		"",
		"/relative/callback",
		"https://app.example.com/cb#fragment",
		"http://app.example.com/callback",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"https:///no-host",
		"https://app.example.com/cb\nHost: evil.com",
	}
	for _, uri := range invalid {
		if err := ValidateRedirectURI(uri); err == nil {
			t.Errorf("ValidateRedirectURI(%q) accepted invalid URI", uri)
		}
	}
}

func TestValidatePKCE(t *testing.T) {
	validVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // 43 chars
	if !ValidatePKCECodeVerifier(validVerifier) {
		t.Fatalf("expected valid 43-char verifier to pass")
	}
	if !ValidatePKCECodeVerifier(strings.Repeat("a", 128)) {
		t.Fatalf("expected valid 128-char verifier to pass")
	}

	sum := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !ValidatePKCECodeChallenge(validChallenge) {
		t.Fatalf("expected valid S256 challenge %q to pass", validChallenge)
	}

	invalidVerifiers := []string{
		"",
		strings.Repeat("a", 42),
		strings.Repeat("a", 129),
		"invalid+plus/slash=pad0000000000000000000000",
		"has spaces 000000000000000000000000000000000",
	}
	for _, v := range invalidVerifiers {
		if ValidatePKCECodeVerifier(v) {
			t.Errorf("ValidatePKCECodeVerifier(%q) unexpectedly accepted invalid verifier", v)
		}
	}

	invalidChallenges := []string{
		"",
		"short",
		validChallenge + "=",
		strings.ReplaceAll(validChallenge, "a", "+"),
	}
	for _, c := range invalidChallenges {
		if ValidatePKCECodeChallenge(c) {
			t.Errorf("ValidatePKCECodeChallenge(%q) unexpectedly accepted invalid challenge", c)
		}
	}
}

func TestSanitizeRelativeTarget(t *testing.T) {
	const fallback = "/home"
	if got := SanitizeRelativeTarget("/oauth?client_id=1", fallback); got != "/oauth?client_id=1" {
		t.Errorf("got %q, want /oauth?client_id=1", got)
	}
	unsafe := []string{
		"",
		"   ",
		"https://evil.com",
		"http://evil.com/home",
		"//evil.com",
		"/\\evil.com",
		"///evil.com",
		"\\evil.com",
		"javascript:alert(1)",
		"relative-without-leading-slash",
	}
	for _, u := range unsafe {
		if got := SanitizeRelativeTarget(u, fallback); got != fallback {
			t.Errorf("SanitizeRelativeTarget(%q) = %q, want %q", u, got, fallback)
		}
	}
}

func TestValidatePasswordAndUsername(t *testing.T) {
	if err := ValidatePassword("short"); err == nil {
		t.Errorf("expected error for short password")
	}
	if err := ValidatePassword(strings.Repeat("p", 73)); err == nil {
		t.Errorf("expected error for >72-byte password")
	}
	if err := ValidatePassword("ValidPass123!"); err != nil {
		t.Errorf("unexpected error for valid password: %v", err)
	}

	if _, err := ValidateUsername("ab"); err == nil {
		t.Errorf("expected error for short username")
	}
	if _, err := ValidateUsername("bad_user"); err == nil {
		t.Errorf("expected error for underscore in username")
	}
	if got, err := ValidateUsername("Alice123"); err != nil || got != "alice123" {
		t.Errorf("got (%q, %v), want (alice123, nil)", got, err)
	}
}

func TestFormatPhoneOTPMessageEskizVerified(t *testing.T) {
	want := "auth.gilos.org is sending this code to verify your phone for Gilos ID registration or access: 123456"
	if got := FormatPhoneOTPMessage("123456"); got != want {
		t.Fatalf("FormatPhoneOTPMessage = %q, want %q", got, want)
	}
}

