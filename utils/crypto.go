package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"gilosauth/config"
	"io"
)

// HashToken returns the SHA-256 hex digest of a token.
// Used to store access/refresh/auth tokens in the database without exposing plaintext.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// ConstantTimeOTPCompare performs a timing-safe comparison of two OTP strings.
// Returns true if they match. Both values are compared in constant time
// regardless of content, preventing timing side-channel attacks.
func ConstantTimeOTPCompare(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// EncryptAES encrypts plaintext using AES-256-GCM with the provided hex-encoded key.
// Returns a base64-encoded string of nonce+ciphertext.
func EncryptAES(plaintext, hexKey string) (string, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("invalid encryption key: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts a base64-encoded AES-256-GCM ciphertext with the provided hex-encoded key.
func DecryptAES(encoded, hexKey string) (string, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("invalid encryption key: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// EncryptTOTPSecret encrypts a user's MFA TOTP secret at rest using config.EncryptionKey when set.
func EncryptTOTPSecret(secret string) (string, error) {
	if secret == "" || config.EncryptionKey == "" {
		return secret, nil
	}
	return EncryptAES(secret, config.EncryptionKey)
}

// DecryptTOTPSecret decrypts a stored MFA TOTP secret.
// If the stored value is a legacy unencrypted Base32 secret while an encryption key is configured,
// it returns the plaintext secret along with needsMigration=true so callers can re-encrypt it.
func DecryptTOTPSecret(stored string) (plain string, needsMigration bool, err error) {
	if stored == "" || config.EncryptionKey == "" {
		return stored, false, nil
	}
	decrypted, decErr := DecryptAES(stored, config.EncryptionKey)
	if decErr == nil {
		return decrypted, false, nil
	}
	if isLegacyBase32Secret(stored) {
		return stored, true, nil
	}
	return "", false, decErr
}

func isLegacyBase32Secret(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isUpper := c >= 'A' && c <= 'Z'
		isDigit := c >= '2' && c <= '7'
		if !isUpper && !isDigit && c != '=' {
			return false
		}
	}
	return true
}
