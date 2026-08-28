package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"gilosauth/config"
)

// Pre-compiled regex for non-digit stripping
var digitsOnly = regexp.MustCompile(`[^0-9]`)

// GenerateRandomString generates a random hex string of the given length in bytes.
func GenerateRandomString(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetClientIP extracts the real client IP address from an HTTP request.
// It checks X-Forwarded-For and X-Real-IP headers only when the request
// comes from a configured trusted proxy. Falls back to RemoteAddr.
func GetClientIP(r *http.Request) string {
	remoteIP := extractRemoteIP(r)

	// Only trust proxy headers if the connection comes from a trusted proxy
	if isTrustedProxy(remoteIP) {
		// Check X-Forwarded-For header (standard for proxies)
		// Format: "client, proxy1, proxy2" - we want the first (leftmost) IP
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				clientIP := strings.TrimSpace(ips[0])
				if clientIP != "" && isValidIP(clientIP) {
					return clientIP
				}
			}
		}

		// Check X-Real-IP header (nginx default)
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			clientIP := strings.TrimSpace(xrip)
			if clientIP != "" && isValidIP(clientIP) {
				return clientIP
			}
		}
	}

	return remoteIP
}

// extractRemoteIP gets the IP from RemoteAddr, stripping the port.
func extractRemoteIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// isTrustedProxy checks if an IP is in the configured trusted proxies list.
func isTrustedProxy(ip string) bool {
	if len(config.TrustedProxies) == 0 {
		return false // No trusted proxies configured — never trust proxy headers
	}
	for _, proxy := range config.TrustedProxies {
		if proxy == ip {
			return true
		}
	}
	return false
}

// isValidIP checks if a string is a valid IPv4 or IPv6 address
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// GenerateOTP generates a cryptographically secure 6-digit OTP.
func GenerateOTP() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		// Fallback should never happen with crypto/rand, but be safe
		return "000000"
	}
	return fmt.Sprintf("%06d", n.Int64())
}

// ParsePhone parses a phone number string to uint64.
func ParsePhone(phone string) (uint64, error) {
	// If the string contains 'e+', it's likely scientific notation from corrupted session data
	if strings.Contains(strings.ToLower(phone), "e+") {
		var f float64
		_, err := fmt.Sscanf(phone, "%e", &f)
		if err == nil {
			return uint64(math.Round(f)), nil
		}
	}

	cleaned := digitsOnly.ReplaceAllString(phone, "")
	if cleaned == "" {
		return 0, nil
	}
	return strconv.ParseUint(cleaned, 10, 64)
}

// FormatPhone formats a uint64 phone number to international format.
func FormatPhone(phone uint64) string {
	if phone == 0 {
		return ""
	}
	return fmt.Sprintf("+%d", phone)
}

// MaskPhone masks a phone number for display (e.g., "+998******567").
func MaskPhone(phone uint64) string {
	if phone == 0 {
		return ""
	}
	phoneStr := fmt.Sprintf("%d", phone)
	if len(phoneStr) <= 3 {
		return "+***" + phoneStr
	}
	// Show country code prefix and last 3 digits, mask the rest
	prefix := phoneStr[:3] // typically country code like 998
	suffix := phoneStr[len(phoneStr)-3:]
	masked := strings.Repeat("*", len(phoneStr)-6)
	return "+" + prefix + masked + suffix
}
