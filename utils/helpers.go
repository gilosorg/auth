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
	"sync"

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
//
// Uses the rightmost-untrusted-IP algorithm for X-Forwarded-For, which is the
// only safe approach in production. The leftmost IP can be trivially spoofed by
// clients; the rightmost untrusted IP is the one appended by the first trusted
// proxy and cannot be forged without compromising the proxy itself.
//
// Trusted proxies are configured via TRUSTED_PROXIES env var (supports both
// individual IPs and CIDR ranges). Loopback addresses (127.0.0.0/8, ::1) are
// always implicitly trusted since this service sits behind a reverse proxy.
func GetClientIP(r *http.Request) string {
	remoteIP := normalizeIP(extractRemoteIP(r))

	// Only trust proxy headers if the direct connection is from a trusted source
	if !isTrustedProxy(remoteIP) {
		return remoteIP
	}

	// Use rightmost-untrusted-IP algorithm on X-Forwarded-For.
	// Format: "client, proxy1, proxy2" — walk right-to-left, skipping trusted proxies.
	// The first non-trusted IP we encounter is the real client IP.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for i := len(ips) - 1; i >= 0; i-- {
			candidate := normalizeIP(strings.TrimSpace(ips[i]))
			if candidate == "" || !isValidIP(candidate) {
				continue
			}
			if !isTrustedProxy(candidate) {
				return candidate
			}
		}
	}

	// Fall back to X-Real-IP (set by nginx: proxy_set_header X-Real-IP $remote_addr)
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		candidate := normalizeIP(strings.TrimSpace(xrip))
		if candidate != "" && isValidIP(candidate) {
			return candidate
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

// normalizeIP converts IPv4-mapped IPv6 addresses (e.g. "::ffff:192.168.1.1")
// to their plain IPv4 form, and trims whitespace. This ensures consistent
// matching against trusted proxy lists regardless of how the OS reports the IP.
func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	// If it's an IPv4-mapped IPv6 address, convert to IPv4 string
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

// Parsed trusted proxy networks, initialized once on first use
var (
	trustedNets     []*net.IPNet
	trustedIPs      []net.IP
	trustedInitOnce sync.Once
)

// initTrustedProxies parses the configured TRUSTED_PROXIES into net.IPNet and
// net.IP values for efficient matching. Called once via sync.Once.
func initTrustedProxies() {
	for _, entry := range config.TrustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Try parsing as CIDR first
		if strings.Contains(entry, "/") {
			if _, network, err := net.ParseCIDR(entry); err == nil {
				trustedNets = append(trustedNets, network)
			}
			continue
		}
		// Parse as individual IP
		if ip := net.ParseIP(entry); ip != nil {
			trustedIPs = append(trustedIPs, ip)
		}
	}
}

// isTrustedProxy checks if an IP is a trusted proxy.
// Loopback addresses are always trusted (the service runs behind nginx on the same host).
// Configured TRUSTED_PROXIES supports both individual IPs and CIDR ranges.
func isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// Always trust loopback — the app always sits behind a local reverse proxy
	if parsed.IsLoopback() {
		return true
	}

	// Check configured trusted proxies
	trustedInitOnce.Do(initTrustedProxies)

	for _, trustedIP := range trustedIPs {
		if trustedIP.Equal(parsed) {
			return true
		}
	}
	for _, network := range trustedNets {
		if network.Contains(parsed) {
			return true
		}
	}

	return false
}

// isValidIP checks if a string is a valid IPv4 or IPv6 address.
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
