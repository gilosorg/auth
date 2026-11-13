package middleware

import (
	"gilosauth/utils"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimitEntry tracks request counts for a given key (IP or IP+endpoint).
type rateLimitEntry struct {
	count    int
	resetAt  time.Time
}

// RateLimiter implements a per-key sliding window rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	entries  map[string]*rateLimitEntry
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter with the given limit per window.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		entries: make(map[string]*rateLimitEntry),
		limit:   limit,
		window:  window,
	}
	// Background cleanup every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()
	return rl
}

// Allow checks if a request from the given key is allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.entries[key]

	if !exists || now.After(entry.resetAt) {
		if len(rl.entries) >= 50000 {
			rl.cleanupLocked(now)
		}
		if len(rl.entries) >= 50000 {
			for k := range rl.entries {
				delete(rl.entries, k)
				break
			}
		}
		rl.entries[key] = &rateLimitEntry{
			count:   1,
			resetAt: now.Add(rl.window),
		}
		return true
	}

	entry.count++
	return entry.count <= rl.limit
}

// cleanup removes expired entries.
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.cleanupLocked(time.Now())
}

func (rl *RateLimiter) cleanupLocked(now time.Time) {
	for key, entry := range rl.entries {
		if now.After(entry.resetAt) {
			delete(rl.entries, key)
		}
	}
}

// Global rate limiters
var (
	// GlobalLimiter: 100 requests per minute per IP
	GlobalLimiter = NewRateLimiter(100, 1*time.Minute)

	// AuthLimiter: 20 requests per minute per IP for auth endpoints
	AuthLimiter = NewRateLimiter(20, 1*time.Minute)

	// LoginLimiter: 10 attempts per 15 minutes per IP for login-specific endpoints
	LoginLimiter = NewRateLimiter(10, 15*time.Minute)
)

// RateLimitMiddleware applies tiered rate limiting based on the request path.
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Bypass rate limiting for health check and static assets
		if path == "/health" || strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/media/") {
			next.ServeHTTP(w, r)
			return
		}

		ip := getClientIPForRateLimit(r)

		// Login/MFA verification rate limiting (strictest)
		if isLoginRequest(r) {
			key := "login:" + ip
			if !LoginLimiter.Allow(key) {
				w.Header().Set("Retry-After", "900") // 15 minutes
				http.Error(w, `{"error":"too many login attempts, please try again later"}`, http.StatusTooManyRequests)
				return
			}
		}

		// Auth endpoint rate limiting
		if isAuthPath(path) {
			key := "auth:" + ip
			if !AuthLimiter.Allow(key) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, `{"error":"too many requests, please try again later"}`, http.StatusTooManyRequests)
				return
			}
		}

		// Global rate limiting
		if !GlobalLimiter.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isLoginRequest checks if the request hits a credential/OTP/MFA verification POST endpoint.
func isLoginRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	switch r.URL.Path {
	case "/auth/login", "/auth/otp/verify", "/auth/reset-password", "/profile/totp/verify":
		return true
	default:
		return false
	}
}

// isAuthPath checks if the path is an auth endpoint.
func isAuthPath(path string) bool {
	return strings.HasPrefix(path, "/auth/") || path == "/o/token"
}

// getClientIPForRateLimit extracts the client IP for rate limiting.
// Uses utils.GetClientIP which securely parses X-Forwarded-For and X-Real-IP
// only when the direct connection is from a trusted proxy (such as Nginx on localhost).
func getClientIPForRateLimit(r *http.Request) string {
	return utils.GetClientIP(r)
}
