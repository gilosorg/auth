package middleware

import (
	"net"
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

	now := time.Now()
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
		ip := getClientIPForRateLimit(r)
		path := r.URL.Path

		// Login-specific rate limiting (strictest)
		if isLoginPath(path) {
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

// isLoginPath checks if the path is a login-specific endpoint.
func isLoginPath(path string) bool {
	loginPaths := []string{"/auth/login", "/auth/state"}
	for _, p := range loginPaths {
		if path == p {
			return true
		}
	}
	return false
}

// isAuthPath checks if the path is an auth endpoint.
func isAuthPath(path string) bool {
	return strings.HasPrefix(path, "/auth/") || path == "/o/token"
}

// getClientIPForRateLimit extracts the client IP for rate limiting.
// Uses RemoteAddr directly to avoid spoofing via X-Forwarded-For.
func getClientIPForRateLimit(r *http.Request) string {
	// For rate limiting, we use RemoteAddr (the actual TCP connection IP)
	// to prevent bypassing via X-Forwarded-For spoofing.
	// If behind a trusted proxy, the proxy's IP is rate-limited,
	// which is acceptable because the proxy itself limits connections.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
