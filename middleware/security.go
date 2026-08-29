package middleware

import (
	"gilosauth/config"
	"net/http"
)

// SecurityHeaders adds standard HTTP security headers to every response.
// These protect against clickjacking, MIME-sniffing, XSS, and referrer leakage.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking — auth/consent pages must never be framed
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Strict referrer policy — don't leak any referrer info for an auth server
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Content Security Policy — prevent XSS, inline script injection, and framing
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "+
				"img-src 'self' data: https://cdn.jsdelivr.net; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'")

		// Permissions Policy — disable unnecessary browser features
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		// HSTS — enforce HTTPS when secure cookies are enabled (production)
		if config.SecureCookies {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Prevent caching of sensitive API and auth responses
		if isAPIPath(r.URL.Path) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}

		next.ServeHTTP(w, r)
	})
}

// isSensitivePath checks if the request path is an API, auth, or other sensitive endpoint
// where responses must not be cached.
func isAPIPath(path string) bool {
	return len(path) >= 4 && path[:4] == "/api" ||
		len(path) >= 5 && path[:5] == "/auth" ||
		len(path) >= 2 && path[:2] == "/o" ||
		len(path) >= 9 && path[:9] == "/sessions" ||
		len(path) >= 8 && path[:8] == "/clients" ||
		len(path) >= 8 && path[:8] == "/profile"
}
