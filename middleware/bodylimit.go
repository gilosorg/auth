package middleware

import (
	"net/http"
)

// MaxRequestBodySize is the maximum allowed request body size (1MB).
const MaxRequestBodySize = 1 << 20 // 1 MB

// BodyLimitMiddleware limits the size of request bodies to prevent
// memory exhaustion attacks.
func BodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only limit body-carrying methods
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)
		}
		next.ServeHTTP(w, r)
	})
}
