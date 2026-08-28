package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// requestIDKey is the context key for the request ID.
type requestIDKey struct{}

// RequestIDMiddleware generates a unique request ID for each request,
// adds it to the context and the X-Request-ID response header.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if there's already a request ID from upstream proxy
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		// Add to response header
		w.Header().Set("X-Request-ID", requestID)

		// Add to context
		ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID retrieves the request ID from the context.
func GetRequestID(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// generateRequestID creates a random 16-byte hex string.
func generateRequestID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(bytes)
}
