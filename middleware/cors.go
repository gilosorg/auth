package middleware

import (
	"net/http"
	"strings"

	"gilosauth/config"

	"github.com/rs/cors"
)

// CorsMiddleware adds CORS support to the application
func CorsMiddleware(next http.Handler) http.Handler {
	strictCors := cors.New(cors.Options{
		AllowedOrigins:   config.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           3600,
	})

	publicCors := cors.New(cors.Options{
		AllowedOrigins: []string{"*"}, // Allow all origins for public APIs
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		MaxAge:         3600,
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// Public CORS for endpoints that external clients call directly:
		// - /o/token: Clients exchange auth codes/refresh tokens
		// - /api/userinfo: Standard OIDC userinfo endpoint
		// - /.well-known/*: Discovery and JWKS metadata
		// Note: /o/introspect and /o/revoke use strict CORS because they require
		// client authentication and should only be called server-to-server.
		if path == "/o/token" || path == "/api/userinfo" || strings.HasPrefix(path, "/.well-known/") {
			publicCors.Handler(next).ServeHTTP(w, r)
			return
		}
		strictCors.Handler(next).ServeHTTP(w, r)
	})
}
