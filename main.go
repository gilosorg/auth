package main

import (
	"context"
	"fmt"
	"gilosauth/config"
	"gilosauth/database"
	"gilosauth/handler"
	"gilosauth/handler/client"
	"gilosauth/i18n"
	"gilosauth/middleware"
	"gilosauth/templates"
	"gilosauth/utils"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Initialize configuration (loads .env)
	config.Init()

	// Initialize database
	database.InitDatabase()
	if err := database.MigrateDatabase(); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Initialize i18n translations
	if err := i18n.Init(); err != nil {
		log.Fatalf("Failed to initialize i18n: %v", err)
	}

	// Initialize session manager
	database.InitSessionManager()

	// Start periodic session cleanup (every hour)
	database.StartCleanupTicker(1 * time.Hour)

	// Parse templates
	tmpls, err := templates.ParseTemplates()
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	// Initialize RSA Keys for OIDC
	if err := utils.InitKeys(); err != nil {
		log.Fatalf("Failed to initialize RSA keys: %v", err)
	}

	// Create a new ServeMux (supports method-based routing in Go 1.22+)
	mux := http.NewServeMux()

	// Serve static files (wrapped to disable directory listing)
	mux.Handle("GET /static/", http.StripPrefix("/static/", noDirectoryListing(http.FileServer(http.Dir("./static")))))
	mux.Handle("GET /media/", http.StripPrefix("/media/", noDirectoryListing(http.FileServer(http.Dir("./media")))))

	// Register OIDC discovery and JWKS before static well-known handler
	mux.HandleFunc("GET /.well-known/openid-configuration", handler.OIDCDiscoveryHandler)
	mux.HandleFunc("GET /.well-known/jwks.json", handler.JWKSHandler)
	mux.Handle("GET /.well-known/", http.StripPrefix("/.well-known/", http.FileServer(http.Dir("./.well-known"))))

	// Health check endpoint — pings database to verify connectivity
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		sqlDB, err := database.DB.DB()
		if err != nil || sqlDB.Ping() != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status": "unhealthy", "database": "unreachable"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	})

	// Define routes with explicit HTTP methods

	// Page routes (GET only)
	mux.HandleFunc("GET /{$}", handler.AuthHandler(tmpls))
	mux.HandleFunc("GET /home", middleware.RequireCookieToken(handler.HomeHandler(tmpls)))
	mux.HandleFunc("GET /docs", handler.DocsHandler(tmpls))

	// Web Auth endpoints (with explicit methods)
	mux.HandleFunc("GET /auth/check-user", handler.CheckUserHandler)
	mux.HandleFunc("POST /auth/login", handler.LoginHandler)
	mux.HandleFunc("POST /auth/register", handler.RegisterHandler)
	mux.HandleFunc("POST /auth/reset-password", handler.ResetPasswordHandler)
	mux.HandleFunc("POST /auth/contact/verify", handler.ContactVerifyHandler)
	mux.HandleFunc("POST /auth/otp/send", handler.SendOTPHandler)
	mux.HandleFunc("POST /auth/otp/verify", handler.VerifyOTPHandler)
	mux.HandleFunc("GET /auth/state", handler.AuthStateHandler)
	mux.HandleFunc("POST /auth/state", handler.AuthStateHandler)

	// Native session endpoints
	mux.HandleFunc("GET /sessions", middleware.RequireCookieToken(handler.SessionsHandler))
	mux.HandleFunc("POST /sessions/terminate", middleware.RequireCookieToken(handler.TerminateSessionHandler))
	mux.HandleFunc("POST /sessions/terminate-others", middleware.RequireCookieToken(handler.TerminateOthersHandler))

	// Client management endpoints
	mux.HandleFunc("GET /clients", middleware.RequireCookieToken(handler.ClientsHandler))
	mux.HandleFunc("POST /clients", middleware.RequireCookieToken(handler.ClientsHandler))
	mux.HandleFunc("GET /clients/edit", middleware.RequireCookieToken(handler.EditClientHandler))
	mux.HandleFunc("POST /clients/edit", middleware.RequireCookieToken(handler.EditClientHandler))
	mux.HandleFunc("POST /clients/delete", middleware.RequireCookieToken(handler.DeleteClientHandler))
	mux.HandleFunc("POST /clients/regenerate-secret", middleware.RequireCookieToken(handler.RegenerateSecretHandler))

	// Profile endpoints
	mux.HandleFunc("GET /profile", middleware.RequireCookieToken(handler.ProfileHandler))
	mux.HandleFunc("POST /profile/names", middleware.RequireCookieToken(handler.NamesUpdateHandler))
	mux.HandleFunc("POST /profile/icon", middleware.RequireCookieToken(handler.IconUpdateHandler))
	mux.HandleFunc("GET /profile/username/check", middleware.RequireCookieToken(handler.UsernameCheckHandler))
	mux.HandleFunc("POST /profile/username/update", middleware.RequireCookieToken(handler.UsernameUpdateHandler))
	mux.HandleFunc("POST /profile/password", middleware.RequireCookieToken(handler.PasswordUpdateHandler))
	mux.HandleFunc("POST /profile/contact", middleware.RequireCookieToken(handler.ProfileContactUpdateHandler))
	mux.HandleFunc("GET /profile/contact/pending", middleware.RequireCookieToken(handler.ProfileContactPendingHandler))
	mux.HandleFunc("POST /profile/contact/resend", middleware.RequireCookieToken(handler.ProfileContactResendHandler))
	mux.HandleFunc("POST /profile/contact/verify", middleware.RequireCookieToken(handler.ProfileContactVerifyHandler))
	mux.HandleFunc("POST /profile/contact/cancel", middleware.RequireCookieToken(handler.ProfileContactCancelHandler))
	mux.HandleFunc("POST /profile/delete", middleware.RequireCookieToken(handler.DeleteAccountHandler))
	mux.HandleFunc("POST /profile/delete/cancel", middleware.RequireCookieToken(handler.CancelDeletionHandler))
	mux.HandleFunc("GET /profile/delete/status", middleware.RequireCookieToken(handler.DeletionStatusHandler))
	mux.HandleFunc("GET /profile/totp/generate", middleware.RequireCookieToken(handler.TOTPGenerateHandler))
	mux.HandleFunc("POST /profile/totp/verify", middleware.RequireCookieToken(handler.TOTPVerifyHandler))
	mux.HandleFunc("POST /profile/totp/disable", middleware.RequireCookieToken(handler.TOTPDisableHandler))

	// OAuth endpoints
	mux.HandleFunc("GET /o/authorize", middleware.RequireCookieToken(handler.OAuthAuthorizeHandler(tmpls)))
	mux.HandleFunc("POST /o/authorize", middleware.RequireCookieToken(handler.OAuthAuthorizeHandler(tmpls)))
	mux.HandleFunc("POST /o/token", handler.OAuthTokenHandler)
	mux.HandleFunc("POST /o/introspect", handler.OAuthIntrospectHandler)
	mux.HandleFunc("POST /o/revoke", handler.OAuthRevokeHandler)

	// OAuth Client API endpoints (Bearer token auth)
	mux.HandleFunc("GET /api/userinfo", middleware.RequireAccessToken(handler.UserInfoHandler))
	mux.HandleFunc("GET /api/me", middleware.RequireAccessToken(middleware.RequireScope("profile", client.MeHandler)))
	mux.HandleFunc("GET /api/sessions", middleware.RequireAccessToken(middleware.RequireScope("user_sessions", client.SessionsHandler)))
	mux.HandleFunc("POST /api/sessions/terminate", middleware.RequireAccessToken(middleware.RequireScope("user_sessions", client.TerminateSessionHandler)))
	mux.HandleFunc("POST /api/sessions/terminate-others", middleware.RequireAccessToken(middleware.RequireScope("user_sessions", client.TerminateOthersHandler)))

	mux.HandleFunc("GET /api/totps", middleware.RequireAccessToken(middleware.RequireScope("user_totps", client.ListTOTPsHandler)))
	mux.HandleFunc("POST /api/totps/sync/push", middleware.RequireAccessToken(middleware.RequireScope("user_totps", client.PushSyncHandler)))
	mux.HandleFunc("POST /api/totps/sync/pull", middleware.RequireAccessToken(middleware.RequireScope("user_totps", client.PullSyncHandler)))

	// Client Profile endpoints
	mux.HandleFunc("GET /api/profile", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.ProfileHandler)))
	mux.HandleFunc("POST /api/profile/names", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.NamesUpdateHandler)))
	mux.HandleFunc("POST /api/profile/icon", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.IconUpdateHandler)))
	mux.HandleFunc("GET /api/profile/username/check", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.UsernameCheckHandler)))
	mux.HandleFunc("POST /api/profile/username/update", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.UsernameUpdateHandler)))
	mux.HandleFunc("POST /api/profile/password", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.PasswordUpdateHandler)))
	mux.HandleFunc("POST /api/profile/contact", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.ProfileContactUpdateHandler)))
	mux.HandleFunc("GET /api/profile/contact/pending", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.ProfileContactPendingHandler)))
	mux.HandleFunc("POST /api/profile/contact/resend", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.ProfileContactResendHandler)))
	mux.HandleFunc("POST /api/profile/contact/verify", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.ProfileContactVerifyHandler)))
	mux.HandleFunc("POST /api/profile/contact/cancel", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.ProfileContactCancelHandler)))
	mux.HandleFunc("POST /api/profile/delete", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.DeleteAccountHandler)))
	mux.HandleFunc("POST /api/profile/delete/cancel", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.CancelDeletionHandler)))
	mux.HandleFunc("GET /api/profile/delete/status", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.DeletionStatusHandler)))
	mux.HandleFunc("GET /api/profile/totp/generate", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.TOTPGenerateHandler)))
	mux.HandleFunc("POST /api/profile/totp/verify", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.TOTPVerifyHandler)))
	mux.HandleFunc("POST /api/profile/totp/disable", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.TOTPDisableHandler)))

	// Browserless OAuth API (for manager apps)
	mux.HandleFunc("GET /api/o/info", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.GetOAuthInquiryHandler)))
	mux.HandleFunc("POST /api/o/approve", middleware.RequireAccessToken(middleware.RequireScope("user_manage_account", client.ApproveOAuthInquiryHandler)))

	// Apply middleware chain (outermost first):
	// RequestID → BodyLimit → RateLimit → SecurityHeaders → CORS → CSRF → Router
	var handler http.Handler = mux
	handler = middleware.CSRFMiddleware(handler)
	handler = middleware.CorsMiddleware(handler)
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.RateLimitMiddleware(handler)
	handler = middleware.BodyLimitMiddleware(handler)
	handler = middleware.RequestIDMiddleware(handler)

	// Create server with graceful shutdown support
	addr := fmt.Sprintf(":%s", config.Port)
	srv := &http.Server{
		Addr:           addr,
		Handler:        handler,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB max header size
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server is running at https://auth.gilos.org")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Allow 10 seconds for in-flight requests to complete
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited gracefully")
}

// noDirectoryListing wraps a http.FileServer to return 404 instead of listing directories.
func noDirectoryListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
