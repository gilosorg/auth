package config

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

// Application identity
var (
	// Version is the current version of the application injected at build time.
	Version string = "v0.0.0-dev"
	// AppName is the display name used in UI, emails, and SMS messages (e.g., "Gilos Auth").
	AppName string
	// AppIDLabel is the label for user identifiers (e.g., "Gilos ID", "Account ID").
	AppIDLabel string
	// IssuerURL is the public-facing base URL, used as the OIDC issuer and in JWT claims.
	IssuerURL string
)

// Database configuration
var (
	DBPath string
)

// Eskiz SMS configuration
var (
	EskizEmail    string
	EskizPassword string
	EskizFromName string
)

// Email API configuration
var (
	EmailAPIEndpoint string
	EmailAPIToken    string
)

// Server configuration
var (
	Port          string
	SecureCookies bool
	CookieDomain  string
	CORSOrigins   []string
)

// Security configuration
var (
	// EncryptionKey is a 64-char hex string (32 bytes) for AES-256-GCM encryption of TOTP secrets.
	EncryptionKey string
	// TrustedProxies is a list of IP addresses/CIDRs whose X-Forwarded-For headers are trusted.
	TrustedProxies []string
	// BcryptCost controls the bcrypt hashing cost (default 12, range 10-14).
	BcryptCost int
)

// Init loads the .env file (if present) and populates config variables from environment.
// Environment variables always take precedence over .env file values.
func Init() {
	// Load .env file first (sets os env vars if not already set)
	loadEnvFile(".env")

	// Application identity
	AppName = getEnv("APP_NAME", "Auth")
	AppIDLabel = getEnv("APP_ID_LABEL", "Account ID")
	IssuerURL = strings.TrimRight(getEnv("ISSUER_URL", "https://auth.gilos.org"), "/")

	// Database
	DBPath = getEnv("DB_PATH", "database/auth.db")

	// Eskiz SMS
	EskizEmail = getEnv("ESKIZ_EMAIL", "")
	EskizPassword = getEnv("ESKIZ_PASSWORD", "")
	EskizFromName = getEnv("ESKIZ_FROM_NAME", "")

	// Email API
	EmailAPIEndpoint = getEnv("EMAIL_API_ENDPOINT", "")
	EmailAPIToken = getEnv("EMAIL_API_TOKEN", "")

	// Server
	Port = getEnv("PORT", "5001")
	SecureCookies = getEnv("SECURE_COOKIES", "true") == "true"
	CookieDomain = getEnv("COOKIE_DOMAIN", "")

	// CORS
	originsStr := getEnv("CORS_ORIGINS", "")
	if originsStr != "" {
		CORSOrigins = strings.Split(originsStr, ",")
		for i := range CORSOrigins {
			CORSOrigins[i] = strings.TrimSpace(CORSOrigins[i])
		}
	}
	// If no CORS origins configured, derive from IssuerURL
	if len(CORSOrigins) == 0 && IssuerURL != "" {
		CORSOrigins = []string{IssuerURL}
	}

	// Security
	EncryptionKey = getEnv("ENCRYPTION_KEY", "")
	if EncryptionKey == "" {
		log.Println("WARNING: ENCRYPTION_KEY not set — TOTP secrets will be stored unencrypted")
	}

	proxiesStr := getEnv("TRUSTED_PROXIES", "")
	if proxiesStr != "" {
		TrustedProxies = strings.Split(proxiesStr, ",")
		for i := range TrustedProxies {
			TrustedProxies[i] = strings.TrimSpace(TrustedProxies[i])
		}
	}

	BcryptCost = 12 // Default to cost 12
	if costStr := getEnv("BCRYPT_COST", "12"); costStr != "" {
		if cost, err := strconv.Atoi(costStr); err == nil && cost >= 10 && cost <= 14 {
			BcryptCost = cost
		}
	}

	log.Println("Configuration loaded successfully")
}

// getEnv reads an environment variable with a fallback default.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// loadEnvFile reads a .env file and sets environment variables.
// It does NOT override variables that are already set in the environment.
func loadEnvFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		// .env file is optional — in production, env vars may be set by the orchestrator
		log.Printf("No .env file found, using environment variables")
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first '='
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove surrounding quotes if present
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		// Only set if not already in environment
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
}
