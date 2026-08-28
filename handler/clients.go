package handler

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"gilosauth/database"
	"gilosauth/middleware"
	"gilosauth/utils"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ClientsHandler returns JSON list of clients or handles creation.
func ClientsHandler(w http.ResponseWriter, r *http.Request) {
	// UserID verified by middleware
	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	if r.Method == http.MethodPost {
		// Handle client creation
		if err := r.ParseForm(); err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "failed to parse form"})
			return
		}

		name := strings.TrimSpace(r.Form.Get("name"))
		clientType := strings.TrimSpace(r.Form.Get("type"))
		// Parse redirect URIs (newline-separated from textarea)
		rawURIs := r.Form.Get("redirect_uris")
		redirectURIs := parseRedirectURIs(rawURIs)

		if name == "" || clientType == "" || len(redirectURIs) == 0 {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "name, type, and at least one redirect URI are required"})
			return
		}

		if clientType != "public" && clientType != "confidential" {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid client type"})
			return
		}

		// Validate and collect scopes
		var scopes []string
		for _, scope := range middleware.Scopes {
			if r.Form.Get(scope) == "on" {
				scopes = append(scopes, scope)
			}
		}
		if len(scopes) == 0 {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "at least one scope is required"})
			return
		}
		scopesStr := strings.Join(scopes, ",")

		// Collect required scopes (must be a subset of selected scopes)
		var requiredScopes []string
		for _, scope := range scopes {
			if r.Form.Get("required_"+scope) == "on" {
				requiredScopes = append(requiredScopes, scope)
			}
		}
		requiredScopesStr := strings.Join(requiredScopes, ",")

		// Create client — secret handling depends on type
		client := database.Client{
			UserID:         userID,
			Name:           name,
			Type:           clientType,
			RedirectURIs:   strings.Join(redirectURIs, ","),
			Scopes:         scopesStr,
			RequiredScopes: requiredScopesStr,
		}

		var plaintextSecret string

		if clientType == "confidential" {
			// Confidential clients get a secret (C1: never store plaintext)
			var err error
			plaintextSecret, err = generateClientSecret()
			if err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate client secret"})
				return
			}

			hashedSecret, err := bcrypt.GenerateFromPassword([]byte(plaintextSecret), bcrypt.DefaultCost)
			if err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash client secret"})
				return
			}

			secretStr := string(hashedSecret)
			client.Secret = &secretStr
			client.SecretPrefix = plaintextSecret[:8]
			now := time.Now()
			client.SecretCreatedAt = &now
		}
		// Public clients: Secret stays nil — they authenticate via PKCE (RFC 7636)

		if err := database.DB.Create(&client).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to create client"})
			return
		}

		// Build response based on client type
		response := map[string]interface{}{
			"success":     true,
			"client_id":   client.ID,
			"client_name": client.Name,
			"client_type": client.Type,
		}

		if clientType == "confidential" {
			// Return the plaintext secret only once — it cannot be recovered after this
			response["client_secret"] = plaintextSecret
			response["secret_prefix"] = client.SecretPrefix
			response["warning"] = "Save this secret now. It will not be shown again."
		} else {
			response["info"] = "Public client created. Use PKCE (code_challenge + code_verifier) for authentication. No client_secret is needed."
		}

		utils.WriteJSONResponse(w, http.StatusOK, response)
		return
	}

	// GET: Fetch clients for the user
	var clients []database.Client
	if err := database.DB.Where("user_id = ?", userID).Find(&clients).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve clients"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, clients)
}

// EditClientHandler returns JSON for single client or handles update.
func EditClientHandler(w http.ResponseWriter, r *http.Request) {
	// UserID verified by middleware
	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Get client ID from query parameter
	clientIDStr := r.URL.Query().Get("id")
	if clientIDStr == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "client ID is required"})
		return
	}

	clientID, err := strconv.ParseUint(clientIDStr, 10, 64)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid client ID"})
		return
	}

	var client database.Client
	if err := database.DB.Where("id = ? AND user_id = ?", clientID, userID).First(&client).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusNotFound, map[string]string{"error": "client not found or unauthorized"})
		return
	}

	if r.Method == http.MethodPost {
		// Handle client update
		if err := r.ParseForm(); err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "failed to parse form"})
			return
		}

		name := strings.TrimSpace(r.Form.Get("name"))
		clientType := strings.TrimSpace(r.Form.Get("type"))

		// Parse redirect URIs (newline-separated from textarea)
		rawURIs := r.Form.Get("redirect_uris")
		redirectURIs := parseRedirectURIs(rawURIs)

		if name == "" || clientType == "" || len(redirectURIs) == 0 {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "name, type, and at least one redirect URI are required"})
			return
		}

		if clientType != "public" && clientType != "confidential" {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid client type"})
			return
		}

		// Validate and collect scopes
		var scopes []string
		for _, scope := range middleware.Scopes {
			if r.Form.Get(scope) == "on" {
				scopes = append(scopes, scope)
			}
		}
		if len(scopes) == 0 {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "at least one scope is required"})
			return
		}
		scopesStr := strings.Join(scopes, ",")

		// Collect required scopes (must be a subset of selected scopes)
		var requiredScopes []string
		for _, scope := range scopes {
			if r.Form.Get("required_"+scope) == "on" {
				requiredScopes = append(requiredScopes, scope)
			}
		}
		requiredScopesStr := strings.Join(requiredScopes, ",")

		// Handle type transition
		oldType := client.Type
		response := map[string]interface{}{"success": true}

		if oldType == "confidential" && clientType == "public" {
			// Confidential → Public: clear the secret (public clients use PKCE)
			client.Secret = nil
			client.SecretPrefix = ""
			client.SecretCreatedAt = nil
			response["info"] = "Client changed to public. Secret has been removed. Use PKCE for authentication."
		} else if oldType == "public" && clientType == "confidential" {
			// Public → Confidential: generate a new secret
			plaintextSecret, err := generateClientSecret()
			if err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate client secret"})
				return
			}

			hashedSecret, err := bcrypt.GenerateFromPassword([]byte(plaintextSecret), bcrypt.DefaultCost)
			if err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash client secret"})
				return
			}

			secretStr := string(hashedSecret)
			client.Secret = &secretStr
			client.SecretPrefix = plaintextSecret[:8]
			now := time.Now()
			client.SecretCreatedAt = &now

			// Return the new secret only once
			response["client_secret"] = plaintextSecret
			response["secret_prefix"] = client.SecretPrefix
			response["warning"] = "Client changed to confidential. Save this secret now. It will not be shown again."
		}

		// Update client fields
		client.Name = name
		client.Type = clientType
		client.RedirectURIs = strings.Join(redirectURIs, ",")
		client.Scopes = scopesStr
		client.RequiredScopes = requiredScopesStr

		if err := database.DB.Save(&client).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update client"})
			return
		}

		utils.WriteJSONResponse(w, http.StatusOK, response)
		return
	}

	// GET: Return single client JSON
	utils.WriteJSONResponse(w, http.StatusOK, client)
}

// DeleteClientHandler deletes an OAuth client and returns JSON.
func DeleteClientHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// UserID verified by middleware
	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Parse client ID
	if err := r.ParseForm(); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "failed to parse form"})
		return
	}
	clientIDStr := r.Form.Get("client_id")
	if clientIDStr == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "client ID is required"})
		return
	}

	clientID, err := strconv.ParseUint(clientIDStr, 10, 64)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid client ID"})
		return
	}

	// Verify client belongs to user
	var client database.Client
	if err := database.DB.Where("id = ? AND user_id = ?", clientID, userID).First(&client).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusNotFound, map[string]string{"error": "client not found or unauthorized"})
		return
	}

	// Delete associated sessions first (GORM AutoMigrate does not add CASCADE to SQLite FKs)
	if err := database.DB.Where("client_id = ?", client.ID).Delete(&database.Session{}).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete client sessions"})
		return
	}

	// Delete the client
	if err := database.DB.Delete(&client).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete client"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}

// RegenerateSecretHandler generates a new secret for an existing client.
// The new plaintext secret is returned exactly once.
func RegenerateSecretHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "failed to parse form"})
		return
	}
	clientIDStr := r.Form.Get("client_id")
	if clientIDStr == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "client ID is required"})
		return
	}

	clientID, err := strconv.ParseUint(clientIDStr, 10, 64)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid client ID"})
		return
	}

	// Verify ownership
	var client database.Client
	if err := database.DB.Where("id = ? AND user_id = ?", clientID, userID).First(&client).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusNotFound, map[string]string{"error": "client not found or unauthorized"})
		return
	}

	// Public clients don't have secrets — reject the request
	if client.IsPublic() {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{
			"error":   "not_applicable",
			"message": "Public clients do not use client secrets. They authenticate via PKCE (RFC 7636).",
		})
		return
	}

	// Generate new secret for confidential client
	plaintextSecret, err := generateClientSecret()
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate client secret"})
		return
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(plaintextSecret), bcrypt.DefaultCost)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash client secret"})
		return
	}

	secretStr := string(hashedSecret)
	secretPrefix := plaintextSecret[:8]
	now := time.Now()

	// Update secret, prefix, and timestamp
	client.Secret = &secretStr
	client.SecretPrefix = secretPrefix
	client.SecretCreatedAt = &now

	if err := database.DB.Save(&client).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update client secret"})
		return
	}

	// Return the new plaintext secret only once
	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":       true,
		"client_id":     client.ID,
		"client_name":   client.Name,
		"client_secret": plaintextSecret,
		"secret_prefix": secretPrefix,
		"warning":       "Save this secret now. It will not be shown again.",
	})
}

// parseRedirectURIs parses a newline-separated (or comma-separated) string of URIs,
// trims whitespace, and returns a deduplicated slice of non-empty URIs.
func parseRedirectURIs(raw string) []string {
	// Support both newline and comma as separators
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, ",", "\n")
	parts := strings.Split(raw, "\n")

	seen := make(map[string]bool)
	var result []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
	}
	return result
}

// generateClientSecret creates a secure random client secret.
func generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate client secret: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
