package client

import (
	"encoding/json"
	"fmt"
	"gilosauth/database"
	"gilosauth/i18n"
	"gilosauth/middleware"
	"gilosauth/utils"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)



// GetOAuthInquiryHandler returns details about an authorization request
func GetOAuthInquiryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Parse query parameters
	clientID := r.URL.Query().Get("client_id")
	scope := r.URL.Query().Get("scope")
	redirectURI := r.URL.Query().Get("redirect_uri")

	if clientID == "" || scope == "" || redirectURI == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "missing required parameters: client_id, scope, redirect_uri"})
		return
	}

	// Validate client
	var client database.Client
	if err := database.DB.Where("id = ?", clientID).First(&client).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusNotFound, map[string]string{"error": "client not found"})
		return
	}

	// Get user info from token (the manager app user)
	userID, _ := middleware.GetUserID(r)
	var clientUser database.User
	if err := database.DB.First(&clientUser, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "user not found"})
		return
	}

	// Validate redirect URI against registered URIs
	if !client.HasRedirectURI(redirectURI) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid redirect_uri"})
		return
	}

	// Get language preference
	lang := "en"
	if langCookie, err := r.Cookie("lang"); err == nil {
		lang = i18n.NormalizeCode(langCookie.Value)
	}

	// Prepare scope descriptions with required/missing info
	requestedScopes := strings.Split(scope, " ")
	clientScopes := strings.Split(client.Scopes, ",")
	requiredScopes := strings.Split(client.RequiredScopes, ",")
	translations := i18n.GetTranslations(lang)

	type APIScopeDetail struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		MaskedValue string `json:"masked_value,omitempty"`
		IsRequired  bool   `json:"is_required"`
		HasData     bool   `json:"has_data"`
	}

	var scopes []APIScopeDetail
	canApprove := true
	var missingFields []string

	for _, s := range requestedScopes {
		if s == "" {
			continue
		}
		// Verify scope is valid and allowed for this client
		if !middleware.IsValidScope(s) || !slices.Contains(clientScopes, s) {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid or unauthorized scope: %s", s)})
			return
		}

		// Get description from translations
		descKey := "access_" + strings.TrimPrefix(s, "user_")
		description := translations[descKey]
		if description == "" {
			description = s
		}

		isRequired := slices.Contains(requiredScopes, s)
		maskedValue := ""
		hasData := true

		// Check data availability and build masked value
		switch s {
		case "email":
			if clientUser.Email != "" {
				maskedValue = utils.MaskEmail(clientUser.Email)
			} else {
				hasData = false
			}
		case "phone":
			if clientUser.Phone != 0 {
				maskedValue = utils.MaskPhone(clientUser.Phone)
			} else {
				hasData = false
			}
		}

		if isRequired && !hasData {
			canApprove = false
			fieldName := translations["scope_"+strings.TrimPrefix(s, "user_")]
			if fieldName == "" {
				fieldName = s
			}
			missingFields = append(missingFields, fieldName)
		}

		scopes = append(scopes, APIScopeDetail{
			ID:          s,
			Description: description,
			MaskedValue: maskedValue,
			IsRequired:  isRequired,
			HasData:     hasData,
		})
	}

	response := map[string]interface{}{
		"client": map[string]interface{}{
			"id":   client.ID,
			"name": client.Name,
			"type": client.Type,
		},
		"scopes":           scopes,
		"redirect_uri":     redirectURI,
		"mfa_totp_enabled": clientUser.MFATOTPEnabled,
		"can_approve":      canApprove,
		"missing_fields":   missingFields,
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// ApproveOAuthInquiryHandler handles the approval and returns an authorization code
func ApproveOAuthInquiryHandler(w http.ResponseWriter, r *http.Request) {
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

	// Parse request body
	var req struct {
		ClientID            string `json:"client_id"`
		Scope               string `json:"scope"`
		RedirectURI         string `json:"redirect_uri"`
		State               string `json:"state"`
		TOTPCode            string `json:"totp_code"`
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.ClientID == "" || req.Scope == "" || req.RedirectURI == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "missing required parameters"})
		return
	}

	// Validate client
	var client database.Client
	if err := database.DB.Where("id = ?", req.ClientID).First(&client).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusNotFound, map[string]string{"error": "client not found"})
		return
	}

	// Validate redirect URI against registered URIs
	if !client.HasRedirectURI(req.RedirectURI) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid redirect_uri"})
		return
	}

	// PKCE validation — mandatory for all clients (OAuth 2.1)
	if req.CodeChallenge == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "PKCE code_challenge required (OAuth 2.1)"})
		return
	}
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "Unsupported code_challenge_method. Use S256 or plain."})
		return
	}
	if req.CodeChallengeMethod == "" && req.CodeChallenge != "" {
		req.CodeChallengeMethod = "plain" // Default per RFC 7636
	}

	// Validate scopes
	requestedScopes := strings.Split(req.Scope, " ")
	clientScopes := strings.Split(client.Scopes, ",")
	for _, s := range requestedScopes {
		if s == "" {
			continue
		}
		isValid := middleware.IsValidScope(s)
		isAllowed := false
		for _, cs := range clientScopes {
			if cs == s {
				isAllowed = true
				break
			}
		}
		if !isValid || !isAllowed {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid or unauthorized scope: %s", s)})
			return
		}
	}

	// Verify TOTP if enabled
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "user not found"})
		return
	}

	// Server-side enforcement: reject if required scope data is missing
	requiredScopes := strings.Split(client.RequiredScopes, ",")
	for _, s := range requestedScopes {
		if s == "" || !slices.Contains(requiredScopes, s) {
			continue
		}
		switch s {
		case "email":
			if user.Email == "" {
				utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "missing_required_data", "message": "Your account is missing a required email address"})
				return
			}
		case "phone":
			if user.Phone == 0 {
				utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "missing_required_data", "message": "Your account is missing a required phone number"})
				return
			}
		}
	}

	if user.MFATOTPEnabled {
		if req.TOTPCode == "" {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "totp_code_required"})
			return
		}

		// Get current session for retry tracking
		sess, err := database.SM.Start(r.Context(), w, r, nil)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
			return
		}

		attempts, _ := database.SM.GetData(sess, "oauth_totp_attempts")
		attemptCount := 0
		if attempts != nil {
			if count, ok := attempts.(float64); ok {
				attemptCount = int(count)
			}
		}
		attemptCount++

		if !totp.Validate(req.TOTPCode, user.TOTPSecret) {
			if attemptCount >= 3 {
				database.SM.ApplyBlock(fmt.Sprintf("user:%d:security", user.ID), sess, 24*time.Hour, "security")
				database.SM.ClearAllData(sess)
				utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "max_attempts_reached"})
				return
			}
			database.SM.SetData(sess, "oauth_totp_attempts", attemptCount)
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]interface{}{
				"error":              "invalid_totp",
				"attempts_remaining": 3 - attemptCount,
			})
			return
		}
		// Clear attempts on success
		database.SM.DeleteData(sess, "oauth_totp_attempts")
	}

	// Generate authorization code
	code, err := utils.GenerateRandomString(16)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate auth code"})
		return
	}

	// Create a NEW session specifically for this OAuth authorization
	clientIDUint := client.ID
	oauthSess := database.Session{
		UserID:     &userID,
		ClientID:   &clientIDUint,
		Type:       "client",
		RawData:    make(database.JSONData),
		LastSeenAt: time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute), // Auth codes expire in 5 minutes (RFC 6749 §4.1.2)
	}
	database.SM.UpdateMetadata(&oauthSess, r)

	// Store auth code and OAuth data in RawData
	// C2: Store hashed auth code (matching browser flow security)
	oauthSess.RawData["auth_code"] = utils.HashToken(code)
	oauthSess.RawData["client_id"] = req.ClientID
	oauthSess.RawData["scopes"] = req.Scope
	oauthSess.RawData["redirect_uri"] = req.RedirectURI

	// Store PKCE challenge if provided
	if req.CodeChallenge != "" {
		oauthSess.RawData["code_challenge"] = req.CodeChallenge
		oauthSess.RawData["code_challenge_method"] = req.CodeChallengeMethod
	}

	// Save the OAuth session
	if err := database.DB.Create(&oauthSess).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to create OAuth session"})
		return
	}

	database.LogAuditEventWithUserID(database.AuditOAuthAuthorized, userID, r,
		fmt.Sprintf("authorized client %s for scopes: %s (browserless)", req.ClientID, req.Scope))

	response := map[string]string{
		"code":         code,
		"redirect_uri": req.RedirectURI,
	}
	if req.State != "" {
		response["state"] = req.State
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}

