package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"gilosauth/config"
	"gilosauth/database"
	"gilosauth/i18n"
	"gilosauth/middleware"
	"gilosauth/utils"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// OAuthAuthorizeHandler handles the OAuth 2.0 authorization endpoint
func OAuthAuthorizeHandler(tmpls *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Step 1: Verify user authentication
		userID, err := middleware.GetUserID(r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Step 2: Parse query parameters
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		responseType := r.URL.Query().Get("response_type")
		scope := r.URL.Query().Get("scope")
		state := r.URL.Query().Get("state")                         // OAuth 2.0 state parameter (RFC 6749 §10.12)
		nonce := r.URL.Query().Get("nonce")                         // OIDC nonce (OIDC Core §3.1.2.1)
		codeChallenge := r.URL.Query().Get("code_challenge")         // PKCE (RFC 7636)
		codeChallengeMethod := r.URL.Query().Get("code_challenge_method") // PKCE method (S256 or plain)

		// Step 3: Validate required parameters
		if clientID == "" || redirectURI == "" || responseType == "" || scope == "" {
			http.Error(w, "Missing required parameters", http.StatusBadRequest)
			return
		}

		// C8: State is mandatory to prevent CSRF in OAuth flow
		if state == "" {
			http.Error(w, "Missing required state parameter (RFC 6749 §10.12)", http.StatusBadRequest)
			return
		}

		// Step 4: Validate response_type
		if responseType != "code" {
			http.Error(w, "Unsupported response_type", http.StatusBadRequest)
			return
		}

		// Step 5: Validate client
		var client database.Client
		if err := database.DB.Where("id = ?", clientID).First(&client).Error; err != nil {
			http.Error(w, "Invalid client_id", http.StatusBadRequest)
			return
		}

		// Step 6: Validate redirect URI against registered URIs
		if !client.HasRedirectURI(redirectURI) {
			http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
			return
		}

		// Step 7: Validate scopes
		requestedScopes := strings.Fields(strings.ReplaceAll(scope, ",", " "))
		if len(requestedScopes) == 0 {
			http.Error(w, "Invalid scope", http.StatusBadRequest)
			return
		}
		clientScopes := strings.Split(client.Scopes, ",")
		for _, s := range requestedScopes {
			if !middleware.IsValidScope(s) || !slices.Contains(clientScopes, s) {
				http.Error(w, "Invalid scope", http.StatusBadRequest)
				return
			}
		}

		// C9: PKCE validation — mandatory for all clients (OAuth 2.1 §4.4.2)
		if codeChallenge == "" {
			http.Error(w, "PKCE code_challenge required (OAuth 2.1)", http.StatusBadRequest)
			return
		}
		// OAuth 2.1 mandates S256 only — "plain" is no longer permitted
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256" // Default to S256 per OAuth 2.1
		}
		if codeChallengeMethod != "S256" {
			http.Error(w, "Unsupported code_challenge_method. Only S256 is supported (OAuth 2.1).", http.StatusBadRequest)
			return
		}
		if !utils.ValidatePKCECodeChallenge(codeChallenge) {
			http.Error(w, "Invalid PKCE code_challenge format", http.StatusBadRequest)
			return
		}

		// Get language preference
		lang := "en"
		if langCookie, err := r.Cookie("lang"); err == nil {
			lang = i18n.NormalizeCode(langCookie.Value)
		}

		tr := i18n.New(lang)

		var csrfToken string
		if sess, err := middleware.GetSession(r); err == nil {
			csrfToken, _ = middleware.EnsureCSRFToken(sess)
		}

		// Step 8: Fetch user and verify status
		var user database.User
		if err := database.DB.First(&user, userID).Error; err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}
		if user.Status == "suspended" {
			http.Error(w, "Account is suspended", http.StatusForbidden)
			return
		}

		translations := i18n.GetTranslations(lang)

		// Build scope details with masked values and required/missing info
		requiredScopes := strings.Split(client.RequiredScopes, ",")
		scopeDetails, hasMissingRequired, missingFields := buildScopeDetails(requestedScopes, requiredScopes, &user, lang)

		if r.Method == http.MethodPost {
			// Handle consent form submission
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Failed to parse form", http.StatusBadRequest)
				return
			}

			if r.Form.Get("approve") == "true" {
				// Server-side enforcement: reject if required data is missing
				if hasMissingRequired {
					errMsg := translations["oauth_missing_required_err"]
					if errMsg == "" {
						errMsg = "Required account data is missing. Please update your profile."
					}
					renderConsentPage(w, tmpls, client, scopeDetails, redirectURI, state, tr, lang, errMsg, &user, hasMissingRequired, missingFields, csrfToken)
					return
				}

				// Extra verification (TOTP)
				if user.MFATOTPEnabled {
					if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", user.ID)); blocked {
						http.Error(w, fmt.Sprintf("Account is temporarily blocked for security until %s.", until.Format(time.RFC3339)), http.StatusTooManyRequests)
						return
					}

					totpCode := r.Form.Get("totp_code")
					if totpCode == "" {
						errMsg := translations["oauth_totp_required"]
						if errMsg == "" {
							errMsg = "TOTP verification code required"
						}
						renderConsentPage(w, tmpls, client, scopeDetails, redirectURI, state, tr, lang, errMsg, &user, hasMissingRequired, missingFields, csrfToken)
						return
					}

					// Get current session for retry tracking
					sess, err := database.SM.Start(r.Context(), w, r, nil)
					if err != nil {
						http.Error(w, "Failed to get session", http.StatusInternalServerError)
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

					// Verify TOTP (supporting encrypted secret at rest)
					if !decryptAndValidateUserTOTP(&user, totpCode) {
						blocked, _, totpLeft := database.SM.RecordTOTPFailure(user.ID, sess)
						if attemptCount >= 3 || blocked {
							_ = database.SM.ApplyBlock(fmt.Sprintf("user:%d:security", user.ID), sess, 24*time.Hour, "security")
							_ = database.SM.DeleteData(sess, "oauth_totp_attempts")
							database.LogAuditEventWithUserID(database.AuditBruteForceBlocked, user.ID, r, "24h block after max OAuth TOTP attempts")
							http.Error(w, "Maximum TOTP attempts reached. Account blocked for 24 hours.", http.StatusForbidden)
							return
						}
						_ = database.SM.SetData(sess, "oauth_totp_attempts", attemptCount)
						remaining := 3 - attemptCount
						if int(totpLeft) < remaining {
							remaining = int(totpLeft)
						}
						errMsg := translations["oauth_invalid_totp"]
						if errMsg != "" {
							errMsg = strings.ReplaceAll(errMsg, "{attempts}", fmt.Sprint(remaining))
						} else {
							errMsg = fmt.Sprintf("Invalid verification code. %d attempt%s remaining.", remaining, utils.Pluralize(remaining))
						}
						renderConsentPage(w, tmpls, client, scopeDetails, redirectURI, state, tr, lang, errMsg, &user, hasMissingRequired, missingFields, csrfToken)
						return
					}
					// Clear attempts on success
					database.SM.ClearTOTPFailures(user.ID)
					_ = database.SM.DeleteData(sess, "oauth_totp_attempts")
				}

				// Generate authorization code
				code, err := generateAuthCode()
				if err != nil {
					http.Error(w, "Failed to generate authorization code", http.StatusInternalServerError)
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
				oauthSess.RawData["auth_code"] = utils.HashToken(code) // C2: Store hashed auth code
				oauthSess.RawData["client_id"] = clientID
				oauthSess.RawData["scopes"] = scope
				oauthSess.RawData["redirect_uri"] = redirectURI
				// Store OIDC nonce for echo-back in id_token
				if nonce != "" {
					oauthSess.RawData["nonce"] = nonce
				}
				// Store PKCE challenge if provided
				if codeChallenge != "" {
					oauthSess.RawData["code_challenge"] = codeChallenge
					oauthSess.RawData["code_challenge_method"] = codeChallengeMethod
				}

				// Save the OAuth session
				if err := database.DB.Create(&oauthSess).Error; err != nil {
					http.Error(w, "Failed to create OAuth session", http.StatusInternalServerError)
					return
				}

				database.LogAuditEventWithUserID(database.AuditOAuthAuthorized, userID, r,
					fmt.Sprintf("authorized client %s for scopes: %s", clientID, scope))

				// Redirect with authorization code and state
				redirectURL, err := url.Parse(redirectURI)
				if err != nil {
					http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
					return
				}
				query := redirectURL.Query()
				query.Set("code", code)
				if state != "" {
					query.Set("state", state)
				}
				redirectURL.RawQuery = query.Encode()
				http.Redirect(w, r, redirectURL.String(), http.StatusFound)
				return
			} else {
				// Handle consent denial
				redirectURL, err := url.Parse(redirectURI)
				if err != nil {
					http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
					return
				}
				query := redirectURL.Query()
				query.Set("error", "access_denied")
				if state != "" {
					query.Set("state", state)
				}
				redirectURL.RawQuery = query.Encode()
				http.Redirect(w, r, redirectURL.String(), http.StatusFound)
				return
			}
		}

		// Render consent page
		renderConsentPage(w, tmpls, client, scopeDetails, redirectURI, state, tr, lang, "", &user, hasMissingRequired, missingFields, csrfToken)
	}
}

// ScopeDetail holds rich scope information for the consent template.
type ScopeDetail struct {
	ID          string // scope identifier (e.g., "user_email")
	Description string // translated description
	MaskedValue string // masked value if data scope (e.g., "te****@gmail.com"), empty for non-data scopes
	IsRequired  bool   // whether this scope requires user data
	IsMissing   bool   // whether the required data is missing
}

// buildScopeDetails creates ScopeDetail entries for each requested scope,
// checking which have data and which are required but missing.
func buildScopeDetails(requestedScopes, requiredScopes []string, user *database.User, lang string) ([]ScopeDetail, bool, []string) {
	translations := i18n.GetTranslations(lang)
	hasMissingRequired := false
	var missingFields []string

	var details []ScopeDetail
	for _, s := range requestedScopes {
		if s == "" {
			continue
		}

		// Get translated description
		descKey := i18n.ScopeDescriptionKey(s)
		description := translations[descKey]
		if description == "" {
			description = s
		}

		isRequired := slices.Contains(requiredScopes, s)
		maskedValue := ""
		isMissing := false

		// Check data availability and build masked value
		switch s {
		case "email":
			if user.Email != "" {
				maskedValue = utils.MaskEmail(user.Email)
			} else if isRequired {
				isMissing = true
				hasMissingRequired = true
				fieldName := translations["scope_email"]
				if fieldName == "" {
					fieldName = "email"
				}
				missingFields = append(missingFields, fieldName)
			}
		case "phone":
			if user.Phone != 0 {
				maskedValue = utils.MaskPhone(user.Phone)
			} else if isRequired {
				isMissing = true
				hasMissingRequired = true
				fieldName := translations["scope_phone"]
				if fieldName == "" {
					fieldName = "phone number"
				}
				missingFields = append(missingFields, fieldName)
			}
		}

		details = append(details, ScopeDetail{
			ID:          s,
			Description: description,
			MaskedValue: maskedValue,
			IsRequired:  isRequired,
			IsMissing:   isMissing,
		})
	}

	return details, hasMissingRequired, missingFields
}

// renderConsentPage is a helper to render the oauth.html template
func renderConsentPage(w http.ResponseWriter, tmpls *template.Template, client database.Client, scopeDetails []ScopeDetail, redirectURI string, state string, tr *i18n.Translator, lang string, errorMessage string, user *database.User, hasMissingRequired bool, missingFields []string, csrfToken string) {
	data := map[string]interface{}{
		"Year":               time.Now().Year(),
		"Client":             client,
		"ScopeDetails":       scopeDetails,
		"RedirectURI":        redirectURI,
		"State":              state,
		"ValidScopes":        middleware.Scopes,
		"Lang":               lang,
		"CurrentLanguage":    tr.Current(),
		"Languages":          tr.All(),
		"T":                  i18n.GetTranslations(lang),
		"AppVersion":         config.Version,
		"AppName":            config.AppName,
		"AppIDLabel":         config.AppIDLabel,
		"Error":              errorMessage,
		"User":               user,
		"HasMissingRequired": hasMissingRequired,
		"MissingFields":      missingFields,
		"CSRFToken":          csrfToken,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpls.ExecuteTemplate(w, "oauth.html", data); err != nil {
		http.Error(w, "Could not render template", http.StatusInternalServerError)
	}
}

// OAuthTokenHandler handles the OAuth 2.0 token endpoint for both authorization_code and refresh_token grant types
func OAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	// RFC 6749 §5.1: Token responses MUST NOT be cached
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Failed to parse form"})
		return
	}

	grantType := r.Form.Get("grant_type")
	code := r.Form.Get("code")
	refreshToken := r.Form.Get("refresh_token")
	redirectURI := r.Form.Get("redirect_uri")

	if grantType != "authorization_code" && grantType != "refresh_token" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type", "error_description": "Only authorization_code and refresh_token grant types are supported"})
		return
	}

	// Authenticate client (supports both form params and HTTP Basic Auth)
	client, err := authenticateClient(r)
	if err != nil {
		if _, _, hasBasic := r.BasicAuth(); hasBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="Gilos Auth"`)
		}
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": err.Error()})
		return
	}

	var session database.Session

	// Shorthand for client ID
	clientID := client.ID
	if grantType == "authorization_code" {
		// Authorization code flow
		if code == "" || redirectURI == "" {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Missing required form parameters"})
			return
		}

		// Validate redirect URI against registered URIs
		if !client.HasRedirectURI(redirectURI) {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid redirect URI"})
			return
		}
		// Find session with hashed auth code in RawData (C5: tokens hashed)
		hashedCode := utils.HashToken(code)
		if err := database.DB.Where("json_extract(raw_data, '$.auth_code') = ? AND client_id = ? AND json_extract(raw_data, '$.redirect_uri') = ? AND expires_at > ?", hashedCode, clientID, redirectURI, time.Now()).First(&session).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Session not found, expired, or invalid grant details"})
			return
		}

		// C9: Verify PKCE code_verifier (Mandatory for all clients in OAuth 2.1)
		codeVerifier := r.Form.Get("code_verifier")
		storedChallenge, exists := database.SM.GetData(&session, "code_challenge")
		if !exists {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "PKCE required for all clients (OAuth 2.1)"})
			return
		}
		if codeVerifier == "" {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "code_verifier required (PKCE)"})
			return
		}
		method, _ := database.SM.GetData(&session, "code_challenge_method")
		methodStr := "S256"
		if m, ok := method.(string); ok && m != "" {
			methodStr = m
		}
		if !verifyPKCE(codeVerifier, fmt.Sprint(storedChallenge), methodStr) {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid code_verifier"})
			return
		}

		// Get scopes before we modify the session
		rawScopes, _ := database.SM.GetData(&session, "scopes")
		scopeStr := ""
		if s, ok := rawScopes.(string); ok {
			scopeStr = s
		}

		// Get user for OIDC claims and verify account is not suspended
		var user database.User
		if err := database.DB.First(&user, *session.UserID).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "User not found"})
			return
		}
		if user.Status == "suspended" {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "access_denied", "error_description": "Account is suspended"})
			return
		}

		// Preserve nonce and scopes from the auth code session before deletion
		nonceFromAuthCode := ""
		if n, exists := database.SM.GetData(&session, "nonce"); exists {
			if nStr, ok := n.(string); ok {
				nonceFromAuthCode = nStr
			}
		}

		// Atomically consume the auth code session (single-use guarantee)
		delRes := database.DB.Where("id = ?", session.ID).Delete(&database.Session{})
		if delRes.Error != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to consume auth code"})
			return
		}
		if delRes.RowsAffected == 0 {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Authorization code has already been used"})
			return
		}

		// Create a new token session first so we have an ID for the JWT
		accessTokenExpiresAt := time.Now().Add(1 * time.Hour)
		tokenSession := database.Session{
			UserID:               session.UserID,
			ClientID:             &clientID,
			Type:                 "client",
			Scopes:               &scopeStr,
			RawData:              make(database.JSONData),
			LastSeenAt:           time.Now(),
			ExpiresAt:            time.Now().Add(30 * 24 * time.Hour),
			AccessTokenExpiresAt: &accessTokenExpiresAt,
		}
		database.SM.UpdateMetadata(&tokenSession, r)
		
		if err := database.DB.Create(&tokenSession).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to create token session"})
			return
		}

		// Store nonce in token session for OIDC id_token generation
		if nonceFromAuthCode != "" {
			tokenSession.RawData["nonce"] = nonceFromAuthCode
			if err := database.DB.Save(&tokenSession).Error; err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to store token metadata"})
				return
			}
		}

		// Generate JWT access token and opaque refresh token
		accessToken, err := GenerateAccessToken(&tokenSession, clientID, scopeStr)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to generate access token"})
			return
		}

		newRefreshToken, err := generateToken()
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to generate refresh token"})
			return
		}

		// Update tokens in session
		hashedAccessToken := utils.HashToken(accessToken)
		hashedRefreshToken := utils.HashToken(newRefreshToken)
		tokenSession.AccessToken = &hashedAccessToken
		tokenSession.RefreshToken = &hashedRefreshToken
		if err := database.DB.Save(&tokenSession).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to persist issued tokens"})
			return
		}

		response := map[string]interface{}{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": newRefreshToken,
			"scope":         scopeStr,
		}

		// Add OIDC id_token if openid scope is requested
		if strings.Contains(" "+scopeStr+" ", " openid ") {
			idToken, err := GenerateIDToken(&user, clientID, scopeStr, accessTokenExpiresAt.Unix(), nonceFromAuthCode, accessToken)
			if err == nil {
				response["id_token"] = idToken
			}
		}

		utils.WriteJSONResponse(w, http.StatusOK, response)
	} else {
		// Refresh token flow
		if refreshToken == "" {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Missing refresh token"})
			return
		}

		// C5: Hash the presented refresh token for DB lookup
		hashedRefreshToken := utils.HashToken(refreshToken)

		// Find session with hashed refresh token
		if err := database.DB.Where("refresh_token = ? AND client_id = ? AND type = ? AND expires_at > ?", hashedRefreshToken, clientID, "client", time.Now()).First(&session).Error; err != nil {
			// OAuth 2.1 §4.3.1: Detect refresh token replay and revoke compromised session family
			var reusedSession database.Session
			if rErr := database.DB.Where("previous_refresh_token = ? AND client_id = ? AND type = ? AND expires_at > ?", hashedRefreshToken, clientID, "client", time.Now()).First(&reusedSession).Error; rErr == nil {
				_ = database.DB.Delete(&reusedSession).Error
				if reusedSession.UserID != nil {
					database.LogAuditEventWithUserID(database.AuditSecurityBlocked, *reusedSession.UserID, r, "refresh token reuse detected; OAuth session revoked")
				}
			}
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid or expired refresh token"})
			return
		}

		// Verify user still exists and is not suspended before refreshing
		if session.UserID == nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Session has no associated user"})
			return
		}
		var user database.User
		if err := database.DB.First(&user, *session.UserID).Error; err != nil || user.Status == "suspended" {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "access_denied", "error_description": "Account is unavailable or suspended"})
			return
		}

		accessTokenExpiresAt := time.Now().Add(1 * time.Hour)
		newExpiresAt := time.Now().Add(30 * 24 * time.Hour)
		session.AccessTokenExpiresAt = &accessTokenExpiresAt
		session.ExpiresAt = newExpiresAt
		session.LastSeenAt = time.Now()
		database.SM.UpdateMetadata(&session, r)

		var scopeStr string
		if session.Scopes != nil {
			scopeStr = *session.Scopes
		}

		// Generate new JWT access token (iat will reflect current time)
		accessToken, err := GenerateAccessToken(&session, clientID, scopeStr)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to generate access token"})
			return
		}

		// Rotate refresh token on every use
		newRefreshToken, err := generateToken()
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to generate refresh token"})
			return
		}

		// Store hashed tokens atomically guarded by previous refresh_token hash
		hashedAccessToken := utils.HashToken(accessToken)
		hashedNewRefreshToken := utils.HashToken(newRefreshToken)
		updateRes := database.DB.Model(&database.Session{}).
			Where("id = ? AND refresh_token = ?", session.ID, hashedRefreshToken).
			Updates(map[string]interface{}{
				"access_token":            hashedAccessToken,
				"refresh_token":           hashedNewRefreshToken,
				"previous_refresh_token":  hashedRefreshToken,
				"access_token_expires_at": accessTokenExpiresAt,
				"expires_at":              newExpiresAt,
				"last_seen_at":            session.LastSeenAt,
				"device_info":             session.DeviceInfo,
				"ip_address":              session.IPAddress,
			})
		if updateRes.Error != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to update session with new token"})
			return
		}
		if updateRes.RowsAffected == 0 {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Refresh token has already been rotated"})
			return
		}

		response := map[string]interface{}{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": newRefreshToken,
			"scope":         scopeStr,
		}

		// Add OIDC id_token if openid scope is requested
		// Note: nonce is NOT echoed on refresh — it's only for the initial auth code exchange (OIDC Core §12.2)
		if strings.Contains(" "+scopeStr+" ", " openid ") {
			idToken, err := GenerateIDToken(&user, clientID, scopeStr, accessTokenExpiresAt.Unix(), "", accessToken)
			if err == nil {
				response["id_token"] = idToken
			}
		}

		utils.WriteJSONResponse(w, http.StatusOK, response)
	}
}

// verifyPKCE validates a PKCE code_verifier against the stored code_challenge.
// OAuth 2.1 mandates S256 only.
func verifyPKCE(verifier, challenge, method string) bool {
	if method != "S256" || !utils.ValidatePKCECodeVerifier(verifier) {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

// generateAuthCode creates a secure random authorization code (256 bits)
func generateAuthCode() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate auth code: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// generateToken creates a secure random token
func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

var dummyClientSecretHash = []byte("$2a$10$7EqJtq98hPqEX7fNZaFWoOe7M7Q9w2M4r7W3xS0Q2m6sP5c6Q1B3G")

// authenticateClient extracts and validates client credentials.
// Supports both form parameters and HTTP Basic Authentication (RFC 6749 §2.3.1).
// Used by token, introspect, and revoke endpoints.
func authenticateClient(r *http.Request) (*database.Client, error) {
	// Ensure form is parsed before reading form values
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("failed to parse request")
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Support HTTP Basic Authentication (RFC 6749 §2.3.1 — values are form-urlencoded)
	if clientID == "" && clientSecret == "" {
		if basicUser, basicPass, ok := r.BasicAuth(); ok {
			if unescaped, err := url.QueryUnescape(basicUser); err == nil {
				clientID = unescaped
			} else {
				clientID = basicUser
			}
			if unescaped, err := url.QueryUnescape(basicPass); err == nil {
				clientSecret = unescaped
			} else {
				clientSecret = basicPass
			}
		}
	}

	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	var client database.Client
	if err := database.DB.Where("id = ?", clientID).First(&client).Error; err != nil {
		if clientSecret != "" {
			_ = bcrypt.CompareHashAndPassword(dummyClientSecretHash, []byte(clientSecret))
		}
		return nil, fmt.Errorf("invalid client credentials")
	}

	// Authentication depends on client type (RFC 6749 §2.1):
	// - Confidential clients MUST authenticate with client_secret
	// - Public clients MUST NOT send client_secret (they use PKCE instead)
	if client.IsConfidential() {
		if clientSecret == "" {
			return nil, fmt.Errorf("client_secret required for confidential clients")
		}
		if !client.HasSecret() {
			return nil, fmt.Errorf("client secret not configured")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*client.Secret), []byte(clientSecret)); err != nil {
			return nil, fmt.Errorf("invalid client credentials")
		}
	} else if client.IsPublic() {
		if clientSecret != "" {
			return nil, fmt.Errorf("public clients must not send client_secret")
		}
	}

	return &client, nil
}

// OAuthIntrospectHandler handles token introspection requests (RFC 7662).
func OAuthIntrospectHandler(w http.ResponseWriter, r *http.Request) {
	// Introspection responses MUST NOT be cached
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	client, err := authenticateClient(r)
	if err != nil {
		if _, _, hasBasic := r.BasicAuth(); hasBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="Gilos Auth"`)
		}
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": err.Error()})
		return
	}

	token := r.FormValue("token")
	if token == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "token is required"})
		return
	}

	hashedToken := utils.HashToken(token)

	var session database.Session
	// Search for active tokens belonging to this client
	if err := database.DB.Where("(access_token = ? OR refresh_token = ?) AND type = ? AND client_id = ?", hashedToken, hashedToken, "client", client.ID).First(&session).Error; err != nil {
		// RFC 7662: If token is not found or invalid, return active: false
		utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"active": false})
		return
	}

	// Verify owning user still exists and is not suspended
	if session.UserID != nil {
		var user database.User
		if err := database.DB.First(&user, *session.UserID).Error; err != nil || user.Status == "suspended" {
			utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"active": false})
			return
		}
	}

	// Check expiration
	isAccess := session.AccessToken != nil && *session.AccessToken == hashedToken
	expTime := session.ExpiresAt
	if isAccess && session.AccessTokenExpiresAt != nil {
		expTime = *session.AccessTokenExpiresAt
	}

	if time.Now().After(expTime) {
		utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"active": false})
		return
	}

	scopes := ""
	if session.Scopes != nil {
		scopes = *session.Scopes
	}

	// RFC 7662 §2.2 — Introspection Response
	response := map[string]interface{}{
		"active":    true,
		"client_id": fmt.Sprint(*session.ClientID),
		"exp":       expTime.Unix(),
		"iat":       session.CreatedAt.Unix(),
	}
	if isAccess {
		response["token_type"] = "Bearer"
	} else {
		response["token_type"] = "refresh_token"
	}
	if session.UserID != nil {
		response["sub"] = fmt.Sprint(*session.UserID)
	}
	if scopes != "" {
		response["scope"] = strings.ReplaceAll(scopes, ",", " ")
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// OAuthRevokeHandler handles token revocation requests (RFC 7009).
func OAuthRevokeHandler(w http.ResponseWriter, r *http.Request) {
	// Revocation responses MUST NOT be cached
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	client, err := authenticateClient(r)
	if err != nil {
		if _, _, hasBasic := r.BasicAuth(); hasBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="Gilos Auth"`)
		}
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	token := r.FormValue("token")
	if token == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "token is required"})
		return
	}

	tokenTypeHint := r.FormValue("token_type_hint")
	hashedToken := utils.HashToken(token)

	// RFC 7009 §2.1: token_type_hint can optimize lookup, but fallback to checking both.
	// Revoking either access or refresh token revokes the entire grant.
	switch tokenTypeHint {
	case "access_token":
		result := database.DB.Where("access_token = ? AND type = ? AND client_id = ?", hashedToken, "client", client.ID).Delete(&database.Session{})
		if result.RowsAffected == 0 {
			database.DB.Where("(refresh_token = ? OR previous_refresh_token = ?) AND type = ? AND client_id = ?", hashedToken, hashedToken, "client", client.ID).Delete(&database.Session{})
		}
	case "refresh_token":
		result := database.DB.Where("(refresh_token = ? OR previous_refresh_token = ?) AND type = ? AND client_id = ?", hashedToken, hashedToken, "client", client.ID).Delete(&database.Session{})
		if result.RowsAffected == 0 {
			database.DB.Where("access_token = ? AND type = ? AND client_id = ?", hashedToken, "client", client.ID).Delete(&database.Session{})
		}
	default:
		database.DB.Where("(access_token = ? OR refresh_token = ? OR previous_refresh_token = ?) AND type = ? AND client_id = ?", hashedToken, hashedToken, hashedToken, "client", client.ID).Delete(&database.Session{})
	}

	// RFC 7009 §2.2: Always return 200 OK
	w.WriteHeader(http.StatusOK)
}
