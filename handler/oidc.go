package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gilosauth/config"
	"gilosauth/database"
	"gilosauth/middleware"
	"gilosauth/utils"
)

// OIDCDiscoveryHandler serves the /.well-known/openid-configuration metadata (RFC 8414 / OIDC Discovery).
func OIDCDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	issuer := config.IssuerURL

	response := map[string]interface{}{
		"issuer":                                          issuer,
		"authorization_endpoint":                          issuer + "/o/authorize",
		"token_endpoint":                                  issuer + "/o/token",
		"introspection_endpoint":                          issuer + "/o/introspect",
		"revocation_endpoint":                             issuer + "/o/revoke",
		"userinfo_endpoint":                               issuer + "/api/userinfo",
		"jwks_uri":                                        issuer + "/.well-known/jwks.json",
		"service_documentation":                           issuer + "/docs",
		"response_types_supported":                        []string{"code"},
		"response_modes_supported":                        []string{"query"},
		"grant_types_supported":                           []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":                []string{"S256"},
		"token_endpoint_auth_methods_supported":           []string{"client_secret_post", "client_secret_basic", "none"},
		"revocation_endpoint_auth_methods_supported":      []string{"client_secret_post", "client_secret_basic", "none"},
		"introspection_endpoint_auth_methods_supported":   []string{"client_secret_post", "client_secret_basic", "none"},
		"subject_types_supported":                         []string{"public"},
		"id_token_signing_alg_values_supported":           []string{"RS256"},
		"scopes_supported":                                middleware.Scopes,
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "nonce", "at_hash",
			"preferred_username", "given_name", "family_name",
			"middle_name", "nickname", "picture",
			"email", "email_verified",
			"phone_number", "phone_number_verified",
			"updated_at",
		},
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// JWKSHandler serves the public RSA keys for JWT verification (RFC 7517).
func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if utils.JWK == nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "keys_not_initialized"})
		return
	}

	response := map[string]interface{}{
		"keys": []map[string]interface{}{utils.JWK},
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// UserInfoHandler serves the standard OIDC userinfo endpoint.
func UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	// Middleware should have already validated the access token and set session context
	session, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok || session.UserID == nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	userID := *session.UserID
	scopesStr := ""
	if session.Scopes != nil {
		scopesStr = *session.Scopes
	}
	scopes := strings.Split(scopesStr, ",")

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}

	// Build OIDC claims based on granted scopes
	hasScope := func(s string) bool {
		for _, scope := range scopes {
			if scope == s {
				return true
			}
		}
		return false
	}

	claims := map[string]interface{}{
		"sub": fmt.Sprint(user.ID),
	}

	// Profile claims (OIDC Core §5.4)
	if hasScope("profile") || hasScope("user_basic_info") || hasScope("user_username") {
		claims["preferred_username"] = user.Username
	}
	if hasScope("profile") || hasScope("user_basic_info") || hasScope("user_first_name") {
		if user.FirstName != "" {
			claims["given_name"] = user.FirstName
		}
	}
	if hasScope("profile") || hasScope("user_basic_info") || hasScope("user_last_name") {
		if user.LastName != "" {
			claims["family_name"] = user.LastName
		}
	}
	if hasScope("profile") || hasScope("user_basic_info") || hasScope("user_middle_name") {
		if user.MiddleName != "" {
			claims["middle_name"] = user.MiddleName
		}
	}
	if hasScope("profile") || hasScope("user_basic_info") || hasScope("user_nickname") {
		if user.Nickname != "" {
			claims["nickname"] = user.Nickname
		}
	}
	if hasScope("profile") || hasScope("user_basic_info") {
		if user.Icon != "" {
			claims["picture"] = config.IssuerURL + "/" + user.Icon
		}
		claims["updated_at"] = user.UpdatedAt.Unix()
	}

	// Email claims (OIDC Core §5.4)
	if hasScope("email") || hasScope("user_email") {
		if user.Email != "" {
			claims["email"] = user.Email
			claims["email_verified"] = user.EmailVerified
		}
	}

	// Phone claims (OIDC Core §5.4) — E.164 format with + prefix
	if hasScope("phone") || hasScope("user_phone") {
		if user.Phone != 0 {
			claims["phone_number"] = fmt.Sprintf("+%d", user.Phone)
			claims["phone_number_verified"] = user.PhoneVerified
		}
	}

	utils.WriteJSONResponse(w, http.StatusOK, claims)
}

// GenerateAccessToken creates a JWT access token for the given session.
func GenerateAccessToken(session *database.Session, clientID uint64, scopes string) (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"iss":   config.IssuerURL,
		"sub":   fmt.Sprint(*session.UserID),
		"aud":   fmt.Sprint(clientID),
		"exp":   session.AccessTokenExpiresAt.Unix(),
		"iat":   now.Unix(),
		"jti":   fmt.Sprintf("sess_%d_%d", session.ID, session.AccessTokenExpiresAt.Unix()),
		"scope": scopes,
	}
	return utils.SignJWT(claims)
}

// GenerateIDToken creates an OIDC id_token for the given user.
// accessToken is used to compute the at_hash claim (OIDC Core §3.1.3.6).
func GenerateIDToken(user *database.User, clientID uint64, scopes string, exp int64, nonce string, accessToken string) (string, error) {
	claims := map[string]interface{}{
		"iss": config.IssuerURL,
		"sub": fmt.Sprint(user.ID),
		"aud": fmt.Sprint(clientID),
		"exp": exp,
		"iat": time.Now().Unix(),
	}

	// Include nonce if provided (OIDC Core §2 — mandatory echo-back)
	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Compute at_hash: left half of SHA-256 of the access token, base64url-encoded (OIDC Core §3.1.3.6)
	if accessToken != "" {
		atHash := sha256.Sum256([]byte(accessToken))
		claims["at_hash"] = base64.RawURLEncoding.EncodeToString(atHash[:16])
	}

	scopesArr := strings.Split(scopes, " ")
	hasScope := func(s string) bool {
		for _, scope := range scopesArr {
			if scope == s {
				return true
			}
		}
		return false
	}

	if hasScope("profile") || hasScope("user_basic_info") || hasScope("user_username") {
		claims["preferred_username"] = user.Username
	}
	if hasScope("profile") || hasScope("user_basic_info") || hasScope("user_first_name") {
		if user.FirstName != "" {
			claims["given_name"] = user.FirstName
		}
	}
	if hasScope("profile") || hasScope("user_basic_info") || hasScope("user_last_name") {
		if user.LastName != "" {
			claims["family_name"] = user.LastName
		}
	}
	if hasScope("email") || hasScope("user_email") {
		if user.Email != "" {
			claims["email"] = user.Email
			claims["email_verified"] = user.EmailVerified
		}
	}
	if hasScope("phone") || hasScope("user_phone") {
		if user.Phone != 0 {
			claims["phone_number"] = fmt.Sprintf("+%d", user.Phone)
			claims["phone_number_verified"] = user.PhoneVerified
		}
	}

	return utils.SignJWT(claims)
}
