package client

import (
	"gilosauth/database"
	"gilosauth/middleware"
	"gilosauth/utils"
	"net/http"
	"strings"
)

// MeHandler returns the current user's information based on authorized scopes.
func MeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// UserID verified by middleware
	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if user.Status != "active" {
		utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account_suspended"})
		return
	}

	// Get session to check granular scopes
	session, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok || session == nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "session not found"})
		return
	}

	scopeList := ""
	if session.Scopes != nil {
		scopeList = *session.Scopes
	}
	scopes := strings.FieldsFunc(scopeList, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '\n'
	})
	scopeMap := make(map[string]bool)
	for _, s := range scopes {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			scopeMap[trimmed] = true
		}
	}

	// Basic info (requires profile, which is checked by middleware)
	response := map[string]interface{}{
		"id":                user.ID,
		"username":          user.Username,
		"icon":              user.Icon,
		"status":            user.Status,
		"mfa_email_enabled": user.MFAEmailEnabled,
		"mfa_phone_enabled": user.MFAPhoneEnabled,
		"mfa_totp_enabled":  user.MFATOTPEnabled,
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"middle_name":       user.MiddleName,
		"nickname":          user.Nickname,
	}

	if scopeMap["email"] && user.Email != "" {
		response["email"] = user.Email
		response["email_verified"] = user.EmailVerified
	}
	if scopeMap["phone"] && user.Phone != 0 {
		response["phone"] = user.Phone
		response["phone_verified"] = user.PhoneVerified
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}
