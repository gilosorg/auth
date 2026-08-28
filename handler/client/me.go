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
	scopes := strings.Split(scopeList, ",")
	scopeMap := make(map[string]bool)
	for _, s := range scopes {
		scopeMap[strings.TrimSpace(s)] = true
	}

	// Basic info (requires user_basic_info, which is checked by middleware but we include fields here)
	response := map[string]interface{}{
		"id":                user.ID,
		"username":          user.Username,
		"icon":              user.Icon,
		"status":            user.Status,
		"mfa_email_enabled": user.MFAEmailEnabled,
		"mfa_phone_enabled": user.MFAPhoneEnabled,
		"mfa_totp_enabled":  user.MFATOTPEnabled,
	}

	// Optional granular scopes
	if scopeMap["user_first_name"] {
		response["first_name"] = user.FirstName
	}
	if scopeMap["user_last_name"] {
		response["last_name"] = user.LastName
	}
	if scopeMap["user_middle_name"] {
		response["middle_name"] = user.MiddleName
	}
	if scopeMap["user_nickname"] {
		response["nickname"] = user.Nickname
	}
	if scopeMap["user_email"] && user.Email != "" {
		response["email"] = user.Email
	}
	if scopeMap["user_phone"] && user.Phone != 0 {
		response["phone"] = user.Phone
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}
