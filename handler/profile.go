package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gilosauth/config"
	"gilosauth/database"
	"gilosauth/middleware"
	"gilosauth/utils"
	"image/png"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// RequirePassword verifies the user's current password from the X-Current-Password header.
// Returns true if verified, false if not (and writes the error response).
// Tracks failed attempts: 3 failures → 24-hour security block.
func RequirePassword(w http.ResponseWriter, r *http.Request, userID uint64) bool {
	password := r.Header.Get("X-Current-Password")
	if password == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "password_required"})
		return false
	}

	// Check if the user is security-blocked
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         "account_blocked",
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return false
	}

	// Fetch user
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve user"})
		return false
	}

	// Get session for attempt tracking
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return false
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		// Track failed attempts
		attempts, _ := database.SM.GetData(sess, "password_verify_attempts")
		attemptCount := 0
		if attempts != nil {
			if count, ok := attempts.(float64); ok {
				attemptCount = int(count)
			}
		}
		attemptCount++

		if attemptCount >= 3 {
			database.SM.ApplyBlock(fmt.Sprintf("user:%d:security", userID), sess, 24*time.Hour, "security")
			database.SM.DeleteData(sess, "password_verify_attempts")
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]interface{}{
				"error":              "max_attempts_reached",
				"attempts_remaining": 0,
			})
			return false
		}

		database.SM.SetData(sess, "password_verify_attempts", attemptCount)
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]interface{}{
			"error":              "incorrect_password",
			"attempts_remaining": 3 - attemptCount,
		})
		return false
	}

	// Success — clear attempt counter
	database.SM.DeleteData(sess, "password_verify_attempts")
	return true
}

// ProfileHandler returns JSON with the user's profile data.
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
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

	// Fetch user data
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	response := map[string]interface{}{
		"id":                user.ID,
		"username":          user.Username,
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"middle_name":       user.MiddleName,
		"nickname":          user.Nickname,
		"email":             user.Email,
		"phone":             user.Phone,
		"phone_raw":         utils.FormatPhone(user.Phone),
		"icon":              user.Icon,
		"status":            user.Status,
		"mfa_email_enabled": user.MFAEmailEnabled,
		"mfa_phone_enabled": user.MFAPhoneEnabled,
		"mfa_totp_enabled":  user.MFATOTPEnabled,
		"created_at":        user.CreatedAt,
		"updated_at":        user.UpdatedAt,
	}

	// Count username changes in last 30 days
	var usernameChanges int64
	database.DB.Model(&database.UsernameChangeLog{}).Where("user_id = ? AND created_at > ?", user.ID, time.Now().Add(-30*24*time.Hour)).Count(&usernameChanges)
	response["username_changes_count"] = usernameChanges

	// Include deletion status if pending
	if delReq, err := database.GetActiveDeletionRequest(user.ID); err == nil && delReq != nil {
		response["deletion_pending"] = true
		response["deletion_scheduled_at"] = delReq.ScheduledAt.Format(time.RFC3339)
		response["deletion_days_remaining"] = delReq.DaysRemaining()
	} else {
		response["deletion_pending"] = false
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// NamesUpdateHandler updates the user's names.
func NamesUpdateHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := r.ParseForm(); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "failed to parse form"})
		return
	}

	// Fetch user
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	user.FirstName = strings.TrimSpace(r.Form.Get("first_name"))
	user.LastName = strings.TrimSpace(r.Form.Get("last_name"))
	user.MiddleName = strings.TrimSpace(r.Form.Get("middle_name"))
	user.Nickname = strings.TrimSpace(r.Form.Get("nickname"))

	if user.FirstName == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "first name is required"})
		return
	}

	// Enforce length limits (GORM size tags don't enforce at SQLite level)
	if len(user.FirstName) > 50 || len(user.LastName) > 50 || len(user.MiddleName) > 50 || len(user.Nickname) > 50 {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "names must be at most 50 characters"})
		return
	}

	if err := database.DB.Save(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update names"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}

// UsernameCheckHandler checks if a username is available.
func UsernameCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}

	cleaned, err := utils.ValidateUsername(username)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{"available": false, "error": err.Error()})
		return
	}

	var user database.User
	if err := database.DB.Where("username = ?", cleaned).First(&user).Error; err == nil {
		utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{"available": false, "error": fmt.Sprintf("%s is already taken", config.AppIDLabel)})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{"available": true})
}

// UsernameUpdateHandler updates the user's username.
func UsernameUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Require password confirmation for username changes
	if !RequirePassword(w, r, userID) {
		return
	}

	var input struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	cleaned, err := utils.ValidateUsername(input.Username)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Start session for block management
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return
	}

	// Check if UserID is blocked
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:username", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked from changing %s until %s", config.AppIDLabel, until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	if user.Username == cleaned {
		utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
		return
	}

	// Count changes in last 30 days
	var count int64
	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)
	database.DB.Model(&database.UsernameChangeLog{}).Where("user_id = ? AND created_at > ?", userID, thirtyDaysAgo).Count(&count)

	if count >= 3 {
		database.SM.ApplyBlock(fmt.Sprintf("user:%d:username", userID), sess, 30*24*time.Hour, "username")
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("you can only change your %s 3 times in 30 days. you are now blocked for the next 30 days.", config.AppIDLabel),
			"is_blocked":    true,
			"blocked_until": time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		})
		return
	}

	var existingUser database.User
	if err := database.DB.Where("username = ?", cleaned).First(&existingUser).Error; err == nil {
		utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("%s is already taken", config.AppIDLabel)})
		return
	}

	oldUsername := user.Username
	if err := database.DB.Model(&user).Update("username", cleaned).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to update %s", config.AppIDLabel)})
		return
	}

	// Log the change
	database.DB.Create(&database.UsernameChangeLog{
		UserID:      userID,
		OldUsername: oldUsername,
		NewUsername: cleaned,
	})

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}

// PasswordUpdateHandler updates the user's password and hint.
func PasswordUpdateHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := r.ParseForm(); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "failed to parse form"})
		return
	}

	// Fetch user
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	password := r.Form.Get("password")
	confirm := r.Form.Get("confirm_password")

	if password != "" {
		// Require current password for password changes — uses centralized
		// RequirePassword which includes brute-force protection (3 attempts → 24h block)
		if !RequirePassword(w, r, userID) {
			return
		}

		// Validate new password
		if err := utils.ValidatePassword(password); err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if password != confirm {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "passwords do not match"})
			return
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(password), config.BcryptCost)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
			return
		}
		user.Password = string(hashed)
	}


	if err := database.DB.Save(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update password"})
		return
	}

	if password != "" {
		database.LogAuditEventWithUserID(database.AuditPasswordChanged, userID, r, "password changed via profile")
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}

// ProfileContactUpdateHandler updates the user's contact info and MFA settings.
func ProfileContactUpdateHandler(w http.ResponseWriter, r *http.Request) {
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

	// Require password confirmation for contact/MFA changes
	if !RequirePassword(w, r, userID) {
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "failed to parse form"})
		return
	}

	// Fetch user
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	// Fetch current session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to get session"})
		return
	}

	// Check if user is blocked by ID
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:username", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	// Check if user is blocked by ID
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", user.ID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	email := strings.TrimSpace(r.Form.Get("email"))
	phoneStr := strings.TrimSpace(r.Form.Get("phone"))
	mfaEmail := r.Form.Get("mfa_email_enabled") == "on"
	mfaPhone := r.Form.Get("mfa_phone_enabled") == "on"

	if email != user.Email && email != "" {
		if blocked, until := database.SM.IsBlocked(email); blocked {
			utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":         "this email is temporarily blocked for security, please try again in 24 hours",
				"is_blocked":    true,
				"blocked_until": until.Format(time.RFC3339),
			})
			return
		}
	}

	if phoneStr != "" {
		cleanedPhone, _, err := utils.ValidateContact(phoneStr)
		if err == nil {
			if blocked, until := database.SM.IsBlocked(cleanedPhone); blocked {
				utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":         "this phone number is temporarily blocked for security, please try again in 24 hours",
					"is_blocked":    true,
					"blocked_until": until.Format(time.RFC3339),
				})
				return
			}
		}
	}

	oldEmail := user.Email
	oldPhone := user.Phone
	verificationNeeded := []string{}
	masked := make(map[string]string)

	// Handle email
	if email != oldEmail {
		if email == "" {
			// Unlink email immediately
			user.Email = ""
			user.MFAEmailEnabled = false
			clearProfileData(sess, "email")
		} else {
			if _, _, err := utils.ValidateContact(email); err != nil {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid email"})
				return
			}
			var existing database.User
			if err := database.DB.Where("email = ? AND id != ?", email, userID).First(&existing).Error; err == nil {
				utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "email already in use"})
				return
			}
			// Store pending email and MFA, send OTP
			otp := utils.GenerateOTP()
			database.SM.SetData(sess, "profile_pending_email", email)
			database.SM.SetData(sess, "profile_pending_mfa_email_enabled", mfaEmail)
			database.SM.SetData(sess, "profile_otp_email", utils.HashToken(otp))
			database.SM.SetData(sess, "profile_attempts_email", 0)
			database.SM.SetData(sess, "profile_resends_email", 0)
			if err := utils.SendVerificationEmail(email, otp); err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to send OTP email"})
				return
			}
			verificationNeeded = append(verificationNeeded, "email")
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				masked["email"] = parts[0][:int(math.Min(2, float64(len(parts[0]))))] + "...@" + parts[1]
			}
		}
	} else {
		// No change, update MFA
		user.MFAEmailEnabled = mfaEmail && user.Email != ""
	}

	// Handle phone
	var newPhone uint64
	if phoneStr != "" {
		newPhone, err = utils.ParsePhone(phoneStr)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid phone number"})
			return
		}
	}

	if newPhone != oldPhone || (phoneStr == "" && oldPhone != 0) {
		if phoneStr == "" {
			// Unlink phone immediately
			user.Phone = 0
			user.MFAPhoneEnabled = false
			clearProfileData(sess, "phone")
		} else {
			var existing database.User
			if err := database.DB.Where("phone = ? AND id != ?", newPhone, userID).First(&existing).Error; err == nil {
				utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "phone already in use"})
				return
			}
			// Store pending phone and MFA, send OTP
			otp := utils.GenerateOTP()
			database.SM.SetData(sess, "profile_pending_phone", newPhone)
			database.SM.SetData(sess, "profile_pending_mfa_phone_enabled", mfaPhone)
			database.SM.SetData(sess, "profile_otp_phone", utils.HashToken(otp))
			database.SM.SetData(sess, "profile_attempts_phone", 0)
			database.SM.SetData(sess, "profile_resends_phone", 0)
			if err := utils.SendPhoneOTP(phoneStr, otp); err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			verificationNeeded = append(verificationNeeded, "phone")
			masked["phone"] = utils.MaskPhone(newPhone)
		}
	} else {
		// No change, update MFA
		user.MFAPhoneEnabled = mfaPhone && user.Phone != 0
	}

	// Save user for non-pending changes
	if err := database.DB.Save(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update contact info"})
		return
	}

	response := map[string]interface{}{"success": true}
	if len(verificationNeeded) > 0 {
		response["verification_needed"] = verificationNeeded
		response["masked"] = masked
	}
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// ProfileContactPendingHandler returns pending verification info.
func ProfileContactPendingHandler(w http.ResponseWriter, r *http.Request) {
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

	// Fetch current session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to get session"})
		return
	}

	// Check if user is blocked by ID
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:username", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	pending := []string{}
	masked := make(map[string]string)
	attempts := make(map[string]int)
	resends := make(map[string]int)

	// Check email pending
	if pendingEmail, exists := database.SM.GetData(sess, "profile_pending_email"); exists {
		pending = append(pending, "email")
		email := fmt.Sprint(pendingEmail)
		if email != "" {
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				masked["email"] = parts[0][:int(math.Min(2, float64(len(parts[0]))))] + "...@" + parts[1]
			}
		} else {
			masked["email"] = ""
		}
		if att, exists := database.SM.GetData(sess, "profile_attempts_email"); exists {
			if count, ok := att.(float64); ok {
				attempts["email"] = int(count)
			}
		}
		if res, exists := database.SM.GetData(sess, "profile_resends_email"); exists {
			if count, ok := res.(float64); ok {
				resends["email"] = int(count)
			}
		}
	}

	// Check phone pending
	if pendingPhone, exists := database.SM.GetData(sess, "profile_pending_phone"); exists {
		pending = append(pending, "phone")
		var val uint64
		switch v := pendingPhone.(type) {
		case float64:
			val = uint64(math.Round(v))
		case uint64:
			val = v
		case string:
			val, _ = utils.ParsePhone(v)
		}
		if val != 0 {
			masked["phone"] = utils.MaskPhone(val)
		} else {
			masked["phone"] = ""
		}
		if att, exists := database.SM.GetData(sess, "profile_attempts_phone"); exists {
			if count, ok := att.(float64); ok {
				attempts["phone"] = int(count)
			}
		}
		if res, exists := database.SM.GetData(sess, "profile_resends_phone"); exists {
			if count, ok := res.(float64); ok {
				resends["phone"] = int(count)
			}
		}
	}

	blocks := make(map[string]interface{})
	if val, exists := database.SM.GetData(sess, "is_blocked"); exists {
		if isBlocked, ok := val.(bool); ok && isBlocked {
			blocks["is_blocked"] = true
			if until, ok := database.SM.GetData(sess, "blocked_until"); ok {
				blocks["blocked_until"] = until
			}
		}
	}

	// Check identifier specific blocks for pending contacts
	for _, typ := range pending {
		if typ == "email" {
			// Actually we should check the REAL pending identifier from session
			if realEmail, exists := database.SM.GetData(sess, "profile_pending_email"); exists {
				if blocked, until := database.SM.IsBlocked(fmt.Sprint(realEmail)); blocked {
					blocks["email"] = map[string]interface{}{
						"is_blocked":    true,
						"blocked_until": until.Format(time.RFC3339),
					}
				}
			}
		} else if typ == "phone" {
			if realPhone, exists := database.SM.GetData(sess, "profile_pending_phone"); exists {
				if blocked, until := database.SM.IsBlocked(fmt.Sprint(realPhone)); blocked {
					blocks["phone"] = map[string]interface{}{
						"is_blocked":    true,
						"blocked_until": until.Format(time.RFC3339),
					}
				}
			}
		}
	}

	response := map[string]interface{}{
		"pending":  pending,
		"masked":   masked,
		"attempts": attempts,
		"resends":  resends,
		"blocks":   blocks,
	}
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// ProfileContactResendHandler resends OTP for a specific type.
func ProfileContactResendHandler(w http.ResponseWriter, r *http.Request) {
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

	typ := r.URL.Query().Get("type")
	if typ != "email" && typ != "phone" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid type"})
		return
	}

	// Fetch current session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to get session"})
		return
	}

	// Check if user is blocked by ID
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:username", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	pendingKey := fmt.Sprintf("profile_pending_%s", typ)
	otpKey := fmt.Sprintf("profile_otp_%s", typ)
	attemptsKey := fmt.Sprintf("profile_attempts_%s", typ)
	resendsKey := fmt.Sprintf("profile_resends_%s", typ)

	pending, exists := database.SM.GetData(sess, pendingKey)
	if !exists {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no pending verification for " + typ})
		return
	}

	resends, _ := database.SM.GetData(sess, resendsKey)
	resendCount := 0
	if count, ok := resends.(float64); ok {
		resendCount = int(count)
	}
	resendCount++
	if resendCount > 3 {
		database.SM.ApplyBlock(fmt.Sprint(pending), sess, 24*time.Hour, "security")
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         "maximum resend attempts reached, blocked for 24 hours",
			"is_blocked":    true,
			"blocked_until": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		return
	}

	otp := utils.GenerateOTP()
	database.SM.SetData(sess, otpKey, utils.HashToken(otp))
	database.SM.SetData(sess, attemptsKey, 0)
	database.SM.SetData(sess, resendsKey, resendCount)

	contact := fmt.Sprint(pending)
	if typ == "email" {
		if contact != "" {
			if err := utils.SendVerificationEmail(contact, otp); err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to send OTP email"})
				return
			}
		}
	} else {
		var val uint64
		switch v := pending.(type) {
		case float64:
			val = uint64(math.Round(v))
		case uint64:
			val = v
		case string:
			val, _ = utils.ParsePhone(v)
		}
		if val != 0 {
			if err := utils.SendPhoneOTP(utils.FormatPhone(val), otp); err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{"success": true, "resends": resendCount})
}

// ProfileContactVerifyHandler verifies OTPs and updates if correct.
func ProfileContactVerifyHandler(w http.ResponseWriter, r *http.Request) {
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

	var input struct {
		EmailOTP string `json:"email_otp"`
		PhoneOTP string `json:"phone_otp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Fetch user
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	// Fetch current session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to get session"})
		return
	}

	// Check if user is blocked by ID
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:username", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	results := make(map[string]interface{})

	// Verify email if OTP provided
	if input.EmailOTP != "" {
		pendingEmail, exists := database.SM.GetData(sess, "profile_pending_email")
		if !exists {
			results["email"] = map[string]interface{}{"success": false, "error": "no pending email verification"}
		} else {
			storedOTP, _ := database.SM.GetData(sess, "profile_otp_email")
			attempts, _ := database.SM.GetData(sess, "profile_attempts_email")
			attemptCount := 0
			if count, ok := attempts.(float64); ok {
				attemptCount = int(count)
			}
			attemptCount++
			database.SM.SetData(sess, "profile_attempts_email", attemptCount)
			if attemptCount > 3 {
				database.SM.ApplyBlock(fmt.Sprint(pendingEmail), sess, 24*time.Hour, "security")
				results["email"] = map[string]interface{}{
					"success":       false,
					"error":         "maximum attempts reached, blocked for 24 hours",
					"is_blocked":    true,
					"blocked_until": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
			} else if utils.ConstantTimeOTPCompare(fmt.Sprint(storedOTP), utils.HashToken(input.EmailOTP)) {
				email := fmt.Sprint(pendingEmail)
				mfa, _ := database.SM.GetData(sess, "profile_pending_mfa_email_enabled")
				mfaEmail := false
				if val, ok := mfa.(bool); ok {
					mfaEmail = val
				}
				user.Email = email
				user.MFAEmailEnabled = mfaEmail && email != ""
				clearProfileData(sess, "email")
				results["email"] = map[string]interface{}{"success": true}
			} else {
				attemptsLeft := 3 - attemptCount
				results["email"] = map[string]interface{}{"success": false, "error": fmt.Sprintf("invalid OTP, %d attempt%s left", attemptsLeft, utils.Pluralize(attemptsLeft))}
			}
		}
	}

	// Verify phone if OTP provided
	if input.PhoneOTP != "" {
		pendingPhone, exists := database.SM.GetData(sess, "profile_pending_phone")
		if !exists {
			results["phone"] = map[string]interface{}{"success": false, "error": "no pending phone verification"}
		} else {
			storedOTP, _ := database.SM.GetData(sess, "profile_otp_phone")
			attempts, _ := database.SM.GetData(sess, "profile_attempts_phone")
			attemptCount := 0
			if count, ok := attempts.(float64); ok {
				attemptCount = int(count)
			}
			attemptCount++
			database.SM.SetData(sess, "profile_attempts_phone", attemptCount)
			if attemptCount > 3 {
				database.SM.ApplyBlock(fmt.Sprint(pendingPhone), sess, 24*time.Hour, "security")
				results["phone"] = map[string]interface{}{
					"success":       false,
					"error":         "maximum attempts reached, blocked for 24 hours",
					"is_blocked":    true,
					"blocked_until": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
			} else if utils.ConstantTimeOTPCompare(fmt.Sprint(storedOTP), utils.HashToken(input.PhoneOTP)) {
				var phone uint64
				switch v := pendingPhone.(type) {
				case float64:
					phone = uint64(math.Round(v))
				case uint64:
					phone = v
				case string:
					phone, _ = utils.ParsePhone(v)
				}
				mfa, _ := database.SM.GetData(sess, "profile_pending_mfa_phone_enabled")
				mfaPhone := false
				if val, ok := mfa.(bool); ok {
					mfaPhone = val
				}
				user.Phone = phone
				user.MFAPhoneEnabled = mfaPhone && phone != 0
				clearProfileData(sess, "phone")
				results["phone"] = map[string]interface{}{"success": true}
			} else {
				attemptsLeft := 3 - attemptCount
				results["phone"] = map[string]interface{}{"success": false, "error": fmt.Sprintf("invalid OTP, %d attempt%s left", attemptsLeft, utils.Pluralize(attemptsLeft))}
			}
		}
	}

	// Save user if any updates
	if err := database.DB.Save(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update contact info"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, results)
}

// ProfileContactCancelHandler cancels pending verification for type(s).
func ProfileContactCancelHandler(w http.ResponseWriter, r *http.Request) {
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

	typ := r.URL.Query().Get("type")
	if typ == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "type required"})
		return
	}

	// Fetch current session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to get session"})
		return
	}

	// Check if user is blocked by ID
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}
	if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:username", userID)); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	types := strings.Split(typ, ",")
	for _, t := range types {
		if t == "email" || t == "phone" {
			clearProfileData(sess, t)
		}
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}

func clearProfileData(sess *database.Session, typ string) {
	keys := []string{"pending_" + typ, "pending_mfa_" + typ, "otp_" + typ, "attempts_" + typ, "resends_" + typ}
	for _, key := range keys {
		database.SM.DeleteData(sess, "profile_"+key)
	}
}

// DeleteAccountHandler initiates a 30-day account deletion request.
// The account enters "pending_deletion" status and will be automatically
// purged after the grace period unless the user cancels.
func DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
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

	// Require password confirmation for account deletion
	if !RequirePassword(w, r, userID) {
		return
	}

	// Parse request body for reason
	var input struct {
		Reason       string `json:"reason"`
		CustomReason string `json:"custom_reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Validate reason
	if !database.IsValidDeletionReason(input.Reason) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_reason"})
		return
	}

	// If reason is "other", require a custom reason
	customReason := strings.TrimSpace(input.CustomReason)
	if input.Reason == database.DeletionReasonOther && customReason == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "custom_reason_required"})
		return
	}
	if len(customReason) > 500 {
		customReason = customReason[:500]
	}

	// Create deletion request
	req, err := database.CreateDeletionRequest(userID, input.Reason, customReason)
	if err != nil {
		if err.Error() == "deletion_already_pending" {
			utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "deletion_already_pending"})
			return
		}
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to create deletion request"})
		return
	}

	// Log audit event
	var user database.User
	if err := database.DB.First(&user, userID).Error; err == nil {
		database.LogAuditEventWithUserID(database.AuditAccountDeletionRequested, userID, r,
			fmt.Sprintf("account deletion requested by %s (reason: %s)", user.Username, input.Reason))
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"scheduled_at":   req.ScheduledAt.Format(time.RFC3339),
		"days_remaining": req.DaysRemaining(),
	})
}

// CancelDeletionHandler cancels a pending account deletion request.
func CancelDeletionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Require password confirmation
	if !RequirePassword(w, r, userID) {
		return
	}

	if err := database.CancelDeletionRequest(userID); err != nil {
		if err.Error() == "no_pending_deletion" {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no_pending_deletion"})
			return
		}
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to cancel deletion"})
		return
	}

	database.LogAuditEventWithUserID(database.AuditAccountDeletionCancelled, userID, r, "account deletion cancelled by user")

	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{"success": true})
}

// DeletionStatusHandler returns the current deletion request status for the user.
func DeletionStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	req, err := database.GetActiveDeletionRequest(userID)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to check deletion status"})
		return
	}

	if req == nil {
		utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{"pending": false})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{
		"pending":        true,
		"scheduled_at":   req.ScheduledAt.Format(time.RFC3339),
		"days_remaining": req.DaysRemaining(),
		"reason":         req.Reason,
		"custom_reason":  req.CustomReason,
		"created_at":     req.CreatedAt.Format(time.RFC3339),
	})
}

// IconUpdateHandler handles user icon uploads.
func IconUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Max 100KB
	r.Body = http.MaxBytesReader(w, r.Body, 100*1024)
	if err := r.ParseMultipartForm(100 * 1024); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "file too large (max 100KB)"})
		return
	}

	file, _, err := r.FormFile("icon")
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no file uploaded"})
		return
	}
	defer file.Close()

	// Validate JPG
	buff := make([]byte, 512)
	if _, err := file.Read(buff); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to read file"})
		return
	}
	if http.DetectContentType(buff) != "image/jpeg" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "only JPG images are allowed"})
		return
	}

	// Seek back to start
	if _, err := file.Seek(0, 0); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to seek file"})
		return
	}

	// Create directory if not exists
	iconDir := "./media/user/icon/"
	if err := os.MkdirAll(iconDir, 0755); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to create storage directory"})
		return
	}

	// Clean up old icons for this user
	pattern := filepath.Join(iconDir, fmt.Sprintf("%d_*.jpg", userID))
	oldFiles, _ := filepath.Glob(pattern)
	for _, oldFile := range oldFiles {
		os.Remove(oldFile)
	}
	// Also check for the legacy {userID}.jpg if it exists
	os.Remove(filepath.Join(iconDir, fmt.Sprintf("%d.jpg", userID)))

	filename := fmt.Sprintf("%d_%d.jpg", userID, time.Now().Unix())
	filepath := filepath.Join(iconDir, filename)

	out, err := os.Create(filepath)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to create file on disk"})
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to save file"})
		return
	}

	// Update user record
	iconURL := "/media/user/icon/" + filename
	if err := database.DB.Model(&database.User{}).Where("id = ?", userID).Update("icon", iconURL).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update user icon path"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{"success": true, "icon_url": iconURL})
}

// TOTPGenerateHandler generates a provisional TOTP secret and returns QR code as base64.
func TOTPGenerateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve user"})
		return
	}

	cookie, err := r.Cookie("session_token")
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "session cookie required"})
		return
	}

	var sess database.Session
	if err := database.DB.Where("cookie_token = ?", cookie.Value).First(&sess).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve session"})
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      config.AppIDLabel,
		AccountName: user.Username,
	})
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate TOTP secret"})
		return
	}

	rawData := sess.RawData
	if rawData == nil {
		rawData = make(database.JSONData)
	}
	rawData["provisional_totp_secret"] = key.Secret()
	if err := database.DB.Model(&sess).Update("raw_data", rawData).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store provisional secret"})
		return
	}

	qrCode, err := qr.Encode(key.URL(), qr.M, qr.Auto)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate QR code"})
		return
	}
	qrCode, err = barcode.Scale(qrCode, 256, 256)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to scale QR code"})
		return
	}

	buffer := new(bytes.Buffer)
	if err := png.Encode(buffer, qrCode); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to encode QR image"})
		return
	}

	qrBase64 := base64.StdEncoding.EncodeToString(buffer.Bytes())

	response := map[string]string{
		"secret":    key.Secret(),
		"url":       key.URL(),
		"qr_base64": qrBase64,
	}
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// TOTPVerifyHandler verifies the TOTP code against the provisional secret and enables MFA if valid.
func TOTPVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var input struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if input.Code == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "code is required"})
		return
	}

	cookie, err := r.Cookie("session_token")
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "session cookie required"})
		return
	}

	var sess database.Session
	if err := database.DB.Where("cookie_token = ?", cookie.Value).First(&sess).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve session"})
		return
	}

	rawData := sess.RawData
	provisional, ok := rawData["provisional_totp_secret"].(string)
	if !ok {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no TOTP setup in progress"})
		return
	}

	if !totp.Validate(input.Code, provisional) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid code"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve user"})
		return
	}

	user.MFATOTPEnabled = true
	user.TOTPSecret = provisional
	if err := database.DB.Save(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to enable TOTP MFA"})
		return
	}

	delete(rawData, "provisional_totp_secret")
	if err := database.DB.Model(&sess).Update("raw_data", rawData).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear provisional secret"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}

// TOTPDisableHandler disables TOTP MFA for the user.
func TOTPDisableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Require password confirmation for TOTP disable
	if !RequirePassword(w, r, userID) {
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve user"})
		return
	}

	user.MFATOTPEnabled = false
	user.TOTPSecret = ""
	if err := database.DB.Save(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to disable TOTP MFA"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}
