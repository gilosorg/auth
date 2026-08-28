package client

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



func ProfileHandler(w http.ResponseWriter, r *http.Request) {
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

func NamesUpdateHandler(w http.ResponseWriter, r *http.Request) {
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
		FirstName  string `json:"first_name"`
		LastName   string `json:"last_name"`
		MiddleName string `json:"middle_name"`
		Nickname   string `json:"nickname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	user.FirstName = strings.TrimSpace(input.FirstName)
	user.LastName = strings.TrimSpace(input.LastName)
	user.MiddleName = strings.TrimSpace(input.MiddleName)
	user.Nickname = strings.TrimSpace(input.Nickname)

	if user.FirstName == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "first name is required"})
		return
	}

	if err := database.DB.Save(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update names"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}

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

func PasswordUpdateHandler(w http.ResponseWriter, r *http.Request) {
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
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	if input.Password != "" {
		if input.Password != input.ConfirmPassword {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "passwords do not match"})
			return
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
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

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}

func ProfileContactUpdateHandler(w http.ResponseWriter, r *http.Request) {
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
		Email    string `json:"email"`
		Phone    string `json:"phone"`
		MFAEmail bool   `json:"mfa_email_enabled"`
		MFAPhone bool   `json:"mfa_phone_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	sess, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok || sess == nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "session not found"})
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

	email := strings.TrimSpace(input.Email)
	phoneStr := strings.TrimSpace(input.Phone)
	mfaEmail := input.MFAEmail
	mfaPhone := input.MFAPhone

	oldEmail := user.Email
	oldPhone := user.Phone
	verificationNeeded := []string{}
	masked := make(map[string]string)

	if email != oldEmail {
		cleanedEmail, _, err := utils.ValidateContact(input.Email)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if blocked, until := database.SM.IsBlocked(cleanedEmail); blocked {
			utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":         "this email is temporarily blocked for security, please try again in 24 hours",
				"is_blocked":    true,
				"blocked_until": until.Format(time.RFC3339),
			})
			return
		}
		if email == "" {
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
			otp := utils.GenerateOTP()
			database.SM.SetData(sess, "profile_pending_email", email)
			database.SM.SetData(sess, "profile_pending_mfa_email_enabled", mfaEmail)
			database.SM.SetData(sess, "profile_otp_email", utils.HashToken(otp))
			database.SM.SetData(sess, "profile_otp_sent_at_email", time.Now().Format(time.RFC3339))
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
		user.MFAEmailEnabled = mfaEmail && user.Email != ""
	}

	var newPhone uint64
	if phoneStr != "" {
		cleanedPhoneStr, _, err := utils.ValidateContact(phoneStr)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if blocked, until := database.SM.IsBlocked(cleanedPhoneStr); blocked {
			utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":         "this phone number is temporarily blocked for security, please try again in 24 hours",
				"is_blocked":    true,
				"blocked_until": until.Format(time.RFC3339),
			})
			return
		}

		newPhone, _ = utils.ParsePhone(cleanedPhoneStr)
		newPhone, err = utils.ParsePhone(phoneStr)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid phone number"})
			return
		}
	}

	if newPhone != oldPhone || (phoneStr == "" && oldPhone != 0) {
		if phoneStr == "" {
			user.Phone = 0
			user.MFAPhoneEnabled = false
			clearProfileData(sess, "phone")
		} else {
			var existing database.User
			if err := database.DB.Where("phone = ? AND id != ?", newPhone, userID).First(&existing).Error; err == nil {
				utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "phone already in use"})
				return
			}
			otp := utils.GenerateOTP()
			database.SM.SetData(sess, "profile_pending_phone", newPhone)
			database.SM.SetData(sess, "profile_pending_mfa_phone_enabled", mfaPhone)
			database.SM.SetData(sess, "profile_otp_phone", utils.HashToken(otp))
			database.SM.SetData(sess, "profile_otp_sent_at_phone", time.Now().Format(time.RFC3339))
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
		user.MFAPhoneEnabled = mfaPhone && user.Phone != 0
	}

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

func ProfileContactPendingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	sess, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok || sess == nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "session not found"})
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

	timeRemainingMap := make(map[string]int)
	resendAvailableMap := make(map[string]int)

	if pendingEmail, exists := database.SM.GetData(sess, "profile_pending_email"); exists {
		// Check for expiration
		sentAt, sentExists := database.SM.GetData(sess, "profile_otp_sent_at_email")
		var sentTime time.Time
		if tStr, ok := sentAt.(string); ok {
			sentTime, _ = time.Parse(time.RFC3339, tStr)
		} else if t, ok := sentAt.(time.Time); ok {
			sentTime = t
		}
		
		if !sentExists || time.Since(sentTime) > 5*time.Minute {
			clearProfileData(sess, "email")
		} else {
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

			tr := 300 - int(time.Since(sentTime).Seconds())
			if tr < 0 { tr = 0 }
			timeRemainingMap["email"] = tr
			
			ra := 60 - int(time.Since(sentTime).Seconds())
			if ra < 0 { ra = 0 }
			resendAvailableMap["email"] = ra

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
	}

	if pendingPhone, exists := database.SM.GetData(sess, "profile_pending_phone"); exists {
		// Check for expiration
		sentAt, sentExists := database.SM.GetData(sess, "profile_otp_sent_at_phone")
		var sentTime time.Time
		if tStr, ok := sentAt.(string); ok {
			sentTime, _ = time.Parse(time.RFC3339, tStr)
		} else if t, ok := sentAt.(time.Time); ok {
			sentTime = t
		}

		if !sentExists || time.Since(sentTime) > 5*time.Minute {
			clearProfileData(sess, "phone")
		} else {
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

			tr := 300 - int(time.Since(sentTime).Seconds())
			if tr < 0 { tr = 0 }
			timeRemainingMap["phone"] = tr
			
			ra := 60 - int(time.Since(sentTime).Seconds())
			if ra < 0 { ra = 0 }
			resendAvailableMap["phone"] = ra

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
	}

	blocks := make(map[string]interface{})
	if isBlocked, exists := database.SM.GetData(sess, "is_blocked"); exists {
		blocks["is_blocked"] = isBlocked
		if until, ok := database.SM.GetData(sess, "blocked_until"); ok {
			blocks["blocked_until"] = until
		}
	}

	response := map[string]interface{}{
		"pending":             pending,
		"masked":              masked,
		"attempts":            attempts,
		"resends":             resends,
		"time_remaining":      timeRemainingMap,
		"resend_available_in": resendAvailableMap,
		"blocks":              blocks,
	}
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

func ProfileContactResendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

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

	sess, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok || sess == nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "session not found"})
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
	sentAtKey := fmt.Sprintf("profile_otp_sent_at_%s", typ)

	pending, exists := database.SM.GetData(sess, pendingKey)
	if !exists {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no pending verification for " + typ})
		return
	}

	// Rate limit check
	if otpSentAt, exists := database.SM.GetData(sess, sentAtKey); exists {
		var sentTime time.Time
		if tStr, ok := otpSentAt.(string); ok {
			sentTime, _ = time.Parse(time.RFC3339, tStr)
		} else if t, ok := otpSentAt.(time.Time); ok {
			sentTime = t
		}
		if !sentTime.IsZero() && time.Since(sentTime) < 1*time.Minute {
			timeLeft := 60 - int(time.Since(sentTime).Seconds())
			utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":               fmt.Sprintf("please wait %d seconds before requesting another code", timeLeft),
				"time_remaining":      300 - int(time.Since(sentTime).Seconds()),
				"resend_available_in": timeLeft,
			})
			return
		}
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
	database.SM.SetData(sess, fmt.Sprintf("profile_otp_sent_at_%s", typ), time.Now().Format(time.RFC3339))
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

func ProfileContactVerifyHandler(w http.ResponseWriter, r *http.Request) {
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
		EmailOTP string `json:"email_otp"`
		PhoneOTP string `json:"phone_otp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve profile"})
		return
	}

	sess, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok || sess == nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "session not found"})
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
			} else {
				// Check for expiration
				sentAt, sentExists := database.SM.GetData(sess, "profile_otp_sent_at_email")
				var sentTime time.Time
				if tStr, ok := sentAt.(string); ok {
					sentTime, _ = time.Parse(time.RFC3339, tStr)
				} else if t, ok := sentAt.(time.Time); ok {
					sentTime = t
				}

				if !sentExists || time.Since(sentTime) > 5*time.Minute {
					clearProfileData(sess, "email")
					results["email"] = map[string]interface{}{"success": false, "error": "verification code expired"}
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
	}

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
			} else {
				// Check for expiration
				sentAt, sentExists := database.SM.GetData(sess, "profile_otp_sent_at_phone")
				var sentTime time.Time
				if tStr, ok := sentAt.(string); ok {
					sentTime, _ = time.Parse(time.RFC3339, tStr)
				} else if t, ok := sentAt.(time.Time); ok {
					sentTime = t
				}

				if !sentExists || time.Since(sentTime) > 5*time.Minute {
					clearProfileData(sess, "phone")
					results["phone"] = map[string]interface{}{"success": false, "error": "verification code expired"}
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
	}

	if err := database.DB.Save(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update contact info"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, results)
}

func ProfileContactCancelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

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

	sess, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok || sess == nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "session not found"})
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
	keys := []string{"pending_" + typ, "pending_mfa_" + typ, "otp_" + typ, "otp_sent_at_" + typ, "attempts_" + typ, "resends_" + typ}
	for _, key := range keys {
		database.SM.DeleteData(sess, "profile_"+key)
	}
}

// DeleteAccountHandler initiates a 30-day account deletion request via API.
func DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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

	customReason := strings.TrimSpace(input.CustomReason)
	if input.Reason == database.DeletionReasonOther && customReason == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "custom_reason_required"})
		return
	}
	if len(customReason) > 500 {
		customReason = customReason[:500]
	}

	req, err := database.CreateDeletionRequest(userID, input.Reason, customReason)
	if err != nil {
		if err.Error() == "deletion_already_pending" {
			utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "deletion_already_pending"})
			return
		}
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to create deletion request"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err == nil {
		database.LogAuditEventWithUserID(database.AuditAccountDeletionRequested, userID, r,
			fmt.Sprintf("account deletion requested via API by %s (reason: %s)", user.Username, input.Reason))
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"scheduled_at":   req.ScheduledAt.Format(time.RFC3339),
		"days_remaining": req.DaysRemaining(),
	})
}

// CancelDeletionHandler cancels a pending account deletion request via API.
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

	if err := database.CancelDeletionRequest(userID); err != nil {
		if err.Error() == "no_pending_deletion" {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no_pending_deletion"})
			return
		}
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to cancel deletion"})
		return
	}

	database.LogAuditEventWithUserID(database.AuditAccountDeletionCancelled, userID, r, "account deletion cancelled via API")

	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{"success": true})
}

// DeletionStatusHandler returns the current deletion request status via API.
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

	buff := make([]byte, 512)
	if _, err := file.Read(buff); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to read file"})
		return
	}
	if http.DetectContentType(buff) != "image/jpeg" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "only JPG images are allowed"})
		return
	}

	if _, err := file.Seek(0, 0); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to seek file"})
		return
	}

	iconDir := "./media/user/icon/"
	if err := os.MkdirAll(iconDir, 0755); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to create storage directory"})
		return
	}

	pattern := filepath.Join(iconDir, fmt.Sprintf("%d_*.jpg", userID))
	oldFiles, _ := filepath.Glob(pattern)
	for _, oldFile := range oldFiles {
		os.Remove(oldFile)
	}
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

	iconURL := "/media/user/icon/" + filename
	if err := database.DB.Model(&database.User{}).Where("id = ?", userID).Update("icon", iconURL).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update user icon path"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{"success": true, "icon_url": iconURL})
}

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

	sess, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok || sess == nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "session not found"})
		return
	}

	// Check if user is blocked by ID

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

	sess, ok := r.Context().Value(database.SessionContextKey).(*database.Session)
	if !ok || sess == nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "session not found"})
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

	response := map[string]interface{}{
		"success": true,
		"uuid":    fmt.Sprintf("%d", sess.ID),
		"secret":  provisional,
		"data": map[string]interface{}{
			"success": true,
		},
	}
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

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
