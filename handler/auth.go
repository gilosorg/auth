// auth.go

package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gilosauth/config"
	"gilosauth/database"
	"gilosauth/i18n"
	"gilosauth/utils"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// updateSessionCookie updates the session cookie's expiration to match the session's ExpiresAt.
func updateSessionCookie(w http.ResponseWriter, session *database.Session) {
	if session.Type == "native" && session.CookieToken != nil {
		database.SetSessionCookieHelper(w, *session.CookieToken, session.ExpiresAt)
	}
}

// getAuthStateResponse constructs the response with current state and user data.
func getAuthStateResponse(sess *database.Session, user *database.User, successMessage string, step string) map[string]interface{} {
	response := map[string]interface{}{
		"success":         true,
		"step":            step,
		"success_message": successMessage,
	}

	// Populate session data
	if username, exists := database.SM.GetData(sess, "username"); exists {
		response["username"] = username
	}
	if firstName, exists := database.SM.GetData(sess, "first_name"); exists {
		response["first_name"] = firstName
	}
	if lastName, exists := database.SM.GetData(sess, "last_name"); exists {
		response["last_name"] = lastName
	}
	if contact, exists := database.SM.GetData(sess, "contact"); exists {
		response["contact"] = contact
	}
	if contactType, exists := database.SM.GetData(sess, "contact_type"); exists {
		response["contact_type"] = contactType
	}
	if attempts, exists := database.SM.GetData(sess, "attempts"); exists {
		response["attempts"] = attempts
	}
	if resends, exists := database.SM.GetData(sess, "resends"); exists {
		response["resends"] = resends
	}

	if otpSentAt, exists := database.SM.GetData(sess, "otp_sent_at"); exists {
		var sentTime time.Time
		if tStr, ok := otpSentAt.(string); ok {
			sentTime, _ = time.Parse(time.RFC3339, tStr)
		} else if t, ok := otpSentAt.(time.Time); ok {
			sentTime = t
		}
		if !sentTime.IsZero() {
			timeRemaining := 300 - int(time.Since(sentTime).Seconds())
			if timeRemaining < 0 {
				timeRemaining = 0
			}
			response["time_remaining"] = timeRemaining

			resendAvailableIn := 60 - int(time.Since(sentTime).Seconds())
			if resendAvailableIn < 0 {
				resendAvailableIn = 0
			}
			response["resend_available_in"] = resendAvailableIn
		}
	}

	if isBlocked, exists := database.SM.GetData(sess, "is_blocked"); exists {
		response["is_blocked"] = isBlocked
		if until, ok := database.SM.GetData(sess, "blocked_until"); ok {
			response["blocked_until"] = until
		}
	}

	// Include user data if available (masked for UI)
	if user != nil {
		response["user_status"] = user.Status
		response["mfa_email_enabled"] = user.MFAEmailEnabled
		response["mfa_phone_enabled"] = user.MFAPhoneEnabled
		response["mfa_totp_enabled"] = user.MFATOTPEnabled
		response["has_email"] = user.Email != ""
		response["has_phone"] = user.Phone != 0
		if user.Email != "" {
			response["email"] = utils.MaskEmail(user.Email)
		}
		if user.Phone > 0 {
			response["phone"] = utils.MaskPhone(user.Phone)
		}
	}

	return response
}

// AuthHandler handles rendering the auth page.
func AuthHandler(tmpls *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for existing user-bound session
		cookie, err := r.Cookie("session_token")
		if err == nil && cookie.Value != "" {
			if sess, err := database.SM.Get(cookie.Value, "native"); err == nil && sess.UserID != nil {
				http.Redirect(w, r, "/home", http.StatusFound)
				return
			}
		}

		// Get language preference
		lang := "en"
		if langCookie, err := r.Cookie("lang"); err == nil {
			lang = i18n.NormalizeCode(langCookie.Value)
		}

		tr := i18n.New(lang)
		data := map[string]interface{}{
			"Lang":            lang,
			"CurrentLanguage": tr.Current(),
			"Languages":       tr.All(),
			"T":               i18n.GetTranslations(lang),
			"AppVersion":      config.Version,
		}

		// Buffer template execution to prevent partial writes on error
		var buf bytes.Buffer
		if err := tmpls.ExecuteTemplate(&buf, "auth.html", data); err != nil {
			http.Error(w, "could not render template", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		buf.WriteTo(w)
	}
}

// LoginHandler handles API login requests.
func LoginHandler(w http.ResponseWriter, r *http.Request) {

	var input struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		TwoStepCode string `json:"two_step_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if input.Username == "" || input.Password == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("%s and password are required", config.AppIDLabel)})
		return
	}

	// Password validation
	if err := utils.ValidatePassword(input.Password); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cleanedUsername, err := utils.ValidateUsername(input.Username)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	var user database.User
	if err := database.DB.Where("username = ?", cleanedUsername).First(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": fmt.Sprintf("invalid %s or password", config.AppIDLabel)})
		return
	}

	if user.Status == "suspended" {
		utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
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

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		// Track failed password attempt for brute-force protection
		failKey := fmt.Sprintf("login_fail:%s", cleanedUsername)
		failCount := int64(0)
		database.DB.Model(&database.SecurityBlock{}).Where("identifier = ? AND blocked_until > ?", failKey, time.Now()).Count(&failCount)
		blockEntry := database.SecurityBlock{
			Identifier:   failKey,
			BlockedUntil: time.Now().Add(1 * time.Hour), // track window
		}
		database.DB.Create(&blockEntry)
		failCount++ // including this attempt
		if failCount >= 15 {
			database.SM.ApplyBlock(fmt.Sprintf("user:%d:security", user.ID), nil, 24*time.Hour, "security")
			database.LogAuditEventWithUserID(database.AuditBruteForceBlocked, user.ID, r, "24h block after 15 failed attempts")
		} else if failCount >= 10 {
			database.SM.ApplyBlock(fmt.Sprintf("user:%d:security", user.ID), nil, 1*time.Hour, "security")
			database.LogAuditEventWithUserID(database.AuditBruteForceBlocked, user.ID, r, "1h block after 10 failed attempts")
		} else if failCount >= 5 {
			database.SM.ApplyBlock(fmt.Sprintf("user:%d:security", user.ID), nil, 15*time.Minute, "security")
			database.LogAuditEventWithUserID(database.AuditBruteForceBlocked, user.ID, r, "15m block after 5 failed attempts")
		}
		database.LogAuditEventWithUserID(database.AuditLoginFailed, user.ID, r, fmt.Sprintf("failed password attempt #%d", failCount))
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": fmt.Sprintf("invalid %s or password", config.AppIDLabel)})
		return
	}

	// Clear failed login attempts on success
	database.DB.Where("identifier = ?", fmt.Sprintf("login_fail:%s", cleanedUsername)).Delete(&database.SecurityBlock{})

	// Pass nil clientID for web-based session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return
	}

	mfaEnabled := (user.MFAEmailEnabled && user.Email != "") || (user.MFAPhoneEnabled && user.Phone != 0) || user.MFATOTPEnabled
	if mfaEnabled && input.TwoStepCode == "" {
		// Two-step is required but no code provided
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "two-step verification code required"})
		return
	}

	mfaValid := !mfaEnabled // If MFA not enabled, consider it valid

	if mfaEnabled && input.TwoStepCode != "" {
		// Check if it's a TOTP code first
		if user.MFATOTPEnabled && totp.Validate(input.TwoStepCode, user.TOTPSecret) {
			mfaValid = true
		}

		// Fallback to session-based OTP (email/phone)
		if !mfaValid {
			storedOTPHash, exists := database.SM.GetData(sess, "otp")
			otpSentAt, sentExists := database.SM.GetData(sess, "otp_sent_at")

			if !exists || !sentExists {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no verification code found in session"})
				return
			}

			// Check if OTP is older than 5 minutes
			var sentTime time.Time
			if tStr, ok := otpSentAt.(string); ok {
				sentTime, _ = time.Parse(time.RFC3339, tStr)
			}

			if time.Since(sentTime) > 5*time.Minute {
				database.SM.ClearAllData(sess)
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "verification code expired"})
				return
			}

			if !utils.ConstantTimeOTPCompare(fmt.Sprint(storedOTPHash), utils.HashToken(input.TwoStepCode)) {
				attempts, exists := database.SM.GetData(sess, "attempts")
				attemptCount := 0
				if exists {
					if count, ok := attempts.(float64); ok {
						attemptCount = int(count)
					}
				}
				attemptCount++
				if err := database.SM.SetData(sess, "attempts", attemptCount); err != nil {
					utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
					return
				}
				if attemptCount >= 3 {
					if err := database.SM.ClearAllData(sess); err != nil {
						utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear session data"})
						return
					}
					utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "maximum OTP attempts reached"})
					return
				}
				attemptsLeft := 3 - attemptCount
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid two-step verification code, %d attempt%s left", attemptsLeft, utils.Pluralize(attemptsLeft))})
				return
			}
			mfaValid = true
		}
	}

	if !mfaValid {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid two-step verification code"})
		return
	}

	if err := database.SM.SetUser(sess, user.ID); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to bind session"})
		return
	}

	// Rotate session to prevent session fixation
	newSess, err := database.SM.RotateSession(w, r, sess)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to rotate session"})
		return
	}
	updateSessionCookie(w, newSess)

	// Clear all session data after successful login
	if err := database.SM.ClearAllData(newSess); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear session data"})
		return
	}

	database.LogAuditEventWithUserID(database.AuditLoginSuccess, user.ID, r, "login via /auth/login")

	response := getAuthStateResponse(newSess, &user, "Login successful", "login")
	response["redirect"] = true
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// RegisterHandler handles API registration requests.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {

	var input struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		FirstName    string `json:"first_name"`
		LastName     string `json:"last_name"`
		Contact      string `json:"contact"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if input.Username == "" || input.Password == "" || input.FirstName == "" || input.Contact == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "username, password, first name, and contact are required"})
		return
	}

	// Password validation
	if err := utils.ValidatePassword(input.Password); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(input.FirstName) > 50 || len(input.LastName) > 50 {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "names must be at most 50 characters"})
		return
	}

	cleanedUsername, err := utils.ValidateUsername(input.Username)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cleanedContact, contactType, err := utils.ValidateContact(input.Contact)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Pass nil clientID for web-based session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return
	}

	// Verify the user actually completed OTP verification (step must be register-password)
	currentStep, stepExists := database.SM.GetData(sess, "step")
	if !stepExists || fmt.Sprint(currentStep) != "register-password" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "OTP verification required"})
		return
	}

	// Verify contact matches session
	storedContact, exists := database.SM.GetData(sess, "contact")
	if !exists || fmt.Sprint(storedContact) != cleanedContact {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "contact does not match session"})
		return
	}

	var existingUser database.User
	if err := database.DB.Where("username = ?", cleanedUsername).First(&existingUser).Error; err == nil {
		utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("%s already taken", config.AppIDLabel)})
		return
	}

	user := database.User{
		Username:        cleanedUsername,
		FirstName:       strings.TrimSpace(input.FirstName),
		LastName:        strings.TrimSpace(input.LastName),
		Status:          "active",
		MFAEmailEnabled: false,
		MFAPhoneEnabled: false,
		MFATOTPEnabled:  false,
	}

	if contactType == "email" {
		if err := database.DB.Where("email = ?", cleanedContact).First(&existingUser).Error; err == nil {
			utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "email already in use"})
			return
		}
		user.Email = cleanedContact
	} else {
		phone, err := utils.ParsePhone(cleanedContact)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid phone number"})
			return
		}
		if err := database.DB.Where("phone = ?", phone).First(&existingUser).Error; err == nil {
			utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "phone number already in use"})
			return
		}
		user.Phone = phone
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), config.BcryptCost)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	if err := database.DB.Create(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
		return
	}

	if err := database.SM.SetUser(sess, user.ID); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to bind session"})
		return
	}

	// Rotate session to prevent session fixation
	newSess, err := database.SM.RotateSession(w, r, sess)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to rotate session"})
		return
	}
	updateSessionCookie(w, newSess)

	// Clear all session data after successful registration
	if err := database.SM.ClearAllData(newSess); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear session data"})
		return
	}

	database.LogAuditEventWithUserID(database.AuditAccountCreated, user.ID, r, "new account registered")

	response := getAuthStateResponse(newSess, &user, "Registration successful", "register")
	response["redirect"] = true
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// ResetPasswordHandler handles API password reset requests.
func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {

	var input struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		Contact      string `json:"contact"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if input.Username == "" || input.Password == "" || input.Contact == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "username, password, and contact are required"})
		return
	}

	// Password validation
	if err := utils.ValidatePassword(input.Password); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cleanedUsername, err := utils.ValidateUsername(input.Username)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cleanedContact, contactType, err := utils.ValidateContact(input.Contact)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	var user database.User
	if err := database.DB.Where("username = ?", cleanedUsername).First(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid %s", config.AppIDLabel)})
		return
	}

	if user.Status == "suspended" {
		utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
		return
	}

	// Pass nil clientID for web-based session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return
	}

	// Verify the user actually completed OTP verification (step must be reset-password)
	currentStep, stepExists := database.SM.GetData(sess, "step")
	if !stepExists || fmt.Sprint(currentStep) != "reset-password" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "OTP verification required"})
		return
	}

	// Verify contact matches session
	storedContact, exists := database.SM.GetData(sess, "contact")
	if !exists || fmt.Sprint(storedContact) != cleanedContact {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "contact does not match session"})
		return
	}

	// Validate contact matches user record
	if contactType == "email" && user.Email != cleanedContact {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "contact does not match account"})
		return
	}
	if contactType == "phone" {
		phone, err := utils.ParsePhone(cleanedContact)
		if err != nil || user.Phone != phone {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "contact does not match account"})
			return
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), config.BcryptCost)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
		return
	}

	user.Password = string(hashedPassword)

	if err := database.DB.Save(&user).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update password"})
		return
	}

	if err := database.SM.SetUser(sess, user.ID); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to bind session"})
		return
	}

	// Rotate session to prevent session fixation
	newSess, err := database.SM.RotateSession(w, r, sess)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to rotate session"})
		return
	}
	updateSessionCookie(w, newSess)

	// Clear all session data after successful password reset
	if err := database.SM.ClearAllData(newSess); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear session data"})
		return
	}

	database.LogAuditEventWithUserID(database.AuditPasswordReset, user.ID, r, "password reset via OTP")

	response := getAuthStateResponse(newSess, &user, "Password reset successful", "reset-password")
	response["redirect"] = true
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// CheckUserHandler checks if a user exists and returns partial contact info.
func CheckUserHandler(w http.ResponseWriter, r *http.Request) {

	username := r.URL.Query().Get("username")
	if username == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("%s is required", config.AppIDLabel)})
		return
	}

	cleanedUsername, err := utils.ValidateUsername(username)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Pass nil clientID for web-based session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return
	}

	if blocked, until := database.SM.IsBlocked(cleanedUsername); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         fmt.Sprintf("this %s is temporarily blocked for security, please try again in 24 hours (until %s)", config.AppIDLabel, until.Format(time.RFC3339)),
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	var user database.User
	if err := database.DB.Where("username = ?", cleanedUsername).First(&user).Error; err == nil {
		if blocked, until := database.SM.IsBlocked(fmt.Sprintf("user:%d:security", user.ID)); blocked {
			utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":         fmt.Sprintf("your account is temporarily blocked for security until %s", until.Format(time.RFC3339)),
				"is_blocked":    true,
				"blocked_until": until.Format(time.RFC3339),
			})
			return
		}
	}

	// Clear existing session data and set new username
	if err := database.SM.ClearAllData(sess); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear session data"})
		return
	}
	if err := database.SM.SetData(sess, "username", cleanedUsername); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
		return
	}

	response := getAuthStateResponse(sess, nil, config.AppIDLabel + " verified", "gilos-id")
	response["status"] = "free"

	if user.ID != 0 {
		response["status"] = user.Status
		if user.Status == "active" || user.Status == "pending_deletion" {
			response["step"] = "password"
			if err := database.SM.SetData(sess, "step", "password"); err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
				return
			}
		} else if user.Status == "suspended" {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
			return
		}
	} else {
		response["step"] = "register-name"
		if err := database.SM.SetData(sess, "step", "register-name"); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
			return
		}
	}

	if user.ID != 0 {
		response["user_status"] = user.Status
		response["mfa_email_enabled"] = user.MFAEmailEnabled
		response["mfa_phone_enabled"] = user.MFAPhoneEnabled
		response["mfa_totp_enabled"] = user.MFATOTPEnabled
		response["has_email"] = user.Email != ""
		response["has_phone"] = user.Phone != 0
		if user.Email != "" {
			response["email"] = utils.MaskEmail(user.Email)
		}
		if user.Phone > 0 {
			response["phone"] = utils.MaskPhone(user.Phone)
		}
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// ContactVerifyHandler verifies the contact for registration, reset, or two-step login.
func ContactVerifyHandler(w http.ResponseWriter, r *http.Request) {

	var input struct {
		Username  string `json:"username"`
		Contact   string `json:"contact"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Step      string `json:"step"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if input.Username == "" || input.Contact == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "username and contact are required"})
		return
	}

	cleanedUsername, err := utils.ValidateUsername(input.Username)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cleanedContact, contactType, err := utils.ValidateContact(input.Contact)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if blocked, until := database.SM.IsBlocked(cleanedContact); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         "this contact is temporarily blocked for security, please try again in 24 hours",
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	// Pass nil clientID for web-based session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return
	}

	currentStep, exists := database.SM.GetData(sess, "step")
	if !exists || input.Step != fmt.Sprintf("%v", currentStep) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid session state"})
		return
	}

	var user database.User
	if input.Step == "forgot-password" {
		if err := database.DB.Where("username = ?", cleanedUsername).First(&user).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid %s", config.AppIDLabel)})
			return
		}
		if user.Status == "suspended" {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
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
		if contactType == "email" && user.Email != cleanedContact {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "contact does not match account"})
			return
		}
		if contactType == "phone" {
			phone, err := utils.ParsePhone(cleanedContact)
			if err != nil || user.Phone != phone {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "contact does not match account"})
				return
			}
		}
	} else if input.Step == "register-contact" {
		var existingUser database.User
		if contactType == "email" {
			if err := database.DB.Where("email = ?", cleanedContact).First(&existingUser).Error; err == nil {
				utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "email already in use"})
				return
			}
		} else {
			phone, err := utils.ParsePhone(cleanedContact)
			if err != nil {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid phone number"})
				return
			}
			if err := database.DB.Where("phone = ?", phone).First(&existingUser).Error; err == nil {
				utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "phone number already in use"})
				return
			}
		}
	}

	// Rate limit check
	if otpSentAt, exists := database.SM.GetData(sess, "otp_sent_at"); exists {
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

	otp := utils.GenerateOTP()
	sessionData := map[string]interface{}{
		"otp":          utils.HashToken(otp),
		"otp_sent_at":  time.Now().Format(time.RFC3339),
		"attempts":     0,
		"resends":      0,
		"contact_type": contactType,
		"contact":      cleanedContact,
	}
	if input.Step == "register-contact" {
		sessionData["first_name"] = input.FirstName
		sessionData["last_name"] = input.LastName
	}

	for key, value := range sessionData {
		if err := database.SM.SetData(sess, key, value); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
			return
		}
	}

	if contactType == "email" {
		if err := utils.SendVerificationEmail(cleanedContact, otp); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to send OTP email"})
			return
		}
	} else {
		if err := utils.SendPhoneOTP(cleanedContact, otp); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	// Update step
	nextStep := "otp"
	if err := database.SM.SetData(sess, "step", nextStep); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
		return
	}

	response := getAuthStateResponse(sess, &user, "OTP sent for contact verification", nextStep)
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// SendOTPHandler sends OTP for any authentication flow.
func SendOTPHandler(w http.ResponseWriter, r *http.Request) {

	var input struct {
		Username string `json:"username"`
		Contact  string `json:"contact"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if input.Username == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}

	cleanedUsername, err := utils.ValidateUsername(input.Username)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if blocked, until := database.SM.IsBlocked(cleanedUsername); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         "this account is temporarily blocked for security, please try again in 24 hours",
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	// Pass nil clientID for web-based session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return
	}

	currentStep, exists := database.SM.GetData(sess, "step")
	if !exists || (fmt.Sprint(currentStep) != "two-step-select" && fmt.Sprint(currentStep) != "otp") {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid session state"})
		return
	}

	var contactType string
	var cleanedContact string
	var user database.User
	if input.Contact == "email" || input.Contact == "phone" || input.Contact == "totp" {
		contactType = input.Contact
		if err := database.DB.Where("username = ?", cleanedUsername).First(&user).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid %s", config.AppIDLabel)})
			return
		}
		if user.Status == "suspended" {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
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
		if contactType == "email" {
			if user.Email == "" || !user.MFAEmailEnabled {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "email not available or MFA not enabled for this account"})
				return
			}
			cleanedContact = user.Email
		} else if contactType == "phone" {
			if user.Phone == 0 || !user.MFAPhoneEnabled {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "phone not available or MFA not enabled for this account"})
				return
			}
			cleanedContact = utils.FormatPhone(user.Phone)
		} else if contactType == "totp" {
			if !user.MFATOTPEnabled {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "authenticator app MFA not enabled for this account"})
				return
			}
			cleanedContact = "totp"
		}
	} else {
		cleanedContact, contactType, err = utils.ValidateContact(input.Contact)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if fmt.Sprint(currentStep) == "otp" {
			if err := database.DB.Where("username = ?", cleanedUsername).First(&user).Error; err == nil && user.Status != "free" {
				if user.Status == "suspended" {
					utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
					return
				}
				if contactType == "email" && user.Email != cleanedContact {
					utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "contact does not match account"})
					return
				}
				if contactType == "phone" {
					phone, err := utils.ParsePhone(cleanedContact)
					if err != nil || user.Phone != phone {
						utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "contact does not match account"})
						return
					}
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
			} else {
				var existingUser database.User
				if contactType == "email" {
					if err := database.DB.Where("email = ?", cleanedContact).First(&existingUser).Error; err == nil {
						utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "email already in use"})
						return
					}
				} else {
					phone, err := utils.ParsePhone(cleanedContact)
					if err != nil {
						utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid phone number"})
						return
					}
					if err := database.DB.Where("phone = ?", phone).First(&existingUser).Error; err == nil {
						utils.WriteJSONResponse(w, http.StatusConflict, map[string]string{"error": "phone number already in use"})
						return
					}
				}
			}
		}
	}

	resends, exists := database.SM.GetData(sess, "resends")
	resendCount := 0
	if exists {
		if count, ok := resends.(float64); ok {
			resendCount = int(count)
		}
	}

	// Rate limit check
	if otpSentAt, exists := database.SM.GetData(sess, "otp_sent_at"); exists {
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
				"resend_available_in": timeLeft,
			})
			return
		}
	}

	if contactType != "totp" {
		resendCount++
	}
	if resendCount > 3 && contactType != "totp" {
		database.SM.ApplyBlock(cleanedContact, sess, 24*time.Hour, "security")
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         "maximum resend attempts reached, blocked for 24 hours",
			"is_blocked":    true,
			"blocked_until": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		return
	}

	var otp string
	sessionData := map[string]interface{}{
		"attempts":     0,
		"resends":      resendCount,
		"contact_type": contactType,
		"contact":      cleanedContact,
	}
	if contactType != "totp" {
		otp = utils.GenerateOTP()
		sessionData["otp"] = utils.HashToken(otp)
		sessionData["otp_sent_at"] = time.Now().Format(time.RFC3339)
	}
	for key, value := range sessionData {
		if err := database.SM.SetData(sess, key, value); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
			return
		}
	}

	if contactType == "email" {
		if err := utils.SendVerificationEmail(cleanedContact, otp); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to send OTP email"})
			return
		}
	} else if contactType == "phone" {
		if err := utils.SendPhoneOTP(cleanedContact, otp); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	} // For totp, no send

	if err := database.SM.SetData(sess, "step", "otp"); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
		return
	}

	response := getAuthStateResponse(sess, &user, "OTP sent successfully", "otp")
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// VerifyOTPHandler verifies the OTP for any authentication flow.
func VerifyOTPHandler(w http.ResponseWriter, r *http.Request) {

	var input struct {
		Username string `json:"username"`
		OTP      string `json:"otp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if input.Username == "" || input.OTP == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "username and OTP are required"})
		return
	}

	cleanedUsername, err := utils.ValidateUsername(input.Username)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if blocked, until := database.SM.IsBlocked(cleanedUsername); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         "this account is temporarily blocked for security, please try again in 24 hours",
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return
	}

	// Pass nil clientID for web-based session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return
	}

	currentStep, exists := database.SM.GetData(sess, "step")
	if !exists || fmt.Sprint(currentStep) != "otp" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid session state"})
		return
	}

	contactType, _ := database.SM.GetData(sess, "contact_type")

	attempts, exists := database.SM.GetData(sess, "attempts")
	attemptCount := 0
	if exists {
		if count, ok := attempts.(float64); ok {
			attemptCount = int(count)
		}
	}
	attemptCount++
	if attemptCount > 3 {
		identifier := ""
		if contact, exists := database.SM.GetData(sess, "contact"); exists {
			identifier = fmt.Sprint(contact)
		} else {
			identifier = cleanedUsername
		}

		database.SM.ApplyBlock(identifier, sess, 24*time.Hour, "security")
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         "maximum OTP attempts reached, blocked for 24 hours",
			"is_blocked":    true,
			"blocked_until": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		return
	}
	if err := database.SM.SetData(sess, "attempts", attemptCount); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
		return
	}

	var user database.User
	valid := false
	if fmt.Sprint(contactType) == "totp" {
		if err := database.DB.Where("username = ?", cleanedUsername).First(&user).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid %s", config.AppIDLabel)})
			return
		}
		if totp.Validate(input.OTP, user.TOTPSecret) {
			valid = true
		}
	} else {
		storedOTPHash, exists := database.SM.GetData(sess, "otp")
		if !exists {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no OTP session found"})
			return
		}
		// Compare hashed OTP (stored) with hash of submitted OTP
		valid = utils.ConstantTimeOTPCompare(fmt.Sprint(storedOTPHash), utils.HashToken(input.OTP))
	}

	if !valid {
		attemptsLeft := 3 - attemptCount
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid OTP, %d attempt%s left", attemptsLeft, utils.Pluralize(attemptsLeft))})
		return
	}

	var nextStep string
	var successMessage string
	// Determine next step based on previous state
	if _, exists := database.SM.GetData(sess, "password_verified"); exists {
		// Two-step login flow
		if err := database.DB.Where("username = ?", cleanedUsername).First(&user).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid %s", config.AppIDLabel)})
			return
		}
		if err := database.SM.SetUser(sess, user.ID); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to bind session"})
			return
		}

		// Rotate session to prevent session fixation
		newSess, err := database.SM.RotateSession(w, r, sess)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to rotate session"})
			return
		}
		updateSessionCookie(w, newSess)

		if err := database.SM.ClearAllData(newSess); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear session data"})
			return
		}

		database.LogAuditEventWithUserID(database.AuditLoginSuccess, user.ID, r, "login via two-step verification")

		nextStep = "login"
		successMessage = "Login successful"
		response := getAuthStateResponse(newSess, &user, successMessage, nextStep)
		response["redirect"] = true
		utils.WriteJSONResponse(w, http.StatusOK, response)
		return
	} else if _, exists := database.SM.GetData(sess, "first_name"); exists {
		// Registration flow
		nextStep = "register-password"
		successMessage = "OTP verified"
	} else {
		// Password reset flow
		if err := database.DB.Where("username = ?", cleanedUsername).First(&user).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid %s", config.AppIDLabel)})
			return
		}
		nextStep = "reset-password"
		successMessage = "OTP verified"
	}

	if err := database.SM.SetData(sess, "step", nextStep); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update session data"})
		return
	}

	response := getAuthStateResponse(sess, &user, successMessage, nextStep)
	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// AuthStateHandler handles GET and POST requests for auth state.
func AuthStateHandler(w http.ResponseWriter, r *http.Request) {
	// Pass nil clientID for web-based session
	sess, err := database.SM.Start(r.Context(), w, r, nil)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
		return
	}

	if r.Method == http.MethodGet {
		var user database.User
		username, exists := database.SM.GetData(sess, "username")
		currentStep, stepExists := database.SM.GetData(sess, "step")
		if !stepExists {
			currentStep = "gilos-id"
		}
		if exists {
			database.DB.Where("username = ?", username).First(&user)
		}
		response := getAuthStateResponse(sess, &user, "", fmt.Sprint(currentStep))
		utils.WriteJSONResponse(w, http.StatusOK, response)
		return
	}

	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var input struct {
		Step      string `json:"step"`
		Password  string `json:"password"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if input.Step == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "step is required"})
		return
	}

	username, exists := database.SM.GetData(sess, "username")
	if !exists && input.Step != "gilos-id" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "username not set in session"})
		return
	}

	// Validate step
	validSteps := []string{
		"gilos-id", "password", "two-step-select", "otp",
		"register-name", "register-contact", "register-password",
		"forgot-password", "reset-password",
	}
	if !slices.Contains(validSteps, input.Step) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid step"})
		return
	}

	var user database.User
	var successMessage string
	var nextStep = input.Step

	if input.Step == "password" && input.Password != "" {
		// Input length validation
		if err := utils.ValidatePassword(input.Password); err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := database.DB.Where("username = ?", username).First(&user).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid %s", config.AppIDLabel)})
			return
		}
		if user.Status == "suspended" {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
			utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
			return
		}
		// Store only a flag, not the actual password
		if err := database.SM.SetData(sess, "password_verified", true); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
			return
		}
		mfaEnabled := (user.MFAEmailEnabled && user.Email != "") || (user.MFAPhoneEnabled && user.Phone != 0) || user.MFATOTPEnabled
		if mfaEnabled {
			nextStep = "two-step-select"
			successMessage = "Password verified"
		} else {
			// Direct login — rotate session to prevent session fixation
			if err := database.SM.SetUser(sess, user.ID); err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to bind session"})
				return
			}
			newSess, err := database.SM.RotateSession(w, r, sess)
			if err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to rotate session"})
				return
			}
			updateSessionCookie(w, newSess)
			if err := database.SM.ClearAllData(newSess); err != nil {
				utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear session data"})
				return
			}
			response := getAuthStateResponse(newSess, &user, "Login successful", "login")
			response["redirect"] = true
			utils.WriteJSONResponse(w, http.StatusOK, response)
			return
		}
	} else if input.Step == "register-name" && input.FirstName != "" {
		// Input length validation
		if len(input.FirstName) > 50 || len(input.LastName) > 50 {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "names must be at most 50 characters"})
			return
		}
		if err := database.SM.SetData(sess, "first_name", input.FirstName); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
			return
		}
		if err := database.SM.SetData(sess, "last_name", input.LastName); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
			return
		}
		nextStep = "register-contact"
		successMessage = "Details saved"
	} else if input.Step == "forgot-password" {
		if err := database.DB.Where("username = ?", username).First(&user).Error; err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid %s", config.AppIDLabel)})
			return
		}
		if user.Status == "suspended" {
			utils.WriteJSONResponse(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
			return
		}
	} else if input.Step == "gilos-id" {
		if err := database.SM.ClearAllData(sess); err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear session data"})
			return
		}
	}

	if err := database.SM.SetData(sess, "step", nextStep); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to store session data"})
		return
	}

	if username != nil {
		database.DB.Where("username = ?", username).First(&user)
	}
	response := getAuthStateResponse(sess, &user, successMessage, nextStep)
	utils.WriteJSONResponse(w, http.StatusOK, response)
}
