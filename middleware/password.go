package middleware

import (
	"fmt"
	"net/http"
	"time"

	"gilosauth/database"
	"gilosauth/utils"

	"golang.org/x/crypto/bcrypt"
)

// VerifyCurrentPassword validates X-Current-Password against the user's stored password hash.
// After 3 consecutive failures, it applies a 24-hour user security block.
func VerifyCurrentPassword(w http.ResponseWriter, r *http.Request, userID uint64) bool {
	password := r.Header.Get("X-Current-Password")
	if password == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "password_required"})
		return false
	}

	securityKey := fmt.Sprintf("user:%d:security", userID)
	if blocked, until := database.SM.IsBlocked(securityKey); blocked {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         "account_blocked",
			"is_blocked":    true,
			"blocked_until": until.Format(time.RFC3339),
		})
		return false
	}

	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve user"})
		return false
	}

	sess, err := GetSession(r)
	if err != nil || sess == nil {
		sess, err = database.SM.Start(r.Context(), w, r, nil)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to start session"})
			return false
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		attempts, _ := database.SM.GetData(sess, "password_verify_attempts")
		attemptCount := 0
		if count, ok := attempts.(float64); ok {
			attemptCount = int(count)
		}
		attemptCount++

		if attemptCount >= 3 {
			database.SM.ApplyBlock(securityKey, sess, 24*time.Hour, "security")
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

	database.SM.DeleteData(sess, "password_verify_attempts")
	return true
}
