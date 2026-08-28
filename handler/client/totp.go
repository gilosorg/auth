package client

import (
	"encoding/json"
	"gilosauth/database"
	"gilosauth/middleware"
	"gilosauth/utils"
	"net/http"
)

// TOTPData represents the TOTP secret data as sent/received by the mobile app.
type TOTPData struct {
	UUID      string  `json:"uuid,omitempty"`
	Secret    string  `json:"secret"`
	Label     string  `json:"label"`
	Issuer    *string `json:"issuer,omitempty"`
	Algorithm string  `json:"algorithm"`
	Digits    *int    `json:"digits,omitempty"`
	Period    *int    `json:"period,omitempty"`
	UpdatedAt int64   `json:"updatedAt"`
}

// sanitizeTotp ensures the TOTP data complies with frontend requirements.
func sanitizeTotp(data TOTPData) TOTPData {
	// Digits: Must be >= 4. Default to 6.
	if data.Digits == nil || *data.Digits < 4 {
		six := 6
		data.Digits = &six
	}

	// Period: Must be > 0. Default to 30.
	if data.Period == nil || *data.Period <= 0 {
		thirty := 30
		data.Period = &thirty
	}

	// Algorithm: Valid values: sha1, sha256, sha512. Default to sha1.
	switch data.Algorithm {
	case "sha1", "sha256", "sha512":
		// valid
	default:
		data.Algorithm = "sha1"
	}

	return data
}

// Convert model to TOTPData
func modelToData(m database.TOTPSecret) TOTPData {
	data := TOTPData{
		UUID:      m.UUID,
		Secret:    m.Secret,
		Label:     m.Label,
		Algorithm: m.Algorithm,
		Digits:    &m.Digits,
		Period:    &m.Period,
		UpdatedAt: m.UpdatedAt,
	}
	if m.Issuer != "" {
		data.Issuer = &m.Issuer
	}
	// Sanitize to handle defaults/invalid database values if any
	return sanitizeTotp(data)
}



// ListTOTPsHandler returns all TOTP secrets for the authenticated user.
func ListTOTPsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var secrets []database.TOTPSecret
	if err := database.DB.Where("user_id = ?", userID).Find(&secrets).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch secrets"})
		return
	}

	response := make(map[string]TOTPData)
	for _, s := range secrets {
		response[s.UUID] = modelToData(s)
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// SyncOperation represents a push operation (set or delete).
type SyncOperation struct {
	Kind      string          `json:"kind"` // "set" or "delete"
	Payload   json.RawMessage `json:"payload"`
	CreatedAt int64           `json:"created_at"`
}

// SyncResult represents the result of a single push operation.
type SyncResult struct {
	OperationUuid string  `json:"operationUuid"`
	TotpUuid      string  `json:"totpUuid"`
	Success       bool    `json:"success"`
	ErrorKind     *string `json:"errorKind"`
	ErrorDetails  *string `json:"errorDetails"`
	CreatedAt     int64   `json:"createdAt"`
}

// PushSyncHandler handles push synchronization operations.
func PushSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req struct {
		Operations []SyncOperation `json:"operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	results := make([]SyncResult, 0)

	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	for _, op := range req.Operations {
		switch op.Kind {
		case "set":
			var payload []TOTPData
			if err := json.Unmarshal(op.Payload, &payload); err != nil {
				tx.Rollback()
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid payload for set"})
				return
			}

			for _, data := range payload {
				var existing database.TOTPSecret
				err := tx.Where("uuid = ? AND user_id = ?", data.UUID, userID).First(&existing).Error

				success := true
				var errKind *string
				var errDetails *string

				if err == nil {
					// Update existing
					if data.UpdatedAt < existing.UpdatedAt {
						success = false
						kind := "invalidUpdateTimestamp"
						details := "timestamp in the past"
						errKind = &kind
						errDetails = &details
					} else {
						data = sanitizeTotp(data)
						existing.Secret = data.Secret
						existing.Label = data.Label
						if data.Issuer != nil {
							existing.Issuer = *data.Issuer
						} else {
							existing.Issuer = ""
						}
						existing.Algorithm = data.Algorithm
						existing.Digits = *data.Digits
						existing.Period = *data.Period
						existing.UpdatedAt = data.UpdatedAt

						if err := tx.Save(&existing).Error; err != nil {
							tx.Rollback()
							utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to update secret"})
							return
						}
					}
				} else {
					// Create new
					data = sanitizeTotp(data)
					newSecret := database.TOTPSecret{
						UUID:      data.UUID,
						UserID:    userID,
						Secret:    data.Secret,
						Label:     data.Label,
						Algorithm: data.Algorithm,
						Digits:    *data.Digits,
						Period:    *data.Period,
						UpdatedAt: data.UpdatedAt,
					}
					if data.Issuer != nil {
						newSecret.Issuer = *data.Issuer
					}
					if err := tx.Create(&newSecret).Error; err != nil {
						tx.Rollback()
						utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to create secret"})
						return
					}
				}

				results = append(results, SyncResult{
					TotpUuid:     data.UUID,
					Success:      success,
					ErrorKind:    errKind,
					ErrorDetails: errDetails,
					CreatedAt:    op.CreatedAt,
				})
			}

		case "delete":
			var uuids []string
			if err := json.Unmarshal(op.Payload, &uuids); err != nil {
				tx.Rollback()
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid payload for delete"})
				return
			}

			for _, totpUUID := range uuids {
				if err := tx.Where("uuid = ? AND user_id = ?", totpUUID, userID).Delete(&database.TOTPSecret{}).Error; err != nil {
					tx.Rollback()
					utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete secret"})
					return
				}
				results = append(results, SyncResult{
					TotpUuid:  totpUUID,
					Success:   true,
					CreatedAt: op.CreatedAt,
				})
			}

		default:
			tx.Rollback()
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "unknown operation kind"})
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to commit transaction"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, results)
}

// PullSyncRequest represents a pull synchronization request.
type PullSyncRequest map[string]int64

// PullSyncResponse represents a pull synchronization response.
type PullSyncResponse struct {
	Inserts map[string]TOTPData `json:"inserts"`
	Updates map[string]TOTPData `json:"updates"`
	Deletes []string            `json:"deletes"`
}

// PullSyncHandler handles pull synchronization (delta).
func PullSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var known PullSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&known); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var allSecrets []database.TOTPSecret
	if err := database.DB.Where("user_id = ?", userID).Find(&allSecrets).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch secrets"})
		return
	}

	response := PullSyncResponse{
		Inserts: make(map[string]TOTPData),
		Updates: make(map[string]TOTPData),
		Deletes: []string{},
	}

	// Current secrets in DB
	currentUUIDs := make(map[string]*database.TOTPSecret)
	for i := range allSecrets {
		currentUUIDs[allSecrets[i].UUID] = &allSecrets[i]
	}

	// Detect inserts and updates
	for uuid, s := range currentUUIDs {
		knownUpdatedAt, exists := known[uuid]
		if !exists {
			response.Inserts[uuid] = modelToData(*s)
		} else if s.UpdatedAt > knownUpdatedAt {
			response.Updates[uuid] = modelToData(*s)
		}
	}

	// Detect deletes (known UUIDs but not in DB)
	for uuid := range known {
		if _, exists := currentUUIDs[uuid]; !exists {
			response.Deletes = append(response.Deletes, uuid)
		}
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}
