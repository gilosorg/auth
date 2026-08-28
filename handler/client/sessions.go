package client

import (
	"gilosauth/database"
	"gilosauth/middleware"
	"gilosauth/utils"
	"math"
	"net/http"
	"strconv"
)

// Pagination metadata
type Pagination struct {
	Total       int64 `json:"total"`
	Page        int   `json:"page"`
	Limit       int   `json:"limit"`
	TotalPages  int   `json:"total_pages"`
	HasNextPage bool  `json:"has_next_page"`
}

// PaginatedResponse wrapper
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

// SessionsHandler returns JSON list of sessions with pagination.
func SessionsHandler(w http.ResponseWriter, r *http.Request) {
	// UserID verified by middleware
	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Parse pagination parameters
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	page, _ := strconv.Atoi(pageStr)
	if page <= 0 {
		page = 1
	}

	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 100 {
		limit = 10 // Default limit
	}

	offset := (page - 1) * limit

	// Fetch sessions for the user with pagination
	var sessions []database.Session
	var total int64

	// Count total sessions for metadata
	database.DB.Model(&database.Session{}).Where("user_id = ?", userID).Count(&total)

	if err := database.DB.Preload("Client").
		Where("user_id = ?", userID).
		Order("id DESC").
		Limit(limit).
		Offset(offset).
		Find(&sessions).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve sessions"})
		return
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))

	response := PaginatedResponse{
		Data: sessions,
		Pagination: Pagination{
			Total:       total,
			Page:        page,
			Limit:       limit,
			TotalPages:  totalPages,
			HasNextPage: page < totalPages,
		},
	}

	utils.WriteJSONResponse(w, http.StatusOK, response)
}

// TerminateSessionHandler terminates a specific session and returns JSON.
func TerminateSessionHandler(w http.ResponseWriter, r *http.Request) {
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

	// Parse session ID
	if err := r.ParseForm(); err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "failed to parse form"})
		return
	}
	sessionIDStr := r.Form.Get("session_id")
	if sessionIDStr == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "session ID is required"})
		return
	}

	sessionID, err := strconv.ParseUint(sessionIDStr, 10, 64)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return
	}

	// Verify session belongs to user
	var session database.Session
	if err := database.DB.Where("id = ? AND user_id = ?", sessionID, userID).First(&session).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusNotFound, map[string]string{"error": "session not found or unauthorized"})
		return
	}

	// Delete session from database
	if err := database.SM.Destroy(&session); err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to terminate session"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}
// TerminateOthersHandler terminates all sessions except the current one.
func TerminateOthersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Get current access token (verified by middleware)
	accessToken := r.Header.Get("Authorization")
	if len(accessToken) > 7 && accessToken[:7] == "Bearer " {
		accessToken = accessToken[7:]
	}

	// Delete all user sessions except the current one
	if err := database.DB.Where("user_id = ? AND access_token != ?", userID, accessToken).Delete(&database.Session{}).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to terminate other sessions"})
		return
	}

	utils.WriteJSONResponse(w, http.StatusOK, map[string]bool{"success": true})
}
