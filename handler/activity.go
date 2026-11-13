package handler

import (
	"gilosauth/database"
	"gilosauth/middleware"
	"gilosauth/utils"
	"math"
	"net/http"
	"strconv"
	"time"
)

// ActivityLogItem represents a single user-facing security audit event.
type ActivityLogItem struct {
	ID        uint64    `json:"id"`
	EventType string    `json:"event_type"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

// ProfileActivityHandler returns recent paginated security audit events for the signed-in user.
func ProfileActivityHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	userID, err := middleware.GetUserID(r)
	if err != nil {
		utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 15
	}
	if limit > 50 {
		limit = 50
	}

	offset := (page - 1) * limit

	var total int64
	query := database.DB.Model(&database.AuditLog{}).Where("user_id = ?", userID)
	if err := query.Count(&total).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Database error"})
		return
	}

	var logs []database.AuditLog
	if err := query.Order("id DESC").Offset(offset).Limit(limit).Find(&logs).Error; err != nil {
		utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Database error"})
		return
	}

	items := make([]ActivityLogItem, 0, len(logs))
	for _, entry := range logs {
		items = append(items, ActivityLogItem{
			ID:        entry.ID,
			EventType: entry.EventType,
			IPAddress: entry.IPAddress,
			UserAgent: entry.UserAgent,
			Details:   entry.Details,
			CreatedAt: entry.CreatedAt,
		})
	}

	totalPages := 1
	if total > 0 {
		totalPages = int(math.Ceil(float64(total) / float64(limit)))
	}

	utils.WriteJSONResponse(w, http.StatusOK, PaginatedResponse{
		Data: items,
		Pagination: Pagination{
			Total:       total,
			Page:        page,
			Limit:       limit,
			TotalPages:  totalPages,
			HasNextPage: page < totalPages,
		},
	})
}