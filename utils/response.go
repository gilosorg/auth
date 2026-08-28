package utils

import (
	"encoding/json"
	"net/http"
)

// WriteJSONResponse writes a JSON response with the given status code.
func WriteJSONResponse(w http.ResponseWriter, status int, response interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error": "failed to encode response"}`, http.StatusInternalServerError)
	}
}
