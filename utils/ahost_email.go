package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"gilosauth/config"
)

// emailPayload defines the structure expected by the email API
type emailPayload struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// SendVerificationEmail sends an email with the verification code using the email API.
func SendVerificationEmail(toEmail, code string) error {
	subject := config.AppName + " — Verification Code"
	htmlBody := fmt.Sprintf(
		"<h3>%s</h3><p>Your verification code is: <strong>%s</strong></p><p>This code expires in 5 minutes.</p>",
		config.AppName, code,
	)

	payload := emailPayload{
		To:      toEmail,
		Subject: subject,
		Body:    htmlBody,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal email payload: %v", err)
	}

	req, err := http.NewRequest("POST", config.EmailAPIEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Token", config.EmailAPIToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call email API: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	log.Printf("Verification email sent successfully to %s", MaskEmail(toEmail))
	return nil
}
