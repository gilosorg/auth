package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"gilosauth/config"
)

var (
	eskizToken string
	loggedIn   bool
	mutex      sync.RWMutex
)

// SMSPayload represents the payload for sending an SMS.
type SMSPayload struct {
	MobilePhone string `json:"mobile_phone"`
	Message     string `json:"message"`
	From        string `json:"from"`
	CallbackURL string `json:"callback_url"`
}

// LoginResponse represents the response from the login API.
type LoginResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}

// login authenticates with the Eskiz API and updates the token.
func login() error {
	mutex.Lock()
	defer mutex.Unlock()

	payload := map[string]string{
		"email":    config.EskizEmail,
		"password": config.EskizPassword,
	}
	data, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("https://notify.eskiz.uz/api/auth/login", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	var loginResp LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return fmt.Errorf("failed to parse login response: %v", err)
	}

	eskizToken = loginResp.Data.Token
	loggedIn = true
	return nil
}

// getEskizToken reads the token under a read lock for thread safety.
func getEskizToken() string {
	mutex.RLock()
	defer mutex.RUnlock()
	return eskizToken
}

// sendEskizSMS sends an SMS using the Eskiz API.
func sendEskizSMS(phone, message string) error {
	if len(message) > 160 {
		message = message[:160]
	}

	payload := SMSPayload{
		MobilePhone: phone,
		Message:     message,
		From:        config.EskizFromName,
		CallbackURL: "",
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", "https://notify.eskiz.uz/api/message/sms/send", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	token := getEskizToken()
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SMS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SMS sending failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SendEskizSMSWithRetry attempts to send an SMS with retries.
func SendEskizSMSWithRetry(phone, message string, retries int) error {
	for attempt := 1; attempt <= retries; attempt++ {
		if !loggedIn {
			if err := login(); err != nil {
				return fmt.Errorf("attempt %d: login failed: %v", attempt, err)
			}
		}

		if err := sendEskizSMS(phone, message); err != nil {
			if attempt == retries {
				return fmt.Errorf("attempt %d: failed to send SMS: %v", attempt, err)
			}
			// Retry by logging in again
			loggedIn = false
			continue
		}

		return nil // Success
	}

	return errors.New("exceeded maximum retries")
}
