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
	eskizToken      string
	loggedIn        bool
	mutex           sync.RWMutex
	loginMu         sync.Mutex
	eskizHTTPClient = &http.Client{Timeout: 10 * time.Second}
)

type eskizStatusError struct {
	statusCode int
	body       string
}

func (e *eskizStatusError) Error() string {
	return fmt.Sprintf("SMS sending failed with status %d: %s", e.statusCode, e.body)
}

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

// login authenticates with the Eskiz API and updates the token without holding mutex across network I/O.
func login() error {
	if config.EskizEmail == "" || config.EskizPassword == "" {
		return errors.New("SMS provider credentials are not configured")
	}

	loginMu.Lock()
	defer loginMu.Unlock()

	if isEskizLoggedIn() {
		return nil
	}

	payload := map[string]string{
		"email":    config.EskizEmail,
		"password": config.EskizPassword,
	}
	data, _ := json.Marshal(payload)

	resp, err := eskizHTTPClient.Post("https://notify.eskiz.uz/api/auth/login", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	var loginResp LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return fmt.Errorf("failed to parse login response: %v", err)
	}

	mutex.Lock()
	eskizToken = loginResp.Data.Token
	loggedIn = true
	mutex.Unlock()
	return nil
}

// getEskizToken reads the token under a read lock for thread safety.
func getEskizToken() string {
	mutex.RLock()
	defer mutex.RUnlock()
	return eskizToken
}

func isEskizLoggedIn() bool {
	mutex.RLock()
	defer mutex.RUnlock()
	return loggedIn
}

func invalidateEskizSession() {
	mutex.Lock()
	defer mutex.Unlock()
	loggedIn = false
	eskizToken = ""
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

	resp, err := eskizHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SMS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &eskizStatusError{statusCode: resp.StatusCode, body: string(body)}
	}

	return nil
}

// SendEskizSMSWithRetry attempts to send an SMS with retries.
func SendEskizSMSWithRetry(phone, message string, retries int) error {
	if retries <= 0 {
		retries = 1
	}
	for attempt := 1; attempt <= retries; attempt++ {
		if !isEskizLoggedIn() {
			if err := login(); err != nil {
				return fmt.Errorf("attempt %d: login failed: %v", attempt, err)
			}
		}

		if err := sendEskizSMS(phone, message); err != nil {
			if attempt == retries {
				return fmt.Errorf("attempt %d: failed to send SMS: %v", attempt, err)
			}
			// Re-authenticate only on expired/unauthorized bearer token (HTTP 401)
			var statusErr *eskizStatusError
			if errors.As(err, &statusErr) {
				if statusErr.statusCode == http.StatusUnauthorized {
					invalidateEskizSession()
					continue
				}
				if statusErr.statusCode >= 400 && statusErr.statusCode < 500 {
					return err
				}
			}
			continue
		}

		return nil // Success
	}

	return errors.New("exceeded maximum retries")
}
