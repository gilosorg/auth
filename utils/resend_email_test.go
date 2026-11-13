package utils

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"gilosauth/config"

	"github.com/resend/resend-go/v4"
)

func newTestResendClient(t *testing.T, serverURL string, apiKey string) *resend.Client {
	t.Helper()
	parsed, err := url.Parse(strings.TrimRight(serverURL, "/") + "/")
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	client := resend.NewCustomClient(&http.Client{Timeout: 2 * time.Second}, apiKey)
	client.BaseURL = parsed
	return client
}

func TestSendVerificationEmailUnconfigured(t *testing.T) {
	origKey, origFrom := config.ResendAPIKey, config.ResendFromEmail
	t.Cleanup(func() {
		config.ResendAPIKey = origKey
		config.ResendFromEmail = origFrom
	})

	config.ResendAPIKey = ""
	config.ResendFromEmail = ""

	if err := SendVerificationEmail("user@example.com", "123456"); err == nil {
		t.Fatal("expected error when RESEND_API_KEY and RESEND_FROM_EMAIL are unset")
	}

	config.ResendAPIKey = "re_test_key"
	config.ResendFromEmail = ""
	if err := SendVerificationEmail("user@example.com", "123456"); err == nil {
		t.Fatal("expected error when RESEND_FROM_EMAIL is unset")
	}
}

func TestSendVerificationEmailSuccessAndEscaping(t *testing.T) {
	type capturedRequest struct {
		AuthHeader     string
		IdempotencyKey string
		Method         string
		Path           string
		Body           struct {
			From    string       `json:"from"`
			To      []string     `json:"to"`
			Subject string       `json:"subject"`
			Html    string       `json:"html"`
			Text    string       `json:"text"`
			Tags    []resend.Tag `json:"tags"`
		}
	}

	var (
		mu       sync.Mutex
		captured capturedRequest
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		mu.Lock()
		captured.AuthHeader = r.Header.Get("Authorization")
		captured.IdempotencyKey = r.Header.Get("Idempotency-Key")
		captured.Method = r.Method
		captured.Path = r.URL.Path
		if err := json.Unmarshal(raw, &captured.Body); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"email_12345"}`))
	}))
	defer srv.Close()

	client := newTestResendClient(t, srv.URL, "re_test_secret_123")
	err := sendVerificationEmailWithRetry(
		context.Background(),
		client,
		"Gilos Auth <noreply@mail.gilos.org>",
		`Gilos & "Test"`,
		"user@example.com",
		"<482910>",
		"otp-verify/abc123",
		3,
		func(context.Context, time.Duration) error { return nil },
	)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if captured.Method != http.MethodPost || captured.Path != "/emails" {
		t.Fatalf("unexpected request %s %s", captured.Method, captured.Path)
	}
	if captured.AuthHeader != "Bearer re_test_secret_123" {
		t.Fatalf("unexpected Authorization header: %q", captured.AuthHeader)
	}
	if captured.IdempotencyKey != "otp-verify/abc123" {
		t.Fatalf("unexpected Idempotency-Key header: %q", captured.IdempotencyKey)
	}
	if captured.Body.From != "Gilos Auth <noreply@mail.gilos.org>" {
		t.Fatalf("unexpected From: %q", captured.Body.From)
	}
	if len(captured.Body.To) != 1 || captured.Body.To[0] != "user@example.com" {
		t.Fatalf("unexpected To: %v", captured.Body.To)
	}
	if !strings.Contains(captured.Body.Html, "Gilos &amp; &#34;Test&#34;") || !strings.Contains(captured.Body.Html, "&lt;482910&gt;") {
		t.Fatalf("HTML content was not properly escaped: %s", captured.Body.Html)
	}
	if !strings.Contains(captured.Body.Text, "<482910>") || !strings.Contains(captured.Body.Text, "5 minutes") {
		t.Fatalf("unexpected plain-text body: %s", captured.Body.Text)
	}
}

func TestSendVerificationEmailRetriesOn500And429WithSameIdempotencyKey(t *testing.T) {
	var (
		mu              sync.Mutex
		attempt         int
		idempotencyKeys []string
		recordedDelays  []time.Duration
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempt++
		cur := attempt
		idempotencyKeys = append(idempotencyKeys, r.Header.Get("Idempotency-Key"))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch cur {
		case 1:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"statusCode":500,"name":"application_error","message":"temporary upstream failure"}`))
		case 2:
			w.Header().Set("Retry-After", "2")
			w.Header().Set("X-RateLimit-Limit", "2")
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"statusCode":429,"name":"rate_limit_exceeded","message":"too many requests"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"email_retried_ok"}`))
		}
	}))
	defer srv.Close()

	client := newTestResendClient(t, srv.URL, "re_test_key")
	err := sendVerificationEmailWithRetry(
		context.Background(),
		client,
		"Gilos Auth <noreply@mail.gilos.org>",
		"Gilos Auth",
		"user@example.com",
		"654321",
		"otp-verify/fixed-key-999",
		3,
		func(_ context.Context, d time.Duration) error {
			recordedDelays = append(recordedDelays, d)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("expected retry sequence to succeed, got: %v", err)
	}

	if attempt != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempt)
	}
	for i, key := range idempotencyKeys {
		if key != "otp-verify/fixed-key-999" {
			t.Fatalf("attempt %d sent wrong Idempotency-Key: %q", i+1, key)
		}
	}
	if len(recordedDelays) != 2 {
		t.Fatalf("expected 2 backoff sleeps, got %d", len(recordedDelays))
	}
	if recordedDelays[0] != 500*time.Millisecond {
		t.Fatalf("expected initial 500ms backoff after 500, got %v", recordedDelays[0])
	}
	if recordedDelays[1] != 2*time.Second {
		t.Fatalf("expected 2s Retry-After delay after 429, got %v", recordedDelays[1])
	}
}

func TestSendVerificationEmailDoesNotRetryOn4xxClientError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "bad_request_400",
			statusCode: http.StatusBadRequest,
			body:       `{"statusCode":400,"name":"validation_error","message":"invalid recipient"}`,
		},
		{
			name:       "unprocessable_entity_422",
			statusCode: http.StatusUnprocessableEntity,
			body:       `{"statusCode":422,"name":"invalid_from_address","message":"domain not verified"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			sleepCalls := 0

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			client := newTestResendClient(t, srv.URL, "re_test_key")
			err := sendVerificationEmailWithRetry(
				context.Background(),
				client,
				"Gilos Auth <noreply@mail.gilos.org>",
				"Gilos Auth",
				"bad-email",
				"111222",
				"otp-verify/non-retry",
				3,
				func(context.Context, time.Duration) error {
					sleepCalls++
					return nil
				},
			)
			if err == nil {
				t.Fatal("expected error for 4xx response")
			}
			var apiErr *resend.ResendError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.statusCode {
				t.Fatalf("expected *resend.ResendError with status %d, got %v", tc.statusCode, err)
			}
			if attempts != 1 {
				t.Fatalf("expected exactly 1 attempt for non-retryable %d, got %d", tc.statusCode, attempts)
			}
			if sleepCalls != 0 {
				t.Fatalf("expected 0 retry sleeps for non-retryable %d, got %d", tc.statusCode, sleepCalls)
			}
		})
	}
}

