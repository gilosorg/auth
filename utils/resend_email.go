package utils

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gilosauth/config"

	"github.com/resend/resend-go/v4"
)

const (
	resendMaxAttempts    = 3
	resendInitialBackoff = 500 * time.Millisecond
	resendMaxRetryDelay  = 10 * time.Second
	resendRequestTimeout = 10 * time.Second
	resendTotalTimeout   = 35 * time.Second
)

type emailSleepFunc func(ctx context.Context, d time.Duration) error

var defaultResendHTTPClient = &http.Client{
	Timeout: resendRequestTimeout,
}

// SendVerificationEmail sends a one-time verification code email via Resend.
func SendVerificationEmail(toEmail, code string) error {
	apiKey := strings.TrimSpace(config.ResendAPIKey)
	fromEmail := strings.TrimSpace(config.ResendFromEmail)
	if apiKey == "" || fromEmail == "" {
		log.Printf("WARNING: Resend email provider is not configured (RESEND_API_KEY / RESEND_FROM_EMAIL missing)")
		return errors.New("email provider is not configured")
	}

	recipient := strings.TrimSpace(toEmail)
	verificationCode := strings.TrimSpace(code)
	if recipient == "" || verificationCode == "" {
		return errors.New("recipient email and verification code are required")
	}

	appName := strings.TrimSpace(config.AppName)
	if appName == "" {
		appName = "Auth"
	}

	idempotencyKey, err := newEmailIdempotencyKey("otp-verify")
	if err != nil {
		return fmt.Errorf("failed to generate idempotency key: %w", err)
	}

	client := resend.NewCustomClient(defaultResendHTTPClient, apiKey)
	ctx, cancel := context.WithTimeout(context.Background(), resendTotalTimeout)
	defer cancel()

	return sendVerificationEmailWithRetry(
		ctx,
		client,
		fromEmail,
		appName,
		recipient,
		verificationCode,
		idempotencyKey,
		resendMaxAttempts,
		sleepWithContext,
	)
}

func sendVerificationEmailWithRetry(
	ctx context.Context,
	client *resend.Client,
	fromEmail, appName, toEmail, code, idempotencyKey string,
	maxAttempts int,
	sleepFn emailSleepFunc,
) error {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if sleepFn == nil {
		sleepFn = sleepWithContext
	}

	params := buildVerificationEmail(fromEmail, appName, toEmail, code)
	opts := &resend.SendEmailOptions{IdempotencyKey: idempotencyKey}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		sent, err := client.Emails.SendWithOptions(ctx, params, opts)
		if err == nil {
			emailID := ""
			if sent != nil {
				emailID = sent.Id
			}
			log.Printf("Verification email sent via Resend to %s (id=%s)", MaskEmail(toEmail), emailID)
			return nil
		}

		lastErr = err
		if ctx.Err() != nil {
			return err
		}

		shouldRetry, delay := classifyResendRetry(err, attempt)
		if !shouldRetry || attempt == maxAttempts-1 {
			log.Printf("ERROR: Resend email delivery failed for %s (attempt %d/%d): %v", MaskEmail(toEmail), attempt+1, maxAttempts, err)
			return err
		}

		log.Printf("WARNING: Resend email delivery attempt %d/%d failed for %s (%v); retrying in %s", attempt+1, maxAttempts, MaskEmail(toEmail), err, delay)
		if sleepErr := sleepFn(ctx, delay); sleepErr != nil {
			return sleepErr
		}
	}

	return lastErr
}

func buildVerificationEmail(fromEmail, appName, toEmail, code string) *resend.SendEmailRequest {
	safeAppName := html.EscapeString(appName)
	safeCode := html.EscapeString(code)

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s Verification Code</title>
</head>
<body style="margin:0;padding:0;background-color:#F5F5F7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1D1D1F;">
  <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="padding:36px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="max-width:460px;background-color:#FFFFFF;border:1px solid #DCDCE2;border-top:3px solid #2495F2;border-radius:0px;padding:32px;">
          <tr>
            <td style="font-size:17px;font-weight:700;letter-spacing:-0.02em;color:#1D1D1F;padding-bottom:14px;border-bottom:1px solid #EAEAEF;">%s</td>
          </tr>
          <tr>
            <td style="font-size:15px;line-height:24px;color:#48484E;padding:18px 0 18px;">
              Use the following verification code to continue:
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:18px 24px;background-color:#F2F2F5;border:1px solid #DCDCE2;border-radius:0px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:32px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:8px;color:#1D1D1F;">
              %s
            </td>
          </tr>
          <tr>
            <td style="font-size:13px;line-height:20px;color:#6C6C75;padding-top:18px;">
              This code expires in 5 minutes. If you did not request this code, you can safely ignore this email.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`, safeAppName, safeAppName, safeCode)

	textBody := fmt.Sprintf(
		"%s Verification Code\n\nUse the following verification code to continue:\n\n%s\n\nThis code expires in 5 minutes. If you did not request this code, you can safely ignore this email.\n",
		appName,
		code,
	)

	return &resend.SendEmailRequest{
		From:    fromEmail,
		To:      []string{toEmail},
		Subject: fmt.Sprintf("%s verification code", appName),
		Html:    htmlBody,
		Text:    textBody,
		Tags: []resend.Tag{
			{Name: "category", Value: "verification_otp"},
		},
	}
}

func classifyResendRetry(err error, attempt int) (bool, time.Duration) {
	backoff := resendInitialBackoff << attempt
	if backoff > resendMaxRetryDelay {
		backoff = resendMaxRetryDelay
	}

	var rateErr *resend.RateLimitError
	if errors.As(err, &rateErr) {
		if sec, parseErr := strconv.Atoi(strings.TrimSpace(rateErr.RetryAfter)); parseErr == nil && sec > 0 {
			delay := time.Duration(sec) * time.Second
			if delay > resendMaxRetryDelay {
				delay = resendMaxRetryDelay
			}
			return true, delay
		}
		return true, backoff
	}

	var apiErr *resend.ResendError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= http.StatusInternalServerError {
			return true, backoff
		}
		return false, 0
	}

	var missingErr *resend.MissingRequiredFieldsError
	if errors.As(err, &missingErr) {
		return false, 0
	}

	// Transport/network failures may recover on retry.
	return true, backoff
}

func newEmailIdempotencyKey(prefix string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s", prefix, hex.EncodeToString(buf)), nil
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

