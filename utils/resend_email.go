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
		appName = "Gilos Auth"
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
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>%s Verification Code</title>
<style>
  :root { color-scheme: light dark; supported-color-schemes: light dark; }
  @media (prefers-color-scheme: dark) {
    .email-bg { background-color: #202020 !important; }
    .email-card { background-color: #2B2B2B !important; border-color: #3D3D3D !important; }
    .email-head { color: #FFFFFF !important; border-bottom-color: #383838 !important; }
    .email-body { color: #D4D4D4 !important; }
    .email-code { background-color: #202020 !important; border-color: #454545 !important; color: #60CDFF !important; }
    .email-foot { color: #B4B4B4 !important; border-top-color: #3D3D3D !important; }
  }
</style>
</head>
<body class="email-bg" style="margin:0;padding:0;background-color:#F3F3F3;font-family:'Segoe UI Variable','Segoe UI',Inter,-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;color:#1B1B1B;">
  <table role="presentation" width="100%%" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center" style="padding:36px 16px;">
        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" class="email-card" style="max-width:460px;background-color:#FFFFFF;border:1px solid #E5E5E5;border-radius:8px;overflow:hidden;">
          <tr>
            <td style="padding:28px 32px;">
              <table role="presentation" width="100%%" cellspacing="0" cellpadding="0">
                <tr>
                  <td class="email-head" style="font-size:16px;font-weight:600;letter-spacing:-0.015em;color:#1B1B1B;padding-bottom:14px;border-bottom:1px solid #EFEFEF;">%s</td>
                </tr>
                <tr>
                  <td class="email-body" style="font-size:14px;line-height:22px;color:#3B3B3B;padding:18px 0 16px 0;">
                    Enter this one-time verification code to confirm your action:
                  </td>
                </tr>
                <tr>
                  <td align="center" class="email-code" style="padding:18px 20px 18px 28px;background-color:#F9F9F9;border:1px solid #E0E0E0;border-radius:6px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:32px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:8px;color:#005FB8;">
                    %s
                  </td>
                </tr>
                <tr>
                  <td style="height:18px;font-size:0;line-height:0;">&nbsp;</td>
                </tr>
                <tr>
                  <td class="email-foot" style="font-size:12px;line-height:18px;color:#616161;padding-top:16px;border-top:1px solid #EFEFEF;">
                    This code expires in 5 minutes and can only be used once. Never share it with anyone.<br>
                    Sent automatically by auth.gilos.org &middot; Need help? Contact info@gilos.org.
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`, safeAppName, safeAppName, safeCode)

	textBody := fmt.Sprintf(
		"%s Verification Code\n\nEnter this one-time verification code to confirm your action:\n\n%s\n\nThis code expires in 5 minutes and can only be used once. Never share it with anyone.\nSent by auth.gilos.org | Support: info@gilos.org\n",
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

