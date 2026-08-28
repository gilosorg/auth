package utils

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"gilosauth/config"

	"github.com/nyaruka/phonenumbers"
)

// SendPhoneOTP sends an OTP via SMS to the specified phone number after validating it and checking country support.
func SendPhoneOTP(phone string, otp string) error {
	var num *phonenumbers.PhoneNumber
	var err error

	if strings.HasPrefix(phone, "+") {
		num, err = phonenumbers.Parse(phone, "")
	} else {
		num, err = phonenumbers.Parse(phone, "UZ")
	}
	if err != nil {
		return fmt.Errorf("invalid phone number: %v", err)
	}
	if !phonenumbers.IsValidNumber(num) {
		return errors.New("invalid phone number")
	}

	country := phonenumbers.GetRegionCodeForNumber(num)
	supportedCountries := []string{"UZ"} // Uzbekistan
	if !slices.Contains(supportedCountries, country) {
		return errors.New("country not supported")
	}

	// Format for Eskiz: international without +, no spaces or dashes
	formatted := strings.Replace(phonenumbers.Format(num, phonenumbers.E164), "+", "", 1)
	if !strings.HasPrefix(formatted, "998") && country == "UZ" {
		formatted = "998" + strings.TrimLeft(formatted, "0")
	}

	message := fmt.Sprintf("%s verification code: %s", config.AppName, otp)

	// Call country-specific sending method
	if country == "UZ" {
		return SendEskizSMSWithRetry(formatted, message, 3)
	}

	return errors.New("no SMS handler for country")
}
