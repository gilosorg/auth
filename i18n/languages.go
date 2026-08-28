package i18n

import "strings"

// Language represents a supported language with BCP 47 standard compliance
type Language struct {
	Code    string   `json:"code"` // ISO 639-1 code (e.g., "en", "uz")
	Name    string   `json:"name"` // Native name (e.g., "English", "O'zbek")
	Flag    string   `json:"flag"` // Flag URL path
	Aliases []string `json:"-"`    // Alternative codes that map to this language
}

// Supported languages - English (default), Uzbek, and Russian
var languages = []Language{
	{
		Code:    "en",
		Name:    "English",
		Flag:    "/static/img/i18n/gb.svg",
		Aliases: []string{"en-us", "en-gb", "en-au", "en-ca"},
	},
	{
		Code:    "uz",
		Name:    "O'zbek",
		Flag:    "/static/img/i18n/uz.svg",
		Aliases: []string{"uz-latn", "uz-cyrl", "uz-uz"},
	},
	{
		Code:    "ru",
		Name:    "Русский",
		Flag:    "/static/img/i18n/ru.svg",
		Aliases: []string{"ru-ru"},
	},
}

// DefaultLang is the fallback language code
const DefaultLang = "en"

// Languages returns all supported languages
func Languages() []Language {
	return languages
}

// GetLanguage returns the Language struct for a given code, or default if not found
func GetLanguage(code string) Language {
	code = NormalizeCode(code)
	for _, lang := range languages {
		if lang.Code == code {
			return lang
		}
	}
	return languages[0] // English default
}

// NormalizeCode converts any language code variant to our standard code
func NormalizeCode(code string) string {
	if code == "" {
		return DefaultLang
	}

	code = strings.ToLower(strings.TrimSpace(code))

	// Direct match
	for _, lang := range languages {
		if lang.Code == code {
			return lang.Code
		}
		for _, alias := range lang.Aliases {
			if alias == code {
				return lang.Code
			}
		}
	}

	// Prefix match (e.g., "en-US" -> "en")
	for _, lang := range languages {
		if strings.HasPrefix(code, lang.Code+"-") || strings.HasPrefix(code, lang.Code+"_") {
			return lang.Code
		}
	}

	return DefaultLang
}

// IsSupported checks if a language code is supported
func IsSupported(code string) bool {
	normalized := NormalizeCode(code)
	for _, lang := range languages {
		if lang.Code == normalized {
			return true
		}
	}
	return false
}
