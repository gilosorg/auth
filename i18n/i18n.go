package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	translations = make(map[string]map[string]string)
	mu           sync.RWMutex
)

// Init loads all translation files from the translations directory
func Init() error {
	dir := "i18n/translations"

	for _, lang := range languages {
		path := filepath.Join(dir, lang.Code+".json")
		if err := loadFile(lang.Code, path); err != nil {
			// Only error if it's the default language
			if lang.Code == DefaultLang {
				return fmt.Errorf("failed to load default language: %w", err)
			}
			// Log warning but continue for non-default languages
			fmt.Printf("Warning: translation file for '%s' not found\n", lang.Code)
		}
	}

	return nil
}

// loadFile loads a single translation JSON file
func loadFile(lang, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var data map[string]string
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return err
	}

	mu.Lock()
	translations[lang] = data
	mu.Unlock()

	return nil
}

// Translator provides translation functions for a specific language
type Translator struct {
	lang string
}

// New creates a Translator for the given language code
func New(lang string) *Translator {
	return &Translator{lang: NormalizeCode(lang)}
}

// T translates a key. Returns the key itself if translation not found.
// This enables graceful degradation - missing translations show the key.
func (tr *Translator) T(key string, args ...interface{}) string {
	mu.RLock()
	defer mu.RUnlock()

	// Try requested language
	if trans, ok := translations[tr.lang]; ok {
		if val, ok := trans[key]; ok {
			return format(val, args...)
		}
	}

	// Fallback to default language
	if tr.lang != DefaultLang {
		if trans, ok := translations[DefaultLang]; ok {
			if val, ok := trans[key]; ok {
				return format(val, args...)
			}
		}
	}

	// Return the key itself (humanized if possible)
	return humanize(key)
}

// Lang returns the current language code
func (tr *Translator) Lang() string {
	return tr.lang
}

// Current returns the Language struct for this translator
func (tr *Translator) Current() Language {
	return GetLanguage(tr.lang)
}

// All returns all supported languages
func (tr *Translator) All() []Language {
	return Languages()
}

// format applies sprintf formatting if args provided
func format(s string, args ...interface{}) string {
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// humanize converts a key like "resend_btn_text" to "Resend btn text"
func humanize(key string) string {
	// Replace underscores with spaces
	s := strings.ReplaceAll(key, "_", " ")
	// Capitalize first letter
	if len(s) > 0 {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// GetFromCookie extracts language from a cookie value
func GetFromCookie(value string) string {
	return NormalizeCode(value)
}

// GetTranslations returns the raw translation map for a language.
// Used by templates for direct key lookup via {{index .T "key"}}.
func GetTranslations(lang string) map[string]string {
	tr := New(lang)
	mu.RLock()
	defer mu.RUnlock()

	result := make(map[string]string)

	// Start with default language
	if def, ok := translations[DefaultLang]; ok {
		for k, v := range def {
			result[k] = v
		}
	}

	// Override with requested language
	if trans, ok := translations[tr.lang]; ok {
		for k, v := range trans {
			result[k] = v
		}
	}

	return result
}

