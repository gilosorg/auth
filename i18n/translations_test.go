package i18n

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTranslationFilesParityAndNoDuplicates(t *testing.T) {
	langs := []string{"en", "ru", "uz"}
	maps := make(map[string]map[string]string, len(langs))

	for _, code := range langs {
		path := filepath.Join("translations", code+".json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed reading %s: %v", path, err)
		}

		// Verify strict JSON object with zero duplicate keys
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		tok, err := dec.Token()
		if err != nil || tok != json.Delim('{') {
			t.Fatalf("%s does not start with JSON object: %v", path, err)
		}

		entries := make(map[string]string)
		for dec.More() {
			kTok, err := dec.Token()
			if err != nil {
				t.Fatalf("%s key parse error: %v", path, err)
			}
			key, ok := kTok.(string)
			if !ok {
				t.Fatalf("%s non-string key %T", path, kTok)
			}
			if _, exists := entries[key]; exists {
				t.Errorf("%s contains duplicate key %q", path, key)
			}
			var val string
			if err := dec.Decode(&val); err != nil {
				t.Fatalf("%s value parse error for %q: %v", path, key, err)
			}
			if strings.TrimSpace(val) == "" {
				t.Errorf("%s has empty translation value for %q", path, key)
			}
			entries[key] = val
		}
		maps[code] = entries
	}

	base := maps["en"]
	for _, code := range []string{"ru", "uz"} {
		other := maps[code]
		for k := range base {
			if _, ok := other[k]; !ok {
				t.Errorf("%s is missing key %q present in en", code, k)
			}
		}
		for k := range other {
			if _, ok := base[k]; !ok {
				t.Errorf("%s has extra key %q missing from en", code, k)
			}
		}
		if len(other) != len(base) {
			t.Errorf("%s key count %d != en key count %d", code, len(other), len(base))
		}
	}
}

func TestTranslatorInitAndLookup(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(".."); err != nil {
		t.Fatalf("Chdir repo root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	if err := Init(); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}

	for _, code := range []string{"en", "ru", "uz"} {
		tr := New(code)
		if tr.Lang() != code {
			t.Errorf("expected lang %q, got %q", code, tr.Lang())
		}
		if got := tr.T("signed_in_as", "alice"); got == "" || strings.Contains(got, "signed_in_as") {
			t.Errorf("unexpected T output for %q signed_in_as: %q", code, got)
		}
	}
}

