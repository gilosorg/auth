package utils

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateContactAndRedirectURIUserinfo(t *testing.T) {
	cleaned, typ, err := ValidateContact("  User.Name@Example.COM ")
	if err != nil {
		t.Fatalf("ValidateContact email failed: %v", err)
	}
	if cleaned != "user.name@example.com" || typ != "email" {
		t.Fatalf("ValidateContact got (%q, %q), want (user.name@example.com, email)", cleaned, typ)
	}

	cleanedPhone, pTyp, err := ValidateContact("+998901234567")
	if err != nil {
		t.Fatalf("ValidateContact phone failed: %v", err)
	}
	if cleanedPhone != "+998901234567" || pTyp != "phone" {
		t.Fatalf("ValidateContact phone got (%q, %q)", cleanedPhone, pTyp)
	}

	for _, bad := range []string{"", "not-an-email", "0012345", "abc@"} {
		if _, _, err := ValidateContact(bad); err == nil {
			t.Errorf("expected ValidateContact(%q) to fail", bad)
		}
	}

	for _, uri := range []string{
		"https://user:pass@app.example.com/cb",
		"https://user@app.example.com/cb",
	} {
		if err := ValidateRedirectURI(uri); err == nil {
			t.Errorf("expected ValidateRedirectURI(%q) with embedded userinfo to fail", uri)
		}
	}
}

func TestMaskPhoneBoundaries(t *testing.T) {
	cases := []struct {
		phone uint64
		want  string
	}{
		{0, ""},
		{1, "+***1"},
		{12, "+***12"},
		{1234, "+**34"},
		{12345, "+***45"},
		{123456, "+****56"},
		{998901234567, "+998******567"},
	}

	for _, tc := range cases {
		if got := MaskPhone(tc.phone); got != tc.want {
			t.Errorf("MaskPhone(%d) = %q, want %q", tc.phone, got, tc.want)
		}
	}
}

func TestParsePhoneInterfaceAndNormalizePendingBlockKey(t *testing.T) {
	if got := ParsePhoneInterface(float64(998901234567)); got != 998901234567 {
		t.Fatalf("float64 ParsePhoneInterface = %d", got)
	}
	if got := ParsePhoneInterface(uint64(998901234567)); got != 998901234567 {
		t.Fatalf("uint64 ParsePhoneInterface = %d", got)
	}
	if got := ParsePhoneInterface(int64(998901234567)); got != 998901234567 {
		t.Fatalf("int64 ParsePhoneInterface = %d", got)
	}
	if got := ParsePhoneInterface("+998901234567"); got != 998901234567 {
		t.Fatalf("string ParsePhoneInterface = %d", got)
	}
	if got := ParsePhoneInterface(-5); got != 0 {
		t.Fatalf("negative ParsePhoneInterface = %d, want 0", got)
	}
	if got := ParsePhoneInterface(math.NaN()); got != 0 {
		t.Fatalf("NaN ParsePhoneInterface = %d, want 0", got)
	}

	phoneKey := NormalizePendingBlockKey("phone", float64(998901234567))
	if phoneKey != "+998901234567" {
		t.Fatalf("NormalizePendingBlockKey(phone, float64) = %q, want +998901234567", phoneKey)
	}
	emailKey := NormalizePendingBlockKey("email", "  MixedCase@Example.COM ")
	if emailKey != "mixedcase@example.com" {
		t.Fatalf("NormalizePendingBlockKey(email) = %q, want mixedcase@example.com", emailKey)
	}
}

func TestSaveValidatedAvatarJPEGAndCleanup(t *testing.T) {
	iconDir := filepath.Join(t.TempDir(), "avatars")

	// Reject non-JPEG payload (PNG)
	var pngBuf bytes.Buffer
	smallImg := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			smallImg.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	if err := png.Encode(&pngBuf, smallImg); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	if _, err := SaveValidatedAvatarJPEG(&pngBuf, iconDir, 42); err == nil {
		t.Fatalf("expected PNG upload to be rejected")
	}

	// Reject empty payload
	if _, err := SaveValidatedAvatarJPEG(bytes.NewReader(nil), iconDir, 42); err == nil {
		t.Fatalf("expected empty upload to be rejected")
	}

	// Reject oversized byte payload (>100KB)
	if _, err := SaveValidatedAvatarJPEG(bytes.NewReader(make([]byte, 100*1024+1)), iconDir, 42); err == nil {
		t.Fatalf("expected >100KB upload to be rejected")
	}

	// Reject oversized dimension JPEG (>2048px wide)
	var wideBuf bytes.Buffer
	wideImg := image.NewRGBA(image.Rect(0, 0, 2049, 1))
	if err := jpeg.Encode(&wideBuf, wideImg, &jpeg.Options{Quality: 50}); err != nil {
		t.Fatalf("wide jpeg.Encode: %v", err)
	}
	if _, err := SaveValidatedAvatarJPEG(&wideBuf, iconDir, 42); err == nil {
		t.Fatalf("expected >2048px JPEG to be rejected")
	}

	// Accept valid JPEG with appended trailing bytes and re-encode cleanly without trailing payload
	var jpgBuf bytes.Buffer
	if err := jpeg.Encode(&jpgBuf, smallImg, &jpeg.Options{Quality: 85}); err != nil {
		t.Fatalf("jpeg.Encode: %v", err)
	}
	trailingMarker := []byte("APPENDED_METADATA_JUNK_SHOULD_BE_STRIPPED")
	jpgBuf.Write(trailingMarker)

	filename, err := SaveValidatedAvatarJPEG(&jpgBuf, iconDir, 42)
	if err != nil {
		t.Fatalf("SaveValidatedAvatarJPEG failed: %v", err)
	}
	if !strings.HasPrefix(filename, "42_") || !strings.HasSuffix(filename, ".jpg") {
		t.Fatalf("unexpected filename %q", filename)
	}

	savedBytes, err := os.ReadFile(filepath.Join(iconDir, filename))
	if err != nil {
		t.Fatalf("read saved avatar: %v", err)
	}
	if bytes.Contains(savedBytes, trailingMarker) {
		t.Fatalf("expected re-encoding to strip appended trailing bytes")
	}
	decoded, err := jpeg.Decode(bytes.NewReader(savedBytes))
	if err != nil {
		t.Fatalf("saved avatar is not valid JPEG: %v", err)
	}
	if decoded.Bounds().Dx() != 16 || decoded.Bounds().Dy() != 16 {
		t.Fatalf("decoded bounds = %v, want 16x16", decoded.Bounds())
	}

	// CleanupOldAvatars removes old user files and legacy <id>.jpg while keeping current file and other users' files
	oldVersion := filepath.Join(iconDir, "42_1000_old1.jpg")
	legacyFile := filepath.Join(iconDir, "42.jpg")
	otherFile := filepath.Join(iconDir, "99_1000_keep.jpg")
	for _, p := range []string{oldVersion, legacyFile, otherFile} {
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatalf("write fixture file %s: %v", p, err)
		}
	}

	CleanupOldAvatars(iconDir, 42, filename)

	if _, err := os.Stat(filepath.Join(iconDir, filename)); err != nil {
		t.Errorf("kept avatar %s was deleted: %v", filename, err)
	}
	if _, err := os.Stat(otherFile); err != nil {
		t.Errorf("other user's avatar %s was deleted: %v", otherFile, err)
	}
	if _, err := os.Stat(oldVersion); !os.IsNotExist(err) {
		t.Errorf("expected old avatar %s to be deleted", oldVersion)
	}
	if _, err := os.Stat(legacyFile); !os.IsNotExist(err) {
		t.Errorf("expected legacy avatar %s to be deleted", legacyFile)
	}
}

