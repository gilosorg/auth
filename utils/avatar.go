package utils

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxAvatarBytes     = 100 * 1024
	maxAvatarDimension = 2048
)

// NormalizePendingBlockKey converts a pending contact session value into the canonical
// identifier key checked by IsBlocked/ApplyBlock.
func NormalizePendingBlockKey(typ string, v interface{}) string {
	if typ == "phone" {
		if phone := ParsePhoneInterface(v); phone != 0 {
			return FormatPhone(phone)
		}
	}
	return strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
}

// ParsePhoneInterface converts a session-stored phone value (float64 from JSON,
// uint64, int, or formatted string) into a normalized uint64 phone number.
func ParsePhoneInterface(v interface{}) uint64 {
	switch val := v.(type) {
	case float64:
		if val < 0 || math.IsNaN(val) || math.IsInf(val, 0) {
			return 0
		}
		return uint64(math.Round(val))
	case int:
		if val < 0 {
			return 0
		}
		return uint64(val)
	case int64:
		if val < 0 {
			return 0
		}
		return uint64(val)
	case uint64:
		return val
	case string:
		parsed, err := ParsePhone(val)
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}

// SaveValidatedAvatarJPEG reads, validates, and re-encodes an uploaded JPEG avatar
// to strip metadata and reject malformed or oversized-dimension images before
// writing it to iconDir under a unique filename.
func SaveValidatedAvatarJPEG(r io.Reader, iconDir string, userID uint64) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxAvatarBytes+1))
	if err != nil {
		return "", errors.New("failed to read file")
	}
	if len(raw) == 0 {
		return "", errors.New("no file uploaded")
	}
	if len(raw) > maxAvatarBytes {
		return "", errors.New("file too large (max 100KB)")
	}

	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || format != "jpeg" {
		return "", errors.New("only valid JPG images are allowed")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxAvatarDimension || cfg.Height > maxAvatarDimension {
		return "", errors.New("image dimensions must be between 1x1 and 2048x2048")
	}

	img, err := jpeg.Decode(bytes.NewReader(raw))
	if err != nil {
		return "", errors.New("invalid or corrupted JPG image")
	}

	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, img, &jpeg.Options{Quality: 90}); err != nil {
		return "", errors.New("failed to encode JPG image")
	}

	if err := os.MkdirAll(iconDir, 0755); err != nil {
		return "", errors.New("failed to create storage directory")
	}

	suffix, err := GenerateRandomString(4)
	if err != nil {
		suffix = fmt.Sprintf("%d", time.Now().UnixNano()%100000)
	}
	filename := fmt.Sprintf("%d_%d_%s.jpg", userID, time.Now().Unix(), suffix)
	destPath := filepath.Join(iconDir, filename)

	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return "", errors.New("failed to create file on disk")
	}
	if _, err := out.Write(encoded.Bytes()); err != nil {
		_ = out.Close()
		_ = os.Remove(destPath)
		return "", errors.New("failed to save file")
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(destPath)
		return "", errors.New("failed to finalize saved file")
	}

	return filename, nil
}

// CleanupOldAvatars removes old avatar files for userID while preserving keepFilename.
func CleanupOldAvatars(iconDir string, userID uint64, keepFilename string) {
	pattern := filepath.Join(iconDir, fmt.Sprintf("%d_*.jpg", userID))
	oldFiles, _ := filepath.Glob(pattern)
	keepPath := filepath.Join(iconDir, keepFilename)
	for _, oldFile := range oldFiles {
		if oldFile != keepPath {
			_ = os.Remove(oldFile)
		}
	}
	_ = os.Remove(filepath.Join(iconDir, fmt.Sprintf("%d.jpg", userID)))
}
