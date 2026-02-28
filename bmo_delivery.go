// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// bmoDeliveryMode represents the parsed delivery mode of a BMO spec entry.
type bmoDeliveryMode int

const (
	bmoModeInline  bmoDeliveryMode = 0
	bmoModeURL     bmoDeliveryMode = 1
	bmoModeMetaURL bmoDeliveryMode = 2
)

// parsedBMOSpec represents a parsed BMO specification entry.
type parsedBMOSpec struct {
	Mode      bmoDeliveryMode
	ImageType string // MIME type (inline/URL modes)
	FilePath  string // local file path (inline mode only)
	URL       string // remote URL (URL/meta-URL modes)
}

// parseBMOSpec parses a single bmo_files entry into its components.
//
// Supported formats:
//   - "type:/path/to/file"           → inline mode
//   - "type:url:https://..."         → URL mode
//   - "meta:https://..."             → meta-URL mode
func parseBMOSpec(spec string) (parsedBMOSpec, error) {
	// Check for meta-URL mode: "meta:https://..."
	if strings.HasPrefix(spec, "meta:") {
		metaURL := strings.TrimPrefix(spec, "meta:")
		if metaURL == "" {
			return parsedBMOSpec{}, fmt.Errorf("invalid BMO meta specification %q: missing URL", spec)
		}
		return parsedBMOSpec{
			Mode: bmoModeMetaURL,
			URL:  metaURL,
		}, nil
	}

	// Split into type and remainder
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return parsedBMOSpec{}, fmt.Errorf("invalid BMO specification %q: expected type:file, type:url:URL, or meta:URL format", spec)
	}

	imageType := parts[0]
	remainder := parts[1]

	// Check for URL mode: remainder starts with "url:"
	if strings.HasPrefix(remainder, "url:") {
		imageURL := strings.TrimPrefix(remainder, "url:")
		if imageURL == "" {
			return parsedBMOSpec{}, fmt.Errorf("invalid BMO URL specification %q: missing URL after 'url:'", spec)
		}
		return parsedBMOSpec{
			Mode:      bmoModeURL,
			ImageType: imageType,
			URL:       imageURL,
		}, nil
	}

	// Default: inline mode — remainder is a file path
	return parsedBMOSpec{
		Mode:      bmoModeInline,
		ImageType: imageType,
		FilePath:  remainder,
	}, nil
}

// loadBMOTlsCA loads a DER-encoded CA certificate from the given file path.
// Returns nil if path is empty.
func loadBMOTlsCA(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read BMO TLS CA cert %q: %w", path, err)
	}
	return data, nil
}

// loadBMOExpectedHash parses a hex-encoded hash string into raw bytes.
// Returns nil if input is empty.
func loadBMOExpectedHash(hexHash string) ([]byte, error) {
	if hexHash == "" {
		return nil, nil
	}
	hash, err := hex.DecodeString(hexHash)
	if err != nil {
		return nil, fmt.Errorf("invalid BMO expected hash %q: %w", hexHash, err)
	}
	return hash, nil
}

// loadBMOMetaSigner loads a COSE_Key from the given file path.
// Returns nil if path is empty.
func loadBMOMetaSigner(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read BMO meta signer key %q: %w", path, err)
	}
	return data, nil
}
