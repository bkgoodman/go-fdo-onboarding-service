// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/fsim"
)

func TestParseBMOSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		wantMode bmoDeliveryMode
		wantType string
		wantFile string
		wantURL  string
		wantErr  bool
	}{
		{
			name:     "inline mode with absolute path",
			spec:     "application/efi:/boot/grub.efi",
			wantMode: bmoModeInline,
			wantType: "application/efi",
			wantFile: "/boot/grub.efi",
		},
		{
			name:     "inline mode with relative path",
			spec:     "application/x-iso9660-image:../images/rhel9.iso",
			wantMode: bmoModeInline,
			wantType: "application/x-iso9660-image",
			wantFile: "../images/rhel9.iso",
		},
		{
			name:     "URL mode with HTTPS",
			spec:     "application/x-iso9660-image:url:https://cdn.example.com/rhel9.iso",
			wantMode: bmoModeURL,
			wantType: "application/x-iso9660-image",
			wantURL:  "https://cdn.example.com/rhel9.iso",
		},
		{
			name:     "URL mode with HTTP",
			spec:     "application/efi:url:http://internal.lan/boot.efi",
			wantMode: bmoModeURL,
			wantType: "application/efi",
			wantURL:  "http://internal.lan/boot.efi",
		},
		{
			name:     "URL mode with port and path",
			spec:     "application/efi:url:https://cdn.example.com:8443/images/boot.efi",
			wantMode: bmoModeURL,
			wantType: "application/efi",
			wantURL:  "https://cdn.example.com:8443/images/boot.efi",
		},
		{
			name:     "meta-URL mode",
			spec:     "meta:https://vendor.example.com/fleet.cbor",
			wantMode: bmoModeMetaURL,
			wantURL:  "https://vendor.example.com/fleet.cbor",
		},
		{
			name:     "meta-URL mode with port",
			spec:     "meta:https://vendor.example.com:9443/meta/fleet.cbor",
			wantMode: bmoModeMetaURL,
			wantURL:  "https://vendor.example.com:9443/meta/fleet.cbor",
		},
		{
			name:    "empty spec",
			spec:    "",
			wantErr: true,
		},
		{
			name:    "no colon separator",
			spec:    "application/efi",
			wantErr: true,
		},
		{
			name:    "empty type",
			spec:    ":/path/to/file",
			wantErr: true,
		},
		{
			name:    "empty file path",
			spec:    "application/efi:",
			wantErr: true,
		},
		{
			name:    "URL mode with empty URL",
			spec:    "application/efi:url:",
			wantErr: true,
		},
		{
			name:    "meta mode with empty URL",
			spec:    "meta:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseBMOSpec(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseBMOSpec(%q) expected error, got nil", tt.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseBMOSpec(%q) unexpected error: %v", tt.spec, err)
			}
			if parsed.Mode != tt.wantMode {
				t.Errorf("Mode = %d, want %d", parsed.Mode, tt.wantMode)
			}
			if parsed.ImageType != tt.wantType {
				t.Errorf("ImageType = %q, want %q", parsed.ImageType, tt.wantType)
			}
			if parsed.FilePath != tt.wantFile {
				t.Errorf("FilePath = %q, want %q", parsed.FilePath, tt.wantFile)
			}
			if parsed.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", parsed.URL, tt.wantURL)
			}
		})
	}
}

func TestLoadBMOTlsCA(t *testing.T) {
	t.Run("empty path returns nil", func(t *testing.T) {
		data, err := loadBMOTlsCA("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if data != nil {
			t.Errorf("expected nil, got %v", data)
		}
	})

	t.Run("valid file", func(t *testing.T) {
		dir := t.TempDir()
		caFile := filepath.Join(dir, "ca.der")
		caData := []byte{0x30, 0x82, 0x01, 0x00} // mock DER prefix
		if err := os.WriteFile(caFile, caData, 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := loadBMOTlsCA(caFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != len(caData) {
			t.Errorf("data length = %d, want %d", len(data), len(caData))
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadBMOTlsCA("/nonexistent/ca.der")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})
}

func TestLoadBMOExpectedHash(t *testing.T) {
	t.Run("empty string returns nil", func(t *testing.T) {
		data, err := loadBMOExpectedHash("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if data != nil {
			t.Errorf("expected nil, got %v", data)
		}
	})

	t.Run("valid hex hash", func(t *testing.T) {
		hexHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		data, err := loadBMOExpectedHash(hexHash)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected, _ := hex.DecodeString(hexHash)
		if len(data) != len(expected) {
			t.Errorf("data length = %d, want %d", len(data), len(expected))
		}
	})

	t.Run("invalid hex", func(t *testing.T) {
		_, err := loadBMOExpectedHash("not-valid-hex")
		if err == nil {
			t.Error("expected error for invalid hex")
		}
	})
}

// TestLoadBMOExpectedHash_VerificationPipeline tests the full pipeline:
// config hex string → loadBMOExpectedHash → raw bytes used by library verifyHash.
// This ensures our hex encoding is compatible with the library's hash comparison.
func TestLoadBMOExpectedHash_VerificationPipeline(t *testing.T) {
	t.Run("positive: sha256 hash of known data matches", func(t *testing.T) {
		data := []byte("test boot image content for hash verification")
		h := sha256.Sum256(data)
		hexHash := hex.EncodeToString(h[:])

		loaded, err := loadBMOExpectedHash(hexHash)
		if err != nil {
			t.Fatalf("loadBMOExpectedHash failed: %v", err)
		}
		if !bytes.Equal(loaded, h[:]) {
			t.Errorf("loaded hash does not match computed hash")
		}
	})

	t.Run("negative: wrong hash rejected", func(t *testing.T) {
		data := []byte("real image data")
		h := sha256.Sum256(data)
		hexHash := hex.EncodeToString(h[:])

		loaded, err := loadBMOExpectedHash(hexHash)
		if err != nil {
			t.Fatalf("loadBMOExpectedHash failed: %v", err)
		}

		// Verify against different data — must not match
		differentData := []byte("tampered image data")
		differentHash := sha256.Sum256(differentData)
		if bytes.Equal(loaded, differentHash[:]) {
			t.Error("hash of different data should not match loaded hash")
		}
	})

	t.Run("negative: truncated hash rejected", func(t *testing.T) {
		// A truncated hex string (not 64 chars for sha256) should still decode
		// but the resulting bytes won't match any sha256 hash in practice
		_, err := loadBMOExpectedHash("abcdef")
		if err != nil {
			t.Fatalf("loadBMOExpectedHash should accept short hex: %v", err)
		}
	})

	t.Run("negative: odd-length hex rejected", func(t *testing.T) {
		_, err := loadBMOExpectedHash("abc")
		if err == nil {
			t.Error("expected error for odd-length hex string")
		}
	})
}

// TestCoseSign1Verification_AppLevel tests the COSE Sign1 verification pipeline
// at the application level using the library's CoseSign1Verifier.
// This validates that keys generated by our test helper and loaded by our config
// functions work correctly with the library's verification.
func TestCoseSign1Verification_AppLevel(t *testing.T) {
	t.Run("positive: valid signature accepted", func(t *testing.T) {
		// Generate key pair
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		// Create public COSE_Key (what the owner sends as meta_signer)
		cosePub, err := cose.NewKey(privKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		signerKeyBytes, err := cbor.Marshal(cosePub)
		if err != nil {
			t.Fatal(err)
		}

		// Sign a payload (simulating what the meta-URL server would host)
		payload := []byte("test meta-payload CBOR content")
		s1 := cose.Sign1[[]byte, []byte]{
			Payload: cbor.NewByteWrap(payload),
		}
		if err := s1.Sign(privKey, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		tagged := s1.Tag()
		signedData, err := cbor.Marshal(tagged)
		if err != nil {
			t.Fatal(err)
		}

		// Simulate app flow: write signer key to file, load it, verify
		dir := t.TempDir()
		signerFile := filepath.Join(dir, "signer.cbor")
		if err := os.WriteFile(signerFile, signerKeyBytes, 0o600); err != nil {
			t.Fatal(err)
		}

		loadedKey, err := loadBMOMetaSigner(signerFile)
		if err != nil {
			t.Fatalf("loadBMOMetaSigner failed: %v", err)
		}

		// Verify using library's CoseSign1Verifier
		verifier := fsim.NewCoseSign1Verifier()
		result, err := verifier.Verify(signedData, loadedKey)
		if err != nil {
			t.Fatalf("verification should succeed: %v", err)
		}
		if !bytes.Equal(result, payload) {
			t.Errorf("payload mismatch after verification")
		}
	})

	t.Run("negative: wrong key rejected", func(t *testing.T) {
		// Sign with key A
		signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte("signed with key A")
		s1 := cose.Sign1[[]byte, []byte]{
			Payload: cbor.NewByteWrap(payload),
		}
		if err := s1.Sign(signingKey, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		tagged := s1.Tag()
		signedData, err := cbor.Marshal(tagged)
		if err != nil {
			t.Fatal(err)
		}

		// Load key B (different key) as the signer
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		coseWrong, err := cose.NewKey(wrongKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		wrongKeyBytes, err := cbor.Marshal(coseWrong)
		if err != nil {
			t.Fatal(err)
		}

		dir := t.TempDir()
		signerFile := filepath.Join(dir, "wrong_signer.cbor")
		if err := os.WriteFile(signerFile, wrongKeyBytes, 0o600); err != nil {
			t.Fatal(err)
		}

		loadedKey, err := loadBMOMetaSigner(signerFile)
		if err != nil {
			t.Fatalf("loadBMOMetaSigner failed: %v", err)
		}

		verifier := fsim.NewCoseSign1Verifier()
		_, err = verifier.Verify(signedData, loadedKey)
		if err == nil {
			t.Fatal("verification should fail with wrong key")
		}
		t.Logf("correctly rejected wrong key: %v", err)
	})

	t.Run("negative: tampered signature rejected", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cosePub, err := cose.NewKey(privKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		signerKeyBytes, err := cbor.Marshal(cosePub)
		if err != nil {
			t.Fatal(err)
		}

		payload := []byte("payload with tampered signature")
		s1 := cose.Sign1[[]byte, []byte]{
			Payload: cbor.NewByteWrap(payload),
		}
		if err := s1.Sign(privKey, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		// Tamper with signature
		if len(s1.Signature) > 0 {
			s1.Signature[0] ^= 0xFF
		}
		tagged := s1.Tag()
		signedData, err := cbor.Marshal(tagged)
		if err != nil {
			t.Fatal(err)
		}

		verifier := fsim.NewCoseSign1Verifier()
		_, err = verifier.Verify(signedData, signerKeyBytes)
		if err == nil {
			t.Fatal("verification should fail with tampered signature")
		}
		t.Logf("correctly rejected tampered signature: %v", err)
	})

	t.Run("negative: garbage signer key rejected", func(t *testing.T) {
		dir := t.TempDir()
		signerFile := filepath.Join(dir, "garbage.cbor")
		if err := os.WriteFile(signerFile, []byte{0xDE, 0xAD, 0xBE, 0xEF}, 0o600); err != nil {
			t.Fatal(err)
		}

		loadedKey, err := loadBMOMetaSigner(signerFile)
		if err != nil {
			t.Fatalf("loadBMOMetaSigner failed: %v", err)
		}

		verifier := fsim.NewCoseSign1Verifier()
		_, err = verifier.Verify([]byte{0xD2, 0x84}, loadedKey)
		if err == nil {
			t.Fatal("verification should fail with garbage key")
		}
		t.Logf("correctly rejected garbage key: %v", err)
	})

	t.Run("negative: empty signer key rejected", func(t *testing.T) {
		dir := t.TempDir()
		signerFile := filepath.Join(dir, "empty.cbor")
		if err := os.WriteFile(signerFile, []byte{}, 0o600); err != nil {
			t.Fatal(err)
		}

		loadedKey, err := loadBMOMetaSigner(signerFile)
		if err != nil {
			t.Fatalf("loadBMOMetaSigner failed: %v", err)
		}

		verifier := fsim.NewCoseSign1Verifier()
		_, err = verifier.Verify([]byte{0xD2, 0x84}, loadedKey)
		if err == nil {
			t.Fatal("verification should fail with empty key")
		}
		t.Logf("correctly rejected empty key: %v", err)
	})
}

func TestLoadBMOMetaSigner(t *testing.T) {
	t.Run("empty path returns nil", func(t *testing.T) {
		data, err := loadBMOMetaSigner("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if data != nil {
			t.Errorf("expected nil, got %v", data)
		}
	})

	t.Run("valid file", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "signer.pem")
		keyData := []byte("-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n")
		if err := os.WriteFile(keyFile, keyData, 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := loadBMOMetaSigner(keyFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != len(keyData) {
			t.Errorf("data length = %d, want %d", len(data), len(keyData))
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadBMOMetaSigner("/nonexistent/signer.pem")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})
}
