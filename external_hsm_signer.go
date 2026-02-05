// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// ExternalHSMSigner implements crypto.Signer by delegating to an external HSM
type ExternalHSMSigner struct {
	publicKey crypto.PublicKey
	executor  *ExternalCommandExecutor
	config    *VoucherSigningConfig
	stationID string
}

// NewExternalHSMSigner creates a new external HSM signer
func NewExternalHSMSigner(publicKey crypto.PublicKey, executor *ExternalCommandExecutor, config *VoucherSigningConfig, stationID string) *ExternalHSMSigner {
	return &ExternalHSMSigner{
		publicKey: publicKey,
		executor:  executor,
		config:    config,
		stationID: stationID,
	}
}

// Public returns the public key
func (s *ExternalHSMSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign implements crypto.Signer by delegating to external HSM
func (s *ExternalHSMSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Generate unique request ID for tracing
	requestID := fmt.Sprintf("req-%d-%d", time.Now().UnixNano(), time.Now().UnixNano()/1000)

	// Debug: Check if publicKey is nil
	if s.publicKey == nil {
		return nil, fmt.Errorf("external signer has nil public key - this should not happen")
	}
	fmt.Printf("🔧 DEBUG: External HSM signer called with key type: %T\n", s.publicKey)

	// Create signing request for HSM
	hashFunc := "unknown"
	if opts != nil {
		hashFunc = opts.HashFunc().String()
	}

	request := HSMSigningRequest{
		Digest:               base64.StdEncoding.EncodeToString(digest),
		RequestID:            requestID,
		Timestamp:            time.Now().UTC(),
		ManufacturingStation: s.stationID,
		SigningOptions: map[string]interface{}{
			"hash":     hashFunc,
			"key_type": keyTypeToString(s.publicKey),
		},
	}

	// Marshal request to JSON
	requestData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HSM signing request: %w", err)
	}

	// Write request to temporary file
	requestFile, err := os.CreateTemp("", "hsm-signing-request-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp request file: %w", err)
	}
	defer func() {
		_ = os.Remove(requestFile.Name())
	}()

	if _, err := requestFile.Write(requestData); err != nil {
		return nil, fmt.Errorf("failed to write request file: %w", err)
	}
	if err := requestFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close request file: %w", err)
	}

	// Call external HSM
	var variables = map[string]string{
		"requestfile": requestFile.Name(),
		"requestid":   requestID,
		"station":     s.stationID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.config.ExternalTimeout)
	defer cancel()

	output, err := s.executor.Execute(ctx, variables)
	if err != nil {
		return nil, fmt.Errorf("HSM signing failed: %w", err)
	}

	// Parse HSM response
	var response HSMSigningResponse
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		return nil, fmt.Errorf("failed to parse HSM response: %w", err)
	}

	if response.Error != "" {
		return nil, fmt.Errorf("HSM signing error: %s", response.Error)
	}

	// Decode signature from base64
	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode HSM signature: %w", err)
	}

	fmt.Printf("✅ HSM signed digest: %s (%d bytes)\n", requestID, len(signature))
	return signature, nil
}

// HSMSigningRequest represents a request to external HSM for signing
type HSMSigningRequest struct {
	Digest               string                 `json:"digest"`
	RequestID            string                 `json:"request_id"`
	Timestamp            time.Time              `json:"timestamp"`
	ManufacturingStation string                 `json:"manufacturing_station"`
	SigningOptions       map[string]interface{} `json:"signing_options"`
}

// HSMSigningResponse represents a response from external HSM
type HSMSigningResponse struct {
	Signature string                 `json:"signature"`
	RequestID string                 `json:"request_id"`
	HSMInfo   map[string]interface{} `json:"hsm_info"`
	Error     string                 `json:"error"`
}

// keyTypeToString converts a public key to a string representation
func keyTypeToString(pubKey crypto.PublicKey) string {
	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%s", key.Params().Name)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", key.Size())
	default:
		return fmt.Sprintf("Unknown-%T", key)
	}
}
