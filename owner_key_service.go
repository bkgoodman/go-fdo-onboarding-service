// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// OwnerKeyResponse is the expected JSON response from owner key service
type OwnerKeyResponse struct {
	OwnerKeyPEM string `json:"owner_key_pem"`
	Error       string `json:"error"`
}

// OwnerKeyService handles retrieval of owner keys for voucher sign-over
type OwnerKeyService struct {
	executor *ExternalCommandExecutor
}

// NewOwnerKeyService creates a new owner key service
func NewOwnerKeyService(executor *ExternalCommandExecutor) *OwnerKeyService {
	return &OwnerKeyService{
		executor: executor,
	}
}

// GetOwnerKey retrieves an owner key for the given device
func (o *OwnerKeyService) GetOwnerKey(ctx context.Context, serial, model string) (any, error) {
	variables := map[string]string{
		"serialno": serial,
		"model":    model,
		"guid":     "", // Not used for owner key retrieval
	}

	output, err := o.executor.Execute(ctx, variables)
	if err != nil {
		return nil, fmt.Errorf("failed to execute owner key command: %w", err)
	}

	// Parse JSON response
	var response OwnerKeyResponse
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		return nil, fmt.Errorf("failed to parse owner key response: %w", err)
	}

	if response.Error != "" {
		return nil, fmt.Errorf("owner key service error: %s", response.Error)
	}

	if response.OwnerKeyPEM == "" {
		return nil, fmt.Errorf("no owner key returned")
	}

	// Parse PEM key
	return parsePublicKeyFromPEM([]byte(response.OwnerKeyPEM))
}

// parsePublicKeyFromPEM parses a public key from PEM format
func parsePublicKeyFromPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try to parse as PKIX public key
	if block.Type == "PUBLIC KEY" {
		return parsePKIXPublicKey(block.Bytes)
	}

	// Try to parse as certificate
	if block.Type == "CERTIFICATE" {
		return parseCertificatePublicKey(block.Bytes)
	}

	return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
}

// parsePKIXPublicKey parses a PKIX public key
func parsePKIXPublicKey(data []byte) (any, error) {
	// Use x509.ParsePKIXPublicKey to parse the key
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	return pubKey, nil
}

// parseCertificatePublicKey parses a public key from a certificate
func parseCertificatePublicKey(data []byte) (any, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert.PublicKey, nil
}
