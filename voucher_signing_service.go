// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// VoucherSigningRequest represents a voucher signing request to external HSM
type VoucherSigningRequest struct {
	Voucher              string         `json:"voucher"`               // base64-encoded CBOR voucher
	OwnerKey             string         `json:"owner_key"`             // PEM-encoded public key
	RequestID            string         `json:"request_id"`            // Unique request identifier
	Timestamp            time.Time      `json:"timestamp"`             // Request timestamp
	ManufacturingStation string         `json:"manufacturing_station"` // Station identifier
	DeviceInfo           DeviceInfo     `json:"device_info"`           // Device details
	OVEExtraData         map[int][]byte `json:"ove_extra_data,omitempty"`
}

// DeviceInfo contains device details for logging/auditing
type DeviceInfo struct {
	SerialNo string `json:"serialno"`
	Model    string `json:"model"`
}

// VoucherSigningResponse represents the JSON response from external HSM
type VoucherSigningResponse struct {
	SignedVoucher string  `json:"signed_voucher"` // base64-encoded CBOR signed voucher
	RequestID     string  `json:"request_id"`     // Echoed request ID
	HSMInfo       HSMInfo `json:"hsm_info"`       // HSM signing details
	Error         string  `json:"error"`          // Error message if any
}

// HSMInfo contains HSM signing details
type HSMInfo struct {
	HSMID       string    `json:"hsm_id"`
	SigningTime time.Time `json:"signing_time"`
	KeyID       string    `json:"key_id"`
}

// VoucherSigningService handles voucher signing operations
type VoucherSigningService struct {
	config    *VoucherSigningConfig
	executor  *ExternalCommandExecutor
	stationID string
}

// NewVoucherSigningService creates a new voucher signing service
func NewVoucherSigningService(config *VoucherSigningConfig, executor *ExternalCommandExecutor, stationID string) *VoucherSigningService {
	return &VoucherSigningService{
		config:    config,
		executor:  executor,
		stationID: stationID,
	}
}

// SignVoucher signs a voucher based on the configured mode
func (s *VoucherSigningService) SignVoucher(ctx context.Context, voucher *fdo.Voucher, nextOwner crypto.PublicKey, serial, model string, extraData map[int][]byte) (*fdo.Voucher, error) {
	switch s.config.Mode {
	case "internal":
		return s.signVoucherInternal(ctx, voucher, nextOwner, extraData)
	case "external":
		return s.signVoucherExternal(ctx, voucher, nextOwner, serial, model, extraData)
	default:
		return nil, fmt.Errorf("unsupported voucher signing mode: %s", s.config.Mode)
	}
}

// signVoucherInternal signs voucher using internal owner key
func (s *VoucherSigningService) signVoucherInternal(ctx context.Context, voucher *fdo.Voucher, nextOwner crypto.PublicKey, extraData map[int][]byte) (*fdo.Voucher, error) {
	fmt.Printf("🔧 Internal voucher signing with OVEExtra data\n")
	fmt.Printf("📋 OVEExtra data keys: %d\n", len(extraData))
	for key, value := range extraData {
		fmt.Printf("   Key %d: %d bytes\n", key, len(value))
	}

	// For internal signing, we need to disable voucher signing and let the library handle it
	// The library will use the manufacturer key from the database automatically
	fmt.Printf("⚠️  Internal voucher signing not implemented - returning original voucher\n")
	return voucher, nil
}

// signVoucherExternal signs voucher using external HSM service
func (s *VoucherSigningService) signVoucherExternal(ctx context.Context, voucher *fdo.Voucher, nextOwner crypto.PublicKey, serial, model string, extraData map[int][]byte) (*fdo.Voucher, error) {
	// For external HSM mode, we need to create an external signer that intercepts the crypto.Sign calls
	// The HSM will receive digest blobs and return signatures

	// TODO: Load the manufacturer private key for this station
	// For now, we'll create a placeholder key
	// In a real implementation, this would be loaded from secure storage or HSM

	fmt.Printf("🔧 External HSM voucher signing with OVEExtra data\n")
	fmt.Printf("📋 OVEExtra data keys: %d\n", len(extraData))
	for key, value := range extraData {
		fmt.Printf("   Key %d: %d bytes\n", key, len(value))
	}

	// Create external HSM signer
	// The external signer needs the manufacturer public key that matches the voucher header
	// This is the public key corresponding to the private key held by the HSM
	manufacturerPubKey := voucher.Header.Val.ManufacturerKey

	// Convert protocol.PublicKey to crypto.PublicKey for the external signer
	cryptoPubKey, convertErr := protocolPublicKeyToCrypto(&manufacturerPubKey)
	if convertErr != nil {
		return nil, fmt.Errorf("failed to convert manufacturer public key: %w", convertErr)
	}

	externalSigner := NewExternalHSMSigner(cryptoPubKey, s.executor, s.config, s.stationID)

	// Use fdo.ExtendVoucher with the external signer
	// The external signer will intercept crypto.Sign calls and delegate to HSM
	var extendedVoucher *fdo.Voucher
	var err error

	// Type assert nextOwner to satisfy protocol.PublicKeyOrChain constraint
	switch key := nextOwner.(type) {
	case *ecdsa.PublicKey:
		extendedVoucher, err = fdo.ExtendVoucher(voucher, externalSigner, key, extraData)
	case *rsa.PublicKey:
		extendedVoucher, err = fdo.ExtendVoucher(voucher, externalSigner, key, extraData)
	case []*x509.Certificate:
		extendedVoucher, err = fdo.ExtendVoucher(voucher, externalSigner, key, extraData)
	default:
		return nil, fmt.Errorf("unsupported nextOwner key type: %T", nextOwner)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to extend voucher with external HSM: %w", err)
	}

	fmt.Printf("✅ Voucher extended successfully using external HSM\n")
	return extendedVoucher, nil
}

// encodePublicKeyToPEM encodes a public key to PEM format
func encodePublicKeyToPEM(pubKey crypto.PublicKey) (string, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return encodeRSAPublicKeyToPEM(key)
	case *ecdsa.PublicKey:
		return encodeECDSAPublicKeyToPEM(key)
	default:
		return "", fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// encodeRSAPublicKeyToPEM encodes RSA public key to PEM
func encodeRSAPublicKeyToPEM(key *rsa.PublicKey) (string, error) {
	// For RSA, we'll use PKIX format
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	pemKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	var pemData bytes.Buffer
	if err := pem.Encode(&pemData, pemKey); err != nil {
		return "", err
	}

	return pemData.String(), nil
}

// encodeECDSAPublicKeyToPEM encodes ECDSA public key to PEM
func encodeECDSAPublicKeyToPEM(key *ecdsa.PublicKey) (string, error) {
	// For ECDSA, we'll use PKIX format
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	pemKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	var pemData bytes.Buffer
	if err := pem.Encode(&pemData, pemKey); err != nil {
		return "", err
	}

	return pemData.String(), nil
}

// generateOwnerKey generates an owner signing key based on key type
func generateOwnerKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case "rsa2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "ec256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported owner key type: %s", keyType)
	}
}

// parseKeyType converts string key type to protocol.KeyType
func parseKeyType(keyType string) (protocol.KeyType, error) {
	switch keyType {
	case "rsa2048":
		return protocol.Rsa2048RestrKeyType, nil
	case "rsa3072":
		return protocol.RsaPkcsKeyType, nil
	case "ec256":
		return protocol.Secp256r1KeyType, nil
	case "ec384":
		return protocol.Secp384r1KeyType, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %s", keyType)
	}
}
