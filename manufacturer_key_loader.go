// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

// LoadManufacturerPublicKey loads the manufacturer public key from a PEM file
func LoadManufacturerPublicKey(filename string) (protocol.PublicKey, error) {
	if filename == "" {
		return protocol.PublicKey{}, fmt.Errorf("manufacturer public key file not specified")
	}

	// Read PEM file
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return protocol.PublicKey{}, fmt.Errorf("failed to read manufacturer public key file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return protocol.PublicKey{}, fmt.Errorf("failed to decode PEM block from %s", filename)
	}

	// Parse public key
	var pubKey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			pubKey = cert.PublicKey
		}
	default:
		return protocol.PublicKey{}, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	if err != nil {
		return protocol.PublicKey{}, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Convert to protocol.PublicKey
	protocolPubKey, err := publicKeyToProtocol(pubKey)
	if err != nil {
		return protocol.PublicKey{}, fmt.Errorf("failed to convert to protocol public key: %w", err)
	}

	fmt.Printf("✅ Loaded manufacturer public key from %s\n", filename)
	return protocolPubKey, nil
}

// protocolPublicKeyToCrypto converts a protocol.PublicKey to crypto.PublicKey
func protocolPublicKeyToCrypto(protocolPubKey *protocol.PublicKey) (crypto.PublicKey, error) {
	// Use the library's built-in method to parse the public key
	return protocolPubKey.Public()
}

// publicKeyToProtocol converts a crypto public key to protocol.PublicKey
func publicKeyToProtocol(pubKey interface{}) (protocol.PublicKey, error) {
	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		// Encode ECDSA public key to ASN.1 DER
		derBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return protocol.PublicKey{}, fmt.Errorf("failed to marshal ECDSA public key: %w", err)
		}

		// Determine key type
		var keyType protocol.KeyType
		switch key.Curve {
		case elliptic.P256():
			keyType = protocol.Secp256r1KeyType
		case elliptic.P384():
			keyType = protocol.Secp384r1KeyType
		default:
			return protocol.PublicKey{}, fmt.Errorf("unsupported ECDSA curve: %s", key.Curve)
		}

		return protocol.PublicKey{
			Type:     keyType,
			Encoding: protocol.X509KeyEnc,
			Body:     derBytes,
		}, nil

	case *rsa.PublicKey:
		// Encode RSA public key to ASN.1 DER
		derBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return protocol.PublicKey{}, fmt.Errorf("failed to marshal RSA public key: %w", err)
		}

		// Determine key type
		var keyType protocol.KeyType
		switch key.Size() {
		case 2048:
			keyType = protocol.Rsa2048RestrKeyType
		case 3072:
			keyType = protocol.RsaPkcsKeyType
		default:
			return protocol.PublicKey{}, fmt.Errorf("unsupported RSA key size: %d", key.Size())
		}

		return protocol.PublicKey{
			Type:     keyType,
			Encoding: protocol.X509KeyEnc,
			Body:     derBytes,
		}, nil

	default:
		return protocol.PublicKey{}, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}
