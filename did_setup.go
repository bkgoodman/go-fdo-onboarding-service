// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/fido-device-onboard/go-fdo/did"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

// setupDID configures the DID identity for this service. It loads the owner
// key from the sqlite database, builds a DID document with service endpoints
// for push (FDOVoucherRecipient) and pull (FDOVoucherHolder), and optionally
// serves it at /.well-known/did.json.
//
// Returns the owner crypto.Signer for use as the PullAuth holder signing key.
func setupDID(ctx context.Context, cfg *Config, mux *http.ServeMux, state *sqlite.DB) (crypto.Signer, error) {
	// Determine host for did:web URI
	host := cfg.DID.Host
	if host == "" {
		host = cfg.Server.ExtAddr
	}
	if host == "" {
		host = cfg.Server.Addr
	}
	if host == "" {
		return nil, fmt.Errorf("DID setup: no host available (set did.host, server.ext_addr, or server.addr)")
	}

	// Parse the configured key type
	keyType, err := parseDIDKeyType(cfg.DID.KeyType)
	if err != nil {
		return nil, fmt.Errorf("DID setup: %w", err)
	}

	// Load owner key from sqlite
	ownerKey, _, err := state.OwnerKey(ctx, keyType, 3072)
	if err != nil {
		return nil, fmt.Errorf("DID setup: failed to load owner key (type %s): %w", cfg.DID.KeyType, err)
	}

	// Build DID URI
	didURI := did.WebDID(host, cfg.DID.Path)

	// Build service endpoint URLs
	scheme := "http"
	if cfg.Server.UseTLS {
		scheme = "https"
	}

	var voucherRecipientURL string
	if cfg.VoucherReceiver.Enabled {
		voucherRecipientURL = scheme + "://" + host + cfg.VoucherReceiver.Endpoint
	}

	var voucherHolderURL string
	if cfg.PullService.Enabled {
		voucherHolderURL = scheme + "://" + host + "/api/v1/pull/vouchers"
	}

	// Create DID document
	doc, err := did.NewDocument(didURI, ownerKey.Public(), voucherRecipientURL, voucherHolderURL)
	if err != nil {
		return nil, fmt.Errorf("DID setup: failed to create DID document: %w", err)
	}

	// Serve the DID document
	if cfg.DID.ServeDocument {
		handler, err := did.NewHandler(doc)
		if err != nil {
			return nil, fmt.Errorf("DID setup: failed to create handler: %w", err)
		}
		handler.RegisterHandlers(mux, cfg.DID.Path)
	}

	slog.Info("DID identity configured",
		"did_uri", didURI,
		"serving", cfg.DID.ServeDocument,
		"voucher_recipient_url", voucherRecipientURL,
		"voucher_holder_url", voucherHolderURL,
		"key_type", cfg.DID.KeyType)

	return ownerKey, nil
}

// parseDIDKeyType maps config key type strings to protocol.KeyType values.
func parseDIDKeyType(keyType string) (protocol.KeyType, error) {
	switch keyType {
	case "ec256":
		return protocol.Secp256r1KeyType, nil
	case "ec384":
		return protocol.Secp384r1KeyType, nil
	case "rsa2048":
		return protocol.Rsa2048RestrKeyType, nil
	case "rsa3072":
		return protocol.RsaPkcsKeyType, nil
	default:
		return 0, fmt.Errorf("unsupported DID key type %q (use ec256, ec384, rsa2048, rsa3072)", keyType)
	}
}
