// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/did"
	"github.com/fido-device-onboard/go-fdo/sqlite"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

// Pull command flags (registered in main.go)
var (
	pullURL           *string
	pullDID           *string
	pullKeyFile       *string
	pullDelegateKey   *string
	pullDelegateChain *string
	pullOwnerPub      *string
	pullHolderKey     *string
	pullOutputDir     *string
	pullListOnly      *bool
	pullJSONOutput    *bool
)

// runPullCommand performs a PullAuth handshake against a remote Holder,
// lists available vouchers, and optionally downloads them. Designed to be
// invoked as a one-shot CLI command, schedulable via cron.
//
// Usage examples:
//
//	# Pull using owner key from database
//	fdo-server --pull-url https://di.factory.example.com
//
//	# Pull using explicit key file
//	fdo-server --pull-url https://di.factory.example.com --pull-key owner.pem
//
//	# Pull using DID discovery
//	fdo-server --pull-did did:web:di.factory.example.com --pull-key owner.pem
//
//	# Delegate-based pull
//	fdo-server --pull-url https://vm.example.com --pull-owner-pub owner-pub.pem \
//	           --pull-delegate-key site1.pem --pull-delegate-chain site1-chain.pem
//
//	# Cron: pull every 5 minutes
//	*/5 * * * * /usr/local/bin/fdo-server --config /etc/fdo/server.cfg \
//	    --pull-url https://di.factory.example.com >> /var/log/fdo-pull.log 2>&1
func runPullCommand(ctx context.Context) error {
	holderURL := *pullURL

	// Resolve holder URL from DID if --pull-did is set
	if *pullDID != "" {
		resolver := did.NewResolver()
		result, err := resolver.Resolve(ctx, *pullDID)
		if err != nil {
			return fmt.Errorf("failed to resolve DID %q: %w", *pullDID, err)
		}
		if result.Document != nil {
			for _, svc := range result.Document.Service {
				if svc.Type == did.FDOVoucherHolderServiceType {
					holderURL = svc.ServiceEndpoint
					slog.Info("pull: resolved holder URL from DID",
						"did", *pullDID,
						"url", holderURL)
					break
				}
			}
		}
		if holderURL == "" {
			return fmt.Errorf("DID %q has no FDOVoucherHolder service endpoint", *pullDID)
		}
	}

	if holderURL == "" {
		return fmt.Errorf("--pull-url or --pull-did is required")
	}

	// Build PullAuth client
	client, err := buildPullClient(ctx, holderURL)
	if err != nil {
		return err
	}

	// Step 1: Authenticate
	slog.Info("pull: authenticating", "holder", holderURL)
	authResult, err := client.Authenticate()
	if err != nil {
		return fmt.Errorf("PullAuth failed: %w", err)
	}
	slog.Info("pull: authenticated",
		"voucher_count", authResult.VoucherCount,
		"token_expires", authResult.TokenExpiresAt)

	initiator := &transfer.HTTPPullInitiator{Auth: client}

	// Step 2: List vouchers
	filter := transfer.ListFilter{}
	var allVouchers []transfer.VoucherInfo
	pageNum := 0
	for {
		pageNum++
		listResp, err := initiator.ListVouchers(ctx, authResult.SessionToken, filter)
		if err != nil {
			return fmt.Errorf("list vouchers failed: %w", err)
		}
		allVouchers = append(allVouchers, listResp.Vouchers...)

		slog.Info("pull: listed page",
			"page", pageNum,
			"vouchers_on_page", len(listResp.Vouchers),
			"has_more", listResp.HasMore,
			"total_so_far", len(allVouchers))

		if listResp.Continuation == "" || !listResp.HasMore {
			break
		}
		filter.Continuation = listResp.Continuation
	}

	// Step 3: Output or download
	outputDir := *pullOutputDir
	if outputDir == "" {
		outputDir = config.DeviceStorage.VoucherDir
	}

	if *pullListOnly || outputDir == "" {
		return outputPullListing(allVouchers)
	}

	// Download each voucher
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	var downloaded int
	for _, vi := range allVouchers {
		data, err := initiator.DownloadVoucher(ctx, authResult.SessionToken, vi.GUID)
		if err != nil {
			slog.Error("pull: failed to download voucher", "guid", vi.GUID, "error", err)
			continue
		}

		// Save as PEM
		raw := data.Raw
		if raw == nil {
			slog.Error("pull: voucher has no raw data", "guid", vi.GUID)
			continue
		}
		pemBytes := fdo.FormatVoucherCBORToPEM(raw)
		filename := fmt.Sprintf("%s/%s.fdoov", outputDir, vi.GUID)
		if err := os.WriteFile(filename, pemBytes, 0644); err != nil {
			slog.Error("pull: failed to write voucher file", "guid", vi.GUID, "error", err)
			continue
		}
		downloaded++
		slog.Info("pull: downloaded voucher", "guid", vi.GUID, "path", filename)
	}

	if *pullJSONOutput {
		out := map[string]interface{}{
			"status":     "success",
			"listed":     len(allVouchers),
			"downloaded": downloaded,
			"output_dir": outputDir,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Printf("Pull completed: %d listed, %d downloaded to %s\n", len(allVouchers), downloaded, outputDir)
	return nil
}

// buildPullClient constructs a PullAuthClient from CLI flags.
func buildPullClient(ctx context.Context, holderURL string) (*transfer.PullAuthClient, error) {
	client := &transfer.PullAuthClient{
		BaseURL:    holderURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}

	// Delegate-based pull
	if *pullDelegateKey != "" || *pullDelegateChain != "" {
		if *pullDelegateKey == "" || *pullDelegateChain == "" {
			return nil, fmt.Errorf("--pull-delegate-key and --pull-delegate-chain must both be set")
		}

		delegateKey, err := loadPrivateKeyFromPEMFile(*pullDelegateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load delegate key: %w", err)
		}
		client.DelegateKey = delegateKey

		delegateChain, err := loadCertChainFromPEMFile(*pullDelegateChain)
		if err != nil {
			return nil, fmt.Errorf("failed to load delegate chain: %w", err)
		}
		client.DelegateChain = delegateChain

		// Owner public key for delegate mode
		if *pullOwnerPub != "" {
			pub, err := loadPublicKeyFromPEMFile(*pullOwnerPub)
			if err != nil {
				return nil, fmt.Errorf("failed to load owner public key: %w", err)
			}
			client.OwnerPublicKey = pub
		} else if *pullKeyFile != "" {
			key, err := loadPrivateKeyFromPEMFile(*pullKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load owner key: %w", err)
			}
			client.OwnerKey = key
		} else {
			return nil, fmt.Errorf("--pull-owner-pub or --pull-key required for delegate pull")
		}

		slog.Info("pull: using delegate-based authentication",
			"delegate_chain_len", len(delegateChain))
	} else {
		// Standard pull: owner private key
		if *pullKeyFile != "" {
			key, err := loadPrivateKeyFromPEMFile(*pullKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load owner key: %w", err)
			}
			client.OwnerKey = key
		} else {
			// Extract from database
			key, err := loadOwnerKeyFromDB(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to load owner key from database: %w", err)
			}
			client.OwnerKey = key
		}
	}

	// Holder key for signature verification
	if *pullHolderKey != "" {
		pub, err := loadPublicKeyFromPEMFile(*pullHolderKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load holder public key: %w", err)
		}
		client.HolderPublicKey = pub
		slog.Info("pull: holder signature verification enabled")
	} else if *pullDID != "" {
		// Auto-resolve holder public key from DID
		resolver := did.NewResolver()
		result, err := resolver.Resolve(ctx, *pullDID)
		if err == nil && result.PublicKey != nil {
			client.HolderPublicKey = result.PublicKey
			slog.Info("pull: holder key resolved from DID for signature verification")
		}
	}

	return client, nil
}

// loadOwnerKeyFromDB loads an owner key from the sqlite database.
func loadOwnerKeyFromDB(ctx context.Context) (crypto.Signer, error) {
	state, err := sqlite.Open(config.Database.Path, config.Database.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = state.Close() }()

	keyType := config.DID.KeyType
	if keyType == "" {
		keyType = "ec384"
	}
	protoKeyType, err := parseDIDKeyType(keyType)
	if err != nil {
		return nil, err
	}

	key, _, err := state.OwnerKey(ctx, protoKeyType, 3072)
	if err != nil {
		return nil, fmt.Errorf("failed to load owner key (type %s): %w", keyType, err)
	}
	return key, nil
}

// loadPrivateKeyFromPEMFile loads a private key from a PEM file.
func loadPrivateKeyFromPEMFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", path, err)
	}
	return did.LoadPrivateKeyPEM(data)
}

// loadPublicKeyFromPEMFile loads a public key from a PEM file.
func loadPublicKeyFromPEMFile(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", path, err)
	}
	return did.LoadPublicKeyPEM(data)
}

// loadCertChainFromPEMFile loads an X.509 certificate chain from a PEM file.
func loadCertChainFromPEMFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", path, err)
	}

	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in %q", path)
	}
	return chain, nil
}

// outputPullListing prints the pull listing to stdout.
func outputPullListing(vouchers []transfer.VoucherInfo) error {
	if *pullJSONOutput {
		out := map[string]interface{}{
			"status":        "success",
			"voucher_count": len(vouchers),
			"vouchers":      vouchers,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Printf("Pull listing: %d voucher(s) found\n", len(vouchers))
	for _, v := range vouchers {
		created := ""
		if v.CreatedAt != nil {
			created = v.CreatedAt.Format(time.RFC3339)
		}
		fmt.Printf("  GUID: %s  DeviceInfo: %s  Created: %s\n",
			v.GUID, v.DeviceInfo, created)
	}
	return nil
}
