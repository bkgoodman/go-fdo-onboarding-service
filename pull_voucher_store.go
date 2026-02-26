// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

// PullVoucherStore adapts the file-based voucher directory to the
// transfer.VoucherStore interface for serving vouchers via the Pull API.
//
// This is an unscoped store: all vouchers in the directory are returned
// regardless of the authenticated owner key fingerprint, because the
// onboarding service is single-tenant (all vouchers belong to us).
type PullVoucherStore struct {
	voucherDir string
}

// NewPullVoucherStore creates a store backed by the given voucher directory.
func NewPullVoucherStore(voucherDir string) *PullVoucherStore {
	return &PullVoucherStore{voucherDir: voucherDir}
}

// Save persists a voucher to disk in PEM format.
func (s *PullVoucherStore) Save(_ context.Context, data *transfer.VoucherData) (string, error) {
	if data == nil || data.Voucher == nil {
		return "", fmt.Errorf("voucher data is nil")
	}

	guid := data.GUID
	if guid == "" {
		guid = fmt.Sprintf("%x", data.Voucher.Header.Val.GUID[:])
	}

	raw := data.Raw
	if raw == nil {
		var err error
		raw, err = cbor.Marshal(data.Voucher)
		if err != nil {
			return "", fmt.Errorf("failed to encode voucher: %w", err)
		}
	}

	path := filepath.Join(s.voucherDir, guid+".fdoov")
	if err := os.MkdirAll(s.voucherDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create voucher directory: %w", err)
	}

	pemBytes := fdo.FormatVoucherCBORToPEM(raw)
	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		return "", fmt.Errorf("failed to write voucher file: %w", err)
	}

	return path, nil
}

// Load retrieves a voucher by GUID from the file directory.
func (s *PullVoucherStore) Load(_ context.Context, guid string) (*transfer.VoucherData, error) {
	path := filepath.Join(s.voucherDir, guid+".fdoov")
	return s.loadFromFile(path, guid)
}

// GetVoucher retrieves a voucher by GUID. The ownerKeyFingerprint parameter
// is accepted but not used for scoping (single-tenant: all vouchers are ours).
func (s *PullVoucherStore) GetVoucher(_ context.Context, _ []byte, guid string) (*transfer.VoucherData, error) {
	path := filepath.Join(s.voucherDir, guid+".fdoov")
	return s.loadFromFile(path, guid)
}

// List returns voucher metadata by scanning the voucher directory.
// The ownerKeyFingerprint is accepted but not used for scoping.
func (s *PullVoucherStore) List(_ context.Context, _ []byte, filter transfer.ListFilter) (*transfer.VoucherListResponse, error) {
	entries, err := os.ReadDir(s.voucherDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &transfer.VoucherListResponse{}, nil
		}
		return nil, fmt.Errorf("failed to read voucher directory: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	var vouchers []transfer.VoucherInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".fdoov") {
			continue
		}

		guid := strings.TrimSuffix(entry.Name(), ".fdoov")
		path := filepath.Join(s.voucherDir, entry.Name())

		info := transfer.VoucherInfo{GUID: guid}

		// Try to extract device info from voucher header
		ov, err := fdo.ParseVoucherFile(path)
		if err != nil {
			slog.Debug("pull store: skipping unreadable voucher", "path", path, "error", err)
			continue
		}
		info.DeviceInfo = ov.Header.Val.DeviceInfo

		vouchers = append(vouchers, info)

		if len(vouchers) > limit {
			break
		}
	}

	hasMore := len(vouchers) > limit
	if hasMore {
		vouchers = vouchers[:limit]
	}

	return &transfer.VoucherListResponse{
		Vouchers:   vouchers,
		HasMore:    hasMore,
		TotalCount: uint(len(vouchers)),
	}, nil
}

// Delete removes a voucher file by GUID.
func (s *PullVoucherStore) Delete(_ context.Context, guid string) error {
	path := filepath.Join(s.voucherDir, guid+".fdoov")
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete voucher: %w", err)
	}
	return nil
}

// loadFromFile reads and parses a voucher file into VoucherData.
func (s *PullVoucherStore) loadFromFile(path, guid string) (*transfer.VoucherData, error) {
	ov, err := fdo.ParseVoucherFile(path)
	if err != nil {
		return nil, fmt.Errorf("voucher not found: %s", guid)
	}

	raw, err := cbor.Marshal(ov)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode voucher CBOR: %w", err)
	}

	return &transfer.VoucherData{
		VoucherInfo: transfer.VoucherInfo{
			GUID:       guid,
			DeviceInfo: ov.Header.Val.DeviceInfo,
		},
		Voucher: ov,
		Raw:     raw,
	}, nil
}
