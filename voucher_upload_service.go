// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// VoucherUploadService handles uploading vouchers to external systems
type VoucherUploadService struct {
	executor *ExternalCommandExecutor
}

// NewVoucherUploadService creates a new voucher upload service
func NewVoucherUploadService(executor *ExternalCommandExecutor) *VoucherUploadService {
	return &VoucherUploadService{
		executor: executor,
	}
}

// UploadVoucher uploads a voucher to an external system
func (v *VoucherUploadService) UploadVoucher(ctx context.Context, serial, model, guid string, voucher *fdo.Voucher) error {
	fmt.Printf("🔍 DEBUG: VoucherUploadService.UploadVoucher called!\n")
	fmt.Printf("🔍 DEBUG: serial=%s, model=%s, guid=%s\n", serial, model, guid)

	// Write voucher to temporary file
	voucherFile, err := os.CreateTemp("", "voucher-*.cbor")
	if err != nil {
		return fmt.Errorf("failed to create temp voucher file: %w", err)
	}
	if err := os.Remove(voucherFile.Name()); err != nil {
		fmt.Printf("Warning: failed to remove voucher file: %v\n", err)
	}

	// Serialize voucher to file
	voucherData, err := cbor.Marshal(voucher)
	if err != nil {
		return fmt.Errorf("failed to marshal voucher: %w", err)
	}
	if _, err := voucherFile.Write(voucherData); err != nil {
		return fmt.Errorf("failed to write voucher file: %w", err)
	}
	if err := voucherFile.Close(); err != nil {
		return fmt.Errorf("failed to close voucher file: %w", err)
	}

	// Ensure we have a GUID if not provided
	if guid == "" {
		guid = hex.EncodeToString(voucher.Header.Val.GUID[:])
	}

	variables := map[string]string{
		"serialno":    serial,
		"model":       model,
		"voucherfile": voucherFile.Name(),
		"guid":        guid,
	}

	_, err = v.executor.Execute(ctx, variables)
	if err != nil {
		return fmt.Errorf("voucher upload failed: %w", err)
	}

	return nil
}
