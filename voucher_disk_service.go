// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// VoucherDiskService handles saving vouchers to disk
type VoucherDiskService struct {
	config *VoucherConfig
}

// NewVoucherDiskService creates a new voucher disk service
func NewVoucherDiskService(config *VoucherConfig) *VoucherDiskService {
	return &VoucherDiskService{
		config: config,
	}
}

// SaveVoucherToDisk saves an ownership voucher to disk in the format used by go-fdo command-line tools
func (v *VoucherDiskService) SaveVoucherToDisk(ov *fdo.Voucher, serialNumber string) error {
	if v.config.SaveToDisk.Directory == "" {
		// Directory not specified, disk saving disabled
		return nil
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(v.config.SaveToDisk.Directory, 0755); err != nil {
		return fmt.Errorf("failed to create voucher directory: %w", err)
	}

	// Generate filename using serial number
	filename := fmt.Sprintf("%s.fdoov", serialNumber)
	filepath := filepath.Join(v.config.SaveToDisk.Directory, filename)

	// Convert voucher to the same format as go-fdo command-line tools
	voucherText, err := v.formatVoucherForDisk(ov, serialNumber)
	if err != nil {
		return fmt.Errorf("failed to format voucher for disk: %w", err)
	}

	// Write voucher to file
	if err := os.WriteFile(filepath, []byte(voucherText), 0644); err != nil {
		return fmt.Errorf("failed to write voucher to disk: %w", err)
	}

	fmt.Printf("💾 Saved ownership voucher to disk: %s\n", filepath)
	return nil
}

// formatVoucherForDisk formats the voucher in the same style as go-fdo command-line tools
func (v *VoucherDiskService) formatVoucherForDisk(ov *fdo.Voucher, serialNumber string) (string, error) {
	// Serialize voucher to CBOR
	voucherBytes, err := cbor.Marshal(ov)
	if err != nil {
		return "", fmt.Errorf("failed to marshal voucher: %w", err)
	}

	// Base64 encode the CBOR (without line breaks)
	voucherBase64 := base64.StdEncoding.EncodeToString(voucherBytes)

	// Create the formatted output like go-fdo tools
	var builder strings.Builder

	// Header
	builder.WriteString("-----BEGIN OWNERSHIP VOUCHER-----\n")

	// Base64-encoded CBOR data
	builder.WriteString(voucherBase64)
	builder.WriteString("\n")

	// Footer
	builder.WriteString("-----END OWNERSHIP VOUCHER-----\n")

	return builder.String(), nil
}

// GenerateTestVoucher creates a test voucher for testing purposes
func (v *VoucherDiskService) GenerateTestVoucher(serialNumber string) (*fdo.Voucher, error) {
	// Generate a test GUID
	guid := make([]byte, 16)
	if _, err := rand.Read(guid); err != nil {
		return nil, fmt.Errorf("failed to generate GUID: %w", err)
	}

	// Create a simple test voucher header
	header := fdo.VoucherHeader{
		Version:    1,
		GUID:       *(*protocol.GUID)(guid),
		RvInfo:     [][]protocol.RvInstruction{},
		DeviceInfo: "TestDevice",
		ManufacturerKey: protocol.PublicKey{
			Type:     0, // Use valid type
			Encoding: 0, // Use valid encoding
		},
		CertChainHash: nil,
	}

	// Create a simple test voucher
	headerBstr := cbor.NewBstr(header)
	ov := &fdo.Voucher{
		Version:   1,
		Header:    *headerBstr,
		Hmac:      protocol.Hmac{},
		CertChain: nil,
		Entries:   []cose.Sign1Tag[fdo.VoucherEntryPayload, []byte]{},
	}

	return ov, nil
}
