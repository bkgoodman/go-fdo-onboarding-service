// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"time"
)

// VoucherSigningConfig contains configuration for voucher signing
type VoucherSigningConfig struct {
	Mode                      string        `yaml:"mode"`                         // "internal" | "external"
	OwnerKeyType              string        `yaml:"owner_key_type"`               // for internal mode
	InitKeysIfMissing         bool          `yaml:"init_keys_if_missing"`         // for internal mode - only create keys if they don't exist
	ExternalCommand           string        `yaml:"external_command"`             // for external mode
	ExternalTimeout           time.Duration `yaml:"external_timeout"`             // for external mode
	ManufacturerPublicKeyFile string        `yaml:"manufacturer_public_key_file"` // PEM file with manufacturer public key
}

// OVEExtraDataConfig contains configuration for OVEExtra data
type OVEExtraDataConfig struct {
	Enabled         bool          `yaml:"enabled"`
	ExternalCommand string        `yaml:"external_command"` // script to call for extra data
	Timeout         time.Duration `yaml:"timeout"`
}

// VoucherConfig contains configuration for voucher management
type VoucherConfig struct {
	PersistToDB bool `yaml:"persist_to_db"`

	// Credential reuse: false = device can only onboard once, true = allows re-onboarding
	ReuseCredential bool `yaml:"reuse_credential"`

	// New voucher signing configuration
	VoucherSigning VoucherSigningConfig `yaml:"voucher_signing"`

	// OVEExtra data configuration
	OVEExtraData OVEExtraDataConfig `yaml:"ove_extra_data"`

	// Save vouchers to disk configuration
	SaveToDisk struct {
		Directory string `yaml:"directory"` // Directory to save vouchers (empty = disabled)
	} `yaml:"save_to_disk"`

	// Owner signover configuration
	OwnerSignover struct {
		Mode            string        `yaml:"mode"`              // "static" or "dynamic"
		StaticPublicKey string        `yaml:"static_public_key"` // PEM-encoded public key for static mode
		ExternalCommand string        `yaml:"external_command"`  // Command for dynamic mode
		Timeout         time.Duration `yaml:"timeout"`
	} `yaml:"owner_signover"`

	VoucherUpload struct {
		Enabled         bool          `yaml:"enabled"`
		ExternalCommand string        `yaml:"external_command"`
		Timeout         time.Duration `yaml:"timeout"`
	} `yaml:"voucher_upload"`
}
