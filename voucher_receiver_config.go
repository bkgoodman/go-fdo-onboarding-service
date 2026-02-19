// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

// VoucherReceiverConfig contains configuration for the voucher receiver service
type VoucherReceiverConfig struct {
	// Enabled controls whether the voucher receiver is active
	Enabled bool `yaml:"enabled"`

	// Endpoint is the HTTP path to mount the receiver (e.g., "/api/v1/vouchers")
	Endpoint string `yaml:"endpoint"`

	// GlobalToken is an optional bearer token that is always accepted
	GlobalToken string `yaml:"global_token"`

	// ValidateOwnership ensures received vouchers are signed to our owner keys
	ValidateOwnership bool `yaml:"validate_ownership"`

	// RequireAuth determines if authentication is mandatory
	RequireAuth bool `yaml:"require_auth"`
}
