// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import "time"

// VoucherReceiverConfig contains configuration for the voucher receiver service.
// Authentication supports two methods:
//   - FDOKeyAuth (primary): Cryptographic challenge-response using the separated auth API.
//     Callers authenticate via {endpoint}/auth/hello and {endpoint}/auth/prove,
//     then use the session token for subsequent push requests.
//   - Bearer token (secondary): Static tokens configured via global_token or managed
//     in the database. Retained for backward compatibility with existing clients.
type VoucherReceiverConfig struct {
	// Enabled controls whether the voucher receiver is active
	Enabled bool `yaml:"enabled"`

	// Endpoint is the HTTP path to mount the receiver (e.g., "/api/v1/vouchers")
	Endpoint string `yaml:"endpoint"`

	// AuthMethod selects which authentication methods are accepted.
	// "fdokeyauth" — FDOKeyAuth only
	// "bearer"     — Bearer token only (legacy)
	// "both"       — FDOKeyAuth primary, Bearer token fallback (default)
	AuthMethod string `yaml:"auth_method"`

	// GlobalToken is an optional bearer token that is always accepted (secondary auth)
	GlobalToken string `yaml:"global_token"`

	// ValidateOwnership ensures received vouchers are signed to our owner keys
	ValidateOwnership bool `yaml:"validate_ownership"`

	// RequireAuth determines if authentication is mandatory
	RequireAuth bool `yaml:"require_auth"`

	// SessionTTL is how long an FDOKeyAuth session remains valid (default 5m)
	SessionTTL time.Duration `yaml:"session_ttl"`

	// MaxSessions is the maximum number of concurrent FDOKeyAuth sessions (default 100)
	MaxSessions int `yaml:"max_sessions"`
}
