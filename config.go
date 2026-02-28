// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the manufacturing station configuration
type Config struct {
	// Basic configuration
	Debug      bool `yaml:"debug"`
	FDOVersion int  `yaml:"fdo_version"` // 101 or 200

	// Server configuration
	Server struct {
		Addr        string `yaml:"addr"`
		ExtAddr     string `yaml:"ext_addr"`
		UseTLS      bool   `yaml:"use_tls"`
		InsecureTLS bool   `yaml:"insecure_tls"`
	} `yaml:"server"`

	// Database configuration
	Database struct {
		Path     string `yaml:"path"`
		Password string `yaml:"password"`
	} `yaml:"database"`

	// Manufacturing configuration
	Manufacturing struct {
		DeviceCAKeyType      string `yaml:"device_ca_key_type"`
		OwnerKeyType         string `yaml:"owner_key_type"`
		GenerateCertificates bool   `yaml:"generate_certificates"`
		InitKeysIfMissing    bool   `yaml:"init_keys_if_missing"`
	} `yaml:"manufacturing"`

	// Rendezvous configuration
	Rendezvous struct {
		Entries []RendezvousEntry `yaml:"entries"`
	} `yaml:"rendezvous"`

	// Owner configuration (from server.go flags)
	Owner struct {
		GenerateCertificates bool `yaml:"generate_certificates"`
	} `yaml:"owner"`

	// TO0 configuration
	TO0 struct {
		GUID              string            `yaml:"guid"`               // Device GUID to register
		Delegate          string            `yaml:"delegate"`           // Delegate cert name
		Bypass            bool              `yaml:"bypass"`             // Skip TO1
		Delay             int               `yaml:"delay"`              // Delay TO1 by N seconds
		ReplacementPolicy string            `yaml:"replacement_policy"` // RV voucher replacement policy
		RvFilter          TO0RvFilterConfig `yaml:"rv_filter"`          // RV entry filtering policy
	} `yaml:"to0"`

	// Resale configuration
	Resale struct {
		GUID string `yaml:"guid"` // Voucher GUID to extend for resale
		Key  string `yaml:"key"`  // Path to PEM-encoded x.509 public key for next owner
	} `yaml:"resale"`

	// FSIM configurations
	FSIM struct {
		Downloads       []string `yaml:"downloads"`         // Files to download
		UploadDir       string   `yaml:"upload_dir"`        // Upload directory
		Uploads         []string `yaml:"uploads"`           // Files to upload
		Wgets           []string `yaml:"wgets"`             // URLs to fetch
		Sysconfig       []string `yaml:"sysconfig"`         // key=value pairs
		PayloadFile     string   `yaml:"payload_file"`      // Single payload file
		PayloadMime     string   `yaml:"payload_mime"`      // MIME type for payload file
		PayloadFiles    []string `yaml:"payload_files"`     // Multiple payload files (type:file format)
		BMOFile         string   `yaml:"bmo_file"`          // Single BMO file
		BMOImageType    string   `yaml:"bmo_image_type"`    // Image type for BMO file
		BMOFiles        []string `yaml:"bmo_files"`         // Multiple BMO files (type:file, type:url:URL, or meta:URL format)
		BMOTlsCA        string   `yaml:"bmo_tls_ca"`        // DER CA cert for URL/meta TLS validation
		BMOExpectedHash string   `yaml:"bmo_expected_hash"` // Hex hash for URL-mode image verification
		BMOMetaSigner   string   `yaml:"bmo_meta_signer"`   // COSE_Key PEM for meta-payload signing
		WiFiConfigFile  string   `yaml:"wifi_config_file"`  // WiFi configuration file
		Credentials     []string `yaml:"credentials"`       // Credential specifications
		PubkeyRequests  []string `yaml:"pubkey_requests"`   // Public key requests
		CommandDate     bool     `yaml:"command_date"`      // Use fdo.command FSIM to run "date +%s"
		SingleSidedWiFi bool     `yaml:"single_sided_wifi"` // Single-sided WiFi setup
	} `yaml:"fsim"`

	// Delegate configuration
	Delegate struct {
		RV      string `yaml:"rv"`      // Use delegate cert for RV blob signing
		Onboard string `yaml:"onboard"` // Use delegate cert for TO2
	} `yaml:"delegate"`

	// Import/Export configuration
	Import struct {
		Voucher string `yaml:"voucher"` // Import PEM encoded voucher file
	} `yaml:"import"`

	Print struct {
		OwnerPublic  string `yaml:"owner_public"`  // Print owner public key of type
		OwnerPrivate string `yaml:"owner_private"` // Print owner private key of type
		OwnerChain   string `yaml:"owner_chain"`   // Print owner chain of type
	} `yaml:"print"`

	// Voucher management configuration
	VoucherManagement VoucherConfig `yaml:"voucher_management"`

	// Device storage configuration
	DeviceStorage struct {
		VoucherDir         string `yaml:"voucher_dir"`          // Directory for voucher files
		ConfigDir          string `yaml:"config_dir"`           // Directory for device configs
		DeleteAfterOnboard bool   `yaml:"delete_after_onboard"` // Delete voucher file after successful onboard
		CacheConfigs       bool   `yaml:"cache_configs"`        // Cache parsed configs in database
	} `yaml:"device_storage"`

	// Voucher receiver configuration
	VoucherReceiver VoucherReceiverConfig `yaml:"voucher_receiver"`

	// DID identity configuration
	DID DIDConfig `yaml:"did"`

	// Pull service configuration (PullAuth server + Pull API)
	PullService PullServiceConfig `yaml:"pull_service"`
}

// DIDConfig controls the DID identity published by this service.
// The DID document advertises the owner's public key and service endpoints
// (push receiver, pull holder) so that partners who exchange DIDs can
// discover keys and endpoints without further configuration.
type DIDConfig struct {
	Host          string `yaml:"host"`           // Hostname for did:web URI; auto-detected from server.ext_addr if empty
	Path          string `yaml:"path"`           // Optional sub-path for did:web URI (e.g., "owner1")
	ServeDocument bool   `yaml:"serve_document"` // Serve /.well-known/did.json
	KeyType       string `yaml:"key_type"`       // Owner key type to use for DID (ec256, ec384, rsa2048, rsa3072)
}

// PullServiceConfig controls the PullAuth server and Pull API that allow
// authenticated recipients (owner key holders or delegates) to pull vouchers.
type PullServiceConfig struct {
	Enabled                bool          `yaml:"enabled"`
	SessionTTL             time.Duration `yaml:"session_ttl"`
	MaxSessions            int           `yaml:"max_sessions"`
	TokenTTL               time.Duration `yaml:"token_ttl"`
	RevealVoucherExistence bool          `yaml:"reveal_voucher_existence"`
}

// RendezvousEntry represents a single rendezvous endpoint
type RendezvousEntry struct {
	Host   string `yaml:"host"`   // IP address or DNS name
	Port   int    `yaml:"port"`   // Port number
	Scheme string `yaml:"scheme"` // "http" or "https"
}

// TO0RvFilterConfig controls which RV entries from voucher headers the OBS
// will attempt TO0 registration against.
//
// Mode determines how the filter operates:
//   - "allow_all" (default): Attempt TO0 to every RV entry from the voucher
//     header EXCEPT those matching the deny list.
//   - "allow_list": Attempt TO0 ONLY to RV entries matching the allow list.
//     All other entries are silently skipped.
//   - "allow_list_warn": Same as allow_list, but logs a warning for every
//     skipped RV entry (useful for auditing during initial deployment).
type TO0RvFilterConfig struct {
	Mode          string          `yaml:"mode"`           // "allow_all", "allow_list", "allow_list_warn"
	MaxAttempts   int             `yaml:"max_attempts"`   // Max TO0 retries per RV entry (0 = infinite)
	RetryInterval time.Duration   `yaml:"retry_interval"` // Delay between retries
	Allow         []RvFilterEntry `yaml:"allow"`          // Used only in allow_list / allow_list_warn modes
	Deny          []RvFilterEntry `yaml:"deny"`           // Used only in allow_all mode
}

// RvFilterEntry matches against a parsed RV directive URL.
type RvFilterEntry struct {
	Host   string `yaml:"host"`   // DNS or IP, case-insensitive, supports glob (e.g. "*.mfg.com")
	Port   int    `yaml:"port"`   // 0 = match any port
	Scheme string `yaml:"scheme"` // "" = match any scheme
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Debug:      false,
		FDOVersion: 101,
		Server: struct {
			Addr        string `yaml:"addr"`
			ExtAddr     string `yaml:"ext_addr"`
			UseTLS      bool   `yaml:"use_tls"`
			InsecureTLS bool   `yaml:"insecure_tls"`
		}{
			Addr:        "localhost:8080",
			ExtAddr:     "",
			UseTLS:      false,
			InsecureTLS: false,
		},
		Database: struct {
			Path     string `yaml:"path"`
			Password string `yaml:"password"`
		}{
			Path:     "manufacturing.db",
			Password: "",
		},
		Manufacturing: struct {
			DeviceCAKeyType      string `yaml:"device_ca_key_type"`
			OwnerKeyType         string `yaml:"owner_key_type"`
			GenerateCertificates bool   `yaml:"generate_certificates"`
			InitKeysIfMissing    bool   `yaml:"init_keys_if_missing"`
		}{
			DeviceCAKeyType:      "ec384",
			OwnerKeyType:         "ec384",
			GenerateCertificates: true,
			InitKeysIfMissing:    true,
		},
		Rendezvous: struct {
			Entries []RendezvousEntry `yaml:"entries"`
		}{
			Entries: []RendezvousEntry{},
		},
		Owner: struct {
			GenerateCertificates bool `yaml:"generate_certificates"`
		}{
			GenerateCertificates: false,
		},
		TO0: struct {
			GUID              string            `yaml:"guid"`
			Delegate          string            `yaml:"delegate"`
			Bypass            bool              `yaml:"bypass"`
			Delay             int               `yaml:"delay"`
			ReplacementPolicy string            `yaml:"replacement_policy"`
			RvFilter          TO0RvFilterConfig `yaml:"rv_filter"`
		}{
			GUID:              "",
			Delegate:          "",
			Bypass:            false,
			Delay:             0,
			ReplacementPolicy: "allow-any",
			RvFilter: TO0RvFilterConfig{
				Mode:          "allow_all",
				MaxAttempts:   3,
				RetryInterval: 30 * time.Second,
				Allow:         []RvFilterEntry{},
				Deny:          []RvFilterEntry{},
			},
		},
		Resale: struct {
			GUID string `yaml:"guid"`
			Key  string `yaml:"key"`
		}{
			GUID: "",
			Key:  "",
		},
		FSIM: struct {
			Downloads       []string `yaml:"downloads"`
			UploadDir       string   `yaml:"upload_dir"`
			Uploads         []string `yaml:"uploads"`
			Wgets           []string `yaml:"wgets"`
			Sysconfig       []string `yaml:"sysconfig"`
			PayloadFile     string   `yaml:"payload_file"`
			PayloadMime     string   `yaml:"payload_mime"`
			PayloadFiles    []string `yaml:"payload_files"`
			BMOFile         string   `yaml:"bmo_file"`
			BMOImageType    string   `yaml:"bmo_image_type"`
			BMOFiles        []string `yaml:"bmo_files"`
			BMOTlsCA        string   `yaml:"bmo_tls_ca"`
			BMOExpectedHash string   `yaml:"bmo_expected_hash"`
			BMOMetaSigner   string   `yaml:"bmo_meta_signer"`
			WiFiConfigFile  string   `yaml:"wifi_config_file"`
			Credentials     []string `yaml:"credentials"`
			PubkeyRequests  []string `yaml:"pubkey_requests"`
			CommandDate     bool     `yaml:"command_date"`
			SingleSidedWiFi bool     `yaml:"single_sided_wifi"`
		}{
			Downloads:       []string{},
			UploadDir:       "uploads",
			Uploads:         []string{},
			Wgets:           []string{},
			Sysconfig:       []string{},
			PayloadFile:     "",
			PayloadMime:     "application/octet-stream",
			PayloadFiles:    []string{},
			BMOFile:         "",
			BMOImageType:    "application/x-iso9660-image",
			BMOFiles:        []string{},
			BMOTlsCA:        "",
			BMOExpectedHash: "",
			BMOMetaSigner:   "",
			WiFiConfigFile:  "",
			Credentials:     []string{},
			PubkeyRequests:  []string{},
			CommandDate:     false,
			SingleSidedWiFi: false,
		},
		Delegate: struct {
			RV      string `yaml:"rv"`
			Onboard string `yaml:"onboard"`
		}{
			RV:      "",
			Onboard: "",
		},
		Import: struct {
			Voucher string `yaml:"voucher"`
		}{
			Voucher: "",
		},
		Print: struct {
			OwnerPublic  string `yaml:"owner_public"`
			OwnerPrivate string `yaml:"owner_private"`
			OwnerChain   string `yaml:"owner_chain"`
		}{
			OwnerPublic:  "",
			OwnerPrivate: "",
			OwnerChain:   "",
		},
		VoucherManagement: VoucherConfig{
			PersistToDB:     true,
			ReuseCredential: false,
			VoucherSigning: VoucherSigningConfig{
				Mode:              "internal",       // "internal" = default, "hsm" = external HSM
				OwnerKeyType:      "ec384",          // for internal mode
				InitKeysIfMissing: true,             // for internal mode - only create keys if they don't exist
				ExternalCommand:   "",               // for hsm mode
				ExternalTimeout:   30 * time.Second, // for hsm mode
			},
			OwnerSignover: struct {
				Mode            string        `yaml:"mode"`              // "static" or "dynamic"
				StaticPublicKey string        `yaml:"static_public_key"` // PEM-encoded public key for static mode
				ExternalCommand string        `yaml:"external_command"`  // Command for dynamic mode
				Timeout         time.Duration `yaml:"timeout"`
			}{
				Mode:            "static", // Default to static mode
				StaticPublicKey: "",       // Empty means no owner signover
				ExternalCommand: "",
				Timeout:         10 * time.Second,
			},
			VoucherUpload: struct {
				Enabled         bool          `yaml:"enabled"`
				ExternalCommand string        `yaml:"external_command"`
				Timeout         time.Duration `yaml:"timeout"`
			}{
				Enabled:         false,
				ExternalCommand: "",
				Timeout:         30 * time.Second,
			},
		},
		DeviceStorage: struct {
			VoucherDir         string `yaml:"voucher_dir"`
			ConfigDir          string `yaml:"config_dir"`
			DeleteAfterOnboard bool   `yaml:"delete_after_onboard"`
			CacheConfigs       bool   `yaml:"cache_configs"`
		}{
			VoucherDir:         "vouchers",
			ConfigDir:          "configs",
			DeleteAfterOnboard: false,
			CacheConfigs:       false,
		},
		VoucherReceiver: VoucherReceiverConfig{
			Enabled:           false,
			Endpoint:          "/api/v1/vouchers",
			GlobalToken:       "",
			ValidateOwnership: true,
			RequireAuth:       true,
		},
		DID: DIDConfig{
			Host:          "",
			Path:          "",
			ServeDocument: true,
			KeyType:       "ec384",
		},
		PullService: PullServiceConfig{
			Enabled:                false,
			SessionTTL:             60 * time.Second,
			MaxSessions:            1000,
			TokenTTL:               1 * time.Hour,
			RevealVoucherExistence: false,
		},
	}
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	if configPath == "" {
		configPath = "manufacturing.cfg"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Config file doesn't exist, return defaults
			return config, nil
		}
		return nil, fmt.Errorf("error reading config file %q: %w", configPath, err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("error parsing config file %q: %w", configPath, err)
	}

	return config, nil
}

// SaveConfig saves the configuration to a YAML file
func SaveConfig(config *Config, configPath string) error {
	if configPath == "" {
		configPath = "fdoserver.cfg"
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("error writing config file %q: %w", configPath, err)
	}

	return nil
}
