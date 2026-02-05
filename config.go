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
	Debug bool `yaml:"debug"`

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
		FirstTimeInit        bool   `yaml:"first_time_init"`
	} `yaml:"manufacturing"`

	// Voucher management configuration
	VoucherManagement VoucherConfig `yaml:"voucher_management"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Debug: false,
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
			FirstTimeInit        bool   `yaml:"first_time_init"`
		}{
			DeviceCAKeyType:      "ec384",
			OwnerKeyType:         "ec384",
			GenerateCertificates: true,
			FirstTimeInit:        false,
		},
		VoucherManagement: VoucherConfig{
			PersistToDB: true,
			VoucherSigning: VoucherSigningConfig{
				Mode:            "",               // "" = disabled, "internal" or "external"
				OwnerKeyType:    "ec384",          // for internal mode
				FirstTimeInit:   false,            // for internal mode
				ExternalCommand: "",               // for external mode
				ExternalTimeout: 30 * time.Second, // for external mode
			},
			OwnerSignover: struct {
				Enabled         bool          `yaml:"enabled"`
				ExternalCommand string        `yaml:"external_command"`
				Timeout         time.Duration `yaml:"timeout"`
			}{
				Enabled:         false,
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
		configPath = "config.yaml"
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
