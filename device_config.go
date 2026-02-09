// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

// FSIMConfig represents device-specific FSIM settings
type FSIMConfig struct {
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
	WiFiConfigFile  string   `yaml:"wifi_config_file"`
	Credentials     []string `yaml:"credentials"`
	PubkeyRequests  []string `yaml:"pubkey_requests"`
	CommandDate     bool     `yaml:"command_date"`
	SingleSidedWiFi bool     `yaml:"single_sided_wifi"`
}

// DeviceConfig represents a device-specific configuration file
type DeviceConfig struct {
	DeviceGUID string     `yaml:"device_guid"`
	Group      string     `yaml:"group"` // Reference to group config
	Hostname   string     `yaml:"hostname"`
	FSIM       FSIMConfig `yaml:"fsim"`
}

// GroupConfig represents a group configuration file
type GroupConfig struct {
	GroupName   string     `yaml:"group_name"`
	Description string     `yaml:"description"`
	FSIM        FSIMConfig `yaml:"fsim"`
}
