// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
	"gopkg.in/yaml.v3"
)

// DeviceStorageManager manages device-specific files (vouchers and configs)
type DeviceStorageManager struct {
	VoucherDir string
	ConfigDir  string
	DB         *sqlite.DB
	Config     *Config
}

// DeviceEvent represents types of device events for metadata tracking
type DeviceEvent int

const (
	DeviceEventSeen DeviceEvent = iota
	DeviceEventOnboarded
	DeviceEventFailed
)

// Voucher retrieves a voucher by GUID, checking files first, then database
func (m *DeviceStorageManager) Voucher(ctx context.Context, guid protocol.GUID) (*fdo.Voucher, error) {
	guidStr := hex.EncodeToString(guid[:])

	// First check if voucher exists in database
	voucher, err := m.DB.Voucher(ctx, guid)
	if err == nil {
		log.Printf("✓ Voucher found in database for device GUID: %s", guidStr)
		return voucher, nil
	}

	// If not in database, try to load from file
	if err == fdo.ErrNotFound {
		log.Printf("Voucher not in database, checking file system for GUID: %s", guidStr)
		voucher, err := m.loadVoucherFromFile(guid)
		if err != nil {
			if err == fdo.ErrNotFound {
				log.Printf("✗ ERROR: Voucher not found for device GUID: %s", guidStr)
				log.Printf("  Expected voucher file: %s/%s.fdoov", m.VoucherDir, guidStr)
				log.Printf("  Device cannot onboard without a valid voucher")
			} else {
				log.Printf("✗ ERROR: Failed to load voucher for GUID %s: %v", guidStr, err)
			}
			return nil, err
		}

		log.Printf("✓ Voucher loaded from file for device GUID: %s", guidStr)

		// Cache voucher in database
		if err := m.DB.AddVoucher(ctx, voucher); err != nil {
			// Log error but don't fail - we have the voucher
			fmt.Fprintf(os.Stderr, "Warning: Failed to cache voucher in database: %v\n", err)
		}

		// Update metadata
		if err := m.updateVoucherMetadata(ctx, guid, "file"); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to update voucher metadata: %v\n", err)
		}

		return voucher, nil
	}

	log.Printf("✗ ERROR: Database error while looking up voucher for GUID %s: %v", guidStr, err)
	return nil, err
}

// AddVoucher stores a voucher in the database
func (m *DeviceStorageManager) AddVoucher(ctx context.Context, ov *fdo.Voucher) error {
	if err := m.DB.AddVoucher(ctx, ov); err != nil {
		return err
	}

	// Update metadata to indicate database source
	guid := ov.Header.Val.GUID
	return m.updateVoucherMetadata(ctx, guid, "database")
}

// ReplaceVoucher stores a new voucher, possibly deleting the previous one
func (m *DeviceStorageManager) ReplaceVoucher(ctx context.Context, guid protocol.GUID, ov *fdo.Voucher) error {
	if err := m.DB.ReplaceVoucher(ctx, guid, ov); err != nil {
		return err
	}

	// Update onboarding metadata
	if err := m.UpdateDeviceMetadata(ctx, guid, DeviceEventOnboarded); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to update device metadata: %v\n", err)
	}

	// Optionally delete voucher file if configured
	if m.Config.DeviceStorage.DeleteAfterOnboard {
		if err := m.deleteVoucherFile(guid); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to delete voucher file: %v\n", err)
		}
	}

	return nil
}

// RemoveVoucher untracks a voucher and returns it for extension
func (m *DeviceStorageManager) RemoveVoucher(ctx context.Context, guid protocol.GUID) (*fdo.Voucher, error) {
	return m.DB.RemoveVoucher(ctx, guid)
}

// loadVoucherFromFile reads and parses a PEM-encoded voucher file
func (m *DeviceStorageManager) loadVoucherFromFile(guid protocol.GUID) (*fdo.Voucher, error) {
	// Find voucher file
	filepath, err := m.findVoucherFile(guid)
	if err != nil {
		return nil, err
	}

	// Read file
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading voucher file: %w", err)
	}

	// Parse PEM format
	pemData := string(data)

	// Extract base64 data between PEM markers
	start := strings.Index(pemData, "-----BEGIN OWNERSHIP VOUCHER-----")
	end := strings.Index(pemData, "-----END OWNERSHIP VOUCHER-----")
	if start == -1 || end == -1 {
		return nil, fmt.Errorf("invalid PEM format: missing markers")
	}

	start += len("-----BEGIN OWNERSHIP VOUCHER-----")
	base64Data := strings.TrimSpace(pemData[start:end])
	base64Data = strings.ReplaceAll(base64Data, "\n", "")
	base64Data = strings.ReplaceAll(base64Data, "\r", "")

	// Decode base64
	cborData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64: %w", err)
	}

	// Unmarshal CBOR to voucher
	var voucher fdo.Voucher
	if err := cbor.Unmarshal(cborData, &voucher); err != nil {
		return nil, fmt.Errorf("error unmarshaling voucher: %w", err)
	}

	return &voucher, nil
}

// findVoucherFile locates voucher file by GUID
func (m *DeviceStorageManager) findVoucherFile(guid protocol.GUID) (string, error) {
	// Convert GUID to hex string (without dashes)
	guidStr := hex.EncodeToString(guid[:])

	// Check for {guid}.fdoov
	filepath := filepath.Join(m.VoucherDir, guidStr+".fdoov")
	if _, err := os.Stat(filepath); err == nil {
		return filepath, nil
	}

	return "", fdo.ErrNotFound
}

// deleteVoucherFile deletes a voucher file
func (m *DeviceStorageManager) deleteVoucherFile(guid protocol.GUID) error {
	filepath, err := m.findVoucherFile(guid)
	if err != nil {
		return err
	}

	return os.Remove(filepath)
}

// updateVoucherMetadata updates voucher metadata in database
func (m *DeviceStorageManager) updateVoucherMetadata(ctx context.Context, guid protocol.GUID, source string) error {
	now := time.Now().UnixMicro()

	_, err := m.DB.DB().ExecContext(ctx, `
		INSERT INTO device_metadata (guid, voucher_source, voucher_loaded_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(guid) DO UPDATE SET
			voucher_source = excluded.voucher_source,
			voucher_loaded_at = excluded.voucher_loaded_at,
			updated_at = excluded.updated_at
	`, guid[:], source, now, now, now)

	return err
}

// UpdateDeviceMetadata tracks device events (seen, onboarded, failed)
func (m *DeviceStorageManager) UpdateDeviceMetadata(ctx context.Context, guid protocol.GUID, event DeviceEvent) error {
	now := time.Now().UnixMicro()

	switch event {
	case DeviceEventSeen:
		_, err := m.DB.DB().ExecContext(ctx, `
			INSERT INTO device_metadata (guid, last_seen, created_at, updated_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(guid) DO UPDATE SET
				last_seen = excluded.last_seen,
				updated_at = excluded.updated_at
		`, guid[:], now, now, now)
		return err

	case DeviceEventOnboarded:
		_, err := m.DB.DB().ExecContext(ctx, `
			INSERT INTO device_metadata (guid, last_onboard, last_seen, onboard_count, created_at, updated_at)
			VALUES (?, ?, ?, 1, ?, ?)
			ON CONFLICT(guid) DO UPDATE SET
				last_onboard = excluded.last_onboard,
				last_seen = excluded.last_seen,
				onboard_count = onboard_count + 1,
				updated_at = excluded.updated_at
		`, guid[:], now, now, now, now)
		return err

	case DeviceEventFailed:
		_, err := m.DB.DB().ExecContext(ctx, `
			INSERT INTO device_metadata (guid, last_seen, created_at, updated_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(guid) DO UPDATE SET
				last_seen = excluded.last_seen,
				updated_at = excluded.updated_at
		`, guid[:], now, now, now)
		return err
	}

	return nil
}

// LoadDeviceConfig loads and merges device-specific configuration
func (m *DeviceStorageManager) LoadDeviceConfig(ctx context.Context, guid protocol.GUID) (*FSIMConfig, error) {
	// Start with global config
	globalConfig := m.configToFSIM(&m.Config.FSIM)

	// Try to load device config
	deviceConfig, groupName, err := m.loadDeviceConfigFile(guid)
	if err != nil {
		// If no device config, return global config
		if os.IsNotExist(err) {
			return globalConfig, nil
		}
		return nil, err
	}

	// Try to load group config if referenced
	var groupConfig *FSIMConfig
	if groupName != "" {
		groupConfig, err = m.loadGroupConfigFile(groupName)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("error loading group config: %w", err)
		}
	}

	// Merge configs: device → group → global
	merged := m.mergeConfigs(globalConfig, groupConfig, deviceConfig)

	// Update metadata
	if err := m.updateConfigMetadata(ctx, guid, groupName); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to update config metadata: %v\n", err)
	}

	return merged, nil
}

// loadDeviceConfigFile loads a device-specific config file
func (m *DeviceStorageManager) loadDeviceConfigFile(guid protocol.GUID) (*FSIMConfig, string, error) {
	guidStr := hex.EncodeToString(guid[:])
	filepath := filepath.Join(m.ConfigDir, "devices", guidStr+".yaml")

	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, "", err
	}

	var deviceConfig DeviceConfig
	if err := yaml.Unmarshal(data, &deviceConfig); err != nil {
		return nil, "", fmt.Errorf("error parsing device config: %w", err)
	}

	return &deviceConfig.FSIM, deviceConfig.Group, nil
}

// loadGroupConfigFile loads a group config file
func (m *DeviceStorageManager) loadGroupConfigFile(groupName string) (*FSIMConfig, error) {
	filepath := filepath.Join(m.ConfigDir, "groups", groupName+".yaml")

	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var groupConfig GroupConfig
	if err := yaml.Unmarshal(data, &groupConfig); err != nil {
		return nil, fmt.Errorf("error parsing group config: %w", err)
	}

	return &groupConfig.FSIM, nil
}

// Helper functions for reflection-based field extraction
func getString(val reflect.Value, fieldName string) string {
	field := val.FieldByName(fieldName)
	if !field.IsValid() || field.Kind() != reflect.String {
		return ""
	}
	return field.String()
}

func getStringSlice(val reflect.Value, fieldName string) []string {
	field := val.FieldByName(fieldName)
	if !field.IsValid() || field.Kind() != reflect.Slice {
		return nil
	}
	result := make([]string, field.Len())
	for i := 0; i < field.Len(); i++ {
		result[i] = field.Index(i).String()
	}
	return result
}

func getBool(val reflect.Value, fieldName string) bool {
	field := val.FieldByName(fieldName)
	if !field.IsValid() || field.Kind() != reflect.Bool {
		return false
	}
	return field.Bool()
}

// configToFSIM converts Config.FSIM to FSIMConfig
func (m *DeviceStorageManager) configToFSIM(src interface{}) *FSIMConfig {
	// Use type assertion to extract the anonymous struct
	type FSIMStruct struct {
		Downloads       []string
		UploadDir       string
		Uploads         []string
		Wgets           []string
		Sysconfig       []string
		PayloadFile     string
		PayloadMime     string
		PayloadFiles    []string
		BMOFile         string
		BMOImageType    string
		BMOFiles        []string
		WiFiConfigFile  string
		Credentials     []string
		PubkeyRequests  []string
		CommandDate     bool
		SingleSidedWiFi bool
	}

	// Handle both pointer and value types using reflection
	// This is needed because the config YAML unmarshals to an anonymous struct
	// that has the same fields but different type identity
	val := reflect.ValueOf(src)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	var fsim FSIMStruct
	if val.Kind() == reflect.Struct {
		// Use reflection to copy fields from src to fsim
		fsim = FSIMStruct{
			Downloads:       getStringSlice(val, "Downloads"),
			UploadDir:       getString(val, "UploadDir"),
			Uploads:         getStringSlice(val, "Uploads"),
			Wgets:           getStringSlice(val, "Wgets"),
			Sysconfig:       getStringSlice(val, "Sysconfig"),
			PayloadFile:     getString(val, "PayloadFile"),
			PayloadMime:     getString(val, "PayloadMime"),
			PayloadFiles:    getStringSlice(val, "PayloadFiles"),
			BMOFile:         getString(val, "BMOFile"),
			BMOImageType:    getString(val, "BMOImageType"),
			BMOFiles:        getStringSlice(val, "BMOFiles"),
			WiFiConfigFile:  getString(val, "WiFiConfigFile"),
			Credentials:     getStringSlice(val, "Credentials"),
			PubkeyRequests:  getStringSlice(val, "PubkeyRequests"),
			CommandDate:     getBool(val, "CommandDate"),
			SingleSidedWiFi: getBool(val, "SingleSidedWiFi"),
		}
	}

	return &FSIMConfig{
		Downloads:       fsim.Downloads,
		UploadDir:       fsim.UploadDir,
		Uploads:         fsim.Uploads,
		Wgets:           fsim.Wgets,
		Sysconfig:       fsim.Sysconfig,
		PayloadFile:     fsim.PayloadFile,
		PayloadMime:     fsim.PayloadMime,
		PayloadFiles:    fsim.PayloadFiles,
		BMOFile:         fsim.BMOFile,
		BMOImageType:    fsim.BMOImageType,
		BMOFiles:        fsim.BMOFiles,
		WiFiConfigFile:  fsim.WiFiConfigFile,
		Credentials:     fsim.Credentials,
		PubkeyRequests:  fsim.PubkeyRequests,
		CommandDate:     fsim.CommandDate,
		SingleSidedWiFi: fsim.SingleSidedWiFi,
	}
}

// mergeConfigs merges three tiers of configuration
func (m *DeviceStorageManager) mergeConfigs(global, group, device *FSIMConfig) *FSIMConfig {
	merged := &FSIMConfig{}

	// Arrays: concatenate (device + group + global)
	if device != nil {
		merged.Downloads = append(merged.Downloads, device.Downloads...)
		merged.Uploads = append(merged.Uploads, device.Uploads...)
		merged.Wgets = append(merged.Wgets, device.Wgets...)
		merged.PayloadFiles = append(merged.PayloadFiles, device.PayloadFiles...)
		merged.BMOFiles = append(merged.BMOFiles, device.BMOFiles...)
		merged.Credentials = append(merged.Credentials, device.Credentials...)
		merged.PubkeyRequests = append(merged.PubkeyRequests, device.PubkeyRequests...)
	}
	if group != nil {
		merged.Downloads = append(merged.Downloads, group.Downloads...)
		merged.Uploads = append(merged.Uploads, group.Uploads...)
		merged.Wgets = append(merged.Wgets, group.Wgets...)
		merged.PayloadFiles = append(merged.PayloadFiles, group.PayloadFiles...)
		merged.BMOFiles = append(merged.BMOFiles, group.BMOFiles...)
		merged.Credentials = append(merged.Credentials, group.Credentials...)
		merged.PubkeyRequests = append(merged.PubkeyRequests, group.PubkeyRequests...)
	}
	if global != nil {
		merged.Downloads = append(merged.Downloads, global.Downloads...)
		merged.Uploads = append(merged.Uploads, global.Uploads...)
		merged.Wgets = append(merged.Wgets, global.Wgets...)
		merged.PayloadFiles = append(merged.PayloadFiles, global.PayloadFiles...)
		merged.BMOFiles = append(merged.BMOFiles, global.BMOFiles...)
		merged.Credentials = append(merged.Credentials, global.Credentials...)
		merged.PubkeyRequests = append(merged.PubkeyRequests, global.PubkeyRequests...)
	}

	// Scalars: device overrides group overrides global
	merged.UploadDir = coalesce(
		device != nil && device.UploadDir != "",
		group != nil && group.UploadDir != "",
		global != nil && global.UploadDir != "",
		func() string {
			if device != nil && device.UploadDir != "" {
				return device.UploadDir
			}
			if group != nil && group.UploadDir != "" {
				return group.UploadDir
			}
			if global != nil {
				return global.UploadDir
			}
			return ""
		}(),
	)

	merged.PayloadFile = coalesceString(device, group, global, func(c *FSIMConfig) string { return c.PayloadFile })
	merged.PayloadMime = coalesceString(device, group, global, func(c *FSIMConfig) string { return c.PayloadMime })
	merged.BMOFile = coalesceString(device, group, global, func(c *FSIMConfig) string { return c.BMOFile })
	merged.BMOImageType = coalesceString(device, group, global, func(c *FSIMConfig) string { return c.BMOImageType })
	merged.WiFiConfigFile = coalesceString(device, group, global, func(c *FSIMConfig) string { return c.WiFiConfigFile })

	// Booleans: device overrides group overrides global
	merged.CommandDate = coalesceBool(device, group, global, func(c *FSIMConfig) bool { return c.CommandDate })
	merged.SingleSidedWiFi = coalesceBool(device, group, global, func(c *FSIMConfig) bool { return c.SingleSidedWiFi })

	// Sysconfig: merge by key with override precedence
	merged.Sysconfig = m.mergeSysconfigByKey(global, group, device)

	return merged
}

// coalesce returns the first non-empty string
func coalesce(checks ...interface{}) string {
	if len(checks) == 0 {
		return ""
	}
	// Last element should be the actual string
	if str, ok := checks[len(checks)-1].(string); ok {
		return str
	}
	return ""
}

// coalesceString returns the first non-empty string field from configs
func coalesceString(device, group, global *FSIMConfig, getter func(*FSIMConfig) string) string {
	if device != nil {
		if val := getter(device); val != "" {
			return val
		}
	}
	if group != nil {
		if val := getter(group); val != "" {
			return val
		}
	}
	if global != nil {
		return getter(global)
	}
	return ""
}

// coalesceBool returns the first true boolean field from configs
func coalesceBool(device, group, global *FSIMConfig, getter func(*FSIMConfig) bool) bool {
	if device != nil && getter(device) {
		return true
	}
	if group != nil && getter(group) {
		return true
	}
	if global != nil {
		return getter(global)
	}
	return false
}

// mergeSysconfigByKey merges sysconfig arrays with key-based override
func (m *DeviceStorageManager) mergeSysconfigByKey(global, group, device *FSIMConfig) []string {
	keyMap := make(map[string]string)

	// Add global configs
	if global != nil {
		for _, kv := range global.Sysconfig {
			if key, val := parseSysconfigKV(kv); key != "" {
				keyMap[key] = val
			}
		}
	}

	// Add group configs (override global)
	if group != nil {
		for _, kv := range group.Sysconfig {
			if key, val := parseSysconfigKV(kv); key != "" {
				keyMap[key] = val
			}
		}
	}

	// Add device configs (override group and global)
	if device != nil {
		for _, kv := range device.Sysconfig {
			if key, val := parseSysconfigKV(kv); key != "" {
				keyMap[key] = val
			}
		}
	}

	// Convert back to array
	result := make([]string, 0, len(keyMap))
	for key, val := range keyMap {
		result = append(result, key+"="+val)
	}

	return result
}

// parseSysconfigKV parses a key=value pair
func parseSysconfigKV(kv string) (string, string) {
	parts := strings.SplitN(kv, "=", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// updateConfigMetadata updates config metadata in database
func (m *DeviceStorageManager) updateConfigMetadata(ctx context.Context, guid protocol.GUID, groupName string) error {
	now := time.Now().UnixMicro()

	_, err := m.DB.DB().ExecContext(ctx, `
		INSERT INTO device_metadata (guid, config_group, config_loaded_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(guid) DO UPDATE SET
			config_group = excluded.config_group,
			config_loaded_at = excluded.config_loaded_at,
			updated_at = excluded.updated_at
	`, guid[:], groupName, now, now, now)

	return err
}
