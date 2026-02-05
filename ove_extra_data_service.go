// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// OVEExtraDataService handles fetching and encoding OVEExtra data
type OVEExtraDataService struct {
	config   *OVEExtraDataConfig
	executor *ExternalCommandExecutor
}

// NewOVEExtraDataService creates a new OVEExtra data service
func NewOVEExtraDataService(config *OVEExtraDataConfig, executor *ExternalCommandExecutor) *OVEExtraDataService {
	return &OVEExtraDataService{
		config:   config,
		executor: executor,
	}
}

// GetOVEExtraData fetches OVEExtra data from external script and returns as CBOR-encoded map
func (s *OVEExtraDataService) GetOVEExtraData(ctx context.Context, serial, model string) (map[int][]byte, error) {
	if !s.config.Enabled {
		return nil, nil // Disabled, return nil
	}

	// Call external script to get JSON data
	jsonData, err := s.fetchExtraData(ctx, serial, model)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch extra data: %w", err)
	}

	if jsonData == "" {
		return nil, nil // No data returned
	}

	// Parse JSON
	var rawData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON extra data: %w", err)
	}

	// Convert to OVEExtra format (map[int][]byte)
	extraData := make(map[int][]byte)
	for key, value := range rawData {
		// Convert key to int (OVEExtraInfoType)
		var keyInt int
		// Try to parse as int first, otherwise use hash
		if parsed, err := json.Number(key).Int64(); err == nil {
			keyInt = int(parsed)
		} else {
			// Use string hash as key type
			keyInt = hashString(key)
		}

		// Encode value as CBOR (handle type conversions)
		var valueToEncode interface{}
		switch v := value.(type) {
		case float64:
			// Convert float64 to string for CBOR compatibility
			valueToEncode = fmt.Sprintf("%.6f", v)
		case map[string]interface{}:
			// Recursively handle nested objects
			converted := make(map[string]interface{})
			for k, val := range v {
				switch val := val.(type) {
				case float64:
					converted[k] = fmt.Sprintf("%.6f", val)
				default:
					converted[k] = val
				}
			}
			valueToEncode = converted
		default:
			valueToEncode = value
		}

		valueBytes, err := cbor.Marshal(valueToEncode)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal extra data value: %w", err)
		}

		extraData[keyInt] = valueBytes
	}

	return extraData, nil
}

// fetchExtraData calls external script to get JSON data
func (s *OVEExtraDataService) fetchExtraData(ctx context.Context, serial, model string) (string, error) {
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// Execute external command
	variables := map[string]string{
		"serial": serial,
		"model":  model,
	}
	output, err := s.executor.Execute(timeoutCtx, variables)
	if err != nil {
		return "", fmt.Errorf("external command failed: %w", err)
	}

	return string(output), nil
}

// hashString creates a simple hash from string for OVEExtra key type
func hashString(s string) int {
	hash := 0
	for _, c := range s {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	// Ensure it's within reasonable range for OVEExtraInfoType
	return (hash % 1000) + 1 // Use keys 1-1000 for string-based keys
}
