// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"database/sql"
	"fmt"
)

// InitDeviceMetadataTable creates the device_metadata table for tracking device-specific information
func InitDeviceMetadataTable(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS device_metadata (
			guid BLOB PRIMARY KEY,
			
			-- Voucher tracking
			voucher_source TEXT,           -- "file" or "database"
			voucher_loaded_at INTEGER,     -- Unix timestamp in microseconds
			
			-- Config tracking
			config_group TEXT,              -- Group name (if any)
			config_loaded_at INTEGER,       -- Unix timestamp in microseconds
			
			-- Onboarding tracking
			last_onboard INTEGER,           -- Last successful onboard timestamp (microseconds)
			last_seen INTEGER,              -- Last TO2 attempt timestamp (microseconds)
			onboard_count INTEGER DEFAULT 0,
			
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS device_metadata_last_onboard
			ON device_metadata(last_onboard DESC)`,
		`CREATE INDEX IF NOT EXISTS device_metadata_last_seen
			ON device_metadata(last_seen DESC)`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("error creating device metadata table: %w", err)
		}
	}

	return nil
}
