#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Test script for voucher disk saving feature

set -e

echo "=== Testing Voucher Disk Saving ==="

# Test directory
TEST_DIR="/tmp/fdo_vouchers"
SERVER_LOG="/tmp/fdo_disk_save_test.log"

# Cleanup function
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        echo "Cleaning up server (PID: $SERVER_PID)..."
        kill -9 $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    # Clean up test directory (comment out to preserve vouchers for inspection)
    # rm -rf "$TEST_DIR"
    rm -f "$SERVER_LOG"
}

# Set trap for cleanup
trap cleanup EXIT

# Clean up any existing test directory (comment out to preserve existing vouchers)
# # rm -rf "$TEST_DIR"

echo "Building..."
go build -o fdo-manufacturing-station .

echo "Starting server with disk save configuration..."
./fdo-manufacturing-station -config tests/config_disk_save_test.cfg > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Server failed to start!"
    cat "$SERVER_LOG"
    exit 1
fi

echo "✅ Server started (PID: $SERVER_PID)"

# Run client
echo "Running client..."
timeout 10s ./go-fdo/examples/cmd/client client -di http://localhost:8080 || true

# Show server log
echo "Server log:"
cat "$SERVER_LOG" | tail -30

# Check if voucher was saved to disk
echo "Checking for saved vouchers..."
if [ -d "$TEST_DIR" ]; then
    echo "✅ Voucher directory created: $TEST_DIR"
    
    # List saved vouchers
    if ls "$TEST_DIR"/*.fdoov >/dev/null 2>&1; then
        echo "✅ Found voucher files:"
        ls -la "$TEST_DIR"/*.fdoov
        
        # Show content of first voucher file
        first_voucher=$(ls "$TEST_DIR"/*.fdoov | head -1)
        echo ""
        echo "Sample voucher content:"
        head -20 "$first_voucher"
        echo ""
        
        # Verify voucher format
        if [ "$(head -1 "$first_voucher")" = "-----BEGIN OWNERSHIP VOUCHER-----" ]; then
            echo "✅ Voucher format is correct"
        else
            echo "❌ Voucher format is incorrect"
            exit 1
        fi
        
        # Verify base64 content
        if [ "$(tail -1 "$first_voucher")" = "-----END OWNERSHIP VOUCHER-----" ]; then
            echo "✅ Voucher has proper footer"
        else
            echo "❌ Voucher footer missing"
            exit 1
        fi
        
        # Validate voucher with go-fdo delegate inspectVoucher
        echo "🔍 Validating voucher with go-fdo delegate inspectVoucher..."
        # Check if voucher can be parsed (look for "Version" in output)
        if (cd go-fdo/examples && go run ./cmd delegate -db /tmp/fdo_disk_save_test.db inspectVoucher "$first_voucher" 2>&1 | grep -q "Version"); then
            echo "✅ Voucher validation passed (go-fdo delegate inspectVoucher)"
            echo "📋 Voucher details:"
            (cd go-fdo/examples && go run ./cmd delegate -db /tmp/fdo_disk_save_test.db inspectVoucher "$first_voucher" | head -10) || true
        else
            echo "❌ Voucher validation failed (go-fdo delegate inspectVoucher)"
            echo "Debug output:"
            (cd go-fdo/examples && go run ./cmd delegate -db /tmp/fdo_disk_save_test.db inspectVoucher "$first_voucher" 2>&1 | head -10) || true
            exit 1
        fi
        
    else
        echo "❌ No voucher files found in directory"
        exit 1
    fi
else
    echo "❌ Voucher directory was not created"
    exit 1
fi

# Check server log for disk save messages
if grep -q "💾 Saved ownership voucher to disk" "$SERVER_LOG"; then
    echo "✅ Server logged voucher save operation"
else
    echo "⚠️  No disk save log found (may be expected if no voucher was processed)"
fi

echo ""
echo "✅ Disk save test completed successfully!"
