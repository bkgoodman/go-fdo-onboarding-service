#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Test script for digest-based HSM signing with OVEExtra data

echo "=== Testing Digest-Based HSM Signing with OVEExtra Data ==="

# Build
echo "Building..."
go build -o fdo-manufacturing-station-digest

# Clean up any existing test directory
rm -rf /tmp/fdo_vouchers_digest

# Start server with digest HSM configuration
echo "Starting server with digest HSM configuration..."
./fdo-manufacturing-station-digest -config tests/config_digest_hsm_test.cfg &
SERVER_PID=$!
sleep 2

# Check if server started
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Failed to start server"
    exit 1
fi

echo "✅ Server started (PID: $SERVER_PID)"

# Run client
echo "Running client..."
cd go-fdo && timeout 10s go run ./examples/cmd/client -di http://localhost:8080 -di-key ec384 2>&1 | head -20
cd ../..

# Check for saved vouchers
echo "Checking for saved vouchers..."
if [ -d "/tmp/fdo_vouchers_digest" ]; then
    echo "✅ Voucher directory created: /tmp/fdo_vouchers_digest"
    echo "✅ Found voucher files:"
    ls -la /tmp/fdo_vouchers_digest/*.fdoov 2>/dev/null || echo "No voucher files found"
    
    # Check if voucher files exist
    voucher_files=(/tmp/fdo_vouchers_digest/*.fdoov)
    if [ ${#voucher_files[@]} -gt 0 ] && [ -f "${voucher_files[0]}" ]; then
        echo "Sample voucher content:"
        head -5 /tmp/fdo_vouchers_digest/*.fdoov | head -10
    fi
else
    echo "❌ Voucher directory not found"
fi

# Cleanup
echo "Cleaning up server (PID: $SERVER_PID)..."
kill -9 $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo "✅ Digest HSM test completed!"
