#!/bin/bash

# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Basic test for voucher management

set -e

# Cleanup function
cleanup() {
    if [ -n "${SERVER_PID:-}" ] && kill -0 $SERVER_PID 2>/dev/null; then
        kill -9 $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

echo "=== Basic Voucher Management Test ==="

# Setup
cd /home/windsurf/go-fdo-di
rm -f test.db
rm -f /tmp/fdo_basic_test.log

# Build
echo "Building..."
go build -o fdo-manufacturing-station .

# Start server
echo "Starting server..."
./fdo-manufacturing-station -config tests/config_mock_test.cfg > /tmp/fdo_basic_test.log 2>&1 &
SERVER_PID=$!
sleep 3

# Check if server started
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Server failed to start!"
    cat /tmp/fdo_basic_test.log
    exit 1
fi

echo "✅ Server started (PID: $SERVER_PID)"

# Run client
echo "Running client..."
timeout 10s ./go-fdo/examples/cmd/client client -di http://localhost:8080 >/dev/null 2>&1 || true

# Check output
echo "Checking voucher handler output..."
if grep -q "Voucher signed successfully\|VoucherUploadService.UploadVoucher" /tmp/fdo_basic_test.log; then
    echo "✅ Found voucher signing/upload output!"
    echo "Handler output:"
    grep "Voucher signed successfully\|VoucherUploadService.UploadVoucher" /tmp/fdo_basic_test.log || true
else
    echo "❌ No voucher output found!"
    echo "Server log:"
    tail -20 /tmp/fdo_basic_test.log
fi

# Stop server
echo "Stopping server..."
kill -9 $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
sleep 1

echo "✅ Basic test completed!"
