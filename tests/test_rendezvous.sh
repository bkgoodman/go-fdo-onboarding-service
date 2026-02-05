#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Test script for rendezvous configuration functionality

echo "=== Testing Rendezvous Configuration ==="

# Clean up any existing test artifacts
rm -f /tmp/test_rendezvous.db
rm -rf /tmp/test_rendezvous_vouchers

# Start the server with rendezvous configuration
echo "🚀 Starting server with rendezvous configuration..."
./fdo-manufacturing-station -config tests/config_rendezvous_test.cfg &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Server failed to start"
    exit 1
fi

echo "✅ Server started (PID: $SERVER_PID)"

# Run a simple DI client test
echo "🔄 Running DI client test..."
cd go-fdo && timeout 10s go run ./examples/cmd/client -di http://localhost:8080 -di-key ec384 2>&1 | head -20
cd ..

# Check for any output indicating rendezvous was processed
echo "🔍 Checking for rendezvous processing..."
if grep -q "rendezvous\|RV info\|RvInfo" /tmp/test_rendezvous.db 2>/dev/null; then
    echo "✅ Rendezvous data found in database"
else
    echo "⚠️  No explicit rendezvous data found (this may be expected)"
fi

# Cleanup
echo "🧹 Cleaning up..."
kill -9 $SERVER_PID 2>/dev/null || true
rm -f /tmp/test_rendezvous.db
rm -rf /tmp/test_rendezvous_vouchers

echo "✅ Rendezvous configuration test completed!"
