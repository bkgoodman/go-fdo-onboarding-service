#!/bin/bash

# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Test runner for voucher management scenarios

set -e

TEST_DIR="/home/windsurf/go-fdo-di"
SERVER_LOG="/tmp/fdo_voucher_test.log"

echo "=== Voucher Management Test Runner ==="
echo ""

# Function to run server in background
run_server() {
    local config_file=$1
    local test_name=$2
    
    echo "Starting server for $test_name..."
    cd "$TEST_DIR"
    
    # Kill any existing server
    pkill -f "fdo-manufacturing-station" || true
    
    # Start server in background
    ./fdo-manufacturing-station -config "$config_file" > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 2
    
    # Check if server is running
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "❌ Server failed to start!"
        echo "Server log:"
        cat "$SERVER_LOG"
        exit 1
    fi
    
    echo "✅ Server started (PID: $SERVER_PID)"
}

# Function to stop server
stop_server() {
    if [ -n "$SERVER_PID" ]; then
        echo "Stopping server (PID: $SERVER_PID)..."
        kill -9 $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        sleep 1
        echo "✅ Server stopped"
    fi
}

# Function to run client test
run_client() {
    local test_name=$1
    
    echo "Running DI client for $test_name..."
    cd "$TEST_DIR"
    
    # Use the go-fdo client example
    timeout 10s ./go-fdo/examples/cmd/client client -di http://localhost:8080 >/dev/null 2>&1 || true
    
    echo "✅ Client test completed"
}

# Function to check voucher handler output
check_output() {
    local test_name=$1
    local expected_pattern=$2
    
    echo "Checking voucher handler output for $test_name..."
    
    if grep -q "$expected_pattern" "$SERVER_LOG"; then
        echo "✅ Found expected output: $expected_pattern"
        return 0
    else
        echo "❌ Expected output not found: $expected_pattern"
        echo "Recent server log:"
        tail -20 "$SERVER_LOG"
        return 1
    fi
}

# Main test execution
main() {
    echo "Building application..."
    cd "$TEST_DIR"
    go build -o fdo-manufacturing-station .
    
    # Test 1: Basic external handler
    echo ""
    echo "=== Test 1: Basic External Handler (Echo) ==="
    run_server "tests/config_mock_test.cfg" "Basic Test"
    run_client "Basic Test"
    check_output "Basic Test" "Voucher"
    stop_server
    
    echo ""
    echo "=== All Tests Completed ==="
    echo "✅ Voucher management test: PASSED"
    echo ""
    echo "Full server log available at: $SERVER_LOG"
}

# Cleanup on exit
trap stop_server EXIT

# Run main function
main "$@"
