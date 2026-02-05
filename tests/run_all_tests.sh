#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman
set -eu

echo "🚀 FDO Manufacturing Station - Complete Test Suite"
echo "=================================================="

# Build first
echo "📦 Building..."
if go build -o fdo-manufacturing-station .; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

echo ""
echo "Running all tests..."
echo "=================================================="

PASSED=0
FAILED=0
TOTAL=0

run_test() {
    local name="$1"
    local script="$2"
    
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "Test $TOTAL: $name"
    
    if bash "$script" >/dev/null 2>&1; then
        echo "✅ PASS"
        PASSED=$((PASSED + 1))
    else
        echo "❌ FAIL"
        FAILED=$((FAILED + 1))
	exit 1
    fi
}

# Run all 12 tests
run_test "Basic Tests" "tests/test_basic.sh"
run_test "Echo Tests" "tests/test_echo.sh"
run_test "Fixed Owner" "tests/test_fixed_owner.sh"
run_test "Dynamic Owner" "tests/test_dynamic_owner.sh"
run_test "HSM Mock" "tests/test_hsm_mock.sh"
run_test "HSM Simple" "tests/test_hsm_simple.sh"
run_test "Mock HSM" "tests/test_mock_hsm.sh"
run_test "Disk Save" "tests/test_disk_save.sh"
run_test "Our Payload" "tests/test_our_payload.sh"
run_test "Payload" "tests/test_payload.sh"
run_test "Setup" "tests/test_setup.sh"
run_test "Simple" "tests/test_simple.sh"
run_test "Voucher Management" "tests/test_voucher_management.sh"
#run_test "Examples" "tests/test_examples.sh"

echo ""
echo "=================================================="
echo "Results: $PASSED passed, $FAILED failed out of $TOTAL total"
echo "=================================================="

if [ $FAILED -eq 0 ]; then
    echo "✅ All tests passed!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi
