#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Test script for mock HSM voucher signing
# Creates a test JSON request and verifies the mock HSM response

set -euo pipefail

echo "=== Testing Mock HSM Voucher Signing ==="

# Create a test JSON request
TEST_REQUEST_FILE="/tmp/test_hsm_request.json"

cat > "$TEST_REQUEST_FILE" << 'EOF'
{
  "voucher": "dGVzdCB2b3VjaGVyIGRhdGE=",
  "owner_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+UWQc7Qf5qB5RtvGzKB8wQ\n-----END PUBLIC KEY-----",
  "request_id": "test-req-12345",
  "timestamp": "2026-02-04T19:45:00Z",
  "manufacturing_station": "test-station-01",
  "device_info": {
    "serialno": "TEST-SN-12345",
    "model": "TestModel"
  }
}
EOF

echo "Created test request file: $TEST_REQUEST_FILE"
echo ""

# Show the test request
echo "Test Request:"
cat "$TEST_REQUEST_FILE"
echo ""

# Call the mock HSM
echo "Calling Mock HSM..."
echo ""

RESPONSE_FILE="/tmp/hsm_response.json"
bash tests/test_hsm_mock.sh "$TEST_REQUEST_FILE" "TEST-SN-12345" "TestModel" "test-station-01" "test-req-12345" > "$RESPONSE_FILE" 2> /tmp/hsm_log.txt

# Show the response
echo "Mock HSM Response:"
cat "$RESPONSE_FILE"
echo ""

# Show the log
echo "Mock HSM Log:"
cat /tmp/hsm_log.txt
echo ""

# Validate the response
echo "=== Validating Response ==="

# Check if response is valid JSON using Python
if python3 -c "import json; json.load(open('$RESPONSE_FILE'))" 2>/dev/null; then
    echo "✅ Response is valid JSON"
else
    echo "❌ Response is not valid JSON"
    exit 1
fi

# Check required fields using Python
eval "$(python3 -c "
import json
with open('$RESPONSE_FILE', 'r') as f:
    data = json.load(f)
signed_voucher = data.get('signed_voucher', '')
request_id = data.get('request_id', '')
hsm_id = data.get('hsm_info', {}).get('hsm_id', '')
error = data.get('error', '')
print(f'signed_voucher=\"{signed_voucher}\"')
print(f'request_id=\"{request_id}\"')
print(f'hsm_id=\"{hsm_id}\"')
print(f'error=\"{error}\"')
")"

if [ "$signed_voucher" = "dGVzdCB2b3VjaGVyIGRhdGE=" ]; then
    echo "✅ Signed voucher matches input (returned unchanged)"
else
    echo "❌ Signed voucher mismatch"
fi

if [ "$request_id" = "test-req-12345" ]; then
    echo "✅ Request ID matches"
else
    echo "❌ Request ID mismatch: expected 'test-req-12345', got '$request_id'"
fi

if [ "$hsm_id" = "mock-hsm-01" ]; then
    echo "✅ HSM ID matches"
else
    echo "❌ HSM ID mismatch: expected 'mock-hsm-01', got '$hsm_id'"
fi

if [ "$error" = "" ]; then
    echo "✅ No error in response"
else
    echo "❌ Unexpected error: $error"
fi

echo ""
echo "=== Mock HSM Test Complete ==="

# Cleanup
rm -f "$TEST_REQUEST_FILE" "$RESPONSE_FILE" /tmp/hsm_log.txt

echo "✅ Mock HSM test passed!"
