#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Mock HSM Handler for Testing
# Simulates HSM voucher signing without real HSM hardware

set -euo pipefail

# Function to output JSON error
error_exit() {
    local message="$1"
    echo "{\"signed_voucher\":\"\",\"request_id\":\"\",\"hsm_info\":{},\"error\":\"$message\"}"
    exit 1
}

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] MOCK-HSM: $*" >&2
}

# If no arguments provided, create a test request and run self-test
if [ $# -lt 1 ]; then
    # Create a test request file
    TEST_REQUEST="/tmp/test_hsm_mock_request.json"
    cat > "$TEST_REQUEST" << 'EOF'
{
  "voucher": "dGVzdCB2b3VjaGVyIGRhdGE=",
  "owner_key": "test_owner_key",
  "request_id": "test-req-123"
}
EOF
    REQUEST_FILE="$TEST_REQUEST"
    SERIALNO="TEST-SN"
    MODEL="TestModel"
    STATION="test-station"
    REQUESTID="test-req-123"
else
    REQUEST_FILE=$1
    SERIALNO=${2:-"unknown"}
    MODEL=${3:-"unknown"}
    STATION=${4:-"unknown"}
    REQUESTID=${5:-"unknown"}
fi

# Validate request file
if [ ! -f "$REQUEST_FILE" ]; then
    error_exit "Request file not found: $REQUEST_FILE"
fi

# Extract required fields using Python
eval "$(python3 -c "
import json
import sys
try:
    with open('$REQUEST_FILE', 'r') as f:
        data = json.load(f)
    voucher = data.get('voucher', '')
    owner_key = data.get('owner_key', '')
    request_id = data.get('request_id', '')
    print(f'voucher_base64=\"{voucher}\"')
    print(f'owner_key=\"{owner_key}\"')
    print(f'request_id=\"{request_id}\"')
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
")" || error_exit "Failed to parse JSON"

if [ -z "$voucher_base64" ] || [ -z "$owner_key" ] || [ -z "$request_id" ]; then
    error_exit "Missing required fields in request"
fi

# Log request details
log "Processing voucher signing request: $request_id"
log "Station: $STATION"
log "Device: $SERIALNO ($MODEL)"
log "Owner key type: $(echo "$owner_key" | head -1)"

# Decode voucher
log "Decoding voucher from base64"
echo "$voucher_base64" | base64 -d > /tmp/voucher.cbor || error_exit "Failed to decode voucher"

# Validate CBOR (simple check)
if [ ! -s /tmp/voucher.cbor ]; then
    error_exit "Decoded voucher is empty"
fi

# Log voucher info
voucher_size=$(wc -c < /tmp/voucher.cbor)
log "Voucher size: $voucher_size bytes"

# MOCK HSM SIGNING - Just return the voucher unchanged
log "MOCK HSM: Simulating voucher signing..."
signing_start=$(date +%s.%N)

# In a real HSM, this would:
# 1. Parse the voucher structure
# 2. Validate the voucher
# 3. Sign with the owner key
# 4. Return the signed voucher

# For testing, we'll just return the voucher unchanged
# This allows testing the JSON communication flow
log "MOCK HSM: Returning voucher unchanged for testing"
cp /tmp/voucher.cbor /tmp/signed.cbor

signing_end=$(date +%s.%N)
signing_duration=$(echo "$signing_end - $signing_start" | bc -l)

log "MOCK HSM: 'Signing' completed in ${signing_duration}s"

# Encode signed voucher to base64 (remove newlines)
log "Encoding signed voucher to base64"
signed_voucher_base64=$(base64 -w 0 /tmp/signed.cbor) || error_exit "Failed to encode signed voucher"

# Create response
response=$(cat <<EOF
{
  "signed_voucher": "$signed_voucher_base64",
  "request_id": "$request_id",
  "hsm_info": {
    "hsm_id": "mock-hsm-01",
    "signing_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "key_id": "mock-key-12345",
    "signing_duration_ms": $(echo "$signing_duration * 1000" | bc -l),
    "note": "Mock HSM - voucher returned unchanged for testing"
  },
  "error": ""
}
EOF
)

# Cleanup
rm -f /tmp/voucher.cbor /tmp/signed.cbor

log "MOCK HSM: Voucher signing request completed: $request_id"

# Output response (must be last thing to stdout)
echo "$response"
