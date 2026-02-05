#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman
# Simple Mock HSM Handler for Testing

# If no arguments provided, create a test request and run self-test
if [ $# -lt 1 ]; then
    # Create a test request file
    TEST_REQUEST="/tmp/test_hsm_simple_request.json"
    cat > "$TEST_REQUEST" << 'EOF'
{
  "voucher": "dGVzdCB2b3VjaGVyIGRhdGE="
}
EOF
    REQUEST_FILE="$TEST_REQUEST"
    SERIALNO="TEST-SN"
    MODEL="TestModel"
    STATION="test-station"
    REQUESTID="test-req-123"
else
    REQUEST_FILE=$1
    SERIALNO=$2
    MODEL=$3
    STATION=$4
    REQUESTID=$5
fi

# Check if request file exists
if [ ! -f "$REQUEST_FILE" ]; then
    # Return error response
    echo '{
      "signed_voucher": "",
      "request_id": "'$REQUESTID'",
      "hsm_info": {},
      "error": "Request file not found: '$REQUEST_FILE'"
    }'
    exit 1
fi

# Extract voucher using Python
voucher_base64=$(python3 -c "
import json
with open('$REQUEST_FILE', 'r') as f:
    data = json.load(f)
    print(data['voucher'])
")

# Create response with the original voucher
echo '{
  "signed_voucher": "'$voucher_base64'",
  "request_id": "'$REQUESTID'",
  "hsm_info": {
    "hsm_id": "mock-hsm-01",
    "signing_time": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "key_id": "mock-key-12345"
  },
  "error": ""
}'

exit 0
