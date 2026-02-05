#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Example Shell Script HSM Handler
# Demonstrates JSON-based voucher signing for external HSM integration

set -euo pipefail

# Function to output JSON error
error_exit() {
    local message="$1"
    echo "{\"signed_voucher\":\"\",\"request_id\":\"\",\"hsm_info\":{},\"error\":\"$message\"}"
    exit 1
}

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

# Validate arguments
if [ $# -lt 1 ]; then
    error_exit "Missing request file argument"
fi

REQUEST_FILE=$1
SERIALNO=${2:-"unknown"}
MODEL=${3:-"unknown"}
STATION=${4:-"unknown"}
REQUESTID=${5:-"unknown"}

# Validate request file
if [ ! -f "$REQUEST_FILE" ]; then
    error_exit "Request file not found: $REQUEST_FILE"
fi

# Read and validate JSON
if ! jq -e . "$REQUEST_FILE" >/dev/null 2>&1; then
    error_exit "Invalid JSON in request file"
fi

# Extract required fields
voucher_base64=$(jq -r '.voucher' "$REQUEST_FILE" 2>/dev/null) || error_exit "Missing 'voucher' field"
owner_key=$(jq -r '.owner_key' "$REQUEST_FILE" 2>/dev/null) || error_exit "Missing 'owner_key' field"
request_id=$(jq -r '.request_id' "$REQUEST_FILE" 2>/dev/null) || error_exit "Missing 'request_id' field"

# Log request details
log "Processing voucher signing request: $request_id"
log "Station: $STATION"
log "Device: $SERIALNO ($MODEL)"

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

# Simulate HSM signing (replace with actual HSM command)
log "Calling HSM for voucher signing..."
signing_start=$(date +%s.%N)

# Example HSM command (replace with actual HSM integration)
# /opt/hsm/bin/sign-voucher /tmp/voucher.cbor "$owner_key" > /tmp/signed.cbor
# For demo, we'll just copy the unsigned voucher
cp /tmp/voucher.cbor /tmp/signed.cbor

signing_end=$(date +%s.%N)
signing_duration=$(echo "$signing_end - $signing_start" | bc -l)

log "HSM signing completed in ${signing_duration}s"

# Encode signed voucher to base64
log "Encoding signed voucher to base64"
signed_voucher_base64=$(base64 /tmp/signed.cbor) || error_exit "Failed to encode signed voucher"

# Create response
response=$(cat <<EOF
{
  "signed_voucher": "$signed_voucher_base64",
  "request_id": "$request_id",
  "hsm_info": {
    "hsm_id": "example-hsm-01",
    "signing_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "key_id": "example-key-12345",
    "signing_duration_ms": $(echo "$signing_duration * 1000" | bc -l)
  },
  "error": ""
}
EOF
)

# Output response
echo "$response"

# Cleanup
rm -f /tmp/voucher.cbor /tmp/signed.cbor

log "Voucher signing request completed: $request_id"
