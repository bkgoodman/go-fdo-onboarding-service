#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Mock HSM Handler for Digest Signing
# Simulates HSM that signs a digest (binary blob) and returns signature

set -euo pipefail

# Function to output JSON error
error_exit() {
    local message="$1"
    echo "{\"signature\":\"\",\"request_id\":\"\",\"hsm_info\":{},\"error\":\"$message\"}"
    exit 1
}

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] MOCK-HSM-DIGEST: $*" >&2
}

# If no arguments provided, create a test request and run self-test
if [ $# -lt 1 ]; then
    # Create a test request file
    TEST_REQUEST="/tmp/test_hsm_digest_request.json"
    cat > "$TEST_REQUEST" << 'EOF'
{
  "digest": "dGVzdCBkaWdlc3QgZGF0YQ==",
  "request_id": "test-req-123",
  "signing_options": {
    "hash": "SHA256",
    "key_type": "ECDSA-P384"
  }
}
EOF
    REQUEST_FILE="$TEST_REQUEST"
    REQUESTID="test-req-123"
    STATION="test-station"
else
    REQUEST_FILE=$1
    REQUESTID=${2:-"unknown"}
    STATION=${3:-"unknown"}
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
    digest = data.get('digest', '')
    request_id = data.get('request_id', '')
    signing_options = data.get('signing_options', {})
    hash_alg = signing_options.get('hash', 'SHA256')
    key_type = signing_options.get('key_type', 'ECDSA-P384')
    print(f'digest_base64=\"{digest}\"')
    print(f'request_id=\"{request_id}\"')
    print(f'hash_alg=\"{hash_alg}\"')
    print(f'key_type=\"{key_type}\"')
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
")" || error_exit "Failed to parse JSON"

if [ -z "$digest_base64" ] || [ -z "$request_id" ]; then
    error_exit "Missing required fields in request"
fi

# Log request details
log "Processing digest signing request: $request_id"
log "Station: $STATION"
log "Hash algorithm: $hash_alg"
log "Key type: $key_type"

# Decode digest
log "Decoding digest from base64"
echo "$digest_base64" | base64 -d > /tmp/digest.bin || error_exit "Failed to decode digest"

# Validate digest (simple check)
if [ ! -s /tmp/digest.bin ]; then
    error_exit "Decoded digest is empty"
fi

# Log digest info
digest_size=$(wc -c < /tmp/digest.bin)
log "Digest size: $digest_size bytes"

# MOCK HSM SIGNING - Create a fake signature
log "MOCK HSM: Simulating digest signing..."
signing_start=$(date +%s.%N)

# In a real HSM, this would:
# 1. Load the appropriate private key
# 2. Sign the digest with the specified hash algorithm
# 3. Return the signature

# For testing, we'll create a deterministic fake signature
# based on the digest content and request metadata
signature_data=$(cat /tmp/digest.bin | sha256sum | cut -d' ' -f1)
signature_base64=$(echo -n "${signature_data}${request_id}${key_type}" | sha256sum | cut -d' ' -f1 | xxd -r -p | base64 -w 0)

signing_end=$(date +%s.%N)
signing_duration=$(echo "$signing_end - $signing_start" | bc -l)

log "MOCK HSM: 'Signing' completed in ${signing_duration}s"
log "MOCK HSM: Generated fake signature for testing"

# Create response
response=$(cat <<EOF
{
  "signature": "$signature_base64",
  "request_id": "$request_id",
  "hsm_info": {
    "hsm_id": "mock-hsm-digest-01",
    "signing_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "key_id": "mock-key-digest-12345",
    "signing_duration_ms": $(echo "$signing_duration * 1000" | bc -l),
    "hash_algorithm": "$hash_alg",
    "key_type": "$key_type",
    "note": "Mock HSM - fake signature for digest signing testing"
  },
  "error": ""
}
EOF
)

# Cleanup
rm -f /tmp/digest.bin

log "MOCK HSM: Digest signing request completed: $request_id"

# Output response (must be last thing to stdout)
echo "$response"
