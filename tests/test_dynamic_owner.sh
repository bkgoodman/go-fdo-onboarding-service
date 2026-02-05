#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Test script for dynamic owner key lookup
# Tests the ability to retrieve owner keys dynamically based on device characteristics

set -e

echo "=== Dynamic Owner Key Test ==="

# Create test owner key
TEST_OWNER_KEY="/tmp/test_owner_key.pem"
cat > "$TEST_OWNER_KEY" << 'EOF'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+UWQc7Qf5qB5RtvGzKB8wQ
-----END PUBLIC KEY-----
EOF

# Create dynamic owner key lookup script
OWNER_LOOKUP_SCRIPT="/tmp/get_owner_key.py"
cat > "$OWNER_LOOKUP_SCRIPT" << 'EOF'
#!/usr/bin/env python3
import sys
import json
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--model', required=True)
    args = parser.parse_args()
    
    # For testing, return the same test key regardless of serial/model
    # In production, this would look up keys based on these parameters
    with open('/tmp/test_owner_key.pem', 'r') as f:
        key_pem = f.read().strip()
    
    response = {
        "owner_key_pem": key_pem,
        "error": ""
    }
    
    print(json.dumps(response))

if __name__ == '__main__':
    main()
EOF

chmod +x "$OWNER_LOOKUP_SCRIPT"

echo "✅ Created dynamic owner key lookup script"

# Test the script directly
echo "Testing dynamic owner key lookup script..."
output=$($OWNER_LOOKUP_SCRIPT --serial TEST-123 --model TestModel)

if echo "$output" | grep -q "owner_key_pem"; then
    echo "✅ Dynamic owner key lookup script works"
else
    echo "❌ Dynamic owner key lookup script failed"
    exit 1
fi

# Verify JSON parsing
if echo "$output" | python3 -c "import sys, json; json.load(sys.stdin)" 2>/dev/null; then
    echo "✅ JSON response is valid"
else
    echo "❌ JSON response is invalid"
    exit 1
fi

echo "✅ Dynamic Owner Key Test Passed"
