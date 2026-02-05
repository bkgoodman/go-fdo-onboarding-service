#!/bin/bash

# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Test setup script for voucher management

echo "Setting up test environment..."

# Clean up any existing test files
rm -f test.db
rm -f /tmp/test_owner_key.pem
rm -f /tmp/get_owner_key.py

# Create a test owner key file (for fixed owner test)
echo "Creating test owner key..."
# Extract the existing owner key from the database
cat > /tmp/test_owner_key.pem << 'EOF'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+UWQc7Qf5qB5RtvGzKB8wQ
-----END PUBLIC KEY-----
EOF

# Create a simple Python script for dynamic owner key lookup
cat > /tmp/get_owner_key.py << 'EOF'
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
    # In real implementation, you would look up keys based on these parameters
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

chmod +x /tmp/get_owner_key.py

echo "Test setup complete!"
echo ""
echo "Test configurations created:"
echo "  - config_basic_test.yaml (echo only)"
echo "  - config_fixed_owner_test.yaml (fixed owner key)"
echo "  - config_dynamic_owner_test.yaml (dynamic owner key)"
echo ""
echo "Test files created:"
echo "  - /tmp/test_owner_key.pem (test owner key)"
echo "  - /tmp/get_owner_key.py (dynamic key lookup script)"
