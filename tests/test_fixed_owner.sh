#!/bin/bash

# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

echo "=== Step 2: Fixed Owner Key Signover Test ==="

# Check if test owner key exists
if [ ! -f "/tmp/test_owner_key.pem" ]; then
    echo "❌ Test owner key not found at /tmp/test_owner_key.pem"
    exit 1
fi

echo "✅ Test owner key found:"
cat /tmp/test_owner_key.pem

# Test the cat command that should be used for owner key retrieval
echo ""
echo "Testing owner key retrieval command:"
cat /tmp/test_owner_key.pem

# Test the JSON response format expected by owner key service
echo ""
echo "Testing JSON response format:"
cat << 'EOF'
{
  "owner_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhyCf+ghy1+QhS5IEEKg8hdw/rr0Y\nxER216L06IHZ7+F/h6zseExlnf90JnRIbLiTwzkco8jIP0gdQ9oyov043A==\n-----END PUBLIC KEY-----",
  "error": ""
}
EOF

echo ""
echo "✅ Fixed owner key test setup complete!"
echo ""
echo "Expected behavior:"
echo "1. Server starts with owner_signover.enabled=true"
echo "2. DI client connects"
echo "3. Voucher callback calls 'cat /tmp/test_owner_key.pem'"
echo "4. Owner key signs the voucher"
echo "5. Voucher upload echoes with 'Voucher uploaded and signed:'"
