#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman
# Simple test for mock HSM

echo "Testing mock HSM..."

# Create test request
cat > /tmp/test_req.json << 'EOF'
{
  "voucher": "dGVzdCB2b3VjaGVyIGRhdGE=",
  "owner_key": "test-key",
  "request_id": "test-123",
  "timestamp": "2026-02-04T19:45:00Z",
  "manufacturing_station": "test-station",
  "device_info": {
    "serialno": "TEST-SN",
    "model": "TestModel"
  }
}
EOF

echo "Created test request:"
cat /tmp/test_req.json
echo ""

# Run mock HSM
echo "Running mock HSM:"
/home/windsurf/go-fdo-di/test_hsm_simple.sh /tmp/test_req.json TEST-SN TestModel test-station test-123
echo ""

# Cleanup
rm -f /tmp/test_req.json

echo "Test completed!"
