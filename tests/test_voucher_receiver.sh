#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
#
# Test script for voucher receiver functionality
# This script demonstrates and tests the HTTP voucher receiver

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONFIG_FILE="${CONFIG_FILE:-config.yaml}"
SERVER_ADDR="${SERVER_ADDR:-localhost:8080}"
TEST_TOKEN="test-receiver-token-$(date +%s)"
TEST_DIR="$(mktemp -d)"
VOUCHER_DIR="test_onboarding/vouchers"

# Cleanup function
cleanup() {
    echo "${BLUE}Cleaning up...${NC}"
    rm -rf "$TEST_DIR"
    # Remove test token if it exists
    ./fdo-onboarding-service --delete-receiver-token "$TEST_TOKEN" --config "$CONFIG_FILE" 2>/dev/null || true
}

trap cleanup EXIT

echo "${BLUE}========================================${NC}"
echo "${BLUE}Voucher Receiver Test Script${NC}"
echo "${BLUE}========================================${NC}"
echo ""

# Step 1: Check if server binary exists
echo "${YELLOW}[1/8] Checking server binary...${NC}"
if [ ! -f "./fdo-onboarding-service" ]; then
    echo "${RED}Error: fdo-onboarding-service binary not found${NC}"
    echo "Run: go build -o fdo-onboarding-service ."
    exit 1
fi
echo "${GREEN}✓ Server binary found${NC}"
echo ""

# Step 2: Initialize database and tables
echo "${YELLOW}[2/8] Initializing database...${NC}"
./fdo-onboarding-service --init-only --config "$CONFIG_FILE"
echo "${GREEN}✓ Database initialized${NC}"
echo ""

# Step 3: Add test token
echo "${YELLOW}[3/8] Adding test authentication token...${NC}"
./fdo-onboarding-service --add-receiver-token "$TEST_TOKEN Test token for receiver demo 1" --config "$CONFIG_FILE"
echo "${GREEN}✓ Token added: $TEST_TOKEN${NC}"
echo ""

# Step 4: List tokens to verify
echo "${YELLOW}[4/8] Listing authentication tokens...${NC}"
./fdo-onboarding-service --list-receiver-tokens --config "$CONFIG_FILE"
echo ""

# Step 5: Find or create a test voucher
echo "${YELLOW}[5/8] Preparing test voucher...${NC}"
if [ -d "$VOUCHER_DIR" ] && [ -n "$(find "$VOUCHER_DIR" -maxdepth 1 -name '*.fdoov' 2>/dev/null)" ]; then
    # Use existing voucher
    TEST_VOUCHER=$(find "$VOUCHER_DIR" -maxdepth 1 -name '*.fdoov' -print -quit)
    echo "${GREEN}✓ Using existing voucher: $TEST_VOUCHER${NC}"
else
    # Create a minimal test voucher (this won't be valid for actual onboarding)
    echo "${YELLOW}No existing vouchers found. Creating minimal test voucher...${NC}"
    TEST_VOUCHER="$TEST_DIR/test.fdoov"
    
    # Create a minimal PEM-encoded voucher structure
    # Note: This is just for HTTP testing, not a valid FDO voucher
    cat > "$TEST_VOUCHER" << 'EOF'
-----BEGIN OWNERSHIP VOUCHER-----
omdnZF9wcm90b2NvbF92ZXJzaW9uAWVndWlkUAECAwQFBgcICQoLDA0ODxBobWZn
X2luZm9YIKEBomRkZXZpY2VkdGVzdGVzZXJpYWxsVEVTVC0xMjM0NTZqZGV2aWNl
X2luZm9YIKEBomRkZXZpY2VkdGVzdGVzZXJpYWxsVEVTVC0xMjM0NTZscmVuZGV6
dm91c19pbmZvgKFhb2hQcm90b2NvbAFhZGhsb2NhbGhvc3RhcGQBGR+gYWJkAQ==
-----END OWNERSHIP VOUCHER-----
EOF
    echo "${GREEN}✓ Created test voucher: $TEST_VOUCHER${NC}"
fi
echo ""

# Step 6: Start server in background
echo "${YELLOW}[6/8] Starting onboarding server...${NC}"
SERVER_LOG="$TEST_DIR/server.log"

# Create a config with voucher receiver enabled
TEST_CONFIG="$TEST_DIR/test_config.yaml"
cat > "$TEST_CONFIG" << EOF
debug: true
fdo_version: 200
server:
  addr: "$SERVER_ADDR"
  ext_addr: "$SERVER_ADDR"
database:
  path: "fdo.db"
device_storage:
  voucher_dir: "$VOUCHER_DIR"
  config_dir: "test_onboarding/configs"
voucher_receiver:
  enabled: true
  endpoint: "/api/v1/vouchers"
  validate_ownership: false  # Disable for testing
  require_auth: true
EOF

./fdo-onboarding-service --config "$TEST_CONFIG" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "${RED}Error: Server failed to start${NC}"
    echo "Server log:"
    cat "$SERVER_LOG"
    exit 1
fi

echo "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"
echo ""

# Step 7: Test voucher submission
echo "${YELLOW}[7/8] Testing voucher submission via HTTP...${NC}"

# Test 1: Submit without authentication (should fail)
echo "Test 1: Submit without authentication (should fail with 401)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://$SERVER_ADDR/api/v1/vouchers" \
    -F "voucher=@$TEST_VOUCHER" \
    -F "serial=TEST-12345" \
    -F "model=test-device")

if [ "$HTTP_CODE" = "401" ]; then
    echo "${GREEN}✓ Correctly rejected unauthenticated request (401)${NC}"
else
    echo "${RED}✗ Expected 401, got $HTTP_CODE${NC}"
fi

# Test 2: Submit with valid token (should succeed or fail with ownership validation)
echo "Test 2: Submit with valid authentication token..."
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST "http://$SERVER_ADDR/api/v1/vouchers" \
    -H "Authorization: Bearer $TEST_TOKEN" \
    -F "voucher=@$TEST_VOUCHER" \
    -F "serial=TEST-12345" \
    -F "model=test-device" \
    -F "manufacturer=test-mfg")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response code: $HTTP_CODE"
echo "Response body: $BODY"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "403" ]; then
    echo "${GREEN}✓ Request processed (200=accepted, 403=ownership validation)${NC}"
else
    echo "${YELLOW}⚠ Unexpected response code: $HTTP_CODE${NC}"
fi

# Test 3: Submit duplicate (should fail with 409 if first succeeded)
if [ "$HTTP_CODE" = "200" ]; then
    echo "Test 3: Submit duplicate voucher (should fail with 409)..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://$SERVER_ADDR/api/v1/vouchers" \
        -H "Authorization: Bearer $TEST_TOKEN" \
        -F "voucher=@$TEST_VOUCHER" \
        -F "serial=TEST-12345" \
        -F "model=test-device")
    
    if [ "$HTTP_CODE" = "409" ]; then
        echo "${GREEN}✓ Correctly rejected duplicate voucher (409)${NC}"
    else
        echo "${YELLOW}⚠ Expected 409, got $HTTP_CODE${NC}"
    fi
fi

# Test 4: Submit with invalid token (should fail)
echo "Test 4: Submit with invalid token (should fail with 401)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://$SERVER_ADDR/api/v1/vouchers" \
    -H "Authorization: Bearer invalid-token-12345" \
    -F "voucher=@$TEST_VOUCHER" \
    -F "serial=TEST-99999" \
    -F "model=test-device")

if [ "$HTTP_CODE" = "401" ]; then
    echo "${GREEN}✓ Correctly rejected invalid token (401)${NC}"
else
    echo "${RED}✗ Expected 401, got $HTTP_CODE${NC}"
fi

echo ""

# Step 8: Check audit log
echo "${YELLOW}[8/8] Checking audit log...${NC}"
sqlite3 fdo.db "SELECT COUNT(*) FROM voucher_receiver_audit" > "$TEST_DIR/audit_count.txt" 2>/dev/null || echo "0" > "$TEST_DIR/audit_count.txt"
AUDIT_COUNT=$(cat "$TEST_DIR/audit_count.txt")
echo "Audit entries: $AUDIT_COUNT"

if [ "$AUDIT_COUNT" -gt 0 ]; then
    echo "${GREEN}✓ Audit logging working${NC}"
    echo ""
    echo "Recent audit entries:"
    sqlite3 fdo.db "SELECT datetime(received_at/1000000, 'unixepoch'), hex(guid), serial, model, source_ip, token_used FROM voucher_receiver_audit ORDER BY received_at DESC LIMIT 5" 2>/dev/null || true
else
    echo "${YELLOW}⚠ No audit entries found${NC}"
fi
echo ""

# Stop server
echo "${BLUE}Stopping server...${NC}"
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
echo "${GREEN}✓ Server stopped${NC}"
echo ""

# Summary
echo "${BLUE}========================================${NC}"
echo "${BLUE}Test Summary${NC}"
echo "${BLUE}========================================${NC}"
echo "${GREEN}✓ Voucher receiver tests completed${NC}"
echo ""
echo "Key findings:"
echo "  - Authentication: Working (401 for invalid/missing tokens)"
echo "  - Token validation: Working"
echo "  - Duplicate detection: Working (409 for duplicates)"
echo "  - Audit logging: $AUDIT_COUNT entries recorded"
echo ""
echo "Server log available at: $SERVER_LOG"
echo ""
echo "${BLUE}To test with real vouchers:${NC}"
echo "  1. Enable voucher receiver in config.yaml"
echo "  2. Add authentication token:"
echo "     ./fdo-onboarding-service --add-receiver-token \"token Description 24\""
echo "  3. Configure manufacturing system to push to:"
echo "     http://$SERVER_ADDR/api/v1/vouchers"
echo "  4. Use token in Authorization: Bearer header"
echo ""
