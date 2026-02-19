#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman
#
# ============================================================================
# FDO End-to-End Integration Test
# ============================================================================
#
# This script demonstrates a complete FDO workflow across three components:
#   1. Manufacturing Station (DI server) - /home/windsurf/go-fdo-di
#   2. Onboarding Service (TO2 server) - /var/bkgdata/go-fdo-onboarding-service
#   3. Device/Endpoint Client - /var/bkgdata/go-fdo-endpoint
#
# WORKFLOW:
#   1. Start Manufacturing Station on port 8081
#   2. Start Onboarding Service on port 8082 (with credential reuse enabled)
#   3. Run Device Client for DI (creates voucher at manufacturing station)
#   4. Manufacturing station pushes voucher to Onboarding Service
#   5. Run Device Client again for TO2 (onboards to Onboarding Service)
#
# ARTIFACTS & DIRECTORIES:
#   Manufacturing Station:
#     - Database: /tmp/fdo_e2e_test/manufacturing.db
#     - Vouchers: /tmp/fdo_e2e_test/mfg_vouchers/
#     - Logs: /tmp/fdo_e2e_test/manufacturing.log
#     - Config: /tmp/fdo_e2e_test/mfg_config.yaml
#
#   Onboarding Service:
#     - Database: /tmp/fdo_e2e_test/onboarding.db
#     - Vouchers: /tmp/fdo_e2e_test/onboarding_vouchers/
#     - Logs: /tmp/fdo_e2e_test/onboarding.log
#     - Config: /tmp/fdo_e2e_test/onboarding_config.yaml
#
#   Device/Endpoint:
#     - Credentials: /tmp/fdo_e2e_test/cred.bin
#     - Logs: /tmp/fdo_e2e_test/device_di.log, device_to2.log
#     - Config: /tmp/fdo_e2e_test/device_config.cfg
#
# NOTES:
#   - This test skips TO0/TO1 (rendezvous) for simplicity
#   - Device connects directly to onboarding service for TO2
#   - Credential reuse is enabled on onboarding service
#   - All services run on localhost with different ports
#   - Further documentation at tests/README_E2E_TEST.md
#
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Project paths
ONBOARDING_DIR="/var/bkgdata/go-fdo-onboarding-service"
MANUFACTURING_DIR="/home/windsurf/go-fdo-di"
ENDPOINT_DIR="/var/bkgdata/go-fdo-endpoint"

# Test artifact directory
TEST_DIR="/tmp/fdo_e2e_test"
MFG_DB="${TEST_DIR}/manufacturing.db"
MFG_VOUCHERS="${TEST_DIR}/mfg_vouchers"
MFG_LOG="${TEST_DIR}/manufacturing.log"
MFG_CONFIG="${TEST_DIR}/mfg_config.yaml"

ONBOARD_DB="${TEST_DIR}/onboarding.db"
ONBOARD_VOUCHERS="${TEST_DIR}/onboarding_vouchers"
ONBOARD_LOG="${TEST_DIR}/onboarding.log"
ONBOARD_CONFIG="${TEST_DIR}/onboarding_config.yaml"

DEVICE_CRED="${TEST_DIR}/cred.bin"
DEVICE_DI_LOG="${TEST_DIR}/device_di.log"
DEVICE_TO2_LOG="${TEST_DIR}/device_to2.log"
DEVICE_CONFIG="${TEST_DIR}/device_config.cfg"

# Port configuration
MFG_PORT=8081
ONBOARD_PORT=8082

# Process IDs
MFG_PID=""
ONBOARD_PID=""

# Cleanup function
cleanup() {
    echo ""
    log_section "CLEANUP"
    
    if [ -n "$MFG_PID" ]; then
        log_info "Stopping Manufacturing Station (PID: $MFG_PID)"
        kill "$MFG_PID" 2>/dev/null || true
        wait "$MFG_PID" 2>/dev/null || true
    fi
    
    if [ -n "$ONBOARD_PID" ]; then
        log_info "Stopping Onboarding Service (PID: $ONBOARD_PID)"
        kill "$ONBOARD_PID" 2>/dev/null || true
        wait "$ONBOARD_PID" 2>/dev/null || true
    fi
    
    # Kill any stray processes
    pkill -f "fdo-manufacturing-station.*${MFG_PORT}" 2>/dev/null || true
    pkill -f "fdo-onboarding-service.*${ONBOARD_PORT}" 2>/dev/null || true
    
    log_success "Cleanup complete"
}

trap cleanup EXIT

# Helper functions
log_section() {
    echo ""
    echo -e "${BLUE}============================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================================================${NC}"
}

log_step() {
    echo -e "${CYAN}>>> $1${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
}

log_info() {
    echo -e "${MAGENTA}ℹ $1${NC}"
}

# ============================================================================
# PHASE 1: Environment Setup
# ============================================================================
setup_environment() {
    log_section "PHASE 1: Environment Setup"
    
    log_step "Checking for existing processes on ports ${MFG_PORT} and ${ONBOARD_PORT}"
    if lsof -i :${MFG_PORT} >/dev/null 2>&1; then
        log_warning "Port ${MFG_PORT} is in use, attempting to kill process"
        lsof -ti :${MFG_PORT} | xargs kill -9 2>/dev/null || true
        sleep 2
    fi
    
    if lsof -i :${ONBOARD_PORT} >/dev/null 2>&1; then
        log_warning "Port ${ONBOARD_PORT} is in use, attempting to kill process"
        lsof -ti :${ONBOARD_PORT} | xargs kill -9 2>/dev/null || true
        sleep 2
    fi
    log_success "Ports are clear"
    
    log_step "Creating test artifact directory: ${TEST_DIR}"
    rm -rf "${TEST_DIR}"
    mkdir -p "${TEST_DIR}"
    mkdir -p "${MFG_VOUCHERS}"
    mkdir -p "${ONBOARD_VOUCHERS}"
    log_success "Test directory created"
    
    log_info "Test artifacts will be stored in: ${TEST_DIR}"
    log_info "  - Manufacturing DB: ${MFG_DB}"
    log_info "  - Manufacturing Vouchers: ${MFG_VOUCHERS}"
    log_info "  - Manufacturing Log: ${MFG_LOG}"
    log_info "  - Onboarding DB: ${ONBOARD_DB}"
    log_info "  - Onboarding Vouchers: ${ONBOARD_VOUCHERS}"
    log_info "  - Onboarding Log: ${ONBOARD_LOG}"
    log_info "  - Device Credentials: ${DEVICE_CRED}"
    log_info "  - Device DI Log: ${DEVICE_DI_LOG}"
    log_info "  - Device TO2 Log: ${DEVICE_TO2_LOG}"
}

# ============================================================================
# PHASE 2: Build Components
# ============================================================================
build_components() {
    log_section "PHASE 2: Build Components"
    
    log_step "Building Manufacturing Station"
    cd "${MANUFACTURING_DIR}"
    if [ ! -f "fdo-manufacturing-station" ] || [ "main.go" -nt "fdo-manufacturing-station" ]; then
        go build -o fdo-manufacturing-station . || {
            log_error "Failed to build manufacturing station"
            exit 1
        }
    fi
    log_success "Manufacturing Station built"
    
    log_step "Building Onboarding Service"
    cd "${ONBOARDING_DIR}"
    if [ ! -f "fdo-onboarding-service" ] || [ "main.go" -nt "fdo-onboarding-service" ]; then
        go build -o fdo-onboarding-service . || {
            log_error "Failed to build onboarding service"
            exit 1
        }
    fi
    log_success "Onboarding Service built"
    
    log_step "Building Device Client"
    cd "${ENDPOINT_DIR}"
    if [ ! -f "fdo-client" ] || [ "main.go" -nt "fdo-client" ]; then
        go build -o fdo-client . || {
            log_error "Failed to build device client"
            exit 1
        }
    fi
    log_success "Device Client built"
}

# ============================================================================
# PHASE 3: Initialize Onboarding Service
# ============================================================================
init_onboarding_service() {
    log_section "PHASE 3: Initialize Onboarding Service"
    
    log_step "Creating onboarding service configuration"
    cat > "${ONBOARD_CONFIG}" <<EOF
debug: true
fdo_version: 200

server:
  addr: "127.0.0.1:${ONBOARD_PORT}"
  ext_addr: "127.0.0.1:${ONBOARD_PORT}"
  use_tls: false
  insecure_tls: false

database:
  path: "${ONBOARD_DB}"
  password: ""

manufacturing:
  device_ca_key_type: "ec384"
  owner_key_type: "ec384"
  generate_certificates: true
  init_keys_if_missing: true

rendezvous:
  entries:
    - host: "127.0.0.1"
      port: ${ONBOARD_PORT}
      scheme: "http"

to0:
  addr: ""
  delay: 0
  bypass: false
  replacement_policy: "allow-any"

delegate:
  onboard: ""
  rv: ""

device_storage:
  voucher_dir: "${ONBOARD_VOUCHERS}"
  config_dir: "${TEST_DIR}/configs"
  delete_after_onboard: false
  cache_configs: false

voucher_management:
  persist_to_db: true
  reuse_credential: true

voucher_receiver:
  enabled: true
  endpoint: "/api/v1/vouchers"
  global_token: "test-integration-token"
  validate_ownership: true
  require_auth: true

fsim:
  downloads: []
  uploads: []
  upload_dir: ""
  wgets: []
  sysconfig:
    - "hostname=E2Etest"
  payload_file: ""
  payload_mime: ""
  payload_files: []
  bmo_file: ""
  bmo_image_type: ""
  bmo_files: []
  wifi_config_file: ""
  credentials: []
  pubkey_requests: []
  command_date: false
  single_sided_wifi: false
EOF
    log_success "Onboarding config created: ${ONBOARD_CONFIG}"
    
    log_step "Initializing onboarding service database and keys"
    cd "${ONBOARDING_DIR}"
    ./fdo-onboarding-service -config "${ONBOARD_CONFIG}" -init-only 2>&1 | tee "${TEST_DIR}/onboarding_init.log"
    log_success "Onboarding service initialized"
    
    log_step "Extracting owner public key for manufacturing station"
    OWNER_KEY=$(./fdo-onboarding-service -config "${ONBOARD_CONFIG}" -print-owner-key 2>/dev/null \
        | sed -n '/--- SECP384R1 ---/,$p' \
        | sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p')
    if [ -z "$OWNER_KEY" ]; then
        log_error "Failed to extract owner public key"
        exit 1
    fi
    log_success "Owner public key extracted"
    echo "$OWNER_KEY" > "${TEST_DIR}/owner_public_key.pem"
    log_info "Owner key saved to: ${TEST_DIR}/owner_public_key.pem"
}

# ============================================================================
# PHASE 4: Initialize Manufacturing Station
# ============================================================================
init_manufacturing_station() {
    log_section "PHASE 4: Initialize Manufacturing Station"
    
    log_step "Creating manufacturing station configuration"
    cat > "${MFG_CONFIG}" <<EOF
debug: true
fdo_version: 200

server:
  addr: "127.0.0.1:${MFG_PORT}"
  ext_addr: "127.0.0.1:${MFG_PORT}"
  use_tls: false
  insecure_tls: false

database:
  path: "${MFG_DB}"
  password: ""

manufacturing:
  device_ca_key_type: "ec384"
  owner_key_type: "ec384"
  generate_certificates: true
  first_time_init: true

rendezvous:
  entries:
    - host: "127.0.0.1"
      port: ${ONBOARD_PORT}
      scheme: "http"

voucher_management:
  persist_to_db: true
  voucher_signing:
    mode: "internal"
    first_time_init: true
  save_to_disk:
    directory: "${MFG_VOUCHERS}"
  owner_signover:
    mode: "static"
    static_public_key: |
$(echo "$OWNER_KEY" | sed 's/^/      /')
    timeout: 10s
  push_service:
    enabled: true
    url: "http://127.0.0.1:${ONBOARD_PORT}/api/v1/vouchers"
    auth_token: "test-integration-token"
    mode: "send_always"
    retain_files: true
    delete_after_success: false
    retry_interval: "2s"
    max_attempts: 3
EOF
    log_success "Manufacturing config created: ${MFG_CONFIG}"
    
    log_step "Initializing manufacturing station database and keys"
    cd "${MANUFACTURING_DIR}"
    ./fdo-manufacturing-station -config "${MFG_CONFIG}" -init-only 2>&1 | tee "${TEST_DIR}/manufacturing_init.log"
    log_success "Manufacturing station initialized"
}

# ============================================================================
# PHASE 5: Create Device Client Configuration
# ============================================================================
create_device_config() {
    log_section "PHASE 5: Create Device Client Configuration"
    
    log_step "Creating device client configuration"
    cat > "${DEVICE_CONFIG}" <<EOF
blob_path: "${DEVICE_CRED}"
debug: true
fdo_version: 200

di:
  url: "http://127.0.0.1:${MFG_PORT}"
  key: "ec384"
  key_enc: "x509"

crypto:
  cipher_suite: "A128GCM"
  kex_suite: "ECDH384"

transport:
  insecure_tls: true
  tpm_path: ""

operation:
  print_device: false
  rv_only: false

service_info:
  download_dir: ""
  echo_commands: false
  wget_dir: ""
  upload_paths: []
EOF
    log_success "Device config created: ${DEVICE_CONFIG}"
}

# ============================================================================
# PHASE 6: Start Services
# ============================================================================
start_services() {
    log_section "PHASE 6: Start Services"
    
    log_step "Starting Manufacturing Station on port ${MFG_PORT}"
    cd "${MANUFACTURING_DIR}"
    ./fdo-manufacturing-station -config "${MFG_CONFIG}" > "${MFG_LOG}" 2>&1 &
    MFG_PID=$!
    log_info "Manufacturing Station PID: ${MFG_PID}"
    
    # Wait for manufacturing station to start
    local retries=20
    while [ $retries -gt 0 ]; do
        if grep -q "Listening" "${MFG_LOG}" 2>/dev/null || \
           grep -q "Starting" "${MFG_LOG}" 2>/dev/null || \
           curl -s "http://127.0.0.1:${MFG_PORT}" >/dev/null 2>&1; then
            log_success "Manufacturing Station is running"
            break
        fi
        if ! kill -0 "$MFG_PID" 2>/dev/null; then
            log_error "Manufacturing Station process died"
            tail -20 "${MFG_LOG}"
            exit 1
        fi
        sleep 1
        retries=$((retries - 1))
    done
    
    if [ $retries -eq 0 ]; then
        log_error "Manufacturing Station failed to start (timeout)"
        tail -20 "${MFG_LOG}"
        exit 1
    fi
    
    log_step "Starting Onboarding Service on port ${ONBOARD_PORT}"
    cd "${ONBOARDING_DIR}"
    ./fdo-onboarding-service -config "${ONBOARD_CONFIG}" > "${ONBOARD_LOG}" 2>&1 &
    ONBOARD_PID=$!
    log_info "Onboarding Service PID: ${ONBOARD_PID}"
    
    # Wait for onboarding service to start
    retries=20
    while [ $retries -gt 0 ]; do
        if grep -q "Listening" "${ONBOARD_LOG}" 2>/dev/null || \
           grep -q "Starting" "${ONBOARD_LOG}" 2>/dev/null || \
           curl -s "http://127.0.0.1:${ONBOARD_PORT}" >/dev/null 2>&1; then
            log_success "Onboarding Service is running"
            break
        fi
        if ! kill -0 "$ONBOARD_PID" 2>/dev/null; then
            log_error "Onboarding Service process died"
            tail -20 "${ONBOARD_LOG}"
            exit 1
        fi
        sleep 1
        retries=$((retries - 1))
    done
    
    if [ $retries -eq 0 ]; then
        log_error "Onboarding Service failed to start (timeout)"
        tail -20 "${ONBOARD_LOG}"
        exit 1
    fi
    
    log_info "Both services are running and ready"
    sleep 2
}

# ============================================================================
# PHASE 7: Run Device Initialization (DI)
# ============================================================================
run_device_di() {
    log_section "PHASE 7: Run Device Initialization (DI)"
    
    log_step "Removing any existing device credentials"
    rm -f "${DEVICE_CRED}"
    log_success "Device credentials cleared"
    
    log_step "Running Device Initialization (DI)"
    log_info "Device will connect to Manufacturing Station at http://127.0.0.1:${MFG_PORT}"
    
    pushd "${TEST_DIR}" >/dev/null
    if "${ENDPOINT_DIR}/fdo-client" -config "${DEVICE_CONFIG}" -di "http://127.0.0.1:${MFG_PORT}" > "${DEVICE_DI_LOG}" 2>&1; then
        log_success "Device Initialization (DI) completed successfully"
    else
        log_error "Device Initialization (DI) failed"
        tail -30 "${DEVICE_DI_LOG}"
        popd >/dev/null
        exit 1
    fi

    popd >/dev/null
    
    log_step "Verifying device credentials were created"
    if [ -f "${DEVICE_CRED}" ]; then
        log_success "Device credentials created: ${DEVICE_CRED}"
    else
        log_error "Device credentials file not found"
        exit 1
    fi
    
    log_step "Verifying voucher was created at manufacturing station"
    sleep 2
    VOUCHER_COUNT=$(find "${MFG_VOUCHERS}" -name "*.fdoov" 2>/dev/null | wc -l)
    if [ "$VOUCHER_COUNT" -gt 0 ]; then
        VOUCHER_FILE=$(find "${MFG_VOUCHERS}" -name "*.fdoov" | head -1)
        log_success "Voucher created: $(basename "$VOUCHER_FILE")"
    else
        log_error "No voucher file found in ${MFG_VOUCHERS}"
        exit 1
    fi
    
    log_step "Verifying voucher was pushed to onboarding service"
    sleep 3
    ONBOARD_VOUCHER_COUNT=$(find "${ONBOARD_VOUCHERS}" -name "*.fdoov" 2>/dev/null | wc -l)
    if [ "$ONBOARD_VOUCHER_COUNT" -gt 0 ]; then
        ONBOARD_VOUCHER_FILE=$(find "${ONBOARD_VOUCHERS}" -name "*.fdoov" | head -1)
        log_success "Voucher received by onboarding service: $(basename "$ONBOARD_VOUCHER_FILE")"
    else
        log_warning "Voucher not found in onboarding service directory yet"
        log_info "Checking manufacturing station logs for push status..."
        if grep -q "voucher transmission delivered" "${MFG_LOG}"; then
            log_success "Manufacturing station reports successful voucher push"
        else
            log_warning "Manufacturing station may not have completed voucher push"
            log_info "This may be expected if using HTTP receiver endpoint"
        fi
    fi
}

# ============================================================================
# PHASE 8: Run Device Onboarding (TO2)
# ============================================================================
run_device_to2() {
    log_section "PHASE 8: Run Device Onboarding (TO2)"
    
    log_step "Running Device Onboarding (TO2)"
    log_info "Device will connect directly to Onboarding Service at http://127.0.0.1:${ONBOARD_PORT}"
    log_info "Skipping TO1 (rendezvous) for this test"
    
    pushd "${TEST_DIR}" >/dev/null
    if "${ENDPOINT_DIR}/fdo-client" -config "${DEVICE_CONFIG}" -to2 "http://127.0.0.1:${ONBOARD_PORT}" > "${DEVICE_TO2_LOG}" 2>&1; then
        log_success "Device Onboarding (TO2) completed successfully"
    else
        log_error "Device Onboarding (TO2) failed"
        tail -30 "${DEVICE_TO2_LOG}"
        log_info "Check logs for details:"
        log_info "  Device: ${DEVICE_TO2_LOG}"
        log_info "  Onboarding: ${ONBOARD_LOG}"
        popd >/dev/null
        exit 1
    fi

    popd >/dev/null
    
    log_step "Verifying credential reuse behavior"
    if grep -q "Credential Reuse: true" "${DEVICE_TO2_LOG}"; then
        log_success "Credential reuse confirmed"
    elif grep -q "Credential Reuse: false" "${DEVICE_TO2_LOG}"; then
        log_info "New credential issued (credential reuse not used)"
    else
        log_info "Credential reuse status not explicitly logged"
    fi

    log_step "Verifying FSIM sysconfig delivery"
    if grep -Eq "hostname[[:space:]]*=[[:space:]]*E2Etest" "${DEVICE_TO2_LOG}"; then
        log_success "FSIM sysconfig applied (hostname=E2Etest observed)"
    else
        log_warning "hostname=E2Etest not found in device TO2 log"
        log_info "Check ${DEVICE_TO2_LOG} for full FSIM output"
    fi
}

# ============================================================================
# PHASE 9: Verification and Summary
# ============================================================================
verify_and_summarize() {
    log_section "PHASE 9: Verification and Summary"
    
    log_step "Checking manufacturing station logs"
    if grep -q "DI.*completed\|Device Initialization" "${MFG_LOG}"; then
        log_success "Manufacturing station processed DI successfully"
    fi
    
    if grep -q "voucher.*created\|voucher transmission" "${MFG_LOG}"; then
        log_success "Manufacturing station created and transmitted voucher"
    fi
    
    log_step "Checking onboarding service logs"
    if grep -q "TO2.*completed\|ownership transfer" "${ONBOARD_LOG}"; then
        log_success "Onboarding service processed TO2 successfully"
    fi
    
    log_step "Checking device logs"
    if grep -q "DI.*completed\|initialization.*success" "${DEVICE_DI_LOG}"; then
        log_success "Device completed DI successfully"
    fi
    
    if grep -q "TO2.*completed\|onboarding.*success\|Success" "${DEVICE_TO2_LOG}"; then
        log_success "Device completed TO2 successfully"
    fi
    
    log_section "TEST SUMMARY"
    echo ""
    log_success "End-to-End Integration Test PASSED"
    echo ""
    log_info "Test Artifacts Location: ${TEST_DIR}"
    echo ""
    log_info "Manufacturing Station:"
    log_info "  - Database: ${MFG_DB}"
    log_info "  - Vouchers: ${MFG_VOUCHERS}"
    log_info "  - Log: ${MFG_LOG}"
    log_info "  - Config: ${MFG_CONFIG}"
    echo ""
    log_info "Onboarding Service:"
    log_info "  - Database: ${ONBOARD_DB}"
    log_info "  - Vouchers: ${ONBOARD_VOUCHERS}"
    log_info "  - Log: ${ONBOARD_LOG}"
    log_info "  - Config: ${ONBOARD_CONFIG}"
    echo ""
    log_info "Device/Endpoint:"
    log_info "  - Credentials: ${DEVICE_CRED}"
    log_info "  - DI Log: ${DEVICE_DI_LOG}"
    log_info "  - TO2 Log: ${DEVICE_TO2_LOG}"
    log_info "  - Config: ${DEVICE_CONFIG}"
    echo ""
    log_info "TODO for Future Testing:"
    log_info "  - Add full TO0/TO1 (Rendezvous) flow"
    log_info "  - Test FSIM modules (file transfer, commands, etc.)"
    log_info "  - Add voucher transfer token authentication"
    log_info "  - Test credential revocation scenarios"
    log_info "  - Add multi-device testing"
    echo ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    log_section "FDO END-TO-END INTEGRATION TEST"
    echo ""
    log_info "This test demonstrates the complete FDO workflow:"
    log_info "  1. Device Initialization (DI) at Manufacturing Station"
    log_info "  2. Voucher creation and transmission to Onboarding Service"
    log_info "  3. Device Onboarding (TO2) to Onboarding Service"
    echo ""
    log_info "Test will use the following ports:"
    log_info "  - Manufacturing Station: ${MFG_PORT}"
    log_info "  - Onboarding Service: ${ONBOARD_PORT}"
    echo ""
    log_info "All artifacts will be stored in: ${TEST_DIR}"
    echo ""
    
    setup_environment
    build_components
    init_onboarding_service
    init_manufacturing_station
    create_device_config
    start_services
    run_device_di
    run_device_to2
    verify_and_summarize
    
    log_section "TEST COMPLETE"
    log_success "All phases completed successfully!"
}

# Run main function
main
