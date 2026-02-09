#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test directories
TEST_DIR="$(pwd)/test_onboarding"
VOUCHER_DIR="${TEST_DIR}/vouchers"
CONFIG_DIR="${TEST_DIR}/configs"
DB_PATH="${TEST_DIR}/fdo.db"
CONFIG_FILE="${TEST_DIR}/config.yaml"

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

usage() {
    cat <<EOF
Usage: $0 {init|server|clean}

Commands:
  init     Initialize the test environment and generate owner keys
           This will create the database, generate owner keys, and show
           you where to place the voucher file after DI.

  server   Run the onboarding server with test configuration
           This assumes you've already run 'init' and placed a voucher
           file in the vouchers directory.

  clean    Remove all test files and directories

Example workflow:
  1. ./test_example.sh init
     - Creates test environment
     - Generates owner keys
     - Shows owner public key for DI service
     - Tells you where to place voucher

  2. Run DI on your device with the owner public key
     Copy the resulting voucher to: ${VOUCHER_DIR}/{GUID}.fdoov

  3. ./test_example.sh server
     - Sets up example configs
     - Starts onboarding server
     - Device can now onboard

EOF
    exit 1
}

init_phase() {
    print_header "PHASE 1: Initialize Test Environment"

    # Clean up any existing test directory
    if [ -d "${TEST_DIR}" ]; then
        print_warning "Test directory already exists. Cleaning up..."
        rm -rf "${TEST_DIR}"
    fi

    # Create test directory structure
    print_info "Creating test directory structure..."
    mkdir -p "${VOUCHER_DIR}"
    mkdir -p "${CONFIG_DIR}/devices"
    mkdir -p "${CONFIG_DIR}/groups"
    print_success "Created directories"

    # Create example device config template
    print_info "Creating example device config template..."
    cat > "${CONFIG_DIR}/devices/example-device-template.yaml" <<'YAML'
# Example Device Configuration Template
# Copy this file to {GUID}.yaml where GUID is your device's GUID in hex format
# Example: cp example-device-template.yaml abc123def456.yaml

group: "example-fedora"  # Reference to group config (optional)

fsim:
  # Device-specific system configuration
  sysconfig:
    - "hostname=my-test-device"
    - "ip_address=192.168.1.100"
    - "timezone=America/New_York"
    - "ssh_enabled=true"
  
  # Device-specific credentials (passwords)
  credentials:
    - "password:testuser:testpassword123"
  
  # Request SSH public keys from device (Registered Credentials flow)
  # Format: type:credential_id[:endpoint_url]
  # The device will generate and send its SSH public key
  pubkey_requests:
    - "ssh-rsa:admin-ssh-key"
    - "ssh-rsa:backup-ssh-key:https://backup.example.com"
YAML
    print_success "Created example device config template"

    # Create test configuration file
    print_info "Creating test configuration..."
    cat > "${CONFIG_FILE}" <<'YAML'
debug: true

server:
  addr: "localhost:8080"
  ext_addr: "localhost:8080"
  use_tls: false

database:
  path: "fdo.db"
  password: ""

manufacturing:
  init_keys_if_missing: true

rendezvous:
  entries:
    - dns: "localhost"
      port: 8080
      protocol: "http"

to0:
  addr: ""
  delay: 0
  bypass: false
  replacement_policy: "allow-any"

delegate:
  onboard: false
  rv: false

device_storage:
  voucher_dir: "vouchers"
  config_dir: "configs"
  delete_after_onboard: false
  cache_configs: false

fsim:
  downloads: []
  uploads: []
  upload_dir: ""
  wgets: []
  sysconfig: []
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
YAML
    print_success "Created config.yaml"

    # Build the server if not already built
    if [ ! -f "./fdo-onboarding-service" ]; then
        print_info "Building FDO onboarding service..."
        go build -o fdo-onboarding-service .
        print_success "Built fdo-onboarding-service"
    fi

    # Initialize database and generate keys
    print_info "Initializing database and keys..."
    cd "${TEST_DIR}"
    ../fdo-onboarding-service -config config.yaml -init-only 2>&1 | tee init_output.txt
    
    # Print owner public keys
    print_info "Printing owner public keys..."
    ../fdo-onboarding-service -config config.yaml -print-owner-key
    cd ..
    
    echo ""
    print_success "Database initialized"
    echo ""
    print_header "NEXT STEPS"
    echo ""
    echo "1. Configure your DI manufacturing station with one of the owner keys above:"
    echo ""
    echo "   Edit your DI config (e.g., /home/windsurf/go-fdo-di/config.yaml):"
    echo ""
    echo "   voucher_management:  # Note: Some configs use 'owner_signover' instead"
    echo "     mode: \"static\""
    echo "     static_public_key: |"
    echo "       -----BEGIN PUBLIC KEY-----"
    echo "       <paste one of the keys from above>"
    echo "       -----END PUBLIC KEY-----"
    echo ""
    echo "2. Run DI on your device to generate a voucher"
    echo ""
    echo "3. Copy the voucher file to:"
    echo -e "   ${GREEN}${VOUCHER_DIR}/{GUID}.fdoov${NC}"
    echo ""
    echo "   Where {GUID} is the device GUID in hex format (no dashes)"
    echo "   Example: cp /path/to/voucher.fdoov ${VOUCHER_DIR}/abc123def456789.fdoov"
    echo ""
    echo "4. (Optional) Create device-specific config:"
    echo ""
    echo "   An example template is available at:"
    echo -e "   ${GREEN}${CONFIG_DIR}/devices/example-device-template.yaml${NC}"
    echo ""
    echo "   Copy and rename it for your device:"
    echo -e "   ${GREEN}cp ${CONFIG_DIR}/devices/example-device-template.yaml \\"
    echo -e "      ${CONFIG_DIR}/devices/{GUID}.yaml${NC}"
    echo ""
    echo "   Then edit the file to customize settings for your device."
    echo "   Example: cp ${CONFIG_DIR}/devices/example-device-template.yaml \\"
    echo "            ${CONFIG_DIR}/devices/abc123def456789.yaml"
    echo ""
    echo "5. Run the onboarding server:"
    echo -e "   ${GREEN}./test_example.sh server${NC}"
    echo ""
}

server_phase() {
    print_header "PHASE 2: Run Onboarding Server"

    # Check if init was run
    if [ ! -d "${TEST_DIR}" ]; then
        print_error "Test directory not found. Run './test_example.sh init' first."
        exit 1
    fi

    if [ ! -f "${TEST_DIR}/fdo.db" ]; then
        print_error "Database not found. Run './test_example.sh init' first."
        exit 1
    fi

    # Check if any vouchers exist
    VOUCHER_COUNT=$(find "${VOUCHER_DIR}" -name "*.fdoov" 2>/dev/null | wc -l)
    if [ "${VOUCHER_COUNT}" -eq 0 ]; then
        print_warning "No voucher files found in ${VOUCHER_DIR}"
        print_info "Place your .fdoov file(s) there before running the server"
        echo ""
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "Found ${VOUCHER_COUNT} voucher file(s)"
    fi

    # Create example group config if it doesn't exist
    if [ ! -f "${CONFIG_DIR}/groups/example-fedora.yaml" ]; then
        print_info "Creating example group config..."
        cat > "${CONFIG_DIR}/groups/example-fedora.yaml" <<'YAML'
group_name: "fedora"
description: "Fedora Workstation systems"

fsim:
  # Group-specific system configuration
  sysconfig:
    - "selinux=enforcing"
    - "firewalld=enabled"
    - "package_manager=dnf"
  
  # Group-specific credentials
  credentials:
    - "password:admin:group-admin-password"
YAML
        print_success "Created example group config"
    fi

    # List any device-specific configs
    DEVICE_CONFIG_COUNT=$(find "${CONFIG_DIR}/devices" -name "*.yaml" 2>/dev/null | wc -l)
    if [ "${DEVICE_CONFIG_COUNT}" -gt 0 ]; then
        print_success "Found ${DEVICE_CONFIG_COUNT} device-specific config(s)"
    else
        print_info "No device-specific configs found (will use group/global only)"
    fi

    print_header "STARTING ONBOARDING SERVER"
    echo ""
    print_info "Server will listen on: localhost:8080"
    print_info "Voucher directory: ${VOUCHER_DIR}"
    print_info "Config directory: ${CONFIG_DIR}"
    echo ""
    print_info "Press Ctrl+C to stop the server"
    echo ""

    # Run the server
    cd "${TEST_DIR}"
    exec ../fdo-onboarding-service -config config.yaml
}

clean_phase() {
    print_header "Cleaning Test Environment"
    
    if [ -d "${TEST_DIR}" ]; then
        print_info "Removing ${TEST_DIR}..."
        rm -rf "${TEST_DIR}"
        print_success "Test environment cleaned"
    else
        print_info "No test environment found"
    fi
}

# Main script
case "${1:-}" in
    init)
        init_phase
        ;;
    server)
        server_phase
        ;;
    clean)
        clean_phase
        ;;
    *)
        usage
        ;;
esac
