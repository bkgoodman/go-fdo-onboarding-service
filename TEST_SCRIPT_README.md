# Test Script Usage Guide

This guide explains how to use `test_example.sh` to test the device onboarding workflow with file-based vouchers and device-specific configurations.

## Overview

The test script operates in two phases to match the real-world FDO workflow:

1. **Init Phase**: Generate owner keys and prepare the environment
2. **Server Phase**: Run the onboarding server to accept device connections

## Prerequisites

- Go 1.21 or later
- A device capable of running FDO DI (Device Initialization)
- Access to an FDO DI service or tool

## Quick Start

### Step 1: Initialize Environment

```bash
./test_example.sh init
```

This will:
- Create a test directory structure (`test_onboarding/`)
- Generate a fresh database with owner keys
- Display the owner public keys
- Show you where to place voucher files

**Output Example**:
```
========================================
OWNER PUBLIC KEYS
========================================

Use these keys when running DI on your device:

  Owner public key (RSA2048): <base64-encoded-key>
  Owner public key (RSA3072): <base64-encoded-key>
  Owner public key (SECP256R1): <base64-encoded-key>
  Owner public key (SECP384R1): <base64-encoded-key>

========================================
NEXT STEPS
========================================

1. Run DI on your device using one of the owner public keys above

2. After DI completes, copy the voucher file to:
   test_onboarding/vouchers/{GUID}.fdoov

   Where {GUID} is the device GUID in hex format (no dashes)
   Example: test_onboarding/vouchers/abc123def456789.fdoov

3. (Optional) Create device-specific config:
   test_onboarding/configs/devices/{GUID}.yaml

4. Run the server:
   ./test_example.sh server
```

### Step 2: Run DI on Your Device

Use one of the owner public keys from Step 1 to initialize your device:

```bash
# Example using go-fdo DI tool
fdo-client-di \
  --owner-key "<owner-public-key-from-step-1>" \
  --device-info "Test Device" \
  --output voucher.fdoov
```

### Step 3: Copy Voucher to Test Directory

After DI completes, you'll have a voucher file. Copy it to the test voucher directory:

```bash
# Get the GUID from the voucher filename or content
GUID="abc123def456789"  # Replace with actual GUID

# Copy voucher to test directory
cp voucher.fdoov test_onboarding/vouchers/${GUID}.fdoov
```

**Important**: The filename MUST be `{GUID}.fdoov` where GUID is in hex format without dashes.

### Step 4: (Optional) Create Device-Specific Config

Create a configuration file for your device:

```bash
GUID="abc123def456789"  # Same GUID as voucher

cat > test_onboarding/configs/devices/${GUID}.yaml <<EOF
group: "example-fedora"  # Reference to group config

fsim:
  sysconfig:
    - "hostname=my-test-device"
    - "ip_address=192.168.1.100"
    - "timezone=America/New_York"
  
  credentials:
    - "password:testuser:testpassword"
EOF
```

**Note**: 
- The filename is `{GUID}.yaml` (matches voucher GUID)
- No `device_guid` field in the YAML (it's implied by filename)
- No `hostname` field (use `sysconfig` instead)

### Step 5: Run the Onboarding Server

```bash
./test_example.sh server
```

This will:
- Verify voucher files exist
- Create example group configs if needed
- Start the onboarding server on `localhost:8080`
- Wait for device connections

**Output Example**:
```
========================================
PHASE 2: Run Onboarding Server
========================================

✓ Found 1 voucher file(s)
✓ Created example group config
ℹ No device-specific configs found (will use group/global only)

========================================
STARTING ONBOARDING SERVER
========================================

ℹ Server will listen on: localhost:8080
ℹ Voucher directory: test_onboarding/vouchers
ℹ Config directory: test_onboarding/configs

ℹ Press Ctrl+C to stop the server

FDO Manufacturing Station starting...
```

### Step 6: Connect Your Device

On your device, run the TO2 (Transfer Ownership 2) protocol to onboard:

```bash
# Example using go-fdo client
fdo-client-to2 \
  --server "http://localhost:8080" \
  --voucher voucher.fdoov
```

The server will:
1. Load the voucher from `test_onboarding/vouchers/{GUID}.fdoov`
2. Cache it in the database
3. Load device-specific config from `test_onboarding/configs/devices/{GUID}.yaml`
4. Load group config from `test_onboarding/configs/groups/example-fedora.yaml`
5. Merge configurations (device → group → global)
6. Send merged FSIM data to device
7. Track metadata in `device_metadata` table

## Directory Structure

After running `init`, you'll have:

```
test_onboarding/
├── config.yaml              # Server configuration
├── fdo.db                   # SQLite database with owner keys
├── init_output.txt          # Output from init phase
├── vouchers/                # Place .fdoov files here
│   └── {GUID}.fdoov
└── configs/
    ├── groups/              # Group configurations
    │   └── example-fedora.yaml
    └── devices/             # Device-specific configs
        └── {GUID}.yaml
```

## Configuration Hierarchy

The system uses a three-tier configuration hierarchy:

1. **Global** (in `config.yaml`): Base defaults for all devices
2. **Group** (in `configs/groups/{name}.yaml`): Shared settings for device families
3. **Device** (in `configs/devices/{GUID}.yaml`): Individual device overrides

### Merge Rules

- **Arrays** (downloads, uploads, credentials): Concatenate all levels
- **Scalars** (upload_dir, etc.): Device overrides group overrides global
- **Key-value pairs** (sysconfig): Merge by key with device taking precedence

### Example Merged Config

**Global** (config.yaml):
```yaml
fsim:
  sysconfig:
    - "global_setting=true"
```

**Group** (configs/groups/example-fedora.yaml):
```yaml
fsim:
  sysconfig:
    - "selinux=enforcing"
    - "package_manager=dnf"
```

**Device** (configs/devices/{GUID}.yaml):
```yaml
fsim:
  sysconfig:
    - "hostname=my-device"
    - "ip_address=192.168.1.100"
```

**Merged Result** (sent to device):
```yaml
fsim:
  sysconfig:
    - "hostname=my-device"           # Device
    - "ip_address=192.168.1.100"     # Device
    - "selinux=enforcing"            # Group
    - "package_manager=dnf"          # Group
    - "global_setting=true"          # Global
```

## Cleaning Up

To remove all test files:

```bash
./test_example.sh clean
```

This removes the entire `test_onboarding/` directory.

## Troubleshooting

### "No voucher files found"

**Problem**: Server can't find voucher files.

**Solution**: 
- Verify voucher file exists in `test_onboarding/vouchers/`
- Check filename format: `{GUID}.fdoov` (hex, no dashes)
- Verify file has `.fdoov` extension

### "Database not found"

**Problem**: Trying to run server before init.

**Solution**: Run `./test_example.sh init` first.

### Device can't connect to server

**Problem**: Device can't reach `localhost:8080`.

**Solution**:
- If device is remote, update `ext_addr` in `test_onboarding/config.yaml`
- Ensure firewall allows port 8080
- Check device is using correct server address

### Config not applying to device

**Problem**: Device not receiving expected configuration.

**Solution**:
- Verify config filename matches device GUID: `{GUID}.yaml`
- Check YAML syntax is valid
- Review server logs for config loading errors
- Verify group reference (if any) points to existing group config

## Advanced Usage

### Multiple Devices

Test with multiple devices by placing multiple vouchers:

```bash
# Device 1
cp device1.fdoov test_onboarding/vouchers/abc123.fdoov
cat > test_onboarding/configs/devices/abc123.yaml <<EOF
group: "example-fedora"
fsim:
  sysconfig:
    - "hostname=device-1"
EOF

# Device 2
cp device2.fdoov test_onboarding/vouchers/def456.fdoov
cat > test_onboarding/configs/devices/def456.yaml <<EOF
group: "example-fedora"
fsim:
  sysconfig:
    - "hostname=device-2"
EOF
```

### Custom Group Configs

Create your own group configurations:

```bash
cat > test_onboarding/configs/groups/my-group.yaml <<EOF
group_name: "my-group"
description: "My custom device group"

fsim:
  sysconfig:
    - "custom_setting=value"
  credentials:
    - "password:admin:group-password"
  downloads:
    - "scripts/setup.sh"
EOF
```

### Inspecting Metadata

After devices onboard, check the metadata:

```bash
sqlite3 test_onboarding/fdo.db "SELECT hex(guid), voucher_source, last_onboard, onboard_count FROM device_metadata;"
```

## Script Commands Reference

```bash
./test_example.sh init     # Initialize environment and generate keys
./test_example.sh server   # Run onboarding server
./test_example.sh clean    # Remove test environment
./test_example.sh          # Show usage help
```

## See Also

- `DEVICE_STORAGE.md` - Comprehensive device storage documentation
- `config.yaml` - Server configuration reference
- `configs/devices/example-device.yaml` - Device config example
- `configs/groups/example-fedora.yaml` - Group config example
