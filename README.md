# FIDO Device Onboarding (FDO) Onboarding Service (Server)

## Overview

This application provides an FDO onboarding service with support for:

- **File-based voucher storage** - Drop `.fdoov` files in a directory for automatic loading
- **Device-specific FSIM configuration** - Hierarchical config system (device → group → global)
- **Metadata tracking** - Track onboarding history and re-onboarding events
- **TO0, TO1, TO2 protocols** - Full FDO protocol support with mutual attestation

The service provides guaranteed mutual attestation between device and onboarding service prior to onboarding, after which all configuration data is exchanged via an encrypted channel.

## Quick Start

### Testing with Example Script

The fastest way to test the onboarding workflow:

```bash
# Step 1: Initialize environment and generate owner keys
./test_example.sh init
# This displays owner public keys and shows where to place vouchers

# Step 2: Configure your DI manufacturing station
# Edit your DI config (e.g., /home/windsurf/go-fdo-di/config.yaml):
#
# voucher_management:  # Note: Some configs use 'owner_signover' instead
#   mode: "static"
#   static_public_key: |
#     -----BEGIN PUBLIC KEY-----
#     <paste one of the PEM keys from step 1>
#     -----END PUBLIC KEY-----

# Step 3: Run DI on your device to generate a voucher

# Step 4: Copy the voucher to the test directory
cp /path/to/voucher.fdoov test_onboarding/vouchers/{GUID}.fdoov

# Step 5: (Optional) Create device-specific config
# An example template is created at:
# test_onboarding/configs/devices/example-device-template.yaml
#
# Copy and customize it for your device:
cp test_onboarding/configs/devices/example-device-template.yaml \
   test_onboarding/configs/devices/{GUID}.yaml
# Then edit the file to set hostname, IP, credentials, etc.

# Step 6: Run the onboarding server
./test_example.sh server
# Server listens on localhost:8080 and waits for device connections
```

See `TEST_SCRIPT_README.md` for detailed testing instructions.

### End-to-End Integration Workflow

To exercise the full Manufacturing Station → Onboarding Service → Device client flow,
run the automated script from this repository:

```bash
./tests/test_e2e_integration.sh
```

All documentation for that workflow (phases, artifacts, troubleshooting, and
extensions) lives alongside the script in `tests/README_E2E_TEST.md`.

## Setup

### Prerequisites

- Go 1.21 or later
- Git

### Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd go-fdo-onboarding-service
```

2. Initialize the git submodule:
```bash
git submodule update --init --recursive
```

3. Build the application:
```bash
go build -o fdo-onboarding-service .
```

## Command-Line Flags

### Key Management

```bash
# Generate new owner keys
./fdo-onboarding-service -config config.yaml -generate-owner-key

# Print existing owner public keys (PEM format)
./fdo-onboarding-service -config config.yaml -print-owner-key

# Import owner private key from PEM file
./fdo-onboarding-service -config config.yaml -import-owner-key owner_key.pem
```

### Voucher Receiver Token Management

```bash
# List all authentication tokens
./fdo-onboarding-service -config config.yaml -list-receiver-tokens

# Add a new token (expires in 24 hours)
./fdo-onboarding-service -config config.yaml -add-receiver-token "my-token Description text 24"

# Add a permanent token (never expires)
./fdo-onboarding-service -config config.yaml -add-receiver-token "permanent-token Description 0"

# Delete a token
./fdo-onboarding-service -config config.yaml -delete-receiver-token "my-token"

# Clean up expired tokens
./fdo-onboarding-service -config config.yaml -cleanup-expired-tokens
```

### Server Operations

```bash
# Initialize database and keys only (don't start server)
./fdo-onboarding-service -config config.yaml -init-only

# Enable debug logging
./fdo-onboarding-service -config config.yaml -debug

# Run the server (default)
./fdo-onboarding-service -config config.yaml
```

**Common Workflow**:
1. Initialize: `./fdo-onboarding-service -init-only` - Creates DB and generates keys
2. Export keys: `./fdo-onboarding-service -print-owner-key` - Get PEM keys for DI
3. Run server: `./fdo-onboarding-service` - Start onboarding service

## Configuration

For comprehensive configuration documentation, see **[CONFIGURATION.md](CONFIGURATION.md)** which covers:

- Complete configuration reference with all options
- Device templates and hierarchical configuration system
- Voucher receiver configuration with FDOKeyAuth
- Pull service and DID configuration
- FSIM modules (BMO, payload, WiFi, etc.)
- Production and development setup examples

### Quick Configuration

The main configuration file is `config.yaml`. Here's a minimal setup:

```yaml
debug: true
server:
  addr: "localhost:8080"
  ext_addr: "localhost:8080"
database:
  path: "test.db"
manufacturing:
  init_keys_if_missing: true
device_storage:
  voucher_dir: "vouchers"
  config_dir: "configs"
```

### Device Templates

The service supports hierarchical device configuration with templates:

```
configs/
├── groups/                      # Group templates
│   ├── fedora.yaml              # Fedora systems
│   └── raspberry-pi.yaml       # Raspberry Pi
└── devices/                     # Device-specific configs
    ├── abc123def456.yaml         # Individual device
    └── def456abc123.yaml         # Individual device
```

**Usage:**
1. Create group templates in `configs/groups/`
2. Copy `configs/devices/example-device-template.yaml` to `{GUID}.yaml`
3. Reference group: `group: "fedora"` in device config
4. Override settings as needed

Configuration merges: **Device** → **Group** → **Global**

### Key Features

- **Hierarchical configuration**: Device → Group → Global
- **Automatic voucher loading**: Place `.fdoov` files in vouchers directory
- **Device-specific FSIM**: Each device can have custom configurations
- **FDOKeyAuth support**: Cryptographic authentication for push/pull
- **Template system**: Reusable device and group configurations

See **[CONFIGURATION.md](CONFIGURATION.md)** for complete documentation.

## Voucher Receiver (HTTP Push)

This service can receive vouchers pushed from manufacturing systems via HTTP, following the FDO Voucher Transfer Protocol specification.

### Features

- **HTTP Endpoint**: Accepts vouchers via `POST /api/v1/vouchers`
- **Authentication**: Supports global token and database-backed tokens with expiration
- **Ownership Validation**: Rejects vouchers not signed to configured owner keys
- **Audit Logging**: Logs all received vouchers (GUID, IP, token, metadata)
- **Storage**: Saves vouchers to existing voucher directory in PEM format
- **Security**: 10MB size limit, duplicate detection, source IP tracking

### Configuration

Enable the voucher receiver in `config.yaml`:

```yaml
voucher_receiver:
  enabled: true                    # Enable the receiver
  endpoint: "/api/v1/vouchers"     # HTTP endpoint path
  auth_method: "both"              # fdokeyauth, bearer, both
  global_token: "secret-token"     # Optional global bearer token
  validate_ownership: true         # Reject vouchers not signed to us
  require_auth: true               # Require authentication
  session_ttl: "5m"               # FDOKeyAuth session TTL
  max_sessions: 100              # Max FDOKeyAuth sessions
```

**Authentication Methods:**
- **`fdokeyauth`** - FDOKeyAuth cryptographic authentication only
- **`bearer`** - Bearer token authentication only  
- **`both`** - FDOKeyAuth primary, Bearer token fallback (recommended)

See **[CONFIGURATION.md](CONFIGURATION.md)** for complete FDOKeyAuth setup and token management.

### Token Management

Add authentication tokens for manufacturing systems:

```bash
# Add a token that expires in 24 hours
./fdo-onboarding-service --add-receiver-token "mfg-system-1 Manufacturing System A 24"

# Add a permanent token (never expires)
./fdo-onboarding-service --add-receiver-token "test-token Test system 0"

# List all tokens
./fdo-onboarding-service --list-receiver-tokens

# Delete a token
./fdo-onboarding-service --delete-receiver-token "mfg-system-1"

# Clean up expired tokens
./fdo-onboarding-service --cleanup-expired-tokens
```

### HTTP API

**Request:**
```bash
curl -X POST http://localhost:8080/api/v1/vouchers \
  -H "Authorization: Bearer your-token-here" \
  -F "voucher=@device.fdoov" \
  -F "serial=ABC123" \
  -F "model=device-model"
```

**Success Response (200 OK):**
```json
{
  "status": "accepted",
  "voucher_id": "550e8400e29b41d4a716446655440000",
  "message": "Voucher accepted and stored",
  "timestamp": "2026-02-19T13:48:16Z"
}
```

**Error Responses:**
- `400` - Invalid voucher format
- `401` - Missing/invalid authentication token
- `403` - Voucher not signed to our owner key
- `409` - Voucher already exists
- `413` - File exceeds 10MB limit
- `500` - Server error

### Testing

Use the demo script to test voucher receiver:

```bash
# Test voucher receiver with a sample voucher
./tests/test_voucher_receiver.sh
```

See `docs/VOUCHER_RECEIVER_IMPLEMENTATION.md` for complete documentation.

## Dependencies

- [go-fdo](https://github.com/bkgoodman/go-fdo): Main FDO library (included as git submodule)
- Standard Go library packages for cryptography, networking, and HTTP transport

## License

This project follows the same license as the go-fdo library: Apache License 2.0

## Contributing

This is a demonstration/stub application. For production use, you would need to:

1. Implement the credential storage/retrieval functions
2. Add proper error handling and logging
3. Implement security best practices for credential management
4. Add comprehensive testing
5. Consider adding configuration file support

## References

- [FIDO Device Onboard Protocol Specification](https://fidoalliance.org/specs/fdo/)
- [go-fdo Library Documentation](https://github.com/bkgoodman/go-fdo)
- [FIDO Alliance](https://fidoalliance.org/)
