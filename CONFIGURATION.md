# Configuration Guide

This guide covers all configuration options for the FDO Onboarding Service.

The configuration has two main concerns:

1. **Server settings** — How the service itself runs (network, database, keys, voucher transfer, etc.)
2. **Device onboarding settings** — What gets configured on each device during onboarding (hostnames, credentials, firmware, WiFi, etc.)

Device onboarding settings use a three-level hierarchy: **Global defaults** → **Group templates** → **Per-device overrides**. This is covered in detail in [Device Onboarding Settings](#device-onboarding-settings).

## Table of Contents

- [Server Configuration](#server-configuration)
- [Device Onboarding Settings](#device-onboarding-settings)
- [Device Storage & Templates](#device-storage--templates)
- [Voucher Receiver (Push)](#voucher-receiver-push)
- [Pull Service](#pull-service)
- [DID Configuration](#did-configuration)
- [TO0 Configuration](#to0-configuration)
- [Quick Examples](#quick-examples)
- [Troubleshooting](#troubleshooting)

---

## Server Configuration

The main configuration file is `config.yaml`. This section covers everything
**except** device onboarding settings, which are documented separately below.

```yaml
# Basic server settings
debug: false
fdo_version: 101                  # 101 for FDO 1.01, 200 for FDO 2.0

# Server network settings
server:
  addr: "localhost:8080"           # Server bind address
  ext_addr: "localhost:8080"       # External address (for DID discovery, etc.)
  use_tls: false                   # Enable TLS
  insecure_tls: false              # Skip TLS verification (testing only)

# Database settings
database:
  path: "fdo.db"                   # SQLite database file
  password: ""                     # Optional database encryption password

# Manufacturing / owner key settings
manufacturing:
  init_keys_if_missing: true       # Auto-generate owner keys on first run
  device_ca_key_type: "ec384"      # Device CA key type (ec256, ec384, ec521)
  owner_key_type: "ec384"          # Owner key type (ec256, ec384, ec521)
  generate_certificates: true      # Generate device certificates during DI
  first_time_init: false           # Force first-time initialization

# Rendezvous servers (devices contact these to find us)
rendezvous:
  entries:
    - host: "127.0.0.1"
      port: 8080
      scheme: "http"

# Device storage — where vouchers and device configs live on disk
device_storage:
  voucher_dir: "vouchers"          # Directory for .fdoov voucher files
  config_dir: "configs"            # Directory for group/device config files
  delete_after_onboard: false      # Remove voucher file after successful onboard
  cache_configs: false             # Cache parsed configs in database

# Voucher management
voucher_management:
  persist_to_db: true              # Store vouchers in database
  reuse_credential: true           # Allow device to re-onboard with same credential
  voucher_signing:
    mode: ""                       # Voucher signing mode (advanced)

# TO0 (rendezvous registration)
to0:
  delay: 0                         # Delay before TO0 registration (seconds)
  bypass: false                    # Bypass TO0 entirely (testing only)
  replacement_policy: "allow-any"  # Device replacement policy
  rv_filter:                       # See "TO0 Configuration" section below
    mode: "allow_all"
    max_attempts: 3
    retry_interval: "30s"
    allow: []
    deny: []

# Delegate certificates
delegate:
  onboard: false                   # Accept delegate certs for onboarding
  rv: false                        # Accept delegate certs for rendezvous

# Voucher receiver (accept pushed vouchers via HTTP)
voucher_receiver:
  enabled: false                   # See "Voucher Receiver (Push)" section below
  endpoint: "/api/v1/vouchers"
  auth_method: "both"
  global_token: ""
  validate_ownership: true
  require_auth: true
  session_ttl: "5m"
  max_sessions: 100

# DID document serving
did:
  host: ""                         # See "DID Configuration" section below
  path: ""
  serve_document: true
  key_type: "ec384"

# Pull service (allow others to pull vouchers from us)
pull_service:
  enabled: false                   # See "Pull Service" section below
  session_ttl: "60s"
  max_sessions: 1000
  token_ttl: "1h"
  reveal_voucher_existence: false

# Global device onboarding defaults (see next section)
# fsim:
#   sysconfig: [...]
#   credentials: [...]
#   ... etc.
```

> **Note:** The `fsim:` block at the bottom of `config.yaml` defines **global
> default** device onboarding settings. Every device inherits these unless
> overridden by a group template or per-device config. See the next section for
> a full explanation.

---

## Device Onboarding Settings

When a device connects and completes the FDO protocol (TO2), the onboarding
service delivers a set of configuration instructions to the device over an
encrypted channel. These instructions tell the device things like:

- What hostname and timezone to use
- What user accounts and credentials to create
- What files or firmware to download and install
- How to configure WiFi

In the YAML config files, all of these settings live under a key called
**`fsim`** (short for "FDO Service Info Modules" — the protocol's name for
these configuration packages). You don't need to know the protocol details;
just think of `fsim` as **"the stuff we send to the device."**

### Where `fsim` Can Appear

The `fsim` block can appear in **three places**, forming a hierarchy:

| Level | File | Purpose |
|-------|------|---------|
| **Global** | `config.yaml` | Default settings for **all** devices |
| **Group** | `configs/groups/{name}.yaml` | Shared settings for a class of devices |
| **Device** | `configs/devices/{GUID}.yaml` | Settings for one specific device |

Settings merge from top to bottom. A device gets the union of all three
levels, with more-specific levels overriding less-specific ones. See
[Configuration Merging Rules](#configuration-merging-rules) for details.

### Field Reference

Below is every field that can appear inside an `fsim:` block, with a
description of what it does.

#### System Configuration

```yaml
fsim:
  sysconfig:
    - "hostname=my-device"
    - "timezone=America/New_York"
    - "ssh_enabled=true"
    - "selinux=enforcing"
```

Sets key=value system parameters on the device. Each entry is a string in
`key=value` format. The device's FDO client interprets these and applies them
(e.g., setting the hostname, enabling SSH, etc.).

#### Credentials

```yaml
fsim:
  credentials:
    - "password:admin:secret123"
    - "password:root:rootpass"
    - "ssh-key:admin:ssh-rsa AAAAB3NzaC1yc2E..."
    - "x509:device:-----BEGIN CERTIFICATE-----..."
```

Creates user accounts, passwords, SSH keys, or X.509 certificates on the
device. Format: `type:identity:value`.

- **`password:user:pass`** — Set password for a user account
- **`ssh-key:user:key`** — Install an SSH public key for a user
- **`x509:name:cert`** — Install an X.509 certificate

#### Public Key Requests

```yaml
fsim:
  pubkey_requests:
    - "ssh-rsa:admin-ssh-key"
    - "ssh-rsa:backup-key:https://backup.example.com"
```

Asks the device to **generate** a key pair and send the public key back.
Format: `type:credential_id[:endpoint_url]`. Useful for bootstrapping SSH
access — the device creates the key and reports it back so you can trust it.

#### File Downloads (Server → Device)

```yaml
fsim:
  downloads:
    - src: "configs/files/agent.tar.gz"
      dst: "/tmp/agent.tar.gz"
```

Sends files from the onboarding server to the device. Each entry specifies a
local source path and a destination path on the device.

#### File Uploads (Device → Server)

```yaml
fsim:
  uploads:
    - "/etc/machine-id"
    - "/var/log/install.log"
  upload_dir: "/var/fdo/uploads"
```

Requests files **from** the device. The server saves them to `upload_dir`.

#### HTTP Downloads

```yaml
fsim:
  wgets:
    - url: "https://example.com/bootstrap.sh"
      dst: "/tmp/bootstrap.sh"
```

Tells the device to download files from URLs (the device fetches them
directly, not via the onboarding server).

#### Payload Files

```yaml
fsim:
  # Single payload (simple case)
  payload_file: "configs/payloads/setup.sh"
  payload_mime: "application/x-sh"

  # Multiple payloads
  payload_files:
    - type: "file"
      path: "configs/payloads/setup.sh"
      mime: "application/x-sh"
    - type: "file"
      path: "configs/payloads/config.json"
      mime: "application/json"
```

Sends payload files to the device with MIME type metadata. The device's FDO
client decides how to handle each payload based on its MIME type (e.g., run a
shell script, apply a JSON config, etc.).

#### BMO (Bare Metal Onboarding)

```yaml
fsim:
  # Single BMO image (simple case)
  bmo_file: "configs/bmo/firmware.bin"
  bmo_image_type: "application/x-bmo"

  # Multiple BMO images with delivery options
  bmo_files:
    # Inline: send the file directly over the FDO channel
    - type: "file"
      path: "configs/bmo/firmware.bin"
      image_type: "application/x-bmo"

    # URL: device downloads from a URL; server provides expected hash
    - type: "url:https://updates.example.com/firmware.bin"
      bmo_tls_ca: "configs/certs/update-ca.pem"
      bmo_expected_hash: "sha256:a1b2c3d4e5f6..."

    # Meta-URL: device downloads a signed manifest, then fetches the image
    - type: "meta:https://updates.example.com/firmware-meta.json"
      bmo_tls_ca: "configs/certs/update-ca.pem"
      bmo_meta_signer: "configs/keys/update-signer.pem"
```

Delivers firmware or disk images for bare-metal provisioning. Three delivery
modes:

- **Inline (`file`)** — Image sent directly through the encrypted FDO channel
- **URL (`url:...`)** — Device downloads from a URL; `bmo_expected_hash` lets the device verify integrity
- **Meta-URL (`meta:...`)** — Device downloads a COSE-signed manifest; `bmo_meta_signer` is the public key to verify the signature

#### WiFi Configuration

```yaml
fsim:
  wifi_config_file: "configs/wifi/office.conf"
  single_sided_wifi: false
```

- **`wifi_config_file`** — Path to a WiFi configuration file to apply on the device
- **`single_sided_wifi`** — If `true`, configure WiFi without waiting for device confirmation

#### Miscellaneous

```yaml
fsim:
  command_date: false
```

- **`command_date`** — If `true`, sync the device's clock during onboarding

### Global Defaults Example

In your main `config.yaml`, the `fsim` section sets the **defaults that every
device inherits** unless overridden:

```yaml
# config.yaml
fsim:
  sysconfig:
    - "timezone=UTC"
    - "ssh_enabled=true"
  credentials:
    - "password:admin:default-admin-pass"
  command_date: true
```

With this configuration, every device that onboards will get UTC timezone,
SSH enabled, the default admin password, and a clock sync — unless a group
template or device-specific config overrides those values.

---

## Device Storage & Templates

### Directory Structure

```text
vouchers/                          # Voucher files (by GUID)
  └── {GUID}.fdoov

configs/
├── groups/                        # Group templates
│   ├── fedora.yaml
│   ├── raspberry-pi.yaml
│   └── industrial.yaml
└── devices/                       # Per-device configs
    ├── example-device-template.yaml
    ├── abc123def456.yaml
    └── def456abc123.yaml
```

### Configuration Hierarchy

When a device onboards, its configuration is assembled by merging three levels:

```text
┌─────────────────────────────────────────────┐
│  config.yaml  →  fsim: { ... }              │  Level 1: Global defaults
├─────────────────────────────────────────────┤
│  configs/groups/fedora.yaml → fsim: { ... } │  Level 2: Group template
├─────────────────────────────────────────────┤
│  configs/devices/{GUID}.yaml → fsim: { ... }│  Level 3: Device overrides
└─────────────────────────────────────────────┘
         ↓ merge ↓
   Final configuration delivered to device
```

More-specific levels take priority. A device config overrides a group
template, which overrides the global defaults.

### Configuration Merging Rules

**Arrays** (downloads, uploads, credentials, payload_files, etc.):
Concatenated from all levels. The device receives entries from global + group
+ device configs combined.

**Scalars** (upload_dir, wifi_config_file, command_date, etc.):
Overridden. Device value wins over group, group wins over global.

**Key-value pairs** (sysconfig entries):
Overridden by key. If global sets `timezone=UTC` and the device sets
`timezone=America/New_York`, the device gets `America/New_York`.

### Group Template Example

`configs/groups/fedora.yaml`:

```yaml
group_name: "fedora"
description: "Fedora Workstation systems"

fsim:
  sysconfig:
    - "selinux=enforcing"
    - "firewalld=enabled"
    - "package_manager=dnf"
    - "timezone=UTC"

  credentials:
    - "password:admin:fedora-admin-pass"
    - "password:root:fedora-root-pass"

  payload_files:
    - type: "file"
      path: "configs/payloads/fedora-setup.sh"
      mime: "application/x-sh"

  wifi_config_file: "configs/wifi/fedora-wifi.conf"
```

### Device Config Example

`configs/devices/abc123def456.yaml`:

```yaml
group: "fedora"                    # Inherit from the fedora group template

fsim:
  sysconfig:
    - "hostname=fedora-device-001"
    - "ip_address=192.168.1.100"
    - "timezone=America/New_York"  # Overrides group's UTC

  credentials:
    - "password:operator:device-pass-123"

  bmo_files:
    - type: "url:https://updates.example.com/firmware.bin"
      bmo_expected_hash: "sha256:a1b2c3d4..."
```

**What this device actually receives** (merged result):

| Setting | Value | Source |
|---------|-------|--------|
| `timezone` | `America/New_York` | Device (overrides group) |
| `hostname` | `fedora-device-001` | Device |
| `ip_address` | `192.168.1.100` | Device |
| `selinux` | `enforcing` | Group |
| `firewalld` | `enabled` | Group |
| `package_manager` | `dnf` | Group |
| `ssh_enabled` | `true` | Global (if set) |
| credentials | All three combined | Device + Group + Global |
| firmware | URL delivery | Device |
| payload | fedora-setup.sh | Group |

### Creating a New Device Config

1. Copy the template:
   ```bash
   cp configs/devices/example-device-template.yaml configs/devices/{GUID}.yaml
   ```
2. Set the `group:` field to reference a group template (optional)
3. Add or override any `fsim:` settings for this specific device

---

## Voucher Receiver (Push)

Accept vouchers pushed from manufacturing systems via HTTP, using FDOKeyAuth
(cryptographic challenge-response) or Bearer token authentication.

```yaml
voucher_receiver:
  enabled: true                    # Enable the receiver
  endpoint: "/api/v1/vouchers"     # HTTP endpoint path

  # Authentication method
  auth_method: "both"              # Options:
                                   #   "fdokeyauth" — Cryptographic auth only
                                   #   "bearer"     — Static bearer tokens only
                                   #   "both"       — FDOKeyAuth primary, bearer fallback

  # Bearer token settings
  global_token: "secret-token"     # Optional static bearer token
  validate_ownership: true         # Reject vouchers not signed to our owner key
  require_auth: true               # Require authentication (disable for testing)

  # FDOKeyAuth settings
  session_ttl: "5m"                # Session token lifetime after handshake
  max_sessions: 100                # Max concurrent FDOKeyAuth sessions
```

### FDOKeyAuth Endpoints

When `auth_method` includes "fdokeyauth", these endpoints are registered:

- `{endpoint}/auth/hello` — FDOKeyAuth hello (start handshake)
- `{endpoint}/auth/prove` — FDOKeyAuth prove (complete handshake)

After a successful handshake, the caller receives a session token to use as
a Bearer token for the actual voucher push.

### Bearer Token Management

```bash
# Add a token (expires in 24 hours)
./fdo-onboarding-service -add-receiver-token "mfg-system-1 Manufacturing System A 24"

# Add a permanent token (never expires)
./fdo-onboarding-service -add-receiver-token "permanent-token Test system 0"

# List all tokens
./fdo-onboarding-service -list-receiver-tokens

# Delete a token
./fdo-onboarding-service -delete-receiver-token "mfg-system-1"
```

---

## Pull Service

Allow other FDO services to pull vouchers from this server using FDOKeyAuth.

```yaml
pull_service:
  enabled: true                    # Enable pull service
  session_ttl: "60s"               # FDOKeyAuth session TTL
  max_sessions: 1000               # Max concurrent sessions
  token_ttl: "1h"                  # Pull token lifetime
  reveal_voucher_existence: false  # If true, disclose voucher count in handshake
```

### Pull Client Usage

```bash
# Pull vouchers using a key file
./fdo-onboarding-service -pull-url https://holder.example.com -pull-key owner.pem

# Pull using DID discovery
./fdo-onboarding-service -pull-did did:web:holder.example.com -pull-key owner.pem

# Pull with delegate certificates
./fdo-onboarding-service -pull-url https://holder.example.com \
  -pull-owner-pub owner-pub.pem \
  -pull-delegate-key site1.pem \
  -pull-delegate-chain site1-chain.pem
```

---

## DID Configuration

Serve a DID document so other services can discover this server's public key
and service endpoints.

```yaml
did:
  host: ""                         # Override auto-detected host
  path: ""                         # DID document path (default: /.well-known/did.json)
  serve_document: true             # Enable DID document serving
  key_type: "ec384"                # Key type (ec256, ec384, ec521)
```

The DID document advertises:

- **FDOVoucherRecipient** endpoint — where to push vouchers
- **FDOVoucherHolder** endpoint — where to pull vouchers
- **Public key** — for FDOKeyAuth signature verification

---

## TO0 Configuration

Control how this service registers itself with rendezvous servers so devices
can find it.

```yaml
to0:
  delay: 0                         # Delay before registration (seconds)
  bypass: false                    # Skip registration entirely (testing only)
  replacement_policy: "allow-any"  # Device replacement policy

  # Rendezvous filtering — control which RV servers to register with
  rv_filter:
    mode: "allow_all"              # Filter mode:
                                   #   "allow_all"      — All except deny list
                                   #   "allow_list"     — Only allow list
                                   #   "allow_list_warn"— Only allow list, log skipped
    max_attempts: 3                # Max retry attempts (0 = infinite)
    retry_interval: "30s"          # Time between retries

    allow:                         # Servers to register with
      - host: "rv.local"
        port: 8080
        scheme: "http"

    deny:                          # Servers to skip
      - host: "rv-cloud.vendor.com"
```

---

## Quick Examples

### Minimal Development Setup

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
fsim:
  sysconfig:
    - "timezone=UTC"
  command_date: true
```

### Production Setup with FDOKeyAuth

```yaml
debug: false
server:
  addr: "0.0.0.0:8443"
  ext_addr: "onboarding.example.com:8443"
  use_tls: true
database:
  path: "/var/lib/fdo/fdo.db"
  password: "${FDO_DB_PASSWORD}"
manufacturing:
  init_keys_if_missing: false
device_storage:
  voucher_dir: "/var/lib/fdo/vouchers"
  config_dir: "/etc/fdo/configs"
  delete_after_onboard: true
voucher_receiver:
  enabled: true
  endpoint: "/api/v1/vouchers"
  auth_method: "fdokeyauth"
  validate_ownership: true
  require_auth: true
did:
  serve_document: true
pull_service:
  enabled: true
fsim:
  sysconfig:
    - "timezone=UTC"
    - "ssh_enabled=true"
  credentials:
    - "password:admin:production-default-pass"
  command_date: true
```

---

## Environment Variables

Some configuration values support environment variable substitution:

```yaml
database:
  password: "${FDO_DB_PASSWORD}"
server:
  addr: "${FDO_SERVER_ADDR:0.0.0.0:8080}"
```

---

## Configuration Validation

The service validates configuration on startup:

- Required files and directories must exist
- TLS certificates are validated if TLS is enabled
- PEM key formats are verified
- Network addresses are checked

---

## Troubleshooting

### Common Issues

1. **Config not found** — Ensure `config.yaml` exists and is readable
2. **Permission errors** — Check file permissions for voucher/config directories
3. **TLS errors** — Verify certificate paths and formats
4. **Database errors** — Ensure database directory is writable

### Debug Mode

```bash
./fdo-onboarding-service -config config.yaml -debug
```

### Test Configuration Without Starting

```bash
./fdo-onboarding-service -config config.yaml -init-only
```
