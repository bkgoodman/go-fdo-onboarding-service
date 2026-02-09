# Unified Device Storage System

This document describes the unified device storage system that handles both voucher files and device-specific FSIM configurations.

## Overview

The FDO onboarding service now supports:

1. **File-based voucher storage** - Vouchers can be stored as `.fdoov` files and automatically loaded during onboarding
2. **Device-specific FSIM configuration** - Each device can have custom configurations that override group and global settings
3. **Hierarchical configuration** - Three-tier system: Device → Group → Global

## Directory Structure

```
/var/bkgdata/go-fdo-onboarding-service/
├── fdoserver.cfg              # Global server configuration
├── vouchers/                  # Voucher files (by GUID)
│   ├── abc123def456.fdoov
│   └── def456abc123.fdoov
└── configs/                   # Device-specific configurations
    ├── groups/                # Group configurations
    │   ├── fedora.yaml
    │   └── raspberry-pi.yaml
    └── devices/               # Device-specific configs (by GUID)
        ├── abc123def456.yaml
        └── def456abc123.yaml
```

## Configuration

Add to `fdoserver.cfg`:

```yaml
device_storage:
  voucher_dir: "vouchers"              # Directory for voucher files
  config_dir: "configs"                # Directory for device configs
  delete_after_onboard: false          # Delete voucher file after successful onboard
  cache_configs: false                 # Cache parsed configs in database (future)
```

## Voucher File Storage

### How It Works

1. **Voucher Creation**: External DI/manufacturing process creates vouchers as `.fdoov` files
2. **File Placement**: Place voucher files in `vouchers/` directory with filename `{GUID}.fdoov`
3. **Automatic Loading**: When device onboards (TO2), server automatically:
   - Checks database for voucher
   - If not found, loads from file
   - Caches in database for future use
   - Tracks metadata (source, loaded_at, last_onboard, last_seen)

### File Format

Vouchers must be PEM-encoded CBOR format:

```
-----BEGIN OWNERSHIP VOUCHER-----
<base64-encoded-cbor-data>
-----END OWNERSHIP VOUCHER-----
```

### File Naming

Filename must be the GUID in hex format (without dashes) with `.fdoov` extension:
- Example: `abc123def456.fdoov`

### Metadata Tracking

The system tracks:
- `voucher_source`: "file" or "database"
- `voucher_loaded_at`: When voucher was loaded from file
- `last_onboard`: Last successful onboard timestamp
- `last_seen`: Last TO2 attempt timestamp
- `onboard_count`: Number of times device has onboarded

## Device-Specific FSIM Configuration

### Three-Tier Hierarchy

1. **Global Config** (`fdoserver.cfg`) - Base defaults for all devices
2. **Group Config** (`configs/groups/{name}.yaml`) - Shared settings for device groups
3. **Device Config** (`configs/devices/{GUID}.yaml`) - Individual device settings

### Configuration Merging

**Arrays** (downloads, uploads, credentials, etc.):
- **Concatenate** all levels: device + group + global
- Device gets all configs from all tiers

**Scalars** (hostname, upload_dir, etc.):
- **Override**: Device overrides group overrides global

**Key-value pairs** (sysconfig):
- **Override by key**: Device key overrides group key overrides global key

### Group Configuration Example

`configs/groups/fedora.yaml`:

```yaml
group_name: "fedora"
description: "Fedora Workstation systems"

fsim:
  bmo_files:
    - "application/x-iso9660-image:images/fedora-workstation-40.iso"
  sysconfig:
    - "selinux=enforcing"
    - "firewalld=enabled"
  credentials:
    - "ssh-key:fedora-admin:/keys/fedora-admin.pub"
```

### Device Configuration Example

`configs/devices/abc123def456.yaml`:

```yaml
device_guid: "abc123def456"
group: "fedora"  # Reference to group config
hostname: "fedora-workstation-01"

fsim:
  sysconfig:
    - "hostname=fedora-workstation-01"
    - "ip_address=192.168.1.101"
  credentials:
    - "password:localuser:device-password"
```

### Merged Result

When device `abc123def456` onboards, it receives:

```yaml
fsim:
  # From global (fdoserver.cfg)
  downloads:
    - "common-admin-key.pub"
  
  # From group (fedora.yaml)
  bmo_files:
    - "application/x-iso9660-image:images/fedora-workstation-40.iso"
  
  # From device (abc123def456.yaml)
  sysconfig:
    - "hostname=fedora-workstation-01"  # Device-specific
    - "ip_address=192.168.1.101"        # Device-specific
    - "selinux=enforcing"                # From group
    - "firewalld=enabled"                # From group
  
  # Credentials concatenated from all levels
  credentials:
    - "password:localuser:device-password"       # Device
    - "ssh-key:fedora-admin:/keys/fedora-admin.pub"  # Group
    - "password:admin:global-password"           # Global
```

## Workflow

### External Tool Integration

1. **Manufacturing/DI Process**:
   - Creates voucher → saves as `vouchers/{GUID}.fdoov`
   - Creates device config → saves as `configs/devices/{GUID}.yaml`

2. **Device Onboarding (TO2)**:
   - Server loads voucher from file (if not in database)
   - Server loads device config and merges with group/global
   - Server provides device-specific FSIM data
   - Server tracks onboarding metadata

3. **Re-onboarding**:
   - Server detects via `last_onboard` and `last_seen` timestamps
   - Optionally deletes voucher file if `delete_after_onboard: true`

### Manual Management

Create device config manually:

```bash
# Create group config
cat > configs/groups/my-group.yaml <<EOF
group_name: "my-group"
description: "My device group"
fsim:
  sysconfig:
    - "group-setting=value"
EOF

# Create device config
GUID="abc123def456"
cat > configs/devices/${GUID}.yaml <<EOF
device_guid: "${GUID}"
group: "my-group"
hostname: "my-device-01"
fsim:
  sysconfig:
    - "hostname=my-device-01"
EOF
```

## Database Schema

The system adds a `device_metadata` table:

```sql
CREATE TABLE device_metadata (
    guid BLOB PRIMARY KEY,
    
    -- Voucher tracking
    voucher_source TEXT,
    voucher_loaded_at INTEGER,
    
    -- Config tracking
    config_group TEXT,
    config_loaded_at INTEGER,
    
    -- Onboarding tracking
    last_onboard INTEGER,
    last_seen INTEGER,
    onboard_count INTEGER DEFAULT 0,
    
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

## Benefits

✅ **Simple voucher transmission** - Just copy `.fdoov` files to directory
✅ **No formal API required** - File-based interface for external tools
✅ **Device-specific customization** - Each device gets tailored configuration
✅ **Scalable grouping** - Manage hundreds of devices with group configs
✅ **Backward compatible** - Works with existing database-only setups
✅ **Metadata tracking** - Track onboarding history and re-onboarding
✅ **Version control friendly** - Config files can be tracked in git

## Troubleshooting

### Voucher not loading from file

Check:
1. File exists in `vouchers/` directory
2. Filename matches GUID in hex format (no dashes)
3. File has `.fdoov` extension
4. File is valid PEM-encoded CBOR format
5. Server has read permissions on the file

### Device config not applying

Check:
1. File exists in `configs/devices/` directory
2. Filename matches GUID in hex format with `.yaml` extension
3. YAML syntax is valid
4. Group reference (if any) points to existing group config
5. Server logs for config loading errors

### Re-onboarding issues

Check:
1. `device_metadata` table for `last_onboard` and `onboard_count`
2. Voucher file still exists (if `delete_after_onboard: false`)
3. Device credentials haven't changed unexpectedly

## Future Enhancements

- Config validation on startup
- CLI tools for config management
- Config hot-reload without server restart
- Web UI for device/group management
- Automatic device-to-group assignment rules
