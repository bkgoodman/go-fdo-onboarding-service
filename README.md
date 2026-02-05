<!-- SPDX-FileCopyrightText: (C) 2026 Dell Technologies -->
<!-- SPDX-License-Identifier: Apache 2.0 -->
<!-- Author: Brad Goodman -->

# FDO Device Manufacturing Station

An "in-factory" manufacturing station for FIDO Device Onboard (FDO) device initialization. This system sits on the factory floor and receives vouchers from newly manufactured devices, signs them over to their next owners, and manages the voucher lifecycle.

## Purpose and Role

This application serves as a **factory-floor manufacturing station** that:

- **Receives vouchers** from newly manufactured devices during the Device Initialization (DI) process
- **Signs vouchers over** to the next owner in the supply chain using secure manufacturing keys
- **Stores and/or transmits** vouchers for subsequent use in the device ownership lifecycle
- **Integrates with existing factory systems** through configurable callbacks

Think of this as the **bridge between physical device manufacturing** and **digital device ownership** - it's where a physical device gets its digital identity and ownership credentials.

## Core Workflow

```
New Device → Manufacturing Station → Voucher Creation → Sign Over → Store/Transmit
```

1. **Device Connection**: Newly manufactured devices connect to this station for initialization
2. **Voucher Creation**: An ownership voucher is created with the device's identity
3. **Secure Signing**: The voucher is signed using the factory's secure signing mechanism
4. **Ownership Transfer**: The voucher is signed over to the next owner in the supply chain
5. **Voucher Management**: The signed voucher is stored, transmitted, or both for later use

## Key Capabilities

### 🔐 **Secure Voucher Signing**

- **External HSM Integration**: Connect to high-security Hardware Security Modules for signing
- **Internal Key Management**: Use built-in key generation for simpler deployments
- **Flexible Trust Models**: Adapt to different security requirements and cost constraints

### 🔄 **Ownership Transfer (Signover)**

- **Static Owner**: Sign all devices to a single well-known owner (common for batch manufacturing)
- **Dynamic Owner**: Use factory systems to determine per-device ownership (custom orders, specific customers)

### 📦 **Voucher Management**

- **Database Storage**: SQLite-based voucher persistence (configurable)
- **Disk Storage**: Save vouchers to filesystem for backup or manual processing
- **Remote Transmission**: Send vouchers to external systems via configurable callbacks

### 📋 **OVEExtra Data Integration**

- **Device Metadata**: Add manufacturing information, configuration details, or other metadata
- **Factory Integration**: Pull data from existing manufacturing systems via callbacks
- **Privacy-Aware**: Designed with consideration for data privacy and anonymity concerns

## Architecture Overview

### 🔐 **Secure Voucher Signing**

This system supports two primary signing approaches to accommodate different security requirements and deployment scenarios:

#### **External HSM Integration (High Security)**

For production environments where trust and security are paramount:

- **Hardware Security Modules (HSMs)**: High-security key management devices that act as "rubber stamps" bolted to the factory floor
- **Digest-Based Signing**: HSMs only sign binary digests - they don't understand FDO voucher structures
- **Trust by Physical Security**: The security of the HSM ensures vouchers MUST have been signed by the legitimate factory
- **Integration Flexibility**: Supports everything from large caged systems to USB security keys

#### **Internal Key Management (Simplified)**

For development, testing, or less security-critical environments:

- **Built-in Key Generation**: Create and manage private keys directly in the application
- **First-Time Setup**: Automatic key generation on initial startup
- **Lower Complexity**: Reduced operational overhead and infrastructure requirements
- **Cost-Effective**: Eliminates need for expensive HSM hardware

**When to use each approach:**

- **External HSM**: Production manufacturing, high-value devices, regulatory compliance, multi-party trust scenarios
- **Internal Keys**: Development/testing, ephemeral systems, trusted environments, cost-sensitive deployments

### 🔄 **Ownership Transfer (Signover)**

The system supports flexible ownership transfer models to match different manufacturing workflows:

#### **Static Owner (Well-Known Recipient)**

Ideal for batch manufacturing and stock production:

- **Single Destination**: All devices are signed over to the same well-known owner
- **Common Use Cases**: OEM building for single reseller, stock manufacturing, centralized voucher collection
- **Configuration**: Simple static key configuration
- **Operational Simplicity**: No per-device decision making required

#### **Dynamic Owner (Per-Device Assignment)**

Perfect for custom manufacturing and multi-customer environments:

- **Customer-Specific**: Devices signed over to different owners based on customer requirements
- **Factory Integration**: Uses existing manufacturing systems to determine ownership
- **Flexible Routing**: Supports complex supply chains and distribution models
- **Callback-Driven**: External scripts determine per-device ownership based on serial number, order info, etc.

### 📦 **Voucher Management**

Multiple options for handling signed vouchers, supporting different operational requirements:

#### **Database Storage**

- **Default**: SQLite-based persistence for reliable voucher storage
- **Queryable**: Easy searching and retrieval of voucher history
- **Transactional**: ACID compliance for data integrity
- **Configurable**: Can be disabled if not needed

#### **Disk Storage**

- **Backup**: Additional safety net for voucher preservation
- **Manual Processing**: Enables offline voucher handling
- **Filesystem Access**: Integration with existing file-based workflows
- **Directory Structure**: Organized storage with clear naming conventions

#### **Remote Transmission**

- **Integration**: Send vouchers to external systems via configurable callbacks
- **Real-Time Processing**: Immediate voucher delivery to downstream systems
- **Error Handling**: Configurable retry and error management
- **Protocol Flexibility**: HTTP, FTP, custom protocols via script integration

### 📋 **OVEExtra Data Integration**

FDO provides a mechanism to add arbitrary metadata to vouchers, enabling rich device information:

#### **Device Metadata**

- **Manufacturing Information**: Build dates, test results, configuration details
- **Hardware Details**: Component versions, capabilities, specifications
- **Order Information**: Customer references, purchase orders, production batches

#### **Factory Integration**

- **External Data Sources**: Pull data from MES, ERP, or other factory systems
- **Callback Architecture**: Shell scripts or external commands for data retrieval
- **Dynamic Content**: Per-device metadata based on manufacturing context

#### **Privacy Considerations**

- **Public by Design**: Voucher data is not private - avoid sensitive information
- **Anonymity Aware**: Consider privacy implications when adding metadata
- **Compliance**: Ensure data handling meets regulatory requirements

## Project Structure

```
.
├── main.go                      # Main server application
├── voucher_signing_service.go   # Voucher signing and extension logic
├── external_hsm_signer.go       # External HSM integration
├── manufacturer_key_loader.go   # Public key loading from PEM files
├── voucher_callback.go          # Voucher processing callbacks
├── ove_extra_data_service.go    # OVEExtra data handling
├── voucher_config.go            # Configuration structures
├── config.yaml                  # Server configuration file
├── go.mod                       # Go module definition
├── go-fdo/                      # go-fdo library as git submodule
├── tests/                       # Test configurations and scripts
│   ├── test_hsm_digest_mock.sh  # Mock HSM for digest signing
│   ├── test_ove_extra_data.sh   # Mock OVEExtra data script
│   └── *.cfg                    # Various test configurations
└── README.md                    # This file
```

## 🔗 **Factory Integration & Callbacks**

This system is designed to integrate with existing factory manufacturing systems through a flexible callback architecture. The manufacturing station handles the FDO protocol specifics, while external systems provide business logic and data.

### **Callback Architecture**

The system uses **external command callbacks** to integrate with factory systems:

- **Shell Commands**: Simple scripts or commands for basic integration
- **HTTP Requests**: Direct API calls to external systems
- **Custom Scripts**: Complex business logic in any scriptable language
- **Database Queries**: Integration with MES/ERP systems

### **Integration Points**

#### **Device Information**

- **Serial Number Lookup**: Query manufacturing databases for device details
- **Order Information**: Retrieve purchase orders, customer data
- **Production Data**: Access build records, test results
- **Configuration Data**: Get device-specific settings and capabilities

#### **Ownership Determination**

- **Customer Assignment**: Determine which customer owns each device
- **Supply Chain Routing**: Decide next owner in distribution chain
- **Key Management**: Retrieve appropriate public keys for signover
- **Compliance Rules**: Apply regulatory or policy requirements

#### **Metadata Enrichment**

- **Hardware Details**: Component versions, capabilities, test results
- **Manufacturing Data**: Build dates, line information, batch numbers
- **Quality Data**: Test results, calibration data, certifications
- **Business Data**: Order numbers, customer references, warranty info

#### **Voucher Distribution**

- **System Integration**: Send vouchers to downstream systems
- **Customer Delivery**: Direct transmission to end customers
- **Archive Storage**: Long-term voucher preservation
- **Compliance Reporting**: Audit trail and regulatory reporting

### **Callback Implementation**

Callbacks are configured as external commands with template substitution:

```yaml
external_command: "bash /factory/scripts/get_owner_key.sh {serial} {model}"
```

**Available Variables:**

- `{serial}`: Device serial number
- `{model}`: Device model information  
- `{guid}`: Device GUID
- `{requestid}`: Unique request identifier
- `{station}`: Manufacturing station ID

### **Error Handling & Resilience**

- **Timeout Configuration**: Configurable timeouts for external calls
- **Retry Logic**: Built-in retry mechanisms for transient failures
- **Fallback Behavior**: Default values when external systems are unavailable
- **Logging**: Comprehensive logging for debugging and audit trails

## Setup

### Prerequisites

- Go 1.21 or later
- Git

### Installation

1. Clone this repository:

```bash
git clone <repository-url>
cd go-fdo-di
```

1. Initialize the git submodule:

```bash
git submodule update --init --recursive
```

1. Build the application:

```bash
go build -o fdo-manufacturing-station .
```

## Configuration

The system uses a comprehensive YAML configuration file that supports different deployment scenarios and integration patterns.

### **Configuration Overview**

```yaml
# Core server configuration
debug: false
server:
  addr: "localhost:8080"
  ext_addr: "localhost:8080"
  use_tls: false
  insecure_tls: false

# Database configuration
database:
  path: "manufacturing.db"
  password: ""

# Manufacturing and device certificate setup
manufacturing:
  device_ca_key_type: "ec384"
  owner_key_type: "ec384"
  generate_certificates: true
  first_time_init: false

# Voucher management and signing
voucher_management:
  persist_to_db: true
  voucher_signing:
    # SIGNING MODE: Choose one of the configurations below
    mode: "external"  # "external" | "internal"
    owner_key_type: "ec384"
    
    # External HSM Configuration
    external_command: "bash /factory/hsm/sign_digest.sh {requestfile} {requestid} {station}"
    external_timeout: "30s"
    manufacturer_public_key_file: "/factory/keys/manufacturer_public.pem"
    
    # OR Internal Key Configuration
    first_time_init: true
    
  # OVEExtra data integration
  ove_extra_data:
    enabled: true
    external_command: "bash /factory/scripts/get_device_metadata.sh {serial} {model}"
    timeout: "5s"
    
  # Voucher storage options
  save_to_disk:
    directory: "/factory/vouchers"
    
  # Voucher transmission
  voucher_upload:
    enabled: true
    external_command: "curl -X POST https://corp-vault.example.com/api/vouchers -d @-"
    timeout: "30s"
```

### **Deployment Scenarios**

#### **🏭 Production Factory with External HSM**

```yaml
voucher_management:
  voucher_signing:
    mode: "external"
    external_command: "bash /factory/hsm/sign_digest.sh {requestfile} {requestid} {station}"
    manufacturer_public_key_file: "/factory/keys/manufacturer_public.pem"
  ove_extra_data:
    enabled: true
    external_command: "python3 /factory/integration/get_device_data.py {serial}"
  voucher_upload:
    enabled: true
    external_command: "curl -X POST https://supplychain.example.com/api/vouchers -d @-"
```

#### **🧪 Development/Test Environment**

```yaml
voucher_management:
  voucher_signing:
    mode: "internal"
    first_time_init: true
  ove_extra_data:
    enabled: false
  save_to_disk:
    directory: "/tmp/test_vouchers"
  voucher_upload:
    enabled: false
```

#### **📦 Batch Manufacturing (Static Owner)**

```yaml
voucher_management:
  voucher_signing:
    mode: "external"
    external_command: "bash /factory/hsm/batch_sign.sh {requestfile}"
  ove_extra_data:
    enabled: true
    external_command: "bash /factory/scripts/batch_metadata.sh {serial}"
  voucher_upload:
    enabled: true
    external_command: "scp {voucher_file} batch_processor@hq:/incoming/"
```

#### **🎯 Custom Manufacturing (Dynamic Owner)**

```yaml
voucher_management:
  voucher_signing:
    mode: "external"
    external_command: "bash /factory/hsm/sign_with_customer_key.sh {requestfile} {serial}"
  ove_extra_data:
    enabled: true
    external_command: "bash /factory/erp/get_customer_data.sh {serial} {order_id}"
  voucher_upload:
    enabled: true
    external_command: "bash /factory/routing/route_to_customer.sh {voucher_file} {customer_id}"
```

### **Key Configuration Options**

#### **Voucher Signing Modes**

| Mode | Description | Use Case | Security |
|------|-------------|----------|----------|
| `external` | Use external HSM for signing | Production, high security | Highest |
| `internal` | Use built-in key management | Development, testing | Moderate |

#### **Supported Key Types**

- `ec256`: ECDSA P-256 (fast, good security)
- `ec384`: ECDSA P-384 (recommended, excellent security)  
- `rsa2048`: RSA 2048-bit (legacy compatibility)
- `rsa3072`: RSA 3072-bit (high security)

#### **Callback Variables**

Available template variables for external commands:

- `{serial}`: Device serial number
- `{model}`: Device model identifier
- `{guid}`: Device GUID
- `{requestid}`: Unique request identifier
- `{station}`: Manufacturing station ID
- `{voucher_file}`: Path to voucher file (for upload callbacks)

### **Command Line Options**

```bash
# Start with custom configuration
./fdo-manufacturing-station -config /factory/config/production.yaml

# Enable debug logging
./fdo-manufacturing-station -debug

# Initialize database and keys only
./fdo-manufacturing-station -init-only

# Custom server address
./fdo-manufacturing-station -config config.yaml -addr "0.0.0.0:8443"
```

  first_time_init: false

# Voucher Management Configuration

voucher_management:
  persist_to_db: true
  owner_signover:
    enabled: false
    external_command: ""
    timeout: "10s"
  voucher_upload:
    enabled: false
    external_command: ""
    timeout: "30s"

```

### Examples

#### Basic Manufacturing Server

```bash
# Start with default configuration (config.yaml)
./fdo-manufacturing-station

# Start with custom configuration file
./fdo-manufacturing-station -config config_custom.yaml

# Start with debug logging
./fdo-manufacturing-station -config config.yaml -debug
```

#### Initialize Manufacturing Environment

```bash
# Initialize database and keys only (first time setup)
./fdo-manufacturing-station -config config.yaml -init-only
```

#### Voucher Management Examples

```bash
# Basic voucher upload to external system
./fdo-manufacturing-station -config config_with_upload.yaml

# Fixed owner key signover
./fdo-manufacturing-station -config config_fixed_owner.yaml

# Dynamic owner key lookup per device
./fdo-manufacturing-station -config config_dynamic_owner.yaml
```

## Voucher Management

The manufacturing station supports advanced voucher management capabilities for factory integration:

### Voucher Persistence

Control whether vouchers are stored in the local database:

```yaml
voucher_management:
  persist_to_db: true  # Store vouchers in SQLite database
  persist_to_db: false # Don't store, only process externally
```

### Owner Key Signover

Automatically sign vouchers to different owners during device initialization:

#### Fixed Owner Key

```yaml
voucher_management:
  owner_signover:
    enabled: true
    external_command: "cat /etc/owner_keys/production.pem"
    timeout: "10s"
```

#### Dynamic Owner Key

```yaml
voucher_management:
  owner_signover:
    enabled: true
    external_command: "python3 /opt/owner_lookup.py --serial {serialno} --model {model}"
    timeout: "10s"
```

**Dynamic Script Example:**

```python
#!/usr/bin/env python3
import json, argparse, sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--model', required=True)
    args = parser.parse_args()
    
    # Lookup owner key based on device characteristics
    if args.model.startswith("Enterprise"):
        key_file = "/etc/owner_keys/enterprise.pem"
    else:
        key_file = "/etc/owner_keys/standard.pem"
    
    with open(key_file, 'r') as f:
        key_pem = f.read().strip()
    
    print(json.dumps({"owner_key_pem": key_pem, "error": ""}))

if __name__ == '__main__':
    main()
```

### Voucher Upload

Send vouchers to external manufacturing systems:

```yaml
voucher_management:
  voucher_upload:
    enabled: true
    external_command: "curl -F 'voucher=@{voucherfile}' -F 'serial={serialno}' -F 'model={model}' https://factory.example.com/api/vouchers"
    timeout: "30s"
```

### Save to Disk

Save ownership vouchers to the local filesystem in the same format as go-fdo command-line tools:

```yaml
voucher_management:
  save_to_disk:
    directory: "/path/to/vouchers"
```

*Note: Disk saving is enabled when a directory is specified. If the directory is empty or omitted, disk saving is disabled.*

Vouchers are saved as `{serialnumber}.fdoov` files in the same format as go-fdo command-line tools:

```
-----BEGIN OWNERSHIP VOUCHER-----
<base64-encoded-cbor-data>
-----END OWNERSHIP VOUCHER-----
```

### OVEExtra Data

Add custom data to the initial voucher entry during device initialization. This allows you to include supply chain information, customer details, or other metadata directly in the voucher.

```yaml
voucher_management:
  ove_extra_data:
    enabled: true
    external_command: "bash /path/to/extra_data_script.sh {serial} {model}"
    timeout: "5s"
```

The external script should return JSON data that will be encoded as CBOR and included in the OVEExtra field of the first voucher entry:

```bash
#!/bin/bash
# Example extra data script
SERIAL="$1"
MODEL="$2"

cat <<EOF
{
  "customer": "ACME Corp",
  "order_number": "ORD-$(date +%s)",
  "serial": "$SERIAL",
  "model": "$MODEL",
  "manufacturing_date": "$(date -I)",
  "facility": "Factory-01"
}
EOF
```

*Note: OVEExtra data is only included in the initial voucher entry created during device initialization. The data is encoded as CBOR and can include any JSON-serializable values.*

### Variable Substitution

The following variables are available in external commands:

- `{serialno}` - Real device serial number from session state
- `{model}` - Device model/info from DeviceInfo callback
- `{guid}` - Voucher GUID for correlation
- `{voucherfile}` - Temporary voucher file path

### Privacy-First Design

- **Serial numbers are NOT stored in vouchers** (maintains privacy)
- **Real serial numbers available to external handlers** (factory integration)
- **Session state storage** (not persistent voucher storage)

## Implementation Notes

This is a **basic manufacturing station** that demonstrates the structure and API usage of the go-fdo library for server-side operations. The following components are implemented:

- **SQLite Backend**: Uses SQLite for persistent storage of vouchers, keys, and session data
- **Key Management**: Generates and manages manufacturing and owner cryptographic keys
- **Device Certificate Authority**: Acts as CA for device certificates during DI
- **Service Info Modules**: Supports file transfer, configuration, and command execution modules

### Architecture

The manufacturing station implements the following FDO protocol components:

1. **DI Server**: Handles device initialization requests
2. **TO0 Server**: Manages rendezvous blob registration
3. **TO1 Server**: Handles ownership transfer rendezvous
4. **Service Info**: Provides device provisioning capabilities

## Dependencies

- [go-fdo](https://github.com/bkgoodman/go-fdo): Main FDO library (included as git submodule)
- Standard Go library packages for cryptography, networking, and HTTP transport
- SQLite for data persistence

## License

This project follows the same license as the go-fdo library: Apache License 2.0

## Contributing

This is a demonstration/manufacturing station application. For production use, you would need to:

1. Implement secure key storage and management
2. Add proper authentication and authorization
3. Implement manufacturing workflow customization
4. Add comprehensive logging and monitoring
5. Consider adding high-availability features
6. Add integration with manufacturing execution systems

## Manufacturing Use Cases

This station is designed for typical in-factory manufacturing scenarios:

- **Device Provisioning**: Initialize devices with cryptographic credentials
- **Batch Manufacturing**: Handle multiple device types with different configurations
- **Quality Control**: Track device provisioning status and certificates
- **Supply Chain Integration**: Register devices with external rendezvous services

## References

- [FIDO Device Onboard Protocol Specification](https://fidoalliance.org/specs/fdo/)
- [go-fdo Library Documentation](https://github.com/bkgoodman/go-fdo)
- [FIDO Alliance](https://fidoalliance.org/)
