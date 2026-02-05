# Device-Side Ownership Voucher Delivery - Implementation TODO

## Overview

This document outlines the implementation work required to support optional ownership voucher (OV) delivery to FDO clients during Device Initialization (DI), including QR code display capabilities and device-signed voucher support.

## Current State Analysis

### Protocol Limitations
- **Current DI Flow**: Device receives only VoucherHeader, not complete OV
- **Missing Data**: Complete voucher entries, signatures, certificate chains
- **Storage Location**: Full voucher created and stored server-side after DI completion

### Voucher Size Analysis
- **PEM Format**: 1,579 bytes (including headers)
- **Base64 Data Only**: 1,513 bytes
- **Full Base64 for QR**: 2,108 bytes
- **QR Code Requirements**: Version 40 (177x177 modules) - 2,953 numeric/1,852 binary bytes capacity

## Implementation Tasks

### Phase 1: Protocol Extension for OV Delivery

#### 1.1 New DI Message Type
- [ ] Define new message type: `DI.OVDelivery` (message type 14)
- [ ] Design message structure for optional voucher delivery
- [ ] Update protocol constants and message type mappings
- [ ] Implement client-side message handler

#### 1.2 Server-Side Implementation
- [ ] Add server-side configuration option: `enable_ov_delivery`
- [ ] Implement `ovDelivery` handler in DIServer
- [ ] Add voucher serialization for client delivery
- [ ] Integrate with existing voucher signing pipeline
- [ ] Add security checks and authorization

#### 1.3 Client-Side Implementation
- [ ] Add client-side flag: `-request-voucher` or `-receive-ov`
- [ ] Implement client-side OV receiver
- [ ] Add voucher validation and storage on client
- [ ] Update client DI flow to request OV after completion

### Phase 2: QR Code Display Support

#### 2.1 QR Code Generation
- [ ] Add QR code library dependency (e.g., `github.com/skip2/go-qrcode`)
- [ ] Implement QR code generation from voucher PEM data
- [ ] Add QR code version detection (auto-select minimum version)
- [ ] Support different error correction levels

#### 2.2 Display Options
- [ ] **Screen QR**: High-resolution QR code display
- [ ] **Terminal QR**: ASCII/Unicode QR code for terminal output
- [ ] **File Output**: Save QR code as PNG/SVG files
- [ ] **Text Format**: Raw voucher PEM for copy-paste

#### 2.3 Client Integration
- [ ] Add QR code display options to client CLI
- [ ] Implement `-display-qr` flag with format options
- [ ] Add QR code size validation and warnings
- [ ] Support multiple output formats simultaneously

### Phase 3: Device-Signed Voucher Support

#### 3.1 Protocol Extension
- [ ] Define device-signed voucher message flow
- [ ] Design voucher signing request/response structure
- [ ] Add device signing capability to client
- [ ] Implement server-side validation of device signatures

#### 3.2 Security Implementation
- [ ] Add device private key access for voucher signing
- [ ] Implement signature verification on server
- [ ] Add device-signed voucher storage options
- [ ] Create audit trail for device-signed vouchers

#### 3.3 Configuration Options
- [ ] Add `enable_device_signing` server option
- [ ] Add `-sign-voucher` client option
- [ ] Configure signing algorithm preferences
- [ ] Add certificate chain validation

### Phase 4: Configuration and Documentation

#### 4.1 Configuration Updates
- [ ] Update YAML configuration schema
- [ ] Add new configuration sections:
  ```yaml
  voucher_management:
    ov_delivery:
      enabled: false
      require_client_request: true
      max_voucher_size: 4096
    device_signing:
      enabled: false
      require_device_cert: true
      signing_algorithm: "ecdsa-p384"
  ```

#### 4.2 Client Configuration
- [ ] Add client configuration file support
- [ ] Implement environment variable overrides
- [ ] Add per-device configuration options
- [ ] Create configuration validation

#### 4.3 Documentation
- [ ] Update README.md with new features
- [ ] Create user guide for QR code display
- [ ] Document security considerations
- [ ] Add troubleshooting guide

### Phase 5: Testing and Validation

#### 5.1 Unit Tests
- [ ] Test new DI message types
- [ ] Test voucher serialization/deserialization
- [ ] Test QR code generation and validation
- [ ] Test device signing functionality

#### 5.2 Integration Tests
- [ ] End-to-end OV delivery test
- [ ] QR code display test scenarios
- [ ] Device-signed voucher flow test
- [ ] Performance impact testing

#### 5.3 Security Testing
- [ ] Test voucher tampering detection
- [ ] Test unauthorized OV delivery attempts
- [ ] Test device signature validation
- [ ] Test replay attack prevention

## Technical Considerations

### QR Code Display Limitations
- **Version 40 Size**: 177x177 modules - requires high-resolution displays
- **Terminal Limitations**: Character resolution may limit readability
- **Print Requirements**: Minimum 300 DPI for reliable scanning
- **Error Correction**: Recommend Medium (Level M) for balance

### Security Implications
- **Voucher Exposure**: OV contains sensitive device identity information
- **Device Signing**: Requires secure private key access on device
- **Network Security**: OV delivery should use encrypted channels
- **Access Control**: Server should validate device authorization

### Performance Impact
- **Message Size**: Additional ~2KB data transfer per device
- **QR Generation**: CPU overhead for QR code creation
- **Storage**: Client-side voucher storage requirements
- **Network**: Potential impact on DI completion time

## Implementation Priority

### High Priority (Phase 1)
1. Basic OV delivery protocol extension
2. Server-side configuration and implementation
3. Client-side request capability

### Medium Priority (Phase 2)
1. QR code generation and display
2. Multiple output format support
3. Size validation and warnings

### Low Priority (Phase 3-4)
1. Device-signed voucher support
2. Advanced configuration options
3. Comprehensive documentation

## Dependencies

### External Libraries
- `github.com/skip2/go-qrcode` - QR code generation
- Potential crypto library updates for device signing

### Protocol Changes
- FDO specification amendment for new message types
- Backward compatibility considerations

### Testing Infrastructure
- QR code validation tools
- Device signing test harness
- Performance benchmarking tools

## Success Criteria

- [ ] Device can optionally receive complete OV during DI
- [ ] OV can be displayed as scannable QR code
- [ ] Device can sign vouchers when enabled
- [ ] All features are configurable and secure
- [ ] Backward compatibility is maintained
- [ ] Comprehensive test coverage exists
- [ ] Documentation is complete and accurate

## Risks and Mitigations

### Technical Risks
- **QR Code Size**: Version 40 may be too large for some displays
  - *Mitigation*: Provide multiple output formats and size warnings
- **Protocol Changes**: May break existing implementations
  - *Mitigation*: Make all features optional and backward compatible

### Security Risks
- **Voucher Exposure**: Sensitive data sent to device
  - *Mitigation*: Require explicit client request and server authorization
- **Device Signing**: Private key access on device
  - *Mitigation*: Implement secure key storage and access controls

### Usability Risks
- **QR Code Readability**: Large QR codes may be difficult to scan
  - *Mitigation*: Provide alternative delivery methods and clear instructions
