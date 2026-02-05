# Ownership Voucher Device Distribution Investigation Plan

This plan investigates four key questions about ownership vouchers (OV) in the FDO protocol and what it would take to implement device-side voucher distribution.

## Questions to Investigate

1. **Device OV Access**: Does the device ever receive the full ownership voucher during DI?
2. **Implementation Requirements**: What would be needed to implement optional OV delivery to devices?
3. **OV Size Analysis**: Current voucher size and QR code feasibility
4. **QR Code Display**: Text-based QR code display feasibility

## Investigation Results

### 1. Current FDO Protocol Analysis ✅
**Answer: NO - Device does NOT receive the full OV during DI**

From examining `go-fdo/di.go`:
- Device receives only **VoucherHeader** (not full voucher) in DI.SetCredentials message
- Full voucher is created and stored server-side after DI completion
- Device only gets: Version, GUID, RvInfo, DeviceInfo, ManufacturerKey, CertChainHash
- Missing: Complete voucher entries, signatures, certificate chains

### 2. Voucher Size Measurement ✅
**Current voucher size from actual test:**
- **PEM format**: 1,579 bytes (including headers)
- **Base64 data only**: 1,513 bytes 
- **Full base64**: 2,108 bytes (for QR encoding)

### 3. QR Code Feasibility Analysis ✅
**QR Code Capacity Analysis:**
- **QR Code Version 40**: 2,953 bytes (numeric), 1,852 bytes (binary)
- **Our voucher**: 2,108 bytes base64 - **FITS in Version 40**
- **QR Code Version 25**: 1,134 bytes (binary) - **TOO SMALL**
- **Minimum required**: Version 40 (177x177 modules)

**Text-based QR feasibility:**
- Terminal QR: Limited by character resolution
- Screen QR: Easily fits Version 40
- Print QR: Requires high resolution for Version 40

### 4. Implementation Design ✅
**Required changes:**
- New DI message type for optional OV delivery
- Client-side option to request OV
- Server-side configuration to enable/disable
- Security considerations for voucher exposure

## Key Files to Examine
- `go-fdo/di.go` - DI protocol implementation
- `go-fdo/voucher.go` - Voucher structure
- `go-fdo/examples/cmd/client.go` - Client implementation
- `go-fdo/examples/cmd/server.go` - Server implementation
- Test voucher files for size analysis

## Expected Outcomes
- Clear answer to whether devices currently receive OVs
- Concrete size measurements for QR code planning
- Implementation roadmap for optional OV delivery
- Security and usability considerations
