# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# TODO: Voucher Management Enhancements

## High Priority

### 1. ✅ COMPLETED: Implement Serial Number Session State Storage

**Status:** ✅ COMPLETED - Real device serial numbers now work!

**Implementation:**
- ✅ Added `DeviceSelfInfo(context.Context) (*custom.DeviceMfgInfo, error)` to SQLite DB
- ✅ Used existing `SetDeviceSelfInfo(context.Context, *custom.DeviceMfgInfo) error` in SQLite DB  
- ✅ Store device info in session table (not persistent vouchers table)
- ✅ Updated DeviceInfo callback to store serial number
- ✅ Updated voucher callback to retrieve real serial number

**Files Modified:**
- ✅ `go-fdo/sqlite/sqlite.go` - Added DeviceSelfInfo method
- ✅ `main.go` - Enabled device info storage in DeviceInfo callback
- ✅ `voucher_callback.go` - Real serial number retrieval with GUID fallback

### 2. ✅ COMPLETED: Implement Certificate Parsing for Owner Keys

**Status:** ✅ COMPLETED - Certificate parsing now works!

**Implementation:**
- ✅ Completed `parseCertificatePublicKey()` function in `owner_key_service.go`
- ✅ Use `x509.ParseCertificate()` to extract public key from certificates
- Ready to test with certificate chains from external services

**Files Modified:**
- ✅ `owner_key_service.go` - Complete certificate parsing implementation

## Medium Priority

### 3. Add Error Handling and Logging

**Enhancements Needed:**
- Add structured logging for voucher operations
- Better error messages for external command failures
- Timeout handling improvements
- Retry logic for external service calls

### 4. Add Configuration Validation

**Validations Needed:**
- Validate external command templates have required variables
- Check timeout values are reasonable
- Verify file paths exist for signing keys
- Validate PEM key formats

### 5. Add Unit Tests

**Test Coverage Needed:**
- External command executor tests
- Owner key service tests (mock external commands)
- Voucher upload service tests
- Configuration loading tests
- Integration tests with mock SQLite storage

## Low Priority

### 6. Performance Optimizations

**Potential Improvements:**
- Cache external command results
- Pool temporary files for voucher uploads
- Optimize voucher serialization
- Batch multiple voucher operations

### 7. Security Enhancements

**Security Considerations:**
- Validate external command paths to prevent injection
- Sanitize variable substitutions
- Add timeouts for all external operations
- Consider signing voucher uploads

## Notes

- Current implementation works for basic scenarios with GUID fallback
- External handlers can be tested with mock scripts
- Configuration system is ready for production use
- Privacy design (serial numbers not in vouchers) is implemented correctly
