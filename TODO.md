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

### 8. ✅ COMPLETED: Delegate Certificate Management CLI

**Status:** ✅ COMPLETED - Full delegate cert lifecycle via CLI

**Implementation:**
- ✅ `--create-delegate <name>` — Parent issues delegate cert signed by owner key, stores in sqlite, outputs PEM
- ✅ `--sign-delegate-csr <csr.pem>` — Parent signs external CSR, outputs signed cert chain
- ✅ `--generate-delegate-csr <name>` — Child generates key + CSR for parent signing
- ✅ `--import-delegate-chain <name>` — Import signed chain for existing delegate key
- ✅ `--list-delegates` — List all delegate keys with permissions, expiry, fingerprint
- ✅ Shared flags: `--delegate-permissions`, `--delegate-key-type`, `--delegate-validity`, `--delegate-subject`, `--delegate-output`, `--delegate-chain`
- ✅ Unit tests (11 tests): positive + negative (wrong owner key, missing permission)
- ✅ Uses library's `fdo.VerifyDelegateChain`, `fdo.OIDPermitVoucherClaim`, `sqlite.AddDelegateKey`

**Files:**
- ✅ `delegate_command.go` — All delegate CLI commands
- ✅ `delegate_command_test.go` — Unit tests
- ✅ `main.go` — Flag registration + dispatch wiring

### 9. ✅ COMPLETED: PullAuth + DID Integration

**Status:** ✅ COMPLETED - Pull voucher service + DID document serving

**Implementation:**
- ✅ DID document serving (did:web) from owner key
- ✅ PullAuth server (challenge-response) with delegate chain validation
- ✅ Pull CLI client (`--pull-url`) for cron-based voucher pulling
- ✅ Config: `DIDConfig`, `PullServiceConfig` structs with defaults

**Files:**
- ✅ `did_setup.go`, `pull_service_setup.go`, `pull_voucher_store.go`, `pull_command.go`
- ✅ `config.go` — DID + PullService config additions

### 10. ✅ COMPLETED: BMO FSIM Delivery Modes (URL + Meta-URL)

**Status:** ✅ COMPLETED - URL and meta-URL delivery modes for fdo.bmo

**Implementation:**
- ✅ Config format extended: `bmo_files` entries support `type:file` (inline), `type:url:URL` (URL mode), `meta:URL` (meta-URL mode)
- ✅ New config fields: `bmo_tls_ca`, `bmo_expected_hash`, `bmo_meta_signer` for URL/meta options
- ✅ `parseBMOSpec()` helper parses all three formats
- ✅ `ownerModules()` dispatches to `AddImageURL()` / `AddImageMetaURL()` for non-inline entries
- ✅ `validateFiles()` skips `os.Stat` for URL/meta entries
- ✅ Config plumbing through `device_config.go`, `device_storage.go` (reflection + merge)
- ✅ Unit tests: 29 tests (parseBMOSpec, loaders, hash pipeline, COSE Sign1 verification)
- ✅ Integration tests: `bmo-url`, `bmo-delivery-nak`, `bmo-url-hash-positive`, `bmo-url-hash-negative`, `bmo-meta-sign-positive`, `bmo-meta-sign-negative`
- ✅ Positive tests: correct hash accepted, valid COSE Sign1 signature accepted
- ✅ Negative tests: wrong hash rejected, wrong signing key rejected, tampered signature rejected, garbage/empty keys rejected

**Files:**
- ✅ `bmo_delivery.go` — Spec parser + config loaders (NEW)
- ✅ `bmo_delivery_test.go` — Unit tests with positive + negative verification (NEW)
- ✅ `tests/bmo_test_helper/main.go` — COSE key + signed meta-payload generator for testing (NEW)
- ✅ `device_config.go`, `config.go`, `device_storage.go` — Config field additions
- ✅ `main.go` — ownerModules() + validateFiles() updates
- ✅ `tests/test_examples.sh` — Integration tests (6 BMO delivery/verification tests)

**Scope:** BMO only — `fdo.payload` does not define delivery modes per spec.

## Medium Priority

### 3. Add Error Handling and Logging

**Enhancements Needed:**
- Add structured logging for voucher operations
- Better error messages for external command failures
- Timeout handling improvements
- Retry logic for external service calls
- Make sure all tests are executed in "run_all_tests.sh"
- Positive and negative tests (voucher rejected because bad token, bad owner, etc)

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
