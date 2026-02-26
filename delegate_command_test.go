// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	fdo "github.com/fido-device-onboard/go-fdo"
)

func TestParsePermissions(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantOID asn1.ObjectIdentifier
		wantErr bool
	}{
		{"empty defaults to voucher-claim", "", 1, fdo.OIDPermitVoucherClaim, false},
		{"voucher-claim", "voucher-claim", 1, fdo.OIDPermitVoucherClaim, false},
		{"permit-voucher-claim", "permit-voucher-claim", 1, fdo.OIDPermitVoucherClaim, false},
		{"redirect", "redirect", 1, fdo.OIDPermitRedirect, false},
		{"multiple", "voucher-claim,redirect", 2, fdo.OIDPermitVoucherClaim, false},
		{"with spaces", " voucher-claim , redirect ", 2, fdo.OIDPermitVoucherClaim, false},
		{"unknown", "bogus-perm", 0, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oids, err := parsePermissions(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(oids) != tt.wantLen {
				t.Fatalf("expected %d OIDs, got %d", tt.wantLen, len(oids))
			}
			if tt.wantOID != nil && !oids[0].Equal(tt.wantOID) {
				t.Fatalf("expected first OID %v, got %v", tt.wantOID, oids[0])
			}
		})
	}
}

func TestGenerateDelegateKeyPair(t *testing.T) {
	tests := []struct {
		keyType string
		wantErr bool
	}{
		{"ec256", false},
		{"ec384", false},
		{"rsa2048", false},
		{"rsa3072", false},
		{"unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			key, err := generateDelegateKeyPair(tt.keyType)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for key type %q", tt.keyType)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == nil {
				t.Fatal("expected non-nil key")
			}
		})
	}
}

func TestCreateDelegateCert(t *testing.T) {
	// Generate owner key (EC P-384)
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	perms := []asn1.ObjectIdentifier{fdo.OIDPermitVoucherClaim}

	cert, err := createDelegateCert(ownerKey, delegateKey.Public(), "test-delegate", perms, 365, false)
	if err != nil {
		t.Fatalf("createDelegateCert failed: %v", err)
	}

	// Verify subject
	if cert.Subject.CommonName != "test-delegate" {
		t.Errorf("expected subject CN 'test-delegate', got %q", cert.Subject.CommonName)
	}

	// Verify it's NOT a CA
	if cert.IsCA {
		t.Error("expected leaf cert to not be CA")
	}

	// Verify digital signature key usage
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		t.Error("expected DigitalSignature key usage")
	}

	// Verify permission OID is present
	if !fdo.CertHasPermissionOID(cert, fdo.OIDPermitVoucherClaim) {
		t.Error("expected permit-voucher-claim OID in certificate")
	}

	// Verify chain validates against owner key
	ownerPub := crypto.PublicKey(ownerKey.Public())
	oid := fdo.OIDPermitVoucherClaim
	if err := fdo.VerifyDelegateChain([]*x509.Certificate{cert}, &ownerPub, &oid); err != nil {
		t.Fatalf("VerifyDelegateChain failed: %v", err)
	}
}

func TestCreateDelegateCertCA(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	perms := []asn1.ObjectIdentifier{fdo.OIDPermitVoucherClaim}

	cert, err := createDelegateCert(ownerKey, delegateKey.Public(), "intermediate-delegate", perms, 365, true)
	if err != nil {
		t.Fatalf("createDelegateCert (CA) failed: %v", err)
	}

	if !cert.IsCA {
		t.Error("expected intermediate cert to be CA")
	}
	if (cert.KeyUsage & x509.KeyUsageCertSign) == 0 {
		t.Error("expected CertSign key usage for CA cert")
	}
}

func TestCreateDelegateCertRSA(t *testing.T) {
	ownerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	perms := []asn1.ObjectIdentifier{fdo.OIDPermitVoucherClaim}

	cert, err := createDelegateCert(ownerKey, delegateKey.Public(), "rsa-delegate", perms, 30, false)
	if err != nil {
		t.Fatalf("createDelegateCert (RSA owner) failed: %v", err)
	}

	ownerPub := crypto.PublicKey(ownerKey.Public())
	oid := fdo.OIDPermitVoucherClaim
	if err := fdo.VerifyDelegateChain([]*x509.Certificate{cert}, &ownerPub, &oid); err != nil {
		t.Fatalf("VerifyDelegateChain (RSA) failed: %v", err)
	}
}

func TestCreateDelegateCertMultiplePermissions(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	perms := []asn1.ObjectIdentifier{
		fdo.OIDPermitVoucherClaim,
		fdo.OIDPermitRedirect,
	}

	cert, err := createDelegateCert(ownerKey, delegateKey.Public(), "multi-perm", perms, 365, false)
	if err != nil {
		t.Fatalf("createDelegateCert failed: %v", err)
	}

	if !fdo.CertHasPermissionOID(cert, fdo.OIDPermitVoucherClaim) {
		t.Error("expected permit-voucher-claim OID")
	}
	if !fdo.CertHasPermissionOID(cert, fdo.OIDPermitRedirect) {
		t.Error("expected permit-redirect OID")
	}
}

// TestCreateDelegateCertWrongOwnerKey is a negative test: verifying a delegate
// chain against a DIFFERENT owner key should fail.
func TestCreateDelegateCertWrongOwnerKey(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	perms := []asn1.ObjectIdentifier{fdo.OIDPermitVoucherClaim}

	cert, err := createDelegateCert(ownerKey, delegateKey.Public(), "test", perms, 365, false)
	if err != nil {
		t.Fatalf("createDelegateCert failed: %v", err)
	}

	// Verify against WRONG owner key — should fail
	wrongPub := crypto.PublicKey(wrongKey.Public())
	oid := fdo.OIDPermitVoucherClaim
	if err := fdo.VerifyDelegateChain([]*x509.Certificate{cert}, &wrongPub, &oid); err == nil {
		t.Fatal("expected VerifyDelegateChain to fail with wrong owner key, but it succeeded")
	}
}

// TestCreateDelegateCertMissingPermission is a negative test: verifying for a
// permission OID that is NOT in the certificate should fail.
func TestCreateDelegateCertMissingPermission(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Only grant voucher-claim
	perms := []asn1.ObjectIdentifier{fdo.OIDPermitVoucherClaim}

	cert, err := createDelegateCert(ownerKey, delegateKey.Public(), "test", perms, 365, false)
	if err != nil {
		t.Fatalf("createDelegateCert failed: %v", err)
	}

	// Verify for redirect permission — should fail
	ownerPub := crypto.PublicKey(ownerKey.Public())
	redirectOID := fdo.OIDPermitRedirect
	if err := fdo.VerifyDelegateChain([]*x509.Certificate{cert}, &ownerPub, &redirectOID); err == nil {
		t.Fatal("expected VerifyDelegateChain to fail for missing permission, but it succeeded")
	}
}

func TestEncodePEMPrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	block, err := encodePEMPrivateKey(key)
	if err != nil {
		t.Fatalf("encodePEMPrivateKey failed: %v", err)
	}

	if block.Type != "PRIVATE KEY" {
		t.Errorf("expected PEM type 'PRIVATE KEY', got %q", block.Type)
	}

	// Should be parseable
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse back: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestEncodePEMCertChain(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	perms := []asn1.ObjectIdentifier{fdo.OIDPermitVoucherClaim}
	cert, err := createDelegateCert(ownerKey, delegateKey.Public(), "test", perms, 365, false)
	if err != nil {
		t.Fatalf("createDelegateCert failed: %v", err)
	}

	pemData := encodePEMCertChain([]*x509.Certificate{cert})

	// Should be decodable
	block, rest := pem.Decode(pemData)
	if block == nil {
		t.Fatal("expected PEM block, got nil")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("expected PEM type 'CERTIFICATE', got %q", block.Type)
	}
	// Only one cert, so rest should decode to nil
	block2, _ := pem.Decode(rest)
	if block2 != nil {
		t.Error("expected only one PEM block for single cert chain")
	}
}

func TestWritePEMFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.pem")

	block := &pem.Block{Type: "TEST", Bytes: []byte("hello")}
	if err := writePEMFile(path, block); err != nil {
		t.Fatalf("writePEMFile failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	decoded, _ := pem.Decode(data)
	if decoded == nil {
		t.Fatal("expected PEM block in written file")
	}
	if decoded.Type != "TEST" {
		t.Errorf("expected PEM type 'TEST', got %q", decoded.Type)
	}

	// Verify restrictive permissions (0600)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat file: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}
