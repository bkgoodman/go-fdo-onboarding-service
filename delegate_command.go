// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

// Delegate command flags (registered in main.go init())
var (
	createDelegate      *string
	signDelegateCSR     *string
	generateDelegateCSR *string
	importDelegateChain *string
	listDelegates       *bool

	// Shared delegate flags
	delegatePermissions *string
	delegateSubject     *string
	delegateKeyType     *string
	delegateValidity    *int
	delegateOutput      *string
	delegateChainFile   *string
)

// isDelegateCommand returns true if any delegate CLI flag was set.
func isDelegateCommand() bool {
	return (*createDelegate != "" ||
		*signDelegateCSR != "" ||
		*generateDelegateCSR != "" ||
		*importDelegateChain != "" ||
		*listDelegates)
}

// runDelegateCommand dispatches the delegate subcommand.
func runDelegateCommand() error {
	state, err := sqlite.Open(config.Database.Path, config.Database.Password)
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	defer func() {
		if err := state.Close(); err != nil {
			slog.Error("Error closing database", "error", err)
		}
	}()

	ctx := context.Background()

	switch {
	case *createDelegate != "":
		return doCreateDelegate(ctx, state, *createDelegate)
	case *signDelegateCSR != "":
		return doSignDelegateCSR(ctx, state, *signDelegateCSR)
	case *generateDelegateCSR != "":
		return doGenerateDelegateCSR(state, *generateDelegateCSR)
	case *importDelegateChain != "":
		return doImportDelegateChainCmd(state, *importDelegateChain)
	case *listDelegates:
		return doListDelegates(state)
	default:
		return fmt.Errorf("no delegate command specified")
	}
}

// parsePermissions converts a comma-separated permission string to OIDs.
func parsePermissions(perms string) ([]asn1.ObjectIdentifier, error) {
	if perms == "" {
		return []asn1.ObjectIdentifier{fdo.OIDPermitVoucherClaim}, nil
	}
	var oids []asn1.ObjectIdentifier
	for _, p := range strings.Split(perms, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		oid, err := fdo.DelegateStringToOID(p)
		if err != nil {
			return nil, fmt.Errorf("unknown permission %q: %w", p, err)
		}
		oids = append(oids, oid)
	}
	if len(oids) == 0 {
		return []asn1.ObjectIdentifier{fdo.OIDPermitVoucherClaim}, nil
	}
	return oids, nil
}

// loadOwnerSigner loads the owner private key from the database based on the
// configured DID key type (or default ec384).
func loadOwnerSigner(ctx context.Context, state *sqlite.DB) (crypto.Signer, error) {
	keyTypeStr := config.DID.KeyType
	if keyTypeStr == "" {
		keyTypeStr = "ec384"
	}

	var keyType protocol.KeyType
	var rsaBits int
	switch keyTypeStr {
	case "ec256":
		keyType = protocol.Secp256r1KeyType
	case "ec384":
		keyType = protocol.Secp384r1KeyType
	case "rsa2048":
		keyType = protocol.Rsa2048RestrKeyType
		rsaBits = 2048
	case "rsa3072":
		keyType = protocol.RsaPkcsKeyType
		rsaBits = 3072
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyTypeStr)
	}

	signer, _, err := state.OwnerKey(ctx, keyType, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("failed to load owner key (type=%s): %w", keyTypeStr, err)
	}
	return signer, nil
}

// generateDelegateKeyPair creates a new key pair for the delegate.
func generateDelegateKeyPair(keyTypeStr string) (crypto.Signer, error) {
	switch keyTypeStr {
	case "ec256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	default:
		return nil, fmt.Errorf("unsupported delegate key type %q", keyTypeStr)
	}
}

// writePEMFile writes PEM-encoded data to a file, creating parent dirs as needed.
func writePEMFile(path string, block *pem.Block) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// encodePEMPrivateKey encodes a private key as a PEM block.
func encodePEMPrivateKey(key crypto.Signer) (*pem.Block, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return &pem.Block{Type: "PRIVATE KEY", Bytes: der}, nil
}

// encodePEMCertChain encodes a certificate chain as concatenated PEM blocks.
func encodePEMCertChain(chain []*x509.Certificate) []byte {
	var buf []byte
	for _, cert := range chain {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	return buf
}

// createDelegateCert creates a delegate certificate signed by the owner key.
// Unlike fdo.GenerateDelegate (which is for testing), this creates proper
// certificates with configurable validity, serial numbers, and permissions.
func createDelegateCert(ownerKey crypto.Signer, delegatePub crypto.PublicKey,
	subject string, permissions []asn1.ObjectIdentifier, validityDays int, isCA bool) (*x509.Certificate, error) {

	ownerCN := "FDO Owner"
	if ecKey, ok := ownerKey.Public().(*ecdsa.PublicKey); ok {
		switch ecKey.Curve {
		case elliptic.P256():
			ownerCN = "FDO Owner (EC256)"
		case elliptic.P384():
			ownerCN = "FDO Owner (EC384)"
		}
	} else if rsaKey, ok := ownerKey.Public().(*rsa.PublicKey); ok {
		ownerCN = fmt.Sprintf("FDO Owner (RSA%d)", rsaKey.Size()*8)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	validity := time.Duration(validityDays) * 24 * time.Hour

	// Self-signed parent cert for the owner key (serves as issuer)
	parentTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: ownerCN},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(validity + 24*time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    permissions,
	}

	delegateKeyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		delegateKeyUsage |= x509.KeyUsageCertSign
	}

	delegateTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              delegateKeyUsage,
		UnknownExtKeyUsage:    permissions,
	}

	// Sign the delegate cert with the owner key, using parent as issuer
	der, err := x509.CreateCertificate(rand.Reader, delegateTemplate, parentTemplate, delegatePub, ownerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create delegate certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return cert, nil
}

// doCreateDelegate handles --create-delegate: generate key + cert, store, output.
func doCreateDelegate(ctx context.Context, state *sqlite.DB, name string) error {
	// Parse options
	perms, err := parsePermissions(*delegatePermissions)
	if err != nil {
		return err
	}
	keyType := *delegateKeyType
	if keyType == "" {
		keyType = "ec384"
	}
	validity := *delegateValidity
	if validity <= 0 {
		validity = 365
	}
	subject := *delegateSubject
	if subject == "" {
		subject = name
	}

	// Load owner signing key
	ownerKey, err := loadOwnerSigner(ctx, state)
	if err != nil {
		return fmt.Errorf("failed to load owner key: %w", err)
	}

	// Generate delegate key pair
	delegateKey, err := generateDelegateKeyPair(keyType)
	if err != nil {
		return fmt.Errorf("failed to generate delegate key: %w", err)
	}

	// Create delegate certificate
	cert, err := createDelegateCert(ownerKey, delegateKey.Public(), subject, perms, validity, false)
	if err != nil {
		return err
	}
	chain := []*x509.Certificate{cert}

	// Verify the chain against owner key
	ownerPub := ownerKey.Public()
	if err := fdo.VerifyDelegateChain(chain, &ownerPub, &perms[0]); err != nil {
		return fmt.Errorf("self-verification of delegate chain failed: %w", err)
	}

	// Store in sqlite
	if err := state.AddDelegateKey(name, delegateKey, chain); err != nil {
		return fmt.Errorf("failed to store delegate key: %w", err)
	}

	// Output
	keyBlock, err := encodePEMPrivateKey(delegateKey)
	if err != nil {
		return err
	}
	chainPEM := encodePEMCertChain(chain)

	if *delegateOutput != "" {
		keyPath := filepath.Join(*delegateOutput, name+"-key.pem")
		chainPath := filepath.Join(*delegateOutput, name+"-chain.pem")

		if err := writePEMFile(keyPath, keyBlock); err != nil {
			return fmt.Errorf("failed to write delegate key: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(chainPath), 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
		if err := os.WriteFile(chainPath, chainPEM, 0644); err != nil {
			return fmt.Errorf("failed to write delegate chain: %w", err)
		}

		fmt.Printf("Delegate %q created and stored in database\n", name)
		fmt.Printf("  Key:   %s\n", keyPath)
		fmt.Printf("  Chain: %s\n", chainPath)
	} else {
		fmt.Fprintf(os.Stderr, "# Delegate %q created and stored in database\n", name)
		fmt.Fprintf(os.Stderr, "# Key type: %s  Validity: %d days  Permissions: %s\n",
			keyType, validity, *delegatePermissions)
		fmt.Fprintf(os.Stderr, "# --- Private Key ---\n")
		if err := pem.Encode(os.Stdout, keyBlock); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "# --- Certificate Chain ---\n")
		if _, err := os.Stdout.Write(chainPEM); err != nil {
			return err
		}
	}

	// Print permission summary
	var permNames []string
	for _, oid := range perms {
		permNames = append(permNames, fdo.DelegateOIDtoString(oid))
	}
	fmt.Fprintf(os.Stderr, "# Permissions: %s\n", strings.Join(permNames, ", "))
	fmt.Fprintf(os.Stderr, "# Fingerprint: %s\n", fdo.KeyToString(delegateKey.Public()))

	return nil
}

// doSignDelegateCSR handles --sign-delegate-csr: sign an external CSR with our owner key.
func doSignDelegateCSR(ctx context.Context, state *sqlite.DB, csrPath string) error {
	perms, err := parsePermissions(*delegatePermissions)
	if err != nil {
		return err
	}
	validity := *delegateValidity
	if validity <= 0 {
		validity = 365
	}

	// Read and parse CSR
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return fmt.Errorf("failed to read CSR file: %w", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("file %q does not contain a PEM-encoded CERTIFICATE REQUEST", csrPath)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature verification failed: %w", err)
	}

	// Load owner signing key
	ownerKey, err := loadOwnerSigner(ctx, state)
	if err != nil {
		return fmt.Errorf("failed to load owner key: %w", err)
	}

	// Use CSR's subject, falling back to a default
	subject := csr.Subject.CommonName
	if subject == "" {
		subject = "FDO Delegate"
	}

	// Create delegate certificate using CSR's public key
	cert, err := createDelegateCert(ownerKey, csr.PublicKey, subject, perms, validity, false)
	if err != nil {
		return err
	}

	// Output: signed certificate chain to stdout
	chainPEM := encodePEMCertChain([]*x509.Certificate{cert})
	if _, err := os.Stdout.Write(chainPEM); err != nil {
		return fmt.Errorf("failed to write chain: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Signed delegate certificate for %q\n", subject)
	fmt.Fprintf(os.Stderr, "  Validity: %d days\n", validity)
	var permNames []string
	for _, oid := range perms {
		permNames = append(permNames, fdo.DelegateOIDtoString(oid))
	}
	fmt.Fprintf(os.Stderr, "  Permissions: %s\n", strings.Join(permNames, ", "))
	fmt.Fprintf(os.Stderr, "  Fingerprint: %s\n", fdo.KeyToString(csr.PublicKey))

	return nil
}

// doGenerateDelegateCSR handles --generate-delegate-csr: create key + CSR for a parent to sign.
func doGenerateDelegateCSR(state *sqlite.DB, name string) error {
	keyType := *delegateKeyType
	if keyType == "" {
		keyType = "ec384"
	}
	subject := *delegateSubject
	if subject == "" {
		subject = name
	}

	// Generate delegate key pair
	delegateKey, err := generateDelegateKeyPair(keyType)
	if err != nil {
		return fmt.Errorf("failed to generate delegate key: %w", err)
	}

	// Create CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: subject},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, delegateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Store key in sqlite (no chain yet — pending parent signature)
	if err := state.AddDelegateKey(name, delegateKey, nil); err != nil {
		return fmt.Errorf("failed to store delegate key: %w", err)
	}

	// Output
	keyBlock, err := encodePEMPrivateKey(delegateKey)
	if err != nil {
		return err
	}
	csrBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}

	if *delegateOutput != "" {
		keyPath := filepath.Join(*delegateOutput, name+"-key.pem")
		csrPath := filepath.Join(*delegateOutput, name+".csr.pem")

		if err := writePEMFile(keyPath, keyBlock); err != nil {
			return fmt.Errorf("failed to write delegate key: %w", err)
		}
		if err := writePEMFile(csrPath, csrBlock); err != nil {
			return fmt.Errorf("failed to write CSR: %w", err)
		}

		fmt.Printf("Delegate CSR %q generated and key stored in database\n", name)
		fmt.Printf("  Key: %s\n", keyPath)
		fmt.Printf("  CSR: %s\n", csrPath)
		fmt.Printf("  Send the CSR to the parent to sign, then import chain with:\n")
		fmt.Printf("    fdo-server --import-delegate-chain %s --delegate-chain <chain.pem>\n", name)
	} else {
		fmt.Fprintf(os.Stderr, "# Delegate CSR %q generated and key stored in database\n", name)
		fmt.Fprintf(os.Stderr, "# Key type: %s  Subject: %s\n", keyType, subject)
		fmt.Fprintf(os.Stderr, "# --- Private Key ---\n")
		if err := pem.Encode(os.Stdout, keyBlock); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "# --- Certificate Signing Request ---\n")
		if err := pem.Encode(os.Stdout, csrBlock); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "# Import signed chain with: fdo-server --import-delegate-chain %s --delegate-chain <chain.pem>\n", name)
	}

	fmt.Fprintf(os.Stderr, "# Fingerprint: %s\n", fdo.KeyToString(delegateKey.Public()))

	return nil
}

// doImportDelegateChainCmd handles --import-delegate-chain: import a signed cert chain for an existing key.
func doImportDelegateChainCmd(state *sqlite.DB, name string) error {
	chainPath := *delegateChainFile
	if chainPath == "" {
		return fmt.Errorf("--delegate-chain is required with --import-delegate-chain")
	}

	// Load existing delegate key from sqlite
	existingKey, existingChain, err := state.DelegateKey(name)
	if err != nil {
		return fmt.Errorf("delegate key %q not found in database: %w", name, err)
	}
	if len(existingChain) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: delegate %q already has a chain (%d certs), replacing\n", name, len(existingChain))
	}

	// Read and parse chain PEM
	chainPEM, err := os.ReadFile(chainPath)
	if err != nil {
		return fmt.Errorf("failed to read chain file: %w", err)
	}
	var chain []*x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return fmt.Errorf("no certificates found in %q", chainPath)
	}

	// Verify leaf cert public key matches our stored key
	leafPub := chain[0].PublicKey
	storedPub := existingKey.Public()
	leafDER, err := x509.MarshalPKIXPublicKey(leafPub)
	if err != nil {
		return fmt.Errorf("failed to marshal leaf public key: %w", err)
	}
	storedDER, err := x509.MarshalPKIXPublicKey(storedPub)
	if err != nil {
		return fmt.Errorf("failed to marshal stored public key: %w", err)
	}
	if string(leafDER) != string(storedDER) {
		return fmt.Errorf("leaf certificate public key does not match stored delegate key %q", name)
	}

	// Store updated key+chain (re-store to update the chain)
	if err := state.AddDelegateKey(name, existingKey, chain); err != nil {
		return fmt.Errorf("failed to update delegate chain: %w", err)
	}

	fmt.Printf("Delegate %q chain imported (%d certificate(s))\n", name, len(chain))
	for i, cert := range chain {
		fmt.Printf("  [%d] Subject: %s  Issuer: %s  NotAfter: %s\n",
			i, cert.Subject.CommonName, cert.Issuer.CommonName,
			cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

// doListDelegates handles --list-delegates: list all delegate keys in the database.
func doListDelegates(state *sqlite.DB) error {
	names, err := state.ListDelegateKeys()
	if err != nil {
		return fmt.Errorf("failed to list delegate keys: %w", err)
	}

	if len(names) == 0 {
		fmt.Println("No delegate keys found")
		return nil
	}

	fmt.Printf("%-20s %-12s %-40s %-20s %s\n", "NAME", "HAS CHAIN", "FINGERPRINT", "EXPIRES", "PERMISSIONS")
	fmt.Println(strings.Repeat("-", 120))

	for _, name := range names {
		signer, chain, err := state.DelegateKey(name)
		if err != nil {
			fmt.Printf("%-20s %-12s (error: %v)\n", name, "error", err)
			continue
		}

		hasChain := "no"
		expires := "-"
		permsStr := "-"

		if len(chain) > 0 {
			hasChain = fmt.Sprintf("yes (%d)", len(chain))
			expires = chain[0].NotAfter.Format("2006-01-02")

			var permNames []string
			for _, oid := range chain[0].UnknownExtKeyUsage {
				permNames = append(permNames, fdo.DelegateOIDtoString(oid))
			}
			if len(permNames) > 0 {
				permsStr = strings.Join(permNames, ",")
			}
		}

		fingerprint := fdo.KeyToString(signer.Public())
		// Truncate fingerprint for display
		if len(fingerprint) > 40 {
			fingerprint = fingerprint[:37] + "..."
		}

		fmt.Printf("%-20s %-12s %-40s %-20s %s\n", name, hasChain, fingerprint, expires, permsStr)
	}

	fmt.Printf("\n%d delegate key(s)\n", len(names))
	return nil
}
