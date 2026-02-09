// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"iter"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/custom"
	"github.com/fido-device-onboard/go-fdo/fsim"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

func init() {
	// Set up logging BEFORE any go-fdo code runs to prevent library from setting its own logger
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

// Global configuration
var config *Config

// Command line flags
var (
	configPath       = flag.String("config", "fdoserver.cfg", "Path to configuration file")
	initOnly         = flag.Bool("init-only", false, "Initialize database and keys only, then exit")
	debug            = flag.Bool("debug", false, "Enable debug logging")
	generateOwnerKey = flag.Bool("generate-owner-key", false, "Generate new owner keys and exit")
	printOwnerKey    = flag.Bool("print-owner-key", false, "Print owner public keys in PEM format and exit")
	importOwnerKey   = flag.String("import-owner-key", "", "Import owner private key from PEM file and exit")
)

func main() {
	flag.Parse()

	// Load configuration
	var err error
	config, err = LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Configure logging based on debug mode
	if *debug || config.Debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	}

	// Handle key management flags
	if *generateOwnerKey || *printOwnerKey || *importOwnerKey != "" {
		if err := handleKeyManagement(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Register event handler for DI and TO2 events
	fdo.RegisterEventHandler(fdo.EventHandlerFunc(func(ctx context.Context, event fdo.Event) {
		switch event.Type {
		case fdo.EventTypeDIStarted:
			fmt.Printf("🚀 DI Started: Device beginning initialization\n")

		case fdo.EventTypeDIAppStartReceived:
			fmt.Printf("📡 DI AppStart Received: Device connecting\n")

		case fdo.EventTypeDIVoucherCreated:
			if event.GUID != nil {
				fmt.Printf("📋 DI Voucher Created: Device %x\n", *event.GUID)
			}

		case fdo.EventTypeDICompleted:
			if event.GUID != nil {
				fmt.Printf("✅ DI Completed: Device %x successfully initialized\n", *event.GUID)

				// Access device info if available
				if data, ok := event.Data.(fdo.DIEventData); ok {
					fmt.Printf("   Device Info: %s\n", data.DeviceInfo)
				}
			}

		case fdo.EventTypeDIFailed:
			if event.GUID != nil {
				fmt.Printf("❌ DI Failed: Device %x - %v\n", *event.GUID, event.Error)
			} else {
				fmt.Printf("❌ DI Failed: %v\n", event.Error)
			}

		case fdo.EventTypeTO1BlobNotFound:
			if event.GUID != nil {
				fmt.Printf("❌ TO1 RV BLOB NOT FOUND: Device %x attempted rendezvous without RV blob\n", *event.GUID)
				fmt.Printf("   Error: %v\n", event.Error)
				fmt.Printf("   Device needs TO0 registration or direct TO2 onboarding\n")
			}

		case fdo.EventTypeTO2Started:
			if event.GUID != nil {
				fmt.Printf("🔐 TO2 Started: Device %x beginning onboarding\n", *event.GUID)
			}

		case fdo.EventTypeTO2VoucherNotFound:
			if event.GUID != nil {
				fmt.Printf("❌ TO2 VOUCHER NOT FOUND: Device %x attempted onboarding without valid voucher\n", *event.GUID)
				fmt.Printf("   Error: %v\n", event.Error)
				fmt.Printf("   Expected voucher file: %s/%x.fdoov\n", config.DeviceStorage.VoucherDir, *event.GUID)
			}

		case fdo.EventTypeTO2VoucherInvalid:
			if event.GUID != nil {
				fmt.Printf("❌ TO2 VOUCHER INVALID: Device %x has invalid voucher\n", *event.GUID)
				if data, ok := event.Data.(fdo.VoucherInvalidReason); ok {
					fmt.Printf("   Reason: %s\n", data.Reason)
				}
				fmt.Printf("   Error: %v\n", event.Error)
				if data, ok := event.Data.(fdo.VoucherInvalidReason); ok && data.Reason == "zero_entries" {
					fmt.Printf("   ⚠ Voucher has zero entries - needs to be extended by owner before onboarding\n")
				}
			}

		case fdo.EventTypeTO2Completed:
			if event.GUID != nil {
				fmt.Printf("✅ TO2 Completed: Device %x successfully onboarded\n", *event.GUID)
			}

		case fdo.EventTypeTO2Failed:
			if event.GUID != nil {
				fmt.Printf("❌ TO2 Failed: Device %x - %v\n", *event.GUID, event.Error)
			} else {
				fmt.Printf("❌ TO2 Failed: %v\n", event.Error)
			}
		}
	}))

	// Handle special operations that don't start the server
	if err := handleSpecialOperations(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Validate required config values
	if config.Database.Path == "" {
		fmt.Fprintf(os.Stderr, "Error: Database path must be specified in config file\n")
		os.Exit(1)
	}

	ctx := context.Background()
	if err := runServer(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// handleKeyManagement handles key management command-line flags
func handleKeyManagement() error {
	ctx := context.Background()

	// Open database
	state, err := sqlite.Open(config.Database.Path, config.Database.Password)
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	defer func() {
		if err := state.Close(); err != nil {
			slog.Error("Error closing database", "error", err)
		}
	}()

	// Generate new owner keys
	if *generateOwnerKey {
		fmt.Println("Generating new owner keys...")
		if err := generateOwnerKeys(state); err != nil {
			return fmt.Errorf("error generating owner keys: %w", err)
		}
		fmt.Println("\n✓ Owner keys generated successfully")
		return nil
	}

	// Print owner public keys
	if *printOwnerKey {
		return printOwnerPublicKeys(ctx, state)
	}

	// Import owner private key
	if *importOwnerKey != "" {
		return importOwnerPrivateKey(ctx, state, *importOwnerKey)
	}

	return nil
}

// handleSpecialOperations handles operations like printing keys, importing vouchers, etc.
func handleSpecialOperations() error {
	// Open database for operations that need it
	if config.Print.OwnerPublic != "" || config.Print.OwnerPrivate != "" || config.Print.OwnerChain != "" || config.Import.Voucher != "" {
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

		// Print owner public key
		if config.Print.OwnerPublic != "" {
			return doPrintOwnerPubKey(ctx, state)
		}

		// Print owner private key
		if config.Print.OwnerPrivate != "" {
			return doPrintOwnerPrivKey(ctx, state)
		}

		// Print owner chain
		if config.Print.OwnerChain != "" {
			return doPrintOwnerChain(ctx, state)
		}

		// Import voucher
		if config.Import.Voucher != "" {
			return doImportVoucher(ctx, state)
		}
	}

	return nil
}

func runServer(ctx context.Context) error {
	// Open database
	state, err := sqlite.Open(config.Database.Path, config.Database.Password)
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	defer func() {
		if err := state.Close(); err != nil {
			slog.Error("Error closing database", "error", err)
		}
	}()

	// Initialize device metadata table
	if err := InitDeviceMetadataTable(state.DB()); err != nil {
		return fmt.Errorf("error initializing device metadata table: %w", err)
	}

	// Create vouchers and configs directories if they don't exist
	if err := os.MkdirAll(config.DeviceStorage.VoucherDir, 0755); err != nil {
		return fmt.Errorf("error creating voucher directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(config.DeviceStorage.ConfigDir, "devices"), 0755); err != nil {
		return fmt.Errorf("error creating device config directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(config.DeviceStorage.ConfigDir, "groups"), 0755); err != nil {
		return fmt.Errorf("error creating group config directory: %w", err)
	}

	// Create device storage manager
	deviceStorage := &DeviceStorageManager{
		VoucherDir: config.DeviceStorage.VoucherDir,
		ConfigDir:  config.DeviceStorage.ConfigDir,
		DB:         state,
		Config:     config,
	}

	// Generate keys if configured and keys don't exist in database
	if config.Manufacturing.InitKeysIfMissing {
		// Check if owner keys already exist
		ctx := context.Background()
		_, _, err := state.OwnerKey(ctx, protocol.Rsa2048RestrKeyType, 2048)
		keysExist := (err == nil)

		if !keysExist {
			log.Printf("Owner keys not found in database (error: %v), initializing...", err)
			fmt.Println("Initializing manufacturing station keys...")
			if err := generateKeys(state); err != nil {
				return fmt.Errorf("error generating keys: %w", err)
			}
			fmt.Println("Manufacturing station initialization completed")
		} else {
			log.Printf("✓ Owner keys found in database, skipping key generation")
		}
	}

	// If init-only mode, exit after key generation
	if *initOnly {
		return nil
	}

	// Validate payload and BMO files exist before starting server
	if err := validateFiles(); err != nil {
		return fmt.Errorf("file validation failed: %w", err)
	}

	// Handle TO0 registration if GUID is specified
	if config.TO0.GUID != "" {
		if err := registerRvBlob(ctx, state); err != nil {
			return err
		}
	}

	// Handle resale protocol if GUID is specified
	if config.Resale.GUID != "" {
		if err := resell(ctx, state); err != nil {
			return err
		}
	}

	// Start the main server
	return startServer(ctx, state, deviceStorage)
}

func generateKeys(state *sqlite.DB) error {
	// Generate manufacturing component keys (these act as the Device CA)
	rsa2048MfgKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rsa3072MfgKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	ec256MfgKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ec384MfgKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	// Generate CA certificates for manufacturing keys
	generateCA := func(key crypto.Signer) ([]*x509.Certificate, error) {
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Manufacturing Station CA"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil
	}

	rsa2048Chain, err := generateCA(rsa2048MfgKey)
	if err != nil {
		return err
	}
	rsa3072Chain, err := generateCA(rsa3072MfgKey)
	if err != nil {
		return err
	}
	ec256Chain, err := generateCA(ec256MfgKey)
	if err != nil {
		return err
	}
	ec384Chain, err := generateCA(ec384MfgKey)
	if err != nil {
		return err
	}

	// Add manufacturing keys to database
	if err := state.AddManufacturerKey(protocol.Rsa2048RestrKeyType, rsa2048MfgKey, rsa2048Chain); err != nil {
		return err
	}
	if err := state.AddManufacturerKey(protocol.RsaPkcsKeyType, rsa3072MfgKey, rsa3072Chain); err != nil {
		return err
	}
	if err := state.AddManufacturerKey(protocol.RsaPssKeyType, rsa3072MfgKey, rsa3072Chain); err != nil {
		return err
	}
	if err := state.AddManufacturerKey(protocol.Secp256r1KeyType, ec256MfgKey, ec256Chain); err != nil {
		return err
	}
	if err := state.AddManufacturerKey(protocol.Secp384r1KeyType, ec384MfgKey, ec384Chain); err != nil {
		return err
	}

	// Generate owner keys
	rsa2048OwnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rsa3072OwnerKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	ec256OwnerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ec384OwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	// Generate owner certificates if requested
	var rsa2048OwnerCert, rsa3072OwnerCert, ec256OwnerCert, ec384OwnerCert []*x509.Certificate
	if config.Owner.GenerateCertificates {
		rsa2048OwnerCert, err = generateCA(rsa2048OwnerKey)
		if err != nil {
			return err
		}
		rsa3072OwnerCert, err = generateCA(rsa3072OwnerKey)
		if err != nil {
			return err
		}
		ec256OwnerCert, err = generateCA(ec256OwnerKey)
		if err != nil {
			return err
		}
		ec384OwnerCert, err = generateCA(ec384OwnerKey)
		if err != nil {
			return err
		}
	}

	if err := state.AddOwnerKey(protocol.Rsa2048RestrKeyType, rsa2048OwnerKey, rsa2048OwnerCert); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.RsaPkcsKeyType, rsa3072OwnerKey, rsa3072OwnerCert); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.RsaPssKeyType, rsa3072OwnerKey, rsa3072OwnerCert); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.Secp256r1KeyType, ec256OwnerKey, ec256OwnerCert); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.Secp384r1KeyType, ec384OwnerKey, ec384OwnerCert); err != nil {
		return err
	}

	// Print owner public keys in PEM format for DI usage
	fmt.Println("\n========================================")
	fmt.Println("OWNER PUBLIC KEYS (PEM Format)")
	fmt.Println("========================================")
	fmt.Println("\nUse these keys in your DI manufacturing station config (owner_signover.static_public_key):\n")

	// Helper to encode public key as PEM
	encodePEM := func(key crypto.PublicKey, label string) error {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return err
		}
		fmt.Printf("--- %s ---\n", label)
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		}); err != nil {
			return err
		}
		fmt.Println()
		return nil
	}

	if err := encodePEM(rsa2048OwnerKey.Public(), "RSA2048"); err != nil {
		return err
	}
	if err := encodePEM(rsa3072OwnerKey.Public(), "RSA3072"); err != nil {
		return err
	}
	if err := encodePEM(ec256OwnerKey.Public(), "SECP256R1"); err != nil {
		return err
	}
	if err := encodePEM(ec384OwnerKey.Public(), "SECP384R1"); err != nil {
		return err
	}

	fmt.Println("========================================")
	fmt.Println("Copy one of the above keys (including BEGIN/END lines) into your")
	fmt.Println("DI manufacturing station config at: owner_signover.static_public_key")
	fmt.Println("========================================")

	fmt.Println("All keys generated successfully")
	return nil
}

// generateOwnerKeys generates only owner keys (without manufacturing keys)
func generateOwnerKeys(state *sqlite.DB) error {
	ctx := context.Background()

	// Generate owner keys
	rsa2048OwnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rsa3072OwnerKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	ec256OwnerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ec384OwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	// Add owner keys to database
	if err := state.AddOwnerKey(protocol.Rsa2048RestrKeyType, rsa2048OwnerKey, nil); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.RsaPkcsKeyType, rsa3072OwnerKey, nil); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.RsaPssKeyType, rsa3072OwnerKey, nil); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.Secp256r1KeyType, ec256OwnerKey, nil); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.Secp384r1KeyType, ec384OwnerKey, nil); err != nil {
		return err
	}

	// Print owner public keys in PEM format
	return printOwnerPublicKeys(ctx, state)
}

// printOwnerPublicKeys prints all owner public keys in PEM format
func printOwnerPublicKeys(ctx context.Context, state *sqlite.DB) error {
	fmt.Println("\n========================================")
	fmt.Println("OWNER PUBLIC KEYS (PEM Format)")
	fmt.Println("========================================")
	fmt.Println("\nUse these keys in your DI manufacturing station config (owner_signover.static_public_key):\n")

	// Helper to encode public key as PEM
	encodePEM := func(key crypto.PublicKey, label string) error {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return err
		}
		fmt.Printf("--- %s ---\n", label)
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		}); err != nil {
			return err
		}
		fmt.Println()
		return nil
	}

	// Get and print each key type
	keyTypes := []struct {
		keyType protocol.KeyType
		label   string
	}{
		{protocol.Rsa2048RestrKeyType, "RSA2048"},
		{protocol.RsaPkcsKeyType, "RSA3072"},
		{protocol.Secp256r1KeyType, "SECP256R1"},
		{protocol.Secp384r1KeyType, "SECP384R1"},
	}

	for _, kt := range keyTypes {
		key, _, err := state.OwnerKey(ctx, kt.keyType, 3072)
		if err != nil {
			fmt.Printf("Warning: Could not retrieve %s key: %v\n", kt.label, err)
			continue
		}
		if err := encodePEM(key.Public(), kt.label); err != nil {
			return err
		}
	}

	fmt.Println("========================================")
	fmt.Println("Copy one of the above keys (including BEGIN/END lines) into your")
	fmt.Println("DI manufacturing station config at: owner_signover.static_public_key")
	fmt.Println("========================================")

	return nil
}

// importOwnerPrivateKey imports an owner private key from a PEM file
func importOwnerPrivateKey(ctx context.Context, state *sqlite.DB, pemFile string) error {
	// Read PEM file
	pemData, err := os.ReadFile(pemFile)
	if err != nil {
		return fmt.Errorf("error reading PEM file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// Parse private key
	var privKey crypto.Signer
	var keyType protocol.KeyType

	// Try parsing as different key types
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			privKey = k
			if k.N.BitLen() == 2048 {
				keyType = protocol.Rsa2048RestrKeyType
			} else {
				keyType = protocol.RsaPkcsKeyType
			}
		case *ecdsa.PrivateKey:
			privKey = k
			if k.Curve == elliptic.P256() {
				keyType = protocol.Secp256r1KeyType
			} else if k.Curve == elliptic.P384() {
				keyType = protocol.Secp384r1KeyType
			} else {
				return fmt.Errorf("unsupported EC curve")
			}
		default:
			return fmt.Errorf("unsupported key type in PKCS8")
		}
	} else if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privKey = key
		if key.N.BitLen() == 2048 {
			keyType = protocol.Rsa2048RestrKeyType
		} else {
			keyType = protocol.RsaPkcsKeyType
		}
	} else if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		privKey = key
		if key.Curve == elliptic.P256() {
			keyType = protocol.Secp256r1KeyType
		} else if key.Curve == elliptic.P384() {
			keyType = protocol.Secp384r1KeyType
		} else {
			return fmt.Errorf("unsupported EC curve")
		}
	} else {
		return fmt.Errorf("failed to parse private key")
	}

	// Add to database
	if err := state.AddOwnerKey(keyType, privKey, nil); err != nil {
		return fmt.Errorf("error adding owner key to database: %w", err)
	}

	fmt.Printf("✓ Successfully imported %s owner private key\n", keyType)
	return nil
}

func validateFiles() error {
	// Validate payload files
	if config.FSIM.PayloadFile != "" {
		if _, err := os.Stat(config.FSIM.PayloadFile); err != nil {
			return fmt.Errorf("payload file not found: %s", config.FSIM.PayloadFile)
		}
	}

	for _, payloadSpec := range config.FSIM.PayloadFiles {
		parts := strings.SplitN(payloadSpec, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid payload specification %q: expected type:file format", payloadSpec)
		}
		filePath := parts[1]
		if _, err := os.Stat(filePath); err != nil {
			return fmt.Errorf("payload file not found: %s", filePath)
		}
	}

	// Validate BMO files
	if config.FSIM.BMOFile != "" {
		if _, err := os.Stat(config.FSIM.BMOFile); err != nil {
			return fmt.Errorf("BMO file not found: %s", config.FSIM.BMOFile)
		}
	}

	for _, bmoSpec := range config.FSIM.BMOFiles {
		parts := strings.SplitN(bmoSpec, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid BMO specification %q: expected type:file format", bmoSpec)
		}
		filePath := parts[1]
		if _, err := os.Stat(filePath); err != nil {
			return fmt.Errorf("BMO file not found: %s", filePath)
		}
	}

	return nil
}

func startServer(ctx context.Context, state *sqlite.DB, deviceStorage *DeviceStorageManager) error {
	// Normalize address
	extAddr := config.Server.ExtAddr
	if extAddr == "" {
		extAddr = config.Server.Addr
	}

	// Parse RV replacement policy
	replacementPolicy, err := fdo.ParseVoucherReplacementPolicy(config.TO0.ReplacementPolicy)
	if err != nil {
		return fmt.Errorf("invalid rv-replacement-policy: %w", err)
	}

	// RV Info
	var rvInfo [][]protocol.RvInstruction
	if config.TO0.Addr != "" {
		rvInfo, err = to0AddrToRvInfo()
	} else {
		rvInfo, err = extAddrToRvInfo()
	}
	if err != nil {
		return err
	}

	// Test RVDelay by introducing a delay before TO1
	rvInfo = append([][]protocol.RvInstruction{{{Variable: protocol.RVDelaysec, Value: mustMarshal(config.TO0.Delay)}}}, rvInfo...)

	// Create FDO responder
	handler, err := newHandler(ctx, rvInfo, state, deviceStorage, replacementPolicy)
	if err != nil {
		return err
	}

	// Set up HTTP server
	mux := http.NewServeMux()
	mux.Handle("POST /fdo/{fdoVer}/msg/{msg}", handler)

	srv := &http.Server{
		Addr:              config.Server.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	// Listen and serve
	lis, err := net.Listen("tcp", config.Server.Addr)
	if err != nil {
		return fmt.Errorf("error listening on %s: %w", config.Server.Addr, err)
	}
	defer func() { _ = lis.Close() }()

	fmt.Printf("🔍 DEBUG: About to start server on %s\n", lis.Addr().String())
	slog.Info("FDO Manufacturing Station starting",
		"local", lis.Addr().String(),
		"external", extAddr,
		"mode", "full-server")
	fmt.Printf("🔍 DEBUG: Server started successfully\n")

	// Start server in goroutine to monitor context cancellation
	errChan := make(chan error, 1)
	go func() {
		if config.Server.UseTLS {
			// TODO: Implement TLS support
			errChan <- srv.Serve(lis)
		} else {
			errChan <- srv.Serve(lis)
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		slog.Info("Shutting down manufacturing station...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("Server shutdown error", "error", err)
			return err
		}
		slog.Info("Manufacturing station stopped")
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

// Helper functions for key operations (from server.go)

func doPrintOwnerPubKey(ctx context.Context, state *sqlite.DB) error {
	keyType, err := protocol.ParseKeyType(config.Print.OwnerPublic)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	key, _, err := state.OwnerKey(ctx, keyType, 3072) // Always use 3072-bit for RSA PKCS/PSS
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", fdo.KeyToString(key.Public()))
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

func doPrintOwnerPrivKey(ctx context.Context, state *sqlite.DB) error {
	var pemBlock *pem.Block
	keyType, err := protocol.ParseKeyType(config.Print.OwnerPrivate)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	key, _, err := state.OwnerKey(ctx, keyType, 3072)
	if err != nil {
		return err
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}
	default:
		return fmt.Errorf("unknown owner key type %T", key)
	}

	return pem.Encode(os.Stdout, pemBlock)
}

func doPrintOwnerChain(ctx context.Context, state *sqlite.DB) error {
	keyType, err := protocol.ParseKeyType(config.Print.OwnerChain)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	_, chain, err := state.OwnerKey(ctx, keyType, 3072)
	if err != nil {
		return err
	}
	fmt.Println(fdo.CertChainToString("CERTIFICATE", chain))
	return nil
}

func doImportVoucher(ctx context.Context, state *sqlite.DB) error {
	// Parse voucher
	pemVoucher, err := os.ReadFile(filepath.Clean(config.Import.Voucher))
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(pemVoucher)
	if blk == nil {
		return fmt.Errorf("invalid PEM encoded file: %s", config.Import.Voucher)
	}
	if blk.Type != "OWNERSHIP VOUCHER" {
		return fmt.Errorf("expected PEM block of ownership voucher type, found %s", blk.Type)
	}
	var ov fdo.Voucher
	if err := cbor.Unmarshal(blk.Bytes, &ov); err != nil {
		return fmt.Errorf("error parsing voucher: %w", err)
	}

	// Check that voucher owner key matches
	expectedPubKey, err := ov.OwnerPublicKey()
	if err != nil {
		return fmt.Errorf("error parsing owner public key from voucher: %w", err)
	}
	ownerKey, _, err := state.OwnerKey(ctx, ov.Header.Val.ManufacturerKey.Type, 3072) // Always use 3072-bit for RSA PKCS/PSS
	if err != nil {
		return fmt.Errorf("error getting owner key: %w", err)
	}
	if !ownerKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedPubKey) {
		return fmt.Errorf("owner key in database does not match the owner of the voucher")
	}

	// Store voucher
	return state.AddVoucher(ctx, &ov)
}

func to0AddrToRvInfo() ([][]protocol.RvInstruction, error) {
	url, err := url.Parse(config.TO0.Addr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse TO0 addr: %w", err)
	}
	prot := protocol.RVProtHTTP
	if url.Scheme == "https" {
		prot = protocol.RVProtHTTPS
	}
	rvInfo := [][]protocol.RvInstruction{{{Variable: protocol.RVProtocol, Value: mustMarshal(prot)}}}
	host, portStr, err := net.SplitHostPort(url.Host)
	if err != nil {
		host = url.Host
	}
	if portStr == "" {
		portStr = "80"
		if url.Scheme == "https" {
			portStr = "443"
		}
	}
	if host == "" {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVIPAddress, Value: mustMarshal(net.IP{127, 0, 0, 1})})
	} else if hostIP := net.ParseIP(host); hostIP.To4() != nil || hostIP.To16() != nil {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVIPAddress, Value: mustMarshal(hostIP)})
	} else {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVDns, Value: mustMarshal(host)})
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid TO0 port: %w", err)
	}
	port := uint16(portNum)
	rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVDevPort, Value: mustMarshal(port)})
	if config.TO0.Bypass {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVBypass})
	}
	return rvInfo, nil
}

func extAddrToRvInfo() ([][]protocol.RvInstruction, error) {
	prot := protocol.RVProtHTTP
	if config.Server.UseTLS {
		prot = protocol.RVProtHTTPS
	}
	rvInfo := [][]protocol.RvInstruction{{{Variable: protocol.RVProtocol, Value: mustMarshal(prot)}}}
	host, portStr, err := net.SplitHostPort(config.Server.ExtAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid external addr: %w", err)
	}
	if host == "" {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVIPAddress, Value: mustMarshal(net.IP{127, 0, 0, 1})})
	} else if hostIP := net.ParseIP(host); hostIP.To4() != nil || hostIP.To16() != nil {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVIPAddress, Value: mustMarshal(hostIP)})
	} else {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVDns, Value: mustMarshal(host)})
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid external port: %w", err)
	}
	port := uint16(portNum)
	rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVDevPort, Value: mustMarshal(port)})
	if config.TO0.Bypass {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVBypass})
	}
	return rvInfo, nil
}

func registerRvBlob(ctx context.Context, state *sqlite.DB) error {
	if config.TO0.Addr == "" {
		return fmt.Errorf("to0-guid depends on to0 addr being set")
	}

	// Parse to0-guid config
	guidBytes, err := hex.DecodeString(strings.ReplaceAll(config.TO0.GUID, "-", ""))
	if err != nil {
		return fmt.Errorf("error parsing GUID of device to register RV blob: %w", err)
	}
	if len(guidBytes) != 16 {
		return fmt.Errorf("error parsing GUID of device to register RV blob: must be 16 bytes")
	}
	var guid protocol.GUID
	copy(guid[:], guidBytes)

	// Construct TO2 addr
	proto := protocol.HTTPTransport
	if config.Server.UseTLS {
		proto = protocol.HTTPSTransport
	}
	host, portStr, err := net.SplitHostPort(config.Server.ExtAddr)
	if err != nil {
		return fmt.Errorf("invalid external addr: %w", err)
	}
	if host == "" {
		host = "localhost"
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid external port: %w", err)
	}
	port := uint16(portNum)
	to2Addrs := []protocol.RvTO2Addr{
		{
			DNSAddress:        &host,
			Port:              port,
			TransportProtocol: proto,
		},
	}

	// Register RV blob with RV server
	refresh, err := (&fdo.TO0Client{
		Vouchers:     state,
		OwnerKeys:    state,
		DelegateKeys: state,
	}).RegisterBlob(ctx, tlsTransport(config.TO0.Addr, nil), guid, to2Addrs, config.TO0.Delegate)
	if err != nil {
		return fmt.Errorf("error performing to0: %w", err)
	}
	slog.Info("RV blob registered", "ttl", time.Duration(refresh)*time.Second)

	return nil
}

func resell(ctx context.Context, state *sqlite.DB) error {
	// Parse resale-guid config
	guidBytes, err := hex.DecodeString(strings.ReplaceAll(config.Resale.GUID, "-", ""))
	if err != nil {
		return fmt.Errorf("error parsing GUID of voucher to resell: %w", err)
	}
	if len(guidBytes) != 16 {
		return fmt.Errorf("error parsing GUID of voucher to resell: must be 16 bytes")
	}
	var guid protocol.GUID
	copy(guid[:], guidBytes)

	// Parse next owner key
	if config.Resale.Key == "" {
		return fmt.Errorf("resale-guid depends on resale-key being set")
	}
	keyBytes, err := os.ReadFile(filepath.Clean(config.Resale.Key))
	if err != nil {
		return fmt.Errorf("error reading next owner key file: %w", err)
	}
	blk, _ := pem.Decode(keyBytes)
	if blk == nil {
		return fmt.Errorf("invalid PEM file: %s", config.Resale.Key)
	}
	nextOwner, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing x.509 public key: %w", err)
	}

	// Perform resale protocol
	extended, err := (&fdo.TO2Server{
		Vouchers:        state,
		OwnerKeys:       state,
		DelegateKeys:    state,
		OnboardDelegate: config.Delegate.Onboard,
		RvDelegate:      config.Delegate.RV,
	}).Resell(ctx, guid, nextOwner, nil)
	if err != nil {
		return fmt.Errorf("resale protocol: %w", err)
	}
	ovBytes, err := cbor.Marshal(extended)
	if err != nil {
		return fmt.Errorf("resale protocol: error marshaling voucher: %w", err)
	}
	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "OWNERSHIP VOUCHER",
		Bytes: ovBytes,
	})
}

func mustMarshal(v any) []byte {
	data, err := cbor.Marshal(v)
	if err != nil {
		panic(err.Error())
	}
	return data
}

func tlsTransport(addr string, certs []*x509.Certificate) fdo.Transport {
	// Create HTTP transport
	httpTransport := &transport.Transport{}
	return httpTransport
}

// WiFiConfigEntry represents a single WiFi network in the JSON config file
type WiFiConfigEntry struct {
	Version    string `json:"version"`
	NetworkID  string `json:"network_id"`
	SSID       string `json:"ssid"`
	AuthType   int    `json:"auth_type"`
	Password   string `json:"password"`
	TrustLevel int    `json:"trust_level"`
	NeedsCert  bool   `json:"needs_cert"`
}

// loadWiFiConfig loads WiFi network configurations from a JSON file
func loadWiFiConfig(filePath string) (*fsim.WiFiOwner, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read WiFi config file: %w", err)
	}

	var entries []WiFiConfigEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse WiFi config JSON: %w", err)
	}

	wifiOwner := &fsim.WiFiOwner{}
	for _, entry := range entries {
		network := &fsim.WiFiNetwork{
			Version:    entry.Version,
			NetworkID:  entry.NetworkID,
			SSID:       entry.SSID,
			AuthType:   entry.AuthType,
			Password:   []byte(entry.Password),
			TrustLevel: entry.TrustLevel,
		}
		wifiOwner.AddNetwork(network)

		// If this is an enterprise network that needs a certificate, add a fake cert and CA bundle
		if entry.NeedsCert && entry.AuthType == 3 {
			fakeCert := []byte("-----BEGIN CERTIFICATE-----\n" +
				"MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n" +
				"BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n" +
				"aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF\n" +
				"-----END CERTIFICATE-----\n")

			cert := fsim.WiFiCertificate{
				NetworkID: entry.NetworkID,
				SSID:      entry.SSID,
				CertRole:  0, // client certificate
				CertData:  fakeCert,
				Metadata: map[string]any{
					"cert_type": "x509",
					"format":    "pem",
				},
			}
			wifiOwner.AddCertificate(cert)

			// Add fake CA bundle (root CA certificate)
			fakeCA := []byte("-----BEGIN CERTIFICATE-----\n" +
				"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n" +
				"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n" +
				"b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n" +
				"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n" +
				"-----END CERTIFICATE-----\n")

			caBundle := fsim.WiFiCABundle{
				NetworkID: entry.NetworkID,
				BundleID:  "root-ca",
				CAData:    fakeCA,
				Metadata: map[string]any{
					"cert_type": "x509",
					"format":    "pem",
				},
			}
			wifiOwner.AddCABundle(caBundle)
		}
	}

	return wifiOwner, nil
}

// newHandler creates the FDO handler with all functionality
func newHandler(ctx context.Context, rvInfo [][]protocol.RvInstruction, state *sqlite.DB, deviceStorage *DeviceStorageManager, replacementPolicy fdo.VoucherReplacementPolicy) (*transport.Handler, error) {
	aio := fdo.AllInOne{
		DIAndOwner:         state,
		RendezvousAndOwner: withOwnerAddrs{state, rvInfo},
	}
	autoExtend := aio.Extend

	// Auto-register RV blob so that TO1 can be tested unless a TO0 address is
	// given or RV bypass is set
	var autoTO0 func(context.Context, fdo.Voucher) error
	if config.TO0.Addr == "" && !config.TO0.Bypass {
		autoTO0 = aio.RegisterOwnerAddr
	}

	// Use Manufacturer key as device certificate authority
	deviceCAKey, deviceCAChain, err := state.ManufacturerKey(ctx, protocol.Secp384r1KeyType, 0)
	if err != nil {
		return nil, fmt.Errorf("error getting manufacturer key for use as device certificate authority: %w", err)
	}

	return &transport.Handler{
		Tokens: state,
		DIResponder: &fdo.DIServer[custom.DeviceMfgInfo]{
			Session:               state,
			Vouchers:              deviceStorage, // Use deviceStorage for voucher operations
			SignDeviceCertificate: custom.SignDeviceCertificate(deviceCAKey, deviceCAChain),
			DeviceInfo: func(ctx context.Context, info *custom.DeviceMfgInfo, _ []*x509.Certificate) (string, protocol.PublicKey, error) {
				// Always use RSA 3072 for non 2048 restricted key type. In a
				// real implementation, the manufacturing server must ensure
				// that the device has the capability to process such crypto
				// (including SHA-384 hashes).
				mfgKey, mfgChain, err := state.ManufacturerKey(ctx, info.KeyType, 3072)
				if err != nil {
					return "", protocol.PublicKey{}, err
				}
				mfgPubKey, err := encodePublicKey(info.KeyType, info.KeyEncoding, mfgKey.Public(), mfgChain)
				if err != nil {
					return "", protocol.PublicKey{}, err
				}
				return info.DeviceInfo, *mfgPubKey, nil
			},
			BeforeVoucherPersist: autoExtend,
			AfterVoucherPersist:  autoTO0,
			RvInfo:               func(context.Context, *fdo.Voucher) ([][]protocol.RvInstruction, error) { return rvInfo, nil },
		},
		TO0Responder: &fdo.TO0Server{
			Session:                  state,
			RVBlobs:                  state,
			VoucherReplacementPolicy: replacementPolicy,
		},
		TO1Responder: &fdo.TO1Server{
			Session: state,
			RVBlobs: state,
		},
		TO2Responder: &fdo.TO2Server{
			Session:         state,
			Modules:         moduleStateMachines{DB: state, DeviceStorage: deviceStorage, states: make(map[string]*moduleStateMachineState)},
			Vouchers:        deviceStorage, // Use deviceStorage for voucher operations
			OwnerKeys:       state,
			DelegateKeys:    state,
			RvInfo:          func(context.Context, fdo.Voucher) ([][]protocol.RvInstruction, error) { return rvInfo, nil },
			OnboardDelegate: config.Delegate.Onboard,
			RvDelegate:      config.Delegate.RV,
			ReuseCredential: func(context.Context, fdo.Voucher) (bool, error) { return config.VoucherManagement.ReuseCredential, nil },
			SingleSidedMode: config.FSIM.SingleSidedWiFi,
		},
	}, nil
}

type withOwnerAddrs struct {
	*sqlite.DB
	RVInfo [][]protocol.RvInstruction
}

func (s withOwnerAddrs) OwnerAddrs(context.Context, fdo.Voucher) ([]protocol.RvTO2Addr, time.Duration, error) {
	var autoTO0Addrs []protocol.RvTO2Addr
	for _, directive := range protocol.ParseDeviceRvInfo(s.RVInfo) {
		if directive.Bypass {
			continue
		}

		for _, url := range directive.URLs {
			to1Host := url.Hostname()
			to1Port, err := strconv.ParseUint(url.Port(), 10, 16)
			if err != nil {
				return nil, 0, fmt.Errorf("error parsing TO1 port to use for TO2: %w", err)
			}
			proto := protocol.HTTPTransport
			if config.Server.UseTLS {
				proto = protocol.HTTPSTransport
			}
			autoTO0Addrs = append(autoTO0Addrs, protocol.RvTO2Addr{
				DNSAddress:        &to1Host,
				Port:              uint16(to1Port),
				TransportProtocol: proto,
			})
		}
	}
	return autoTO0Addrs, 0, nil
}

func encodePublicKey(keyType protocol.KeyType, keyEncoding protocol.KeyEncoding, pub crypto.PublicKey, chain []*x509.Certificate) (*protocol.PublicKey, error) {
	if pub == nil && len(chain) > 0 {
		pub = chain[0].PublicKey
	}
	if pub == nil {
		return nil, fmt.Errorf("no key to encode")
	}

	switch keyEncoding {
	case protocol.X509KeyEnc, protocol.CoseKeyEnc:
		// Intentionally panic if pub is not the correct key type
		switch keyType {
		case protocol.Secp256r1KeyType, protocol.Secp384r1KeyType:
			return protocol.NewPublicKey(keyType, pub.(*ecdsa.PublicKey), keyEncoding == protocol.CoseKeyEnc)
		case protocol.Rsa2048RestrKeyType, protocol.RsaPkcsKeyType, protocol.RsaPssKeyType:
			return protocol.NewPublicKey(keyType, pub.(*rsa.PublicKey), keyEncoding == protocol.CoseKeyEnc)
		default:
			return nil, fmt.Errorf("unsupported key type: %s", keyType)
		}
	case protocol.X5ChainKeyEnc:
		return protocol.NewPublicKey(keyType, chain, false)
	default:
		return nil, fmt.Errorf("unsupported key encoding: %s", keyEncoding)
	}
}

type moduleStateMachines struct {
	DB            *sqlite.DB
	DeviceStorage *DeviceStorageManager
	// current module state machine state for all sessions (indexed by token)
	states map[string]*moduleStateMachineState
}

type moduleStateMachineState struct {
	Name string
	Impl serviceinfo.OwnerModule
	Next func() (string, serviceinfo.OwnerModule, bool)
	Stop func()
}

func (s moduleStateMachines) Module(ctx context.Context) (string, serviceinfo.OwnerModule, error) {
	token, ok := s.DB.TokenFromContext(ctx)
	if !ok {
		return "", nil, fmt.Errorf("invalid context: no token")
	}
	module, ok := s.states[token]
	if !ok {
		return "", nil, fmt.Errorf("NextModule not called")
	}
	return module.Name, module.Impl, nil
}

func (s moduleStateMachines) NextModule(ctx context.Context) (bool, error) {
	token, ok := s.DB.TokenFromContext(ctx)
	if !ok {
		return false, fmt.Errorf("invalid context: no token")
	}
	module, ok := s.states[token]
	if !ok {
		// Create a new module state machine
		// Get GUID from session for device-specific config
		guid, err := s.DB.GUID(ctx)
		if err != nil {
			return false, fmt.Errorf("error getting GUID: %w", err)
		}

		_, modules, _, err := s.DB.Devmod(ctx)
		if err != nil {
			return false, fmt.Errorf("error getting devmod: %w", err)
		}
		next, stop := iter.Pull2(ownerModules(ctx, guid, s.DeviceStorage, modules))
		module = &moduleStateMachineState{
			Next: next,
			Stop: stop,
		}
		s.states[token] = module
	}

	var valid bool
	module.Name, module.Impl, valid = module.Next()
	return valid, nil
}

func (s moduleStateMachines) CleanupModules(ctx context.Context) {
	token, ok := s.DB.TokenFromContext(ctx)
	if !ok {
		return
	}
	module, ok := s.states[token]
	if !ok {
		return
	}
	module.Stop()
	delete(s.states, token)
}

func ownerModules(ctx context.Context, guid protocol.GUID, deviceStorage *DeviceStorageManager, modules []string) iter.Seq2[string, serviceinfo.OwnerModule] { //nolint:gocyclo
	return func(yield func(string, serviceinfo.OwnerModule) bool) {
		// Load device-specific configuration
		fsimConfig, err := deviceStorage.LoadDeviceConfig(ctx, guid)
		if err != nil {
			// Fall back to global config if device config fails to load
			log.Printf("Warning: Failed to load device config for %s, using global config: %v", hex.EncodeToString(guid[:]), err)
			fsimConfig = deviceStorage.configToFSIM(&config.FSIM)
		}

		if slices.Contains(modules, "fdo.download") {
			for _, name := range fsimConfig.Downloads {
				f, err := os.Open(filepath.Clean(name))
				if err != nil {
					log.Fatalf("error opening %q for download FSIM: %v", name, err)
				}
				defer func() { _ = f.Close() }()

				if !yield("fdo.download", &fsim.DownloadContents[*os.File]{
					Name:         name,
					Contents:     f,
					MustDownload: true,
				}) {
					return
				}
			}
		}

		if slices.Contains(modules, "fdo.upload") {
			for _, name := range fsimConfig.Uploads {
				if !yield("fdo.upload", &fsim.UploadRequest{
					Dir:  fsimConfig.UploadDir,
					Name: name,
				}) {
					return
				}
			}
		}

		if slices.Contains(modules, "fdo.wget") {
			for _, urlString := range fsimConfig.Wgets {
				url, err := url.Parse(urlString)
				if err != nil || url.Path == "" {
					continue
				}
				if !yield("fdo.wget", &fsim.WgetCommand{
					Name: path.Base(url.Path),
					URL:  url,
				}) {
					return
				}
			}
		}

		if slices.Contains(modules, "fdo.sysconfig") && len(fsimConfig.Sysconfig) > 0 {
			sysconfigOwner := &fsim.SysConfigOwner{}
			for _, param := range fsimConfig.Sysconfig {
				parts := strings.SplitN(param, "=", 2)
				if len(parts) != 2 {
					log.Fatalf("invalid sysconfig parameter %q: expected key=value format", param)
				}
				sysconfigOwner.AddParameter(parts[0], parts[1])
			}
			if !yield("fdo.sysconfig", sysconfigOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.payload") && (fsimConfig.PayloadFile != "" || len(fsimConfig.PayloadFiles) > 0) {
			payloadOwner := &fsim.PayloadOwner{}

			// Handle multi-file NAK testing mode (with RequireAck)
			if len(fsimConfig.PayloadFiles) > 0 {
				for _, payloadSpec := range fsimConfig.PayloadFiles {
					parts := strings.SplitN(payloadSpec, ":", 2)
					if len(parts) != 2 {
						log.Fatalf("invalid payload specification %q: expected type:file format", payloadSpec)
					}
					mimeType, filePath := parts[0], parts[1]
					data, err := os.ReadFile(filePath)
					if err != nil {
						log.Fatalf("error reading payload file %q: %v", filePath, err)
					}
					payloadOwner.AddPayloadWithAck(mimeType, filepath.Base(filePath), data, nil)
					log.Printf("Payload: Added payload with RequireAck: type=%s, file=%s", mimeType, filePath)
				}
			} else {
				// Single file mode (no RequireAck)
				data, err := os.ReadFile(fsimConfig.PayloadFile)
				if err != nil {
					log.Fatalf("error reading payload file %q: %v", fsimConfig.PayloadFile, err)
				}
				payloadOwner.AddPayload(fsimConfig.PayloadMime, filepath.Base(fsimConfig.PayloadFile), data, nil)
			}

			if !yield("fdo.payload", payloadOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.bmo") && (fsimConfig.BMOFile != "" || len(fsimConfig.BMOFiles) > 0) {
			bmoOwner := &fsim.BMOOwner{}

			// Handle multi-file NAK testing mode (with RequireAck)
			if len(fsimConfig.BMOFiles) > 0 {
				for _, bmoSpec := range fsimConfig.BMOFiles {
					parts := strings.SplitN(bmoSpec, ":", 2)
					if len(parts) != 2 {
						log.Fatalf("invalid BMO specification %q: expected type:file format", bmoSpec)
					}
					imageType, filePath := parts[0], parts[1]
					data, err := os.ReadFile(filePath)
					if err != nil {
						log.Fatalf("error reading BMO file %q: %v", filePath, err)
					}
					bmoOwner.AddImageWithAck(imageType, filepath.Base(filePath), data, nil)
					log.Printf("BMO: Added image with RequireAck: type=%s, file=%s", imageType, filePath)
				}
			} else {
				// Single file mode (no RequireAck)
				data, err := os.ReadFile(fsimConfig.BMOFile)
				if err != nil {
					log.Fatalf("error reading BMO file %q: %v", fsimConfig.BMOFile, err)
				}
				bmoOwner.AddImage(fsimConfig.BMOImageType, filepath.Base(fsimConfig.BMOFile), data, nil)
			}

			if !yield("fdo.bmo", bmoOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.wifi") && fsimConfig.WiFiConfigFile != "" {
			wifiOwner, err := loadWiFiConfig(fsimConfig.WiFiConfigFile)
			if err != nil {
				log.Fatalf("error loading WiFi config from %q: %v", fsimConfig.WiFiConfigFile, err)
			}
			if !yield("fdo.wifi", wifiOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.credentials") {
			var provisionedCreds []fsim.ProvisionedCredential
			for _, credSpec := range fsimConfig.Credentials {
				parts := strings.SplitN(credSpec, ":", 4)
				if len(parts) < 3 {
					log.Fatalf("invalid credential specification %q: expected type:id:data[:endpoint_url] format", credSpec)
				}
				credType, _, credData := parts[0], parts[1], parts[2]
				var endpointURL string
				if len(parts) == 4 {
					endpointURL = parts[3]
				}

				// Convert string credential type to integer
				var credTypeInt int
				switch credType {
				case "password":
					credTypeInt = fsim.CredentialTypePassword
				case "api_key", "oauth2_client_secret", "bearer_token":
					credTypeInt = fsim.CredentialTypeSecret
				default:
					log.Fatalf("invalid credential type %q: must be one of password, api_key, oauth2_client_secret, bearer_token", credType)
				}

				// For password type, create metadata with username
				var data []byte
				var metadata map[string]any
				if credType == "password" {
					// credData format for password: "username:password"
					userPass := strings.SplitN(credData, ":", 2)
					if len(userPass) == 2 {
						metadata = map[string]any{"username": userPass[0]}
						data = []byte(userPass[1])
					} else {
						data = []byte(credData)
					}
				} else {
					data = []byte(credData)
				}

				provisionedCreds = append(provisionedCreds, fsim.ProvisionedCredential{
					CredentialID:   credTypeInt,
					CredentialData: data,
					Metadata:       metadata,
					EndpointURL:    endpointURL,
				})
			}

			credentialsOwner := fsim.NewCredentialsOwner(provisionedCreds)

			// Add public key requests (Registered Credentials flow)
			for _, reqSpec := range fsimConfig.PubkeyRequests {
				parts := strings.SplitN(reqSpec, ":", 3)
				if len(parts) < 2 {
					log.Fatalf("invalid pubkey request specification %q: expected type:id[:endpoint_url] format", reqSpec)
				}
				credType, credID := parts[0], parts[1]
				var endpointURL string
				if len(parts) == 3 {
					endpointURL = parts[2]
				}
				// Convert SSH key type to integer
				var credTypeInt int
				switch credType {
				case "ssh-rsa":
					credTypeInt = fsim.CredentialTypeSSHPublicKey
				default:
					credTypeInt = fsim.CredentialTypeSSHPublicKey
				}
				credentialsOwner.PublicKeyRequests = append(credentialsOwner.PublicKeyRequests, fsim.PublicKeyRequest{
					CredentialID: credTypeInt,
					Metadata:     map[string]any{"credential_id": credID},
					EndpointURL:  endpointURL,
				})
			}

			// Add handler for receiving public keys from device
			credentialsOwner.OnPublicKeyReceived = func(credentialID string, credentialType int, publicKey []byte, metadata map[string]any) error {
				fmt.Printf("[fdo.credentials] Received public key registration:\n")
				fmt.Printf("  ID:   %s\n", credentialID)
				fmt.Printf("  Type: %d\n", credentialType)
				if metadata != nil {
					fmt.Printf("  Metadata: %v\n", metadata)
				}
				fmt.Printf("  Key:  %s (length: %d bytes)\n", string(publicKey), len(publicKey))
				return nil
			}

			// Add handler for enrollment requests (CSR signing, etc.)
			credentialsOwner.OnEnrollmentRequest = func(credentialID string, credentialType int, requestData []byte, metadata map[string]any) (responseData []byte, responseMetadata map[string]any, err error) {
				fmt.Printf("[fdo.credentials] SERVER received CSR:\n")
				fmt.Printf("  ID:   %s\n", credentialID)
				fmt.Printf("  Type: %d\n", credentialType)
				fmt.Printf("  CSR:  %s\n", string(requestData))

				// For demo purposes, return a fake signed certificate + CA bundle
				fakeCert := fmt.Sprintf("-----BEGIN CERTIFICATE-----\nSigned certificate for %s\n-----END CERTIFICATE-----\n", credentialID)
				fakeCA := "-----BEGIN CERTIFICATE-----\nFake CA Certificate\n-----END CERTIFICATE-----\n"
				responseData = []byte(fakeCert + fakeCA)

				fmt.Printf("[fdo.credentials] SERVER sending signed cert + CA:\n")
				fmt.Printf("  Cert: %d bytes\n", len(fakeCert))
				fmt.Printf("  CA:   %d bytes\n", len(fakeCA))

				responseMeta := map[string]any{
					"cert_format":        "pem",
					"ca_bundle_included": true,
				}
				return responseData, responseMeta, nil
			}
			if !yield("fdo.credentials", credentialsOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.command") {
			if !yield("fdo.command", &fsim.RunCommand{
				Command: "date",
				Args:    []string{"+%s"},
				Stdout:  os.Stdout,
				Stderr:  os.Stderr,
			}) {
				return
			}
		}
	}
}
