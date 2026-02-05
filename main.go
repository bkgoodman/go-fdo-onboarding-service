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
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/custom"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/protocol"
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
	configPath = flag.String("config", "config.yaml", "Path to configuration file")
	initOnly   = flag.Bool("init-only", false, "Initialize database and keys only, then exit")
	debug      = flag.Bool("debug", false, "Enable debug logging")
)

func main() {
	flag.Parse()

	// Load configuration
	var err error
	config, err = LoadConfig(*configPath)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
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

	// Register DI event handler to print device GUID
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
		}
	}))

	// Validate required config values
	if config.Database.Path == "" {
		fmt.Fprintf(os.Stderr, "Error: Database path must be specified in config file\n")
		os.Exit(1)
	}

	if *debug || config.Debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		// Also set global default logger level to enable go-fdo library debug output
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	} else {
		// Create a custom handler that completely disables debug output
		noDebug := &noDebugHandler{
			handler: slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		}
		slog.SetDefault(slog.New(noDebug))
	}

	ctx := context.Background()
	if err := runManufacturingStation(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// noDebugHandler is a custom slog.Handler that filters out debug messages
type noDebugHandler struct {
	handler slog.Handler
}

// disabledHandler is a slog.Handler that completely disables all logging
type disabledHandler struct{}

func (h *noDebugHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// Block DEBUG level completely
	if level == slog.LevelDebug {
		return false
	}
	// Delegate to underlying handler for other levels
	return h.handler.Enabled(ctx, level)
}

func (h *noDebugHandler) Handle(ctx context.Context, record slog.Record) error {
	// Double-check: don't handle DEBUG records even if they get through
	if record.Level == slog.LevelDebug {
		return nil
	}
	return h.handler.Handle(ctx, record)
}

func (h *noDebugHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &noDebugHandler{handler: h.handler.WithAttrs(attrs)}
}

func (h *noDebugHandler) WithGroup(name string) slog.Handler {
	return &noDebugHandler{handler: h.handler.WithGroup(name)}
}

func (h *disabledHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return false // Never enable any logging
}

func (h *disabledHandler) Handle(ctx context.Context, record slog.Record) error {
	return nil // Do nothing
}

func (h *disabledHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h // Return self
}

func (h *disabledHandler) WithGroup(name string) slog.Handler {
	return h // Return self
}

// debugDisabledHandler wraps a handler but lies about debug being disabled
type debugDisabledHandler struct {
	slog.Handler
}

func (h *debugDisabledHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// Lie about debug being disabled - always return false for debug level
	if level == slog.LevelDebug {
		return false
	}
	return h.Handler.Enabled(ctx, level)
}

// noopHandler completely discards all log messages
type noopHandler struct{}

func (h *noopHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return false // Never enable any logging
}

func (h *noopHandler) Handle(ctx context.Context, record slog.Record) error {
	return nil // Do nothing
}

func (h *noopHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h // Return self
}

func (h *noopHandler) WithGroup(name string) slog.Handler {
	return h // Return self
}

func runManufacturingStation(ctx context.Context) error {
	// Check if database exists
	_, dbStatErr := os.Stat(config.Database.Path)

	// Open database
	state, err := sqlite.Open(config.Database.Path, config.Database.Password)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}

	// Generate keys if first-time init or database doesn't exist
	if config.Manufacturing.FirstTimeInit || errors.Is(dbStatErr, fs.ErrNotExist) {
		fmt.Println("Initializing manufacturing station keys...")
		if err := generateManufacturingKeys(state); err != nil {
			return fmt.Errorf("error generating manufacturing keys: %w", err)
		}
		fmt.Println("Manufacturing station initialization completed")
	}

	// If init-only mode, exit after key generation
	if *initOnly {
		return nil
	}

	// Start DI server
	return startDIServer(ctx, state)
}

func generateManufacturingKeys(state *sqlite.DB) error {
	// Generate manufacturing component keys (these act as the Device CA)
	rsa2048MfgKey, err := rsa.GenerateKey(rand.Reader, 2048)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
	if err != nil {
		return err
	}
	rsa3072MfgKey, err := rsa.GenerateKey(rand.Reader, 3072)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
	if err != nil {
		return err
	}
	ec256MfgKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
	if err != nil {
		return err
	}
	ec384MfgKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
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
		fmt.Printf("DEBUG: Config loaded: %+v\n", config)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		fmt.Printf("DEBUG: Config loaded: %+v\n", config)
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil
	}

	rsa2048Chain, err := generateCA(rsa2048MfgKey)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
	if err != nil {
		return err
	}
	rsa3072Chain, err := generateCA(rsa3072MfgKey)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
	if err != nil {
		return err
	}
	ec256Chain, err := generateCA(ec256MfgKey)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
	if err != nil {
		return err
	}
	ec384Chain, err := generateCA(ec384MfgKey)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
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

	fmt.Println("Manufacturing keys generated successfully")
	return nil
}

func startDIServer(ctx context.Context, state *sqlite.DB) error {
	// Normalize address
	extAddr := config.Server.ExtAddr
	if extAddr == "" {
		extAddr = config.Server.Addr
	}

	// Use Manufacturer key as device certificate authority
	deviceCAKey, deviceCAChain, err := state.ManufacturerKey(ctx, protocol.Secp384r1KeyType, 0)
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
	if err != nil {
		return fmt.Errorf("error getting manufacturer key for device certificate authority: %w", err)
	}

	// Initialize voucher management services
	ownerKeyExecutor := NewExternalCommandExecutor(config.VoucherManagement.OwnerSignover.ExternalCommand, config.VoucherManagement.OwnerSignover.Timeout)
	ownerKeyService := NewOwnerKeyService(ownerKeyExecutor)

	voucherUploadExecutor := NewExternalCommandExecutor(config.VoucherManagement.VoucherUpload.ExternalCommand, config.VoucherManagement.VoucherUpload.Timeout)
	voucherUploadService := NewVoucherUploadService(voucherUploadExecutor)

	// Initialize voucher signing service
	voucherSigningService := NewVoucherSigningService(
		&config.VoucherManagement.VoucherSigning,
		NewExternalCommandExecutor(config.VoucherManagement.VoucherSigning.ExternalCommand, config.VoucherManagement.VoucherSigning.ExternalTimeout),
		"factory-01", // TODO: Make configurable
	)

	// Initialize voucher disk service
	voucherDiskService := NewVoucherDiskService(&config.VoucherManagement)

	// Initialize OVEExtra data service
	oveExtraDataService := NewOVEExtraDataService(
		&config.VoucherManagement.OVEExtraData,
		NewExternalCommandExecutor(config.VoucherManagement.OVEExtraData.ExternalCommand, config.VoucherManagement.OVEExtraData.Timeout),
	)

	voucherCallbackService := NewVoucherCallbackService(
		&config.VoucherManagement,
		ownerKeyService,
		voucherSigningService,
		voucherUploadService,
		voucherDiskService,
		oveExtraDataService,
		deviceCAKey, // Use device CA key for signing vouchers
	)

	// Create DI-only handler with minimal required components
	handler := &transport.Handler{
		Tokens: state,
		DIResponder: &fdo.DIServer[custom.DeviceMfgInfo]{
			Session:               state,
			Vouchers:              state,
			SignDeviceCertificate: custom.SignDeviceCertificate(deviceCAKey, deviceCAChain),
			DeviceInfo: func(ctx context.Context, info *custom.DeviceMfgInfo, chain []*x509.Certificate) (string, protocol.PublicKey, error) {
				// Store full device info (including serial) in session for later use
				if err := state.SetDeviceSelfInfo(ctx, info); err != nil {
					return "", protocol.PublicKey{}, fmt.Errorf("failed to store device info: %w", err)
				}

				var mfgPubKey protocol.PublicKey
				var err error

				// Check if we're using external HSM mode with manufacturer public key from config
				if config.VoucherManagement.VoucherSigning.Mode == "external" &&
					config.VoucherManagement.VoucherSigning.ManufacturerPublicKeyFile != "" {
					// Load manufacturer public key from config file (for external HSM mode)
					mfgPubKey, err = LoadManufacturerPublicKey(config.VoucherManagement.VoucherSigning.ManufacturerPublicKeyFile)
					if err != nil {
						return "", protocol.PublicKey{}, fmt.Errorf("failed to load manufacturer public key from config: %w", err)
					}
					fmt.Printf("✅ Using manufacturer public key from config for external HSM mode\n")
				} else {
					// Use traditional database-stored manufacturer key
					mfgKey, mfgChain, err := state.ManufacturerKey(ctx, info.KeyType, 3072)
					if err != nil {
						return "", protocol.PublicKey{}, err
					}
					encodedPubKey, err := encodePublicKey(info.KeyType, info.KeyEncoding, mfgKey.Public(), mfgChain)
					if err != nil {
						return "", protocol.PublicKey{}, err
					}
					mfgPubKey = *encodedPubKey
					fmt.Printf("✅ Using manufacturer public key from database\n")
				}

				// Return only device info (model) for voucher - keep serial private
				return info.DeviceInfo, mfgPubKey, nil
			},
			// Add required callbacks for DI server
			BeforeVoucherPersist: func(ctx context.Context, voucher *fdo.Voucher) error {
				{
					_, err := voucherCallbackService.BeforeVoucherPersist(ctx, state, voucher)
					return err
				}
			},
			AfterVoucherPersist: func(ctx context.Context, voucher fdo.Voucher) error { return nil },
			RvInfo:              func(ctx context.Context, voucher *fdo.Voucher) ([][]protocol.RvInstruction, error) { return nil, nil },
		},
		// Include empty TO0/TO1/TO2 responders to prevent panics, but they won't be used for DI
		TO0Responder: &fdo.TO0Server{
			Session: state,
			RVBlobs: state,
		},
		TO1Responder: &fdo.TO1Server{
			Session: state,
			RVBlobs: state,
		},
		TO2Responder: &fdo.TO2Server{
			Session:      state,
			Vouchers:     state,
			OwnerKeys:    state,
			DelegateKeys: state,
		},
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
	fmt.Printf("DEBUG: Config loaded: %+v\n", config)
	if err != nil {
		return fmt.Errorf("error listening on %s: %w", config.Server.Addr, err)
	}
	defer func() { _ = lis.Close() }()

	slog.Info("FDO Manufacturing Station starting",
		"local", lis.Addr().String(),
		"external", extAddr,
		"mode", "DI-only")

	// Start server in goroutine to monitor context cancellation
	errChan := make(chan error, 1)
	go func() {
		if config.Server.InsecureTLS {
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

func encodePublicKey(keyType protocol.KeyType, keyEncoding protocol.KeyEncoding, pub crypto.PublicKey, chain []*x509.Certificate) (*protocol.PublicKey, error) {
	if pub == nil && len(chain) > 0 {
		pub = chain[0].PublicKey
	}
	if pub == nil {
		return nil, fmt.Errorf("no key to encode")
	}

	switch keyEncoding {
	case protocol.X509KeyEnc, protocol.CoseKeyEnc:
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
