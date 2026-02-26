// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

// to0RegistrationState tracks per-(GUID, RV-URL) TO0 registration state.
type to0RegistrationState struct {
	GUID        protocol.GUID
	RVURL       string
	Voucher     *fdo.Voucher
	Attempts    int
	MaxAttempts int
	LastAttempt time.Time
	LastError   error
	Registered  bool
	TTL         uint32
}

// registrationKey returns a unique key for tracking a (GUID, URL) pair.
func registrationKey(guid protocol.GUID, rvURL string) string {
	return hex.EncodeToString(guid[:]) + "|" + rvURL
}

// TO0Dispatcher handles TO0 registration for vouchers by extracting RV entries
// from voucher headers and applying the configured filter policy.
type TO0Dispatcher struct {
	config *Config
	db     *sqlite.DB

	mu      sync.Mutex
	entries map[string]*to0RegistrationState
	queue   chan *fdo.Voucher
	wg      sync.WaitGroup
}

// NewTO0Dispatcher creates a new dispatcher. Call Start() to begin processing.
func NewTO0Dispatcher(cfg *Config, db *sqlite.DB) *TO0Dispatcher {
	return &TO0Dispatcher{
		config:  cfg,
		db:      db,
		entries: make(map[string]*to0RegistrationState),
		queue:   make(chan *fdo.Voucher, 64),
	}
}

// Start launches the background processing goroutines.
func (d *TO0Dispatcher) Start(ctx context.Context) {
	d.wg.Add(2)

	// Voucher submission processor
	go func() {
		defer d.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case ov := <-d.queue:
				d.processVoucher(ctx, ov)
			}
		}
	}()

	// Retry loop
	go func() {
		defer d.wg.Done()
		d.retryLoop(ctx)
	}()

	slog.Info("TO0 dispatcher started",
		"mode", d.config.TO0.RvFilter.Mode,
		"max_attempts", d.config.TO0.RvFilter.MaxAttempts,
		"retry_interval", d.config.TO0.RvFilter.RetryInterval)
}

// Stop waits for background goroutines to finish.
func (d *TO0Dispatcher) Stop() {
	d.wg.Wait()
}

// SubmitVoucher enqueues a voucher for async TO0 processing.
func (d *TO0Dispatcher) SubmitVoucher(_ context.Context, ov *fdo.Voucher) {
	guid := ov.Header.Val.GUID
	guidStr := hex.EncodeToString(guid[:])
	slog.Info("TO0 dispatcher: voucher submitted for processing", "guid", guidStr)
	select {
	case d.queue <- ov:
	default:
		slog.Warn("TO0 dispatcher: queue full, dropping voucher", "guid", guidStr)
	}
}

// processVoucher extracts RV directives from the voucher header, filters them,
// and enqueues registration attempts.
func (d *TO0Dispatcher) processVoucher(ctx context.Context, ov *fdo.Voucher) {
	guid := ov.Header.Val.GUID
	guidStr := hex.EncodeToString(guid[:])

	directives := protocol.ParseOwnerRvInfo(ov.Header.Val.RvInfo)
	if len(directives) == 0 {
		slog.Warn("TO0 dispatcher: voucher has no RV directives", "guid", guidStr)
		return
	}

	for _, directive := range directives {
		if directive.Bypass {
			continue
		}
		for _, u := range directive.URLs {
			if u == nil {
				continue
			}
			rvURL := u.String()
			decision := d.shouldAttempt(u)

			switch decision {
			case filterAllow:
				slog.Info("TO0 dispatcher: RV entry accepted by filter",
					"guid", guidStr, "rv_url", rvURL)
				d.enqueueRegistration(ov, rvURL)
			case filterDeny:
				slog.Info("TO0 dispatcher: RV entry denied by filter",
					"guid", guidStr, "rv_url", rvURL)
			case filterSkip:
				slog.Debug("TO0 dispatcher: RV entry skipped (not in allow list)",
					"guid", guidStr, "rv_url", rvURL)
			case filterSkipWarn:
				slog.Warn("TO0 dispatcher: RV entry skipped (not in allow list)",
					"guid", guidStr, "rv_url", rvURL)
			}
		}
	}

	// Attempt all newly enqueued registrations immediately
	d.attemptPending(ctx)
}

type filterDecision int

const (
	filterAllow    filterDecision = iota // attempt TO0
	filterDeny                           // explicitly denied
	filterSkip                           // not in allow list (silent)
	filterSkipWarn                       // not in allow list (warn)
)

// shouldAttempt applies the mode-specific filter to a parsed RV URL.
func (d *TO0Dispatcher) shouldAttempt(u *url.URL) filterDecision {
	mode := d.config.TO0.RvFilter.Mode
	switch mode {
	case "allow_all", "":
		// Try everything except deny list
		if d.matchesList(u, d.config.TO0.RvFilter.Deny) {
			return filterDeny
		}
		return filterAllow

	case "allow_list":
		if d.matchesList(u, d.config.TO0.RvFilter.Allow) {
			return filterAllow
		}
		return filterSkip

	case "allow_list_warn":
		if d.matchesList(u, d.config.TO0.RvFilter.Allow) {
			return filterAllow
		}
		return filterSkipWarn

	default:
		slog.Warn("TO0 dispatcher: unknown filter mode, defaulting to allow_all",
			"mode", mode)
		return filterAllow
	}
}

// matchesList checks if a URL matches any entry in a filter list.
func (d *TO0Dispatcher) matchesList(u *url.URL, entries []RvFilterEntry) bool {
	for _, entry := range entries {
		if d.matchesEntry(u, entry) {
			return true
		}
	}
	return false
}

// matchesEntry checks if a URL matches a single filter entry.
func (d *TO0Dispatcher) matchesEntry(u *url.URL, entry RvFilterEntry) bool {
	// Match host (required) — case-insensitive, supports glob
	host := strings.ToLower(u.Hostname())
	pattern := strings.ToLower(entry.Host)
	if pattern == "" {
		return false
	}
	matched, err := filepath.Match(pattern, host)
	if err != nil || !matched {
		return false
	}

	// Match port (optional)
	if entry.Port != 0 {
		portStr := u.Port()
		if portStr == "" {
			// Derive default port from scheme
			switch u.Scheme {
			case "http":
				portStr = "80"
			case "https":
				portStr = "443"
			default:
				portStr = "0"
			}
		}
		port, _ := strconv.Atoi(portStr)
		if port != entry.Port {
			return false
		}
	}

	// Match scheme (optional)
	if entry.Scheme != "" {
		if !strings.EqualFold(u.Scheme, entry.Scheme) {
			return false
		}
	}

	return true
}

// enqueueRegistration adds a pending registration if not already tracked.
func (d *TO0Dispatcher) enqueueRegistration(ov *fdo.Voucher, rvURL string) {
	guid := ov.Header.Val.GUID
	key := registrationKey(guid, rvURL)

	d.mu.Lock()
	defer d.mu.Unlock()

	if existing, ok := d.entries[key]; ok {
		if existing.Registered {
			return // already registered
		}
		// Re-submit resets attempts (e.g. new voucher push)
		existing.Voucher = ov
		existing.Attempts = 0
		existing.LastError = nil
		return
	}

	d.entries[key] = &to0RegistrationState{
		GUID:        guid,
		RVURL:       rvURL,
		Voucher:     ov,
		MaxAttempts: d.config.TO0.RvFilter.MaxAttempts,
	}
}

// attemptPending tries TO0 for all pending (non-registered, eligible) entries.
func (d *TO0Dispatcher) attemptPending(ctx context.Context) {
	d.mu.Lock()
	// Snapshot pending entries
	var pending []*to0RegistrationState
	for _, entry := range d.entries {
		if !entry.Registered && d.isEligibleForRetry(entry) {
			pending = append(pending, entry)
		}
	}
	d.mu.Unlock()

	for _, entry := range pending {
		if ctx.Err() != nil {
			return
		}
		d.attemptRegistration(ctx, entry)
	}
}

// isEligibleForRetry checks if an entry should be retried.
func (d *TO0Dispatcher) isEligibleForRetry(entry *to0RegistrationState) bool {
	if entry.Registered {
		return false
	}
	// Max attempts exhausted (0 = infinite)
	if entry.MaxAttempts > 0 && entry.Attempts >= entry.MaxAttempts {
		return false
	}
	// Respect retry interval
	if entry.Attempts > 0 && time.Since(entry.LastAttempt) < d.config.TO0.RvFilter.RetryInterval {
		return false
	}
	return true
}

// attemptRegistration performs a single TO0 registration attempt.
func (d *TO0Dispatcher) attemptRegistration(ctx context.Context, entry *to0RegistrationState) {
	guidStr := hex.EncodeToString(entry.GUID[:])

	d.mu.Lock()
	entry.Attempts++
	entry.LastAttempt = time.Now()
	d.mu.Unlock()

	slog.Info("TO0 dispatcher: attempting registration",
		"guid", guidStr,
		"rv_url", entry.RVURL,
		"attempt", entry.Attempts,
		"max_attempts", entry.MaxAttempts)

	// Build TO2 address from our external address
	to2Addrs, err := d.buildTO2Addrs()
	if err != nil {
		d.mu.Lock()
		entry.LastError = err
		d.mu.Unlock()
		slog.Error("TO0 dispatcher: failed to build TO2 addresses",
			"guid", guidStr, "error", err)
		return
	}

	// Build transport for the RV server
	rvTransport := d.buildRVTransport(entry.RVURL)

	// Perform TO0
	client := &fdo.TO0Client{
		Vouchers:     d.db,
		OwnerKeys:    d.db,
		DelegateKeys: d.db,
	}

	refresh, err := client.RegisterBlob(ctx, rvTransport, entry.GUID, to2Addrs, d.config.TO0.Delegate)
	if err != nil {
		d.mu.Lock()
		entry.LastError = err
		d.mu.Unlock()
		slog.Error("TO0 dispatcher: registration failed",
			"guid", guidStr,
			"rv_url", entry.RVURL,
			"attempt", entry.Attempts,
			"error", err)
		return
	}

	d.mu.Lock()
	entry.Registered = true
	entry.TTL = refresh
	entry.LastError = nil
	d.mu.Unlock()

	slog.Info("TO0 dispatcher: registration successful",
		"guid", guidStr,
		"rv_url", entry.RVURL,
		"ttl", time.Duration(refresh)*time.Second)
}

// buildTO2Addrs constructs the TO2 address list from the server's external address.
func (d *TO0Dispatcher) buildTO2Addrs() ([]protocol.RvTO2Addr, error) {
	extAddr := d.config.Server.ExtAddr
	if extAddr == "" {
		extAddr = d.config.Server.Addr
	}

	proto := protocol.HTTPTransport
	if d.config.Server.UseTLS {
		proto = protocol.HTTPSTransport
	}

	host, portStr, err := net.SplitHostPort(extAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid external addr %q: %w", extAddr, err)
	}
	if host == "" {
		host = "localhost"
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid external port %q: %w", portStr, err)
	}

	return []protocol.RvTO2Addr{
		{
			DNSAddress:        &host,
			Port:              uint16(portNum),
			TransportProtocol: proto,
		},
	}, nil
}

// buildRVTransport creates an HTTP transport for communicating with an RV server.
func (d *TO0Dispatcher) buildRVTransport(rvURL string) fdo.Transport {
	return tlsTransport(rvURL, nil)
}

// retryLoop periodically scans for entries that need retry.
func (d *TO0Dispatcher) retryLoop(ctx context.Context) {
	// Use half the retry interval for tick frequency, with a minimum of 5s
	tickInterval := d.config.TO0.RvFilter.RetryInterval / 2
	if tickInterval < 5*time.Second {
		tickInterval = 5 * time.Second
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.attemptPending(ctx)
		}
	}
}

// RegisterVoucherByGUID performs TO0 for a specific voucher GUID. Used for the
// to0.guid CLI flag at startup.
func (d *TO0Dispatcher) RegisterVoucherByGUID(ctx context.Context, guidStr string) error {
	guidBytes, err := hex.DecodeString(strings.ReplaceAll(guidStr, "-", ""))
	if err != nil {
		return fmt.Errorf("error parsing GUID: %w", err)
	}
	if len(guidBytes) != 16 {
		return fmt.Errorf("GUID must be 16 bytes, got %d", len(guidBytes))
	}
	var guid protocol.GUID
	copy(guid[:], guidBytes)

	ov, err := d.db.Voucher(ctx, guid)
	if err != nil {
		return fmt.Errorf("error looking up voucher for GUID %s: %w", guidStr, err)
	}

	d.processVoucher(ctx, ov)
	return nil
}

// SubmitVoucherFunc returns a callback suitable for use as AfterVoucherPersist.
func (d *TO0Dispatcher) SubmitVoucherFunc() func(context.Context, fdo.Voucher) error {
	return func(ctx context.Context, ov fdo.Voucher) error {
		d.SubmitVoucher(ctx, &ov)
		return nil
	}
}

// tlsTransport is expected to be defined in main.go (already exists).
// We reference it here since both files are in package main.

// Ensure the TO0Dispatcher uses the http transport type for building transports.
var _ fdo.Transport = (*transport.Transport)(nil)
