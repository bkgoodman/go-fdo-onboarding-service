// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

// setupVoucherReceiver configures and registers the voucher push receiver with
// FDOKeyAuth (primary) and Bearer token (secondary) authentication on the given mux.
// It registers:
//   - POST {endpoint}            — voucher push (via library HTTPPushReceiver)
//   - POST {endpoint}/auth/hello — FDOKeyAuth handshake step 1
//   - POST {endpoint}/auth/prove — FDOKeyAuth handshake step 2
func setupVoucherReceiver(
	cfg *Config,
	mux *http.ServeMux,
	state *sqlite.DB,
	serverKey crypto.Signer,
	deviceStorage *DeviceStorageManager,
	dispatcher *TO0Dispatcher,
) {
	tokenManager := NewVoucherReceiverTokenManager(state.DB())

	// FDOKeyAuth token store for push sessions
	pushTokenStore := newPushTokenStore(cfg.VoucherReceiver.SessionTTL)

	// Set up FDOKeyAuth server for push endpoint
	authMethod := strings.ToLower(cfg.VoucherReceiver.AuthMethod)
	if authMethod == "" {
		authMethod = "both"
	}

	if authMethod == "fdokeyauth" || authMethod == "both" {
		if serverKey == nil {
			slog.Error("voucher receiver: FDOKeyAuth requires server key (enable DID or provide owner key)")
		} else {
			authServer := &transfer.FDOKeyAuthServer{
				ServerKey: serverKey,
				HashAlg:   protocol.Sha256Hash,
				Sessions: transfer.NewSessionStore(
					cfg.VoucherReceiver.SessionTTL,
					cfg.VoucherReceiver.MaxSessions,
				),
				IssueToken: func(callerKey protocol.PublicKey) (string, time.Time, error) {
					return pushTokenStore.issue(callerKey)
				},
			}
			authServer.RegisterHandlers(mux, cfg.VoucherReceiver.Endpoint)
			slog.Info("voucher receiver: FDOKeyAuth endpoints registered",
				"hello", cfg.VoucherReceiver.Endpoint+"/auth/hello",
				"prove", cfg.VoucherReceiver.Endpoint+"/auth/prove")
		}
	}

	// Build hybrid authenticator
	authenticator := buildPushAuthenticator(cfg, tokenManager, pushTokenStore)

	// Build the library push receiver
	pushStore := NewPullVoucherStore(deviceStorage.VoucherDir)
	receiver := &transfer.HTTPPushReceiver{
		Store:        pushStore,
		Authenticate: authenticator,
		OnReceive: func(ctx context.Context, data *transfer.VoucherData, storagePath string) {
			// Audit logging
			var guid protocol.GUID
			if data.Voucher != nil {
				guid = data.Voucher.Header.Val.GUID
			}
			if err := tokenManager.LogReceivedVoucher(ctx, guid, data.SerialNumber, data.ModelNumber, "", "", "", 0); err != nil {
				slog.Error("voucher receiver: failed to log audit entry", "guid", data.GUID, "error", err)
			}

			// Submit to TO0 dispatcher for RV registration
			if dispatcher != nil && !cfg.TO0.Bypass && data.Voucher != nil {
				dispatcher.SubmitVoucher(ctx, data.Voucher)
			}
		},
	}

	mux.Handle("POST "+cfg.VoucherReceiver.Endpoint, receiver)

	slog.Info("Voucher receiver enabled",
		"endpoint", cfg.VoucherReceiver.Endpoint,
		"auth_method", authMethod,
		"validate_ownership", cfg.VoucherReceiver.ValidateOwnership,
		"require_auth", cfg.VoucherReceiver.RequireAuth)
}

// buildPushAuthenticator creates a PushReceiverAuth function that checks
// FDOKeyAuth session tokens first, then falls back to Bearer tokens.
func buildPushAuthenticator(
	cfg *Config,
	tokenManager *VoucherReceiverTokenManager,
	pushTokenStore *pushTokenStore,
) transfer.PushReceiverAuth {
	authMethod := strings.ToLower(cfg.VoucherReceiver.AuthMethod)
	if authMethod == "" {
		authMethod = "both"
	}

	return func(r *http.Request) bool {
		// If auth not required, allow all
		if !cfg.VoucherReceiver.RequireAuth {
			return true
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return false
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			return false
		}

		token := parts[1]

		// Try FDOKeyAuth session token (primary)
		if authMethod == "fdokeyauth" || authMethod == "both" {
			if strings.EqualFold(parts[0], "Bearer") {
				if _, err := pushTokenStore.validate(token); err == nil {
					return true
				}
			}
		}

		// Try static Bearer tokens (secondary / fallback)
		if authMethod == "bearer" || authMethod == "both" {
			if strings.EqualFold(parts[0], "Bearer") {
				// Check global token
				if cfg.VoucherReceiver.GlobalToken != "" && token == cfg.VoucherReceiver.GlobalToken {
					return true
				}
				// Check database tokens
				if tokenManager != nil {
					ctx := r.Context()
					valid, err := tokenManager.ValidateReceiverToken(ctx, token)
					if err != nil {
						slog.Error("voucher receiver: token validation error", "error", err)
						return false
					}
					if valid {
						return true
					}
				}
			}
		}

		return false
	}
}

// pushTokenStore manages session tokens issued after successful FDOKeyAuth
// for push operations. Mirrors the pullTokenStore pattern used by the pull service.
type pushTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*pushToken
	ttl    time.Duration
}

type pushToken struct {
	callerKeyFingerprint []byte
	expiresAt            time.Time
}

func newPushTokenStore(ttl time.Duration) *pushTokenStore {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &pushTokenStore{
		tokens: make(map[string]*pushToken),
		ttl:    ttl,
	}
}

func (s *pushTokenStore) issue(callerKey protocol.PublicKey) (string, time.Time, error) {
	keyBytes, err := cbor.Marshal(callerKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to encode caller key: %w", err)
	}
	hash := sha256.Sum256(keyBytes)
	fingerprint := hash[:]

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(s.ttl)

	s.mu.Lock()
	defer s.mu.Unlock()

	// GC expired tokens
	now := time.Now()
	for k, v := range s.tokens {
		if now.After(v.expiresAt) {
			delete(s.tokens, k)
		}
	}

	s.tokens[token] = &pushToken{
		callerKeyFingerprint: fingerprint,
		expiresAt:            expiresAt,
	}

	return token, expiresAt, nil
}

func (s *pushTokenStore) validate(token string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tokens[token]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}
	if time.Now().After(t.expiresAt) {
		return nil, fmt.Errorf("token expired")
	}
	return t.callerKeyFingerprint, nil
}
