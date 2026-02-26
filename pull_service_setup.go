// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

// setupPullService configures and registers the PullAuth and Pull API handlers.
// The holderKey is the owner key used for PullAuth challenge signing — this is
// the same key published in the DID document, so recipients can verify the
// holder's identity.
func setupPullService(cfg *Config, mux *http.ServeMux, holderKey crypto.Signer, voucherDir string) {
	if holderKey == nil {
		slog.Error("pull service: holder key is nil — cannot configure PullAuth")
		return
	}

	sessionStore := transfer.NewSessionStore(
		cfg.PullService.SessionTTL,
		cfg.PullService.MaxSessions,
	)

	tokenTTL := cfg.PullService.TokenTTL
	if tokenTTL == 0 {
		tokenTTL = 1 * time.Hour
	}

	tokenStore := newPullTokenStore(tokenTTL)

	pullAuthServer := &transfer.PullAuthServer{
		HolderKey:              holderKey,
		HashAlg:                protocol.Sha256Hash,
		Sessions:               sessionStore,
		RevealVoucherExistence: cfg.PullService.RevealVoucherExistence,
		IssueToken: func(ownerKey protocol.PublicKey) (string, time.Time, error) {
			return tokenStore.issue(ownerKey)
		},
	}

	pullAuthServer.RegisterHandlers(mux)
	slog.Info("pull service: PullAuth endpoints registered",
		"session_ttl", cfg.PullService.SessionTTL,
		"token_ttl", tokenTTL)

	// Wire the Pull API list/download handlers
	pullStore := NewPullVoucherStore(voucherDir)
	pullHolder := &transfer.HTTPPullHolder{
		Store:           pullStore,
		ValidateToken:   tokenStore.validate,
		DefaultPageSize: 50,
	}
	pullHolder.RegisterHandlers(mux)
	slog.Info("pull service: Pull API list/download endpoints registered",
		"voucher_dir", voucherDir)
}

// pullTokenStore manages session tokens issued after successful PullAuth.
type pullTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*pullToken
	ttl    time.Duration
}

type pullToken struct {
	ownerKeyFingerprint []byte
	expiresAt           time.Time
}

func newPullTokenStore(ttl time.Duration) *pullTokenStore {
	return &pullTokenStore{
		tokens: make(map[string]*pullToken),
		ttl:    ttl,
	}
}

func (s *pullTokenStore) issue(ownerKey protocol.PublicKey) (string, time.Time, error) {
	// Compute fingerprint from the CBOR-encoded owner key
	keyBytes, err := cbor.Marshal(ownerKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to encode owner key: %w", err)
	}
	hash := sha256.Sum256(keyBytes)
	fingerprint := hash[:]

	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate token: %w", err)
	}
	token := fmt.Sprintf("%x", tokenBytes)
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

	s.tokens[token] = &pullToken{
		ownerKeyFingerprint: fingerprint,
		expiresAt:           expiresAt,
	}

	return token, expiresAt, nil
}

func (s *pullTokenStore) validate(token string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tokens[token]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}
	if time.Now().After(t.expiresAt) {
		return nil, fmt.Errorf("token expired")
	}
	return t.ownerKeyFingerprint, nil
}
