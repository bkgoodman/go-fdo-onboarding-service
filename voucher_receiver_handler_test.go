// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

// --- pushTokenStore unit tests ---

func TestPushTokenStore_IssueAndValidate(t *testing.T) {
	store := newPushTokenStore(5 * time.Minute)

	callerKey := testProtocolPublicKey(t)
	token, expiresAt, err := store.issue(callerKey)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if expiresAt.Before(time.Now()) {
		t.Fatal("expected future expiration")
	}

	fingerprint, err := store.validate(token)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if len(fingerprint) == 0 {
		t.Fatal("expected non-empty fingerprint")
	}
}

func TestPushTokenStore_InvalidToken(t *testing.T) {
	store := newPushTokenStore(5 * time.Minute)

	_, err := store.validate("nonexistent-token")
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}
}

func TestPushTokenStore_ExpiredToken(t *testing.T) {
	store := newPushTokenStore(1 * time.Nanosecond)

	callerKey := testProtocolPublicKey(t)
	token, _, err := store.issue(callerKey)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	// Wait for expiration
	time.Sleep(2 * time.Millisecond)

	_, err = store.validate(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestPushTokenStore_GarbageCollection(t *testing.T) {
	store := newPushTokenStore(1 * time.Nanosecond)

	callerKey := testProtocolPublicKey(t)
	// Issue multiple tokens
	for i := 0; i < 5; i++ {
		_, _, err := store.issue(callerKey)
		if err != nil {
			t.Fatalf("issue %d failed: %v", i, err)
		}
	}

	// Wait for all to expire
	time.Sleep(2 * time.Millisecond)

	// Issue one more — should trigger GC of expired tokens
	_, _, err := store.issue(callerKey)
	if err != nil {
		t.Fatalf("issue after GC failed: %v", err)
	}

	store.mu.RLock()
	count := len(store.tokens)
	store.mu.RUnlock()

	if count != 1 {
		t.Fatalf("expected 1 token after GC, got %d", count)
	}
}

// --- buildPushAuthenticator unit tests ---

func TestBuildPushAuthenticator_NoAuthRequired(t *testing.T) {
	cfg := &Config{}
	cfg.VoucherReceiver.RequireAuth = false
	cfg.VoucherReceiver.AuthMethod = "both"

	auth := buildPushAuthenticator(cfg, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	if !auth(req) {
		t.Fatal("expected auth to pass when RequireAuth=false")
	}
}

func TestBuildPushAuthenticator_NoAuthHeader(t *testing.T) {
	cfg := &Config{}
	cfg.VoucherReceiver.RequireAuth = true
	cfg.VoucherReceiver.AuthMethod = "both"

	auth := buildPushAuthenticator(cfg, nil, newPushTokenStore(5*time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	if auth(req) {
		t.Fatal("expected auth to fail with no Authorization header")
	}
}

func TestBuildPushAuthenticator_FDOKeyAuthTokenAccepted(t *testing.T) {
	cfg := &Config{}
	cfg.VoucherReceiver.RequireAuth = true
	cfg.VoucherReceiver.AuthMethod = "fdokeyauth"

	store := newPushTokenStore(5 * time.Minute)
	callerKey := testProtocolPublicKey(t)
	token, _, err := store.issue(callerKey)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	auth := buildPushAuthenticator(cfg, nil, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if !auth(req) {
		t.Fatal("expected FDOKeyAuth session token to be accepted")
	}
}

func TestBuildPushAuthenticator_FDOKeyAuthMode_RejectsStaticToken(t *testing.T) {
	cfg := &Config{}
	cfg.VoucherReceiver.RequireAuth = true
	cfg.VoucherReceiver.AuthMethod = "fdokeyauth"
	cfg.VoucherReceiver.GlobalToken = "static-secret"

	store := newPushTokenStore(5 * time.Minute)
	auth := buildPushAuthenticator(cfg, nil, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	req.Header.Set("Authorization", "Bearer static-secret")
	if auth(req) {
		t.Fatal("expected static token to be rejected in fdokeyauth-only mode")
	}
}

func TestBuildPushAuthenticator_BearerMode_AcceptsGlobalToken(t *testing.T) {
	cfg := &Config{}
	cfg.VoucherReceiver.RequireAuth = true
	cfg.VoucherReceiver.AuthMethod = "bearer"
	cfg.VoucherReceiver.GlobalToken = "my-global-token"

	auth := buildPushAuthenticator(cfg, nil, newPushTokenStore(5*time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	req.Header.Set("Authorization", "Bearer my-global-token")
	if !auth(req) {
		t.Fatal("expected global token to be accepted in bearer mode")
	}
}

func TestBuildPushAuthenticator_BothMode_FDOKeyAuthFirst(t *testing.T) {
	cfg := &Config{}
	cfg.VoucherReceiver.RequireAuth = true
	cfg.VoucherReceiver.AuthMethod = "both"
	cfg.VoucherReceiver.GlobalToken = "static-secret"

	store := newPushTokenStore(5 * time.Minute)
	callerKey := testProtocolPublicKey(t)
	token, _, err := store.issue(callerKey)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	auth := buildPushAuthenticator(cfg, nil, store)

	// FDOKeyAuth token should work
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if !auth(req) {
		t.Fatal("expected FDOKeyAuth session token to be accepted in both mode")
	}

	// Static token should also work as fallback
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	req2.Header.Set("Authorization", "Bearer static-secret")
	if !auth(req2) {
		t.Fatal("expected static token to be accepted as fallback in both mode")
	}
}

func TestBuildPushAuthenticator_BothMode_InvalidToken(t *testing.T) {
	cfg := &Config{}
	cfg.VoucherReceiver.RequireAuth = true
	cfg.VoucherReceiver.AuthMethod = "both"
	cfg.VoucherReceiver.GlobalToken = "correct-token"

	store := newPushTokenStore(5 * time.Minute)
	// tokenManager is nil here, but that's fine — the global token check
	// happens before database token check, and we're testing that a wrong
	// token fails both FDOKeyAuth and bearer checks.
	auth := buildPushAuthenticator(cfg, nil, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	if auth(req) {
		t.Fatal("expected invalid token to be rejected")
	}
}

func TestBuildPushAuthenticator_MalformedAuthHeader(t *testing.T) {
	cfg := &Config{}
	cfg.VoucherReceiver.RequireAuth = true
	cfg.VoucherReceiver.AuthMethod = "both"

	auth := buildPushAuthenticator(cfg, nil, newPushTokenStore(5*time.Minute))

	// No space separator
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	req.Header.Set("Authorization", "BearerNoSpace")
	if auth(req) {
		t.Fatal("expected malformed auth header to be rejected")
	}
}

func TestBuildPushAuthenticator_DefaultsToAuthMethodBoth(t *testing.T) {
	cfg := &Config{}
	cfg.VoucherReceiver.RequireAuth = true
	cfg.VoucherReceiver.AuthMethod = "" // empty → defaults to "both"
	cfg.VoucherReceiver.GlobalToken = "my-token"

	auth := buildPushAuthenticator(cfg, nil, newPushTokenStore(5*time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vouchers", nil)
	req.Header.Set("Authorization", "Bearer my-token")
	if !auth(req) {
		t.Fatal("expected default auth_method to accept bearer token (both mode)")
	}
}

// --- test helpers ---

func testProtocolPublicKey(t *testing.T) protocol.PublicKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	pubKey, err := protocol.NewPublicKey(protocol.Secp256r1KeyType, &key.PublicKey, true)
	if err != nil {
		t.Fatalf("failed to create protocol public key: %v", err)
	}
	return *pubKey
}
