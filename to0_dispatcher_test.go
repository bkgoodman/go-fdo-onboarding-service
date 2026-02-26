// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"net/url"
	"testing"
	"time"
)

func newTestDispatcher(mode string, allow []RvFilterEntry, deny []RvFilterEntry) *TO0Dispatcher {
	cfg := DefaultConfig()
	cfg.TO0.RvFilter = TO0RvFilterConfig{
		Mode:          mode,
		MaxAttempts:   3,
		RetryInterval: 30 * time.Second,
		Allow:         allow,
		Deny:          deny,
	}
	return &TO0Dispatcher{
		config:  cfg,
		entries: make(map[string]*to0RegistrationState),
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", raw, err)
	}
	return u
}

// --- allow_all mode tests ---

func TestFilterAllowAll_NoLists(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, nil)
	u := mustParseURL(t, "http://rv.example.com:8080")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("allow_all with no lists: got %d, want filterAllow", got)
	}
}

func TestFilterAllowAll_DenyMatch(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, []RvFilterEntry{
		{Host: "rv.example.com"},
	})
	u := mustParseURL(t, "http://rv.example.com:8080")
	if got := d.shouldAttempt(u); got != filterDeny {
		t.Errorf("allow_all with deny match: got %d, want filterDeny", got)
	}
}

func TestFilterAllowAll_DenyNoMatch(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, []RvFilterEntry{
		{Host: "other.example.com"},
	})
	u := mustParseURL(t, "http://rv.example.com:8080")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("allow_all with non-matching deny: got %d, want filterAllow", got)
	}
}

func TestFilterAllowAll_DenyGlob(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, []RvFilterEntry{
		{Host: "*.example.com"},
	})

	u1 := mustParseURL(t, "http://rv.example.com:8080")
	if got := d.shouldAttempt(u1); got != filterDeny {
		t.Errorf("allow_all glob deny *.example.com vs rv.example.com: got %d, want filterDeny", got)
	}

	u2 := mustParseURL(t, "http://rv.local:8080")
	if got := d.shouldAttempt(u2); got != filterAllow {
		t.Errorf("allow_all glob deny *.example.com vs rv.local: got %d, want filterAllow", got)
	}
}

func TestFilterAllowAll_DenyWithPort(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, []RvFilterEntry{
		{Host: "rv.local", Port: 8083},
	})

	u1 := mustParseURL(t, "http://rv.local:8083")
	if got := d.shouldAttempt(u1); got != filterDeny {
		t.Errorf("deny with matching port: got %d, want filterDeny", got)
	}

	u2 := mustParseURL(t, "http://rv.local:9090")
	if got := d.shouldAttempt(u2); got != filterAllow {
		t.Errorf("deny with non-matching port: got %d, want filterAllow", got)
	}
}

func TestFilterAllowAll_DenyWithScheme(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, []RvFilterEntry{
		{Host: "rv.local", Scheme: "https"},
	})

	u1 := mustParseURL(t, "https://rv.local:443")
	if got := d.shouldAttempt(u1); got != filterDeny {
		t.Errorf("deny with matching scheme: got %d, want filterDeny", got)
	}

	u2 := mustParseURL(t, "http://rv.local:8080")
	if got := d.shouldAttempt(u2); got != filterAllow {
		t.Errorf("deny with non-matching scheme: got %d, want filterAllow", got)
	}
}

// --- allow_list mode tests ---

func TestFilterAllowList_Match(t *testing.T) {
	d := newTestDispatcher("allow_list", []RvFilterEntry{
		{Host: "rv.local"},
	}, nil)

	u := mustParseURL(t, "http://rv.local:8080")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("allow_list with match: got %d, want filterAllow", got)
	}
}

func TestFilterAllowList_NoMatch(t *testing.T) {
	d := newTestDispatcher("allow_list", []RvFilterEntry{
		{Host: "rv.local"},
	}, nil)

	u := mustParseURL(t, "http://rv.cloud.com:443")
	if got := d.shouldAttempt(u); got != filterSkip {
		t.Errorf("allow_list with no match: got %d, want filterSkip", got)
	}
}

func TestFilterAllowList_Glob(t *testing.T) {
	d := newTestDispatcher("allow_list", []RvFilterEntry{
		{Host: "rv?.local"},
	}, nil)

	u1 := mustParseURL(t, "http://rv1.local:8080")
	if got := d.shouldAttempt(u1); got != filterAllow {
		t.Errorf("allow_list glob rv?.local vs rv1.local: got %d, want filterAllow", got)
	}

	u2 := mustParseURL(t, "http://rv12.local:8080")
	if got := d.shouldAttempt(u2); got != filterSkip {
		t.Errorf("allow_list glob rv?.local vs rv12.local: got %d, want filterSkip", got)
	}
}

func TestFilterAllowList_WithPort(t *testing.T) {
	d := newTestDispatcher("allow_list", []RvFilterEntry{
		{Host: "127.0.0.1", Port: 8083},
	}, nil)

	u1 := mustParseURL(t, "http://127.0.0.1:8083")
	if got := d.shouldAttempt(u1); got != filterAllow {
		t.Errorf("allow_list with matching port: got %d, want filterAllow", got)
	}

	u2 := mustParseURL(t, "http://127.0.0.1:9090")
	if got := d.shouldAttempt(u2); got != filterSkip {
		t.Errorf("allow_list with non-matching port: got %d, want filterSkip", got)
	}
}

// --- allow_list_warn mode tests ---

func TestFilterAllowListWarn_Match(t *testing.T) {
	d := newTestDispatcher("allow_list_warn", []RvFilterEntry{
		{Host: "rv.local"},
	}, nil)

	u := mustParseURL(t, "http://rv.local:8080")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("allow_list_warn with match: got %d, want filterAllow", got)
	}
}

func TestFilterAllowListWarn_NoMatch(t *testing.T) {
	d := newTestDispatcher("allow_list_warn", []RvFilterEntry{
		{Host: "rv.local"},
	}, nil)

	u := mustParseURL(t, "http://rv.cloud.com:443")
	if got := d.shouldAttempt(u); got != filterSkipWarn {
		t.Errorf("allow_list_warn with no match: got %d, want filterSkipWarn", got)
	}
}

// --- Empty/default mode tests ---

func TestFilterEmptyMode_DefaultsToAllowAll(t *testing.T) {
	d := newTestDispatcher("", nil, nil)
	u := mustParseURL(t, "http://rv.example.com:8080")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("empty mode should default to allow_all: got %d, want filterAllow", got)
	}
}

func TestFilterUnknownMode_DefaultsToAllowAll(t *testing.T) {
	d := newTestDispatcher("invalid_mode", nil, nil)
	u := mustParseURL(t, "http://rv.example.com:8080")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("unknown mode should default to allow_all: got %d, want filterAllow", got)
	}
}

// --- Case insensitivity ---

func TestFilterCaseInsensitive(t *testing.T) {
	d := newTestDispatcher("allow_list", []RvFilterEntry{
		{Host: "RV.Local"},
	}, nil)

	u := mustParseURL(t, "http://rv.local:8080")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("case insensitive match: got %d, want filterAllow", got)
	}
}

// --- Default port inference ---

func TestFilterDefaultPortHTTP(t *testing.T) {
	d := newTestDispatcher("allow_list", []RvFilterEntry{
		{Host: "rv.local", Port: 80},
	}, nil)

	// URL without explicit port — should infer 80 for http
	u := mustParseURL(t, "http://rv.local")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("http default port 80 match: got %d, want filterAllow", got)
	}
}

func TestFilterDefaultPortHTTPS(t *testing.T) {
	d := newTestDispatcher("allow_list", []RvFilterEntry{
		{Host: "rv.local", Port: 443},
	}, nil)

	u := mustParseURL(t, "https://rv.local")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("https default port 443 match: got %d, want filterAllow", got)
	}
}

// --- Retry eligibility ---

func TestRetryEligibility_Fresh(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, nil)
	entry := &to0RegistrationState{
		MaxAttempts: 3,
		Attempts:    0,
	}
	if !d.isEligibleForRetry(entry) {
		t.Error("fresh entry should be eligible for retry")
	}
}

func TestRetryEligibility_MaxExhausted(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, nil)
	entry := &to0RegistrationState{
		MaxAttempts: 3,
		Attempts:    3,
	}
	if d.isEligibleForRetry(entry) {
		t.Error("entry at max attempts should not be eligible")
	}
}

func TestRetryEligibility_TooSoon(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, nil)
	entry := &to0RegistrationState{
		MaxAttempts: 3,
		Attempts:    1,
		LastAttempt: time.Now(),
	}
	if d.isEligibleForRetry(entry) {
		t.Error("entry attempted just now should not be eligible (retry interval not elapsed)")
	}
}

func TestRetryEligibility_IntervalElapsed(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, nil)
	d.config.TO0.RvFilter.RetryInterval = 1 * time.Millisecond
	entry := &to0RegistrationState{
		MaxAttempts: 3,
		Attempts:    1,
		LastAttempt: time.Now().Add(-1 * time.Second),
	}
	if !d.isEligibleForRetry(entry) {
		t.Error("entry with elapsed interval should be eligible")
	}
}

func TestRetryEligibility_Registered(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, nil)
	entry := &to0RegistrationState{
		Registered: true,
	}
	if d.isEligibleForRetry(entry) {
		t.Error("registered entry should not be eligible")
	}
}

func TestRetryEligibility_InfiniteRetries(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, nil)
	entry := &to0RegistrationState{
		MaxAttempts: 0, // infinite
		Attempts:    999,
		LastAttempt: time.Now().Add(-1 * time.Hour),
	}
	if !d.isEligibleForRetry(entry) {
		t.Error("entry with max_attempts=0 (infinite) should always be eligible if interval elapsed")
	}
}

// --- matchesEntry edge cases ---

func TestMatchesEntry_EmptyHost(t *testing.T) {
	d := newTestDispatcher("allow_all", nil, nil)
	u := mustParseURL(t, "http://rv.local:8080")
	if d.matchesEntry(u, RvFilterEntry{Host: ""}) {
		t.Error("empty host pattern should never match")
	}
}

func TestMatchesEntry_IPAddress(t *testing.T) {
	d := newTestDispatcher("allow_list", []RvFilterEntry{
		{Host: "192.168.1.100"},
	}, nil)

	u := mustParseURL(t, "http://192.168.1.100:8080")
	if got := d.shouldAttempt(u); got != filterAllow {
		t.Errorf("IP address match: got %d, want filterAllow", got)
	}
}
