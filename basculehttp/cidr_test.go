// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
)

const testCIDRPrefix = "x1:webpa:cidr:"

// capsToken is a token that carries capabilities.
type capsToken []string

func (capsToken) Principal() string { return "test" }

func (ct capsToken) Capabilities() []string { return ct }

// approveCIDR runs a CIDRApprover against a request from remoteAddr, returning
// the error and the text of every warning raised.
func approveCIDR(t *testing.T, a *CIDRApprover, remoteAddr string, caps ...string) (error, []string) {
	t.Helper()
	ctx := bascule.WithWarnings(context.Background())
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = remoteAddr

	err := a.Approve(ctx, request, capsToken(caps))

	collected := bascule.GetWarnings(ctx)
	if len(collected) == 0 {
		return err, nil
	}

	warnings := make([]string, 0, len(collected))
	for _, w := range collected {
		warnings = append(warnings, w.String())
	}

	return err, warnings
}

func newCIDRApprover(t *testing.T, opts ...CIDRApproverOption) *CIDRApprover {
	t.Helper()
	a, err := NewCIDRApprover(opts...)
	require.NoError(t, err)
	require.NotNil(t, a)
	return a
}

func TestNewCIDRApproverErrors(t *testing.T) {
	tests := []struct {
		name string
		opts []CIDRApproverOption
	}{
		{name: "no prefixes"},
		{name: "empty prefixes", opts: []CIDRApproverOption{WithCIDRPrefixes()}},
		{name: "bad prefix regex", opts: []CIDRApproverOption{WithCIDRPrefixes("x1:(")}},
		{
			name: "nil resolver",
			opts: []CIDRApproverOption{WithCIDRPrefixes(testCIDRPrefix), WithOriginResolver(nil)},
		},
		{
			name: "zero cache size",
			opts: []CIDRApproverOption{WithCIDRPrefixes(testCIDRPrefix), WithCIDRCacheSize(0)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewCIDRApprover(tc.opts...)
			assert.Error(t, err)
			assert.Nil(t, a)
		})
	}
}

// TestCIDRApproverModes runs every row of the decision table in all four modes.
func TestCIDRApproverModes(t *testing.T) {
	const (
		malformed33  = `malformed; kind=cidr; cap="x1:webpa:cidr:10.0.0.0/33"`
		noCapability = "would-reject; kind=cidr; reason=no-cidr-capability"
		unknown      = "would-reject; kind=cidr; reason=unknown-origin"
		notAllowed   = `would-reject; kind=cidr; reason=origin-not-allowed; origin=192.0.2.60`
	)

	resolver, err := NewOriginResolver(WithTrustedProxies(netip.MustParsePrefix("10.0.0.0/8")))
	require.NoError(t, err)

	tests := []struct {
		name       string
		remoteAddr string
		caps       []string

		// requiredErr and correctErr are what the enforcing modes return.
		// The permissive modes return nil, raising rejectWarning instead.
		requiredErr   error
		correctErr    error
		rejectWarning string

		// malformed are the warnings raised in every mode
		malformed []string
	}{
		{
			name:          "no capabilities",
			remoteAddr:    "192.0.2.60:1234",
			requiredErr:   ErrNoCIDRCapability,
			rejectWarning: noCapability,
		},
		{
			name:          "only other prefixes",
			remoteAddr:    "192.0.2.60:1234",
			caps:          []string{"x1:webpa:api:.*:all", "x1:other:cidr:192.0.2.0/24"},
			requiredErr:   ErrNoCIDRCapability,
			rejectWarning: noCapability,
		},
		{
			name:          "unknown origin",
			remoteAddr:    "10.1.1.1:1234", // trusted, but forwarded nothing
			caps:          []string{testCIDRPrefix + "192.0.2.0/24"},
			requiredErr:   ErrUnknownOrigin,
			correctErr:    ErrUnknownOrigin,
			rejectWarning: unknown,
		},
		{
			name:       "origin inside",
			remoteAddr: "192.0.2.60:1234",
			caps:       []string{testCIDRPrefix + "198.51.100.0/24", testCIDRPrefix + "192.0.2.0/24"},
		},
		{
			name:          "origin inside none",
			remoteAddr:    "192.0.2.60:1234",
			caps:          []string{testCIDRPrefix + "198.51.100.0/24"},
			requiredErr:   ErrOriginNotAllowed,
			correctErr:    ErrOriginNotAllowed,
			rejectWarning: notAllowed,
		},
		{
			name:          "only malformed",
			remoteAddr:    "192.0.2.60:1234",
			caps:          []string{testCIDRPrefix + "10.0.0.0/33"},
			requiredErr:   ErrOriginNotAllowed,
			correctErr:    ErrOriginNotAllowed,
			rejectWarning: notAllowed,
			malformed:     []string{malformed33},
		},
		{
			name:       "malformed alongside a match",
			remoteAddr: "192.0.2.60:1234",
			caps:       []string{testCIDRPrefix + "10.0.0.0/33", testCIDRPrefix + "192.0.2.0/24"},
			malformed:  []string{malformed33},
		},
	}

	modes := []struct {
		name       string
		option     CIDRApproverOption
		required   bool
		permissive bool
	}{
		{name: "Required", option: WithCIDRRequired(), required: true},
		{name: "CorrectIfPresent", option: WithCIDRCorrectIfPresent()},
		{name: "PermissiveRequired", option: WithCIDRPermissiveRequired(), required: true, permissive: true},
		{name: "PermissiveCorrectIfPresent", option: WithCIDRPermissiveCorrectIfPresent(), permissive: true},
	}

	for _, mode := range modes {
		a := newCIDRApprover(t,
			WithCIDRPrefixes(testCIDRPrefix),
			WithOriginResolver(resolver),
			mode.option,
		)

		for _, tc := range tests {
			t.Run(fmt.Sprintf("%s/%s", mode.name, tc.name), func(t *testing.T) {
				expectedErr := tc.correctErr
				if mode.required {
					expectedErr = tc.requiredErr
				}

				expectedWarnings := tc.malformed
				if expectedErr != nil && mode.permissive {
					expectedWarnings = append(append([]string{}, tc.malformed...), tc.rejectWarning)
					expectedErr = nil
				}

				err, warnings := approveCIDR(t, a, tc.remoteAddr, tc.caps...)
				if expectedErr == nil {
					assert.NoError(t, err)
				} else {
					assert.ErrorIs(t, err, bascule.ErrUnauthorized)
					assert.ErrorIs(t, err, expectedErr)
				}

				assert.Equal(t, expectedWarnings, warnings)
			})
		}
	}
}

func TestCIDRApproverDefaultMode(t *testing.T) {
	a := newCIDRApprover(t, WithCIDRPrefixes(testCIDRPrefix))

	// Correct If Present: a token without a CIDR capability is Unrestricted ...
	err, warnings := approveCIDR(t, a, "192.0.2.60:1234")
	assert.NoError(t, err)
	assert.Empty(t, warnings)

	// ... but one that has a CIDR capability is enforced
	err, _ = approveCIDR(t, a, "192.0.2.60:1234", testCIDRPrefix+"198.51.100.0/24")
	assert.ErrorIs(t, err, ErrOriginNotAllowed)
}

func TestCIDRApproverLastModeWins(t *testing.T) {
	a := newCIDRApprover(t,
		WithCIDRPrefixes(testCIDRPrefix),
		WithCIDRPermissiveRequired(),
		WithCIDRRequired(),
	)

	err, warnings := approveCIDR(t, a, "192.0.2.60:1234")
	assert.ErrorIs(t, err, ErrNoCIDRCapability)
	assert.Empty(t, warnings)

	a = newCIDRApprover(t,
		WithCIDRPrefixes(testCIDRPrefix),
		WithCIDRRequired(),
		WithCIDRPermissiveCorrectIfPresent(),
	)

	err, warnings = approveCIDR(t, a, "192.0.2.60:1234")
	assert.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestCIDRApproverCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		prefixes   []string
		remoteAddr string
		capability string
		allowed    bool
		malformed  bool
	}{
		{
			name:       "IPv6 network",
			remoteAddr: "[2001:db8::1]:1234",
			capability: testCIDRPrefix + "2001:db8::/32",
			allowed:    true,
		},
		{
			name:       "single host",
			remoteAddr: "192.0.2.60:1234",
			capability: testCIDRPrefix + "192.0.2.60/32",
			allowed:    true,
		},
		{
			name:       "bare IP is malformed",
			remoteAddr: "192.0.2.60:1234",
			capability: testCIDRPrefix + "192.0.2.60",
			malformed:  true,
		},
		{
			name:       "garbage is malformed",
			remoteAddr: "192.0.2.60:1234",
			capability: testCIDRPrefix + "not-a-network",
			malformed:  true,
		},
		{
			name:       "IPv6 zone is malformed",
			remoteAddr: "[fe80::1]:1234",
			capability: testCIDRPrefix + "fe80::1%eth0/64",
			malformed:  true,
		},
		{
			name:       "IPv4 origin against an IPv6 network",
			remoteAddr: "192.0.2.60:1234",
			capability: testCIDRPrefix + "::/0",
		},
		{
			name:       "IPv6 origin against an IPv4 network",
			remoteAddr: "[2001:db8::1]:1234",
			capability: testCIDRPrefix + "0.0.0.0/0",
		},
		{
			name:       "IPv4-mapped IPv6 network",
			remoteAddr: "192.0.2.60:1234",
			capability: testCIDRPrefix + "::ffff:192.0.2.0/120",
			allowed:    true,
		},
		{
			name:       "IPv4-mapped IPv6 origin",
			remoteAddr: "[::ffff:192.0.2.60]:1234",
			capability: testCIDRPrefix + "192.0.2.0/24",
			allowed:    true,
		},
		{
			name:       "host bits set",
			remoteAddr: "192.0.2.60:1234",
			capability: testCIDRPrefix + "192.0.2.1/24",
			allowed:    true,
		},
		{
			name:       "regex prefix with subexpressions",
			prefixes:   []string{`x1:(webpa|xmidt):(cidr|net):`},
			remoteAddr: "192.0.2.60:1234",
			capability: "x1:xmidt:net:192.0.2.0/24",
			allowed:    true,
		},
		{
			name:       "top-level alternation stays anchored",
			prefixes:   []string{`x1:a:|x1:b:`},
			remoteAddr: "192.0.2.60:1234",
			capability: "junk:x1:b:192.0.2.0/24",
			allowed:    true, // not selected, so Unrestricted
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefixes := tc.prefixes
			if len(prefixes) == 0 {
				prefixes = []string{testCIDRPrefix}
			}

			a := newCIDRApprover(t, WithCIDRPrefixes(prefixes...))
			err, warnings := approveCIDR(t, a, tc.remoteAddr, tc.capability)
			if tc.allowed {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrOriginNotAllowed)
			}

			if tc.malformed {
				assert.Equal(t, []string{
					fmt.Sprintf(`malformed; kind=cidr; cap=%q`, tc.capability),
				}, warnings)
			} else {
				assert.Empty(t, warnings)
			}
		})
	}
}

func TestCIDRApproverNoWarningCollector(t *testing.T) {
	a := newCIDRApprover(t,
		WithCIDRPrefixes(testCIDRPrefix),
		WithCIDRPermissiveRequired(),
	)

	request := httptest.NewRequest("GET", "/", nil)
	assert.NotPanics(t, func() {
		assert.NoError(t, a.Approve(context.Background(), request, capsToken{testCIDRPrefix + "bad"}))
	})
}

func TestCIDRApproverCache(t *testing.T) {
	a := newCIDRApprover(t,
		WithCIDRPrefixes(testCIDRPrefix),
		WithCIDRCacheSize(2),
	)

	for i := range 5 {
		capability := fmt.Sprintf("%s192.0.2.%d/32", testCIDRPrefix, i)
		err, _ := approveCIDR(t, a, fmt.Sprintf("192.0.2.%d:1234", i), capability)
		assert.NoError(t, err)

		// a cached result is used the second time
		err, _ = approveCIDR(t, a, fmt.Sprintf("192.0.2.%d:1234", i), capability)
		assert.NoError(t, err)
	}

	assert.Equal(t, 2, a.cache.Len())
}
