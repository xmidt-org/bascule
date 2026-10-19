// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"fmt"
	"net/http"
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
func approveCIDR(t *testing.T, a *CIDRApprover, remoteAddr string, caps ...string) ([]string, error) {
	t.Helper()
	ctx := bascule.WithWarnings(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = remoteAddr

	err := a.Approve(ctx, request, capsToken(caps))

	collected := bascule.GetWarnings(ctx)
	if len(collected) == 0 {
		return nil, err
	}

	warnings := make([]string, 0, len(collected))
	for _, w := range collected {
		warnings = append(warnings, w.String())
	}

	return warnings, err
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
		{name: "empty literal prefixes", opts: []CIDRApproverOption{WithCIDRPrefixLiterals()}},
		{name: "empty regex prefixes", opts: []CIDRApproverOption{WithCIDRPrefixRegexes()}},
		{name: "bad prefix regex", opts: []CIDRApproverOption{WithCIDRPrefixRegexes("x1:(")}},
		{name: "bad deprecated prefix regex", opts: []CIDRApproverOption{WithCIDRPrefixes("x1:(")}},
		{
			name: "nil resolver",
			opts: []CIDRApproverOption{WithCIDRPrefixLiterals(testCIDRPrefix), WithOriginResolver(nil)},
		},
		{
			name: "zero cache size",
			opts: []CIDRApproverOption{WithCIDRPrefixLiterals(testCIDRPrefix), WithCIDRCacheSize(0)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewCIDRApprover(tc.opts...)
			require.Error(t, err)
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
			WithCIDRPrefixLiterals(testCIDRPrefix),
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

				warnings, err := approveCIDR(t, a, tc.remoteAddr, tc.caps...)
				if expectedErr == nil {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, bascule.ErrUnauthorized)
					require.ErrorIs(t, err, expectedErr)
				}

				assert.Equal(t, expectedWarnings, warnings)
			})
		}
	}
}

func TestCIDRApproverDefaultMode(t *testing.T) {
	a := newCIDRApprover(t, WithCIDRPrefixLiterals(testCIDRPrefix))

	// Correct If Present: a token without a CIDR capability is Unrestricted ...
	warnings, err := approveCIDR(t, a, "192.0.2.60:1234")
	require.NoError(t, err)
	assert.Empty(t, warnings)

	// ... but one that has a CIDR capability is enforced
	_, err = approveCIDR(t, a, "192.0.2.60:1234", testCIDRPrefix+"198.51.100.0/24")
	assert.ErrorIs(t, err, ErrOriginNotAllowed)
}

func TestCIDRApproverLastModeWins(t *testing.T) {
	a := newCIDRApprover(t,
		WithCIDRPrefixLiterals(testCIDRPrefix),
		WithCIDRPermissiveRequired(),
		WithCIDRRequired(),
	)

	warnings, err := approveCIDR(t, a, "192.0.2.60:1234")
	require.ErrorIs(t, err, ErrNoCIDRCapability)
	assert.Empty(t, warnings)

	a = newCIDRApprover(t,
		WithCIDRPrefixLiterals(testCIDRPrefix),
		WithCIDRRequired(),
		WithCIDRPermissiveCorrectIfPresent(),
	)

	warnings, err = approveCIDR(t, a, "192.0.2.60:1234")
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestCIDRApproverCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		prefixes   []string
		regex      bool
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
			name:       "literal prefix with metacharacters",
			prefixes:   []string{`foo-bar|`},
			remoteAddr: "192.0.2.60:1234",
			capability: "foo-bar|198.51.100.0/24",
			allowed:    false,
		},
		{
			name:       "literal trailing bar is not an empty alternative",
			prefixes:   []string{`foo-bar|`},
			remoteAddr: "192.0.2.60:1234",
			capability: "198.51.100.0/24",
			allowed:    true, // not selected, so Unrestricted
		},
		{
			name:       "literal dot is not a wildcard",
			prefixes:   []string{`x1.webpa:cidr:`},
			remoteAddr: "192.0.2.60:1234",
			capability: "x1Xwebpa:cidr:198.51.100.0/24",
			allowed:    true, // not selected, so Unrestricted
		},
		{
			name:       "regex prefix with subexpressions",
			prefixes:   []string{`x1:(webpa|xmidt):(cidr|net):`},
			regex:      true,
			remoteAddr: "192.0.2.60:1234",
			capability: "x1:xmidt:net:192.0.2.0/24",
			allowed:    true,
		},
		{
			name:       "regex top-level alternation stays anchored",
			prefixes:   []string{`x1:a:|x1:b:`},
			regex:      true,
			remoteAddr: "192.0.2.60:1234",
			capability: "junk:x1:b:192.0.2.0/24",
			allowed:    true, // not selected, so Unrestricted
		},
		{
			name:       "regex trailing bar is an empty alternative",
			prefixes:   []string{`foo-bar|`},
			regex:      true,
			remoteAddr: "192.0.2.60:1234",
			capability: "198.51.100.0/24",
			allowed:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefixes := tc.prefixes
			if len(prefixes) == 0 {
				prefixes = []string{testCIDRPrefix}
			}

			option := WithCIDRPrefixLiterals
			if tc.regex {
				option = WithCIDRPrefixRegexes
			}

			a := newCIDRApprover(t, option(prefixes...))
			warnings, err := approveCIDR(t, a, tc.remoteAddr, tc.capability)
			if tc.allowed {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrOriginNotAllowed)
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
		WithCIDRPrefixLiterals(testCIDRPrefix),
		WithCIDRPermissiveRequired(),
	)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.NotPanics(t, func() {
		assert.NoError(t, a.Approve(context.Background(), request, capsToken{testCIDRPrefix + "bad"}))
	})
}

func TestCIDRApproverCache(t *testing.T) {
	a := newCIDRApprover(t,
		WithCIDRPrefixLiterals(testCIDRPrefix),
		WithCIDRCacheSize(2),
	)

	for i := range 5 {
		capability := fmt.Sprintf("%s192.0.2.%d/32", testCIDRPrefix, i)
		_, err := approveCIDR(t, a, fmt.Sprintf("192.0.2.%d:1234", i), capability)
		require.NoError(t, err)

		// a cached result is used the second time
		_, err = approveCIDR(t, a, fmt.Sprintf("192.0.2.%d:1234", i), capability)
		require.NoError(t, err)
	}

	assert.Equal(t, 2, a.cache.Len())
}
