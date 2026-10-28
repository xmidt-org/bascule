// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xmidt-org/bascule"
)

const testCIDRPrefix = "webpa-prefix-cidr:"

// capsToken is a token that carries capabilities.
type capsToken []string

func (capsToken) Principal() string { return "test" }

func (ct capsToken) Capabilities() []string { return ct }

// principalToken is a token with a chosen principal that carries capabilities.
type principalToken struct {
	principal string
	caps      []string
}

func (pt principalToken) Principal() string { return pt.principal }

func (pt principalToken) Capabilities() []string { return pt.caps }

// approveCIDR runs a CIDRApprover against a request from remoteAddr, returning
// the error and the text of every warning raised.
func approveCIDR(t *testing.T, a *CIDRApprover, remoteAddr string, caps ...string) ([]string, error) {
	t.Helper()

	return approveCIDRToken(t, a, remoteAddr, capsToken(caps))
}

// approveCIDRToken runs a CIDRApprover against a request from remoteAddr
// presenting token, returning the error and the text of every warning raised.
func approveCIDRToken(t *testing.T, a *CIDRApprover, remoteAddr string, token bascule.Token) ([]string, error) {
	t.Helper()
	ctx := bascule.WithWarnings(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = remoteAddr

	err := a.Approve(ctx, request, token)

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
	t.Parallel()
	tests := []struct {
		name string
		opts []CIDRApproverOption
	}{
		{name: "no prefixes"},
		{name: "empty literal prefixes", opts: []CIDRApproverOption{WithCIDRPrefixLiterals()}},
		{name: "empty regex prefixes", opts: []CIDRApproverOption{WithCIDRPrefixRegexes()}},
		{name: "bad prefix regex", opts: []CIDRApproverOption{WithCIDRPrefixRegexes("prefix:(")}},
		{name: "bad deprecated prefix regex", opts: []CIDRApproverOption{WithCIDRPrefixes("prefix:(")}},
		{
			name: "nil resolver",
			opts: []CIDRApproverOption{WithCIDRPrefixLiterals(testCIDRPrefix), WithOriginResolver(nil)},
		},
		{
			name: "zero cache size",
			opts: []CIDRApproverOption{WithCIDRPrefixLiterals(testCIDRPrefix), WithCIDRCacheSize(0)},
		},
		{
			name: "nil cidr resolver",
			opts: []CIDRApproverOption{WithCIDRPrefixLiterals(testCIDRPrefix), WithCIDRResolver(nil)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := NewCIDRApprover(tc.opts...)
			require.Error(t, err)
			assert.Nil(t, a)
		})
	}
}

// TestCIDRApproverModes runs every row of the decision table in all four modes.
func TestCIDRApproverModes(t *testing.T) {
	t.Parallel()
	const (
		malformed33  = `malformed; kind=cidr; cap="webpa-prefix-cidr:10.0.0.0/33"`
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
			caps:          []string{"webpa-prefix-api:.*:all", "prefix:other:cidr:192.0.2.0/24"},
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
				t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
			prefixes:   []string{`webpa.prefix-cidr:`},
			remoteAddr: "192.0.2.60:1234",
			capability: "webpaXprefix-cidr:198.51.100.0/24",
			allowed:    true, // not selected, so Unrestricted
		},
		{
			name:       "regex prefix with subexpressions",
			prefixes:   []string{`(webpa|xmidt)-prefix-(cidr|net):`},
			regex:      true,
			remoteAddr: "192.0.2.60:1234",
			capability: "xmidt-prefix-net:192.0.2.0/24",
			allowed:    true,
		},
		{
			name:       "regex top-level alternation stays anchored",
			prefixes:   []string{`prefix-a:|prefix-b:`},
			regex:      true,
			remoteAddr: "192.0.2.60:1234",
			capability: "junk:prefix-b:192.0.2.0/24",
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
			t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// principalNetworks is a CIDRResolver that adds networks configured per
// principal to those the token carries, the common case for an issuer that
// does not put networks in tokens.
func principalNetworks(configured map[string][]string) CIDRResolver {
	parsed := make(map[string][]netip.Prefix, len(configured))
	for principal, networks := range configured {
		for _, n := range networks {
			parsed[principal] = append(parsed[principal], netip.MustParsePrefix(n))
		}
	}

	return func(_ context.Context, principal string, provided []netip.Prefix) ([]netip.Prefix, error) {
		return append(provided, parsed[principal]...), nil
	}
}

// TestCIDRApproverResolverPrincipals verifies a resolver can vouch for
// principals, and that what it returns is treated as carried by the token.
func TestCIDRApproverResolverPrincipals(t *testing.T) {
	t.Parallel()
	resolver := principalNetworks(map[string][]string{
		"joe":  {"192.0.2.0/24", "2001:db8::/32"},
		"jane": {"::ffff:198.51.100.0/120"}, // normalized like a capability
	})

	tests := []struct {
		name       string
		opts       []CIDRApproverOption
		token      principalToken
		remoteAddr string
		err        error
	}{
		{
			name:       "configured, inside",
			token:      principalToken{principal: "joe"},
			remoteAddr: "192.0.2.60:1234",
		},
		{
			name:       "configured, inside v6",
			token:      principalToken{principal: "joe"},
			remoteAddr: "[2001:db8::1]:1234",
		},
		{
			name:       "configured, outside",
			token:      principalToken{principal: "joe"},
			remoteAddr: "203.0.113.9:1234",
			err:        ErrOriginNotAllowed,
		},
		{
			name:       "configured, IPv4-mapped network",
			token:      principalToken{principal: "jane"},
			remoteAddr: "198.51.100.7:1234",
		},
		{
			name:       "not configured is unrestricted",
			token:      principalToken{principal: "nobody"},
			remoteAddr: "203.0.113.9:1234",
		},
		{
			name:       "not configured and required",
			opts:       []CIDRApproverOption{WithCIDRRequired()},
			token:      principalToken{principal: "nobody"},
			remoteAddr: "203.0.113.9:1234",
			err:        ErrNoCIDRCapability,
		},
		{
			name:       "configured satisfies required",
			opts:       []CIDRApproverOption{WithCIDRRequired()},
			token:      principalToken{principal: "joe"},
			remoteAddr: "192.0.2.60:1234",
		},
		{
			name: "token capability adds to configured",
			token: principalToken{
				principal: "joe",
				caps:      []string{testCIDRPrefix + "203.0.113.0/24"},
			},
			remoteAddr: "203.0.113.9:1234",
		},
		{
			name: "configured adds to token capability",
			token: principalToken{
				principal: "joe",
				caps:      []string{testCIDRPrefix + "203.0.113.0/24"},
			},
			remoteAddr: "192.0.2.60:1234",
		},
		{
			name: "outside both",
			token: principalToken{
				principal: "joe",
				caps:      []string{testCIDRPrefix + "203.0.113.0/24"},
			},
			remoteAddr: "198.51.100.7:1234",
			err:        ErrOriginNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := append(
				[]CIDRApproverOption{
					WithCIDRPrefixLiterals(testCIDRPrefix),
					WithCIDRResolver(resolver),
				},
				tc.opts...,
			)

			warnings, err := approveCIDRToken(t, newCIDRApprover(t, opts...), tc.remoteAddr, tc.token)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, bascule.ErrUnauthorized)
				require.ErrorIs(t, err, tc.err)
			}

			assert.Empty(t, warnings, "resolved networks never raise warnings")
		})
	}
}

// TestCIDRApproverResolverRequiresPrefixes verifies a resolver does not
// replace the prefixes: a CIDRApprover must still know which capabilities are
// its own.
func TestCIDRApproverResolverRequiresPrefixes(t *testing.T) {
	t.Parallel()
	a, err := NewCIDRApprover(WithCIDRResolver(principalNetworks(map[string][]string{"joe": {"192.0.2.0/24"}})))
	require.ErrorIs(t, err, ErrNoCIDRPrefixes)
	assert.Nil(t, a)
}

// TestCIDRApproverResolverInput verifies what a resolver is handed: the
// context, the principal, and the provided networks in token order with an
// invalid prefix for each malformed capability, whose warning is still raised.
func TestCIDRApproverResolverInput(t *testing.T) {
	t.Parallel()
	type key struct{}
	ctx := context.WithValue(bascule.WithWarnings(context.Background()), key{}, "marker")

	var (
		gotPrincipal string
		gotProvided  []netip.Prefix
	)

	a := newCIDRApprover(t,
		WithCIDRPrefixLiterals(testCIDRPrefix),
		WithCIDRResolver(func(ctx context.Context, principal string, provided []netip.Prefix) ([]netip.Prefix, error) {
			assert.Equal(t, "marker", ctx.Value(key{}), "the request's context is passed through")
			gotPrincipal = principal
			gotProvided = provided

			return provided, nil
		}),
	)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "192.0.2.60:1234"

	err := a.Approve(ctx, request, principalToken{
		principal: "joe",
		caps: []string{
			"webpa-prefix-api:.*:all", // not selected
			testCIDRPrefix + "198.51.100.0/24",
			testCIDRPrefix + "10.0.0.0/33", // malformed
			testCIDRPrefix + "192.0.2.0/24",
		},
	})
	require.NoError(t, err)

	assert.Equal(t, "joe", gotPrincipal)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		{},
		netip.MustParsePrefix("192.0.2.0/24"),
	}, gotProvided)

	warnings := bascule.GetWarnings(ctx)
	require.Len(t, warnings, 1)
	assert.Equal(t, `malformed; kind=cidr; cap="webpa-prefix-cidr:10.0.0.0/33"`, warnings[0].String())
}

// TestCIDRApproverResolverOutput verifies the approver uses what a resolver
// returns in place of the token's networks.
func TestCIDRApproverResolverOutput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		resolved   []netip.Prefix
		remoteAddr string
		err        error
	}{
		{
			name:       "override allows",
			resolved:   []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			remoteAddr: "203.0.113.9:1234",
		},
		{
			name:       "override rejects a carried network",
			resolved:   []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			remoteAddr: "192.0.2.60:1234",
			err:        ErrOriginNotAllowed,
		},
		{
			name:       "none is unrestricted",
			remoteAddr: "198.51.100.7:1234",
		},
		{
			name:       "only an invalid network is present but matches nothing",
			resolved:   []netip.Prefix{{}},
			remoteAddr: "192.0.2.60:1234",
			err:        ErrOriginNotAllowed,
		},
		{
			name:       "IPv4-mapped is normalized",
			resolved:   []netip.Prefix{netip.MustParsePrefix("::ffff:203.0.113.0/120")},
			remoteAddr: "203.0.113.9:1234",
		},
		{
			name:       "host bits are masked",
			resolved:   []netip.Prefix{netip.MustParsePrefix("203.0.113.77/24")},
			remoteAddr: "203.0.113.9:1234",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := newCIDRApprover(t,
				WithCIDRPrefixLiterals(testCIDRPrefix),
				WithCIDRResolver(func(context.Context, string, []netip.Prefix) ([]netip.Prefix, error) {
					return tc.resolved, nil
				}),
			)

			// the token carries 192.0.2.0/24, which the resolver replaces
			warnings, err := approveCIDR(t, a, tc.remoteAddr, testCIDRPrefix+"192.0.2.0/24")
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, bascule.ErrUnauthorized)
				require.ErrorIs(t, err, tc.err)
			}

			assert.Empty(t, warnings)
		})
	}
}

// TestCIDRApproverResolverDenies verifies a resolver error denies the request
// in an enforcing mode and warns in a permissive one, without showing the
// error to the caller, and before the origin is consulted.
func TestCIDRApproverResolverDenies(t *testing.T) {
	t.Parallel()
	denied := errors.New("joe is blocked")
	resolver := func(_ context.Context, principal string, provided []netip.Prefix) ([]netip.Prefix, error) {
		if principal == "joe" {
			return nil, denied
		}

		return provided, nil
	}

	// the origin resolver would report unknown-origin for a trusted peer that
	// forwarded nothing, which must not be reached
	origin, err := NewOriginResolver(WithTrustedProxies(netip.MustParsePrefix("10.0.0.0/8")))
	require.NoError(t, err)

	for _, mode := range []CIDRApproverOption{WithCIDRRequired(), WithCIDRCorrectIfPresent()} {
		a := newCIDRApprover(t,
			WithCIDRPrefixLiterals(testCIDRPrefix),
			WithCIDRResolver(resolver),
			WithOriginResolver(origin),
			mode,
		)

		warnings, err := approveCIDRToken(t, a, "10.1.1.1:1234", principalToken{principal: "joe"})
		require.ErrorIs(t, err, bascule.ErrUnauthorized)
		require.ErrorIs(t, err, ErrCIDRDenied)
		require.ErrorIs(t, err, denied, "the resolver's error is reachable for logging")
		assert.Empty(t, warnings)
		assert.Equal(t, http.StatusForbidden, DefaultErrorStatusCoder(nil, err))

		_, err = approveCIDRToken(t, a, "192.0.2.60:1234",
			principalToken{principal: "jane", caps: []string{testCIDRPrefix + "192.0.2.0/24"}})
		require.NoError(t, err, "other principals are unaffected")
	}

	for _, mode := range []CIDRApproverOption{WithCIDRPermissiveRequired(), WithCIDRPermissiveCorrectIfPresent()} {
		a := newCIDRApprover(t,
			WithCIDRPrefixLiterals(testCIDRPrefix),
			WithCIDRResolver(resolver),
			WithOriginResolver(origin),
			mode,
		)

		warnings, err := approveCIDRToken(t, a, "10.1.1.1:1234", principalToken{principal: "joe"})
		require.NoError(t, err)
		assert.Equal(t, []string{"would-reject; kind=cidr; reason=denied"}, warnings)
	}
}

// TestCIDRApproverResolverNilToken verifies a missing token does not panic,
// and reaches the resolver as an empty principal with nothing provided.
func TestCIDRApproverResolverNilToken(t *testing.T) {
	t.Parallel()
	called := false
	a := newCIDRApprover(t,
		WithCIDRPrefixLiterals(testCIDRPrefix),
		WithCIDRResolver(func(_ context.Context, principal string, provided []netip.Prefix) ([]netip.Prefix, error) {
			called = true
			assert.Empty(t, principal)
			assert.Empty(t, provided)

			return nil, nil
		}),
	)

	assert.NotPanics(t, func() {
		_, err := approveCIDRToken(t, a, "203.0.113.9:1234", nil)
		assert.NoError(t, err)
	})

	assert.True(t, called)
}

func TestDefaultCIDRResolver(t *testing.T) {
	t.Parallel()
	provided := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), {}}

	got, err := DefaultCIDRResolver(context.Background(), "joe", provided)
	require.NoError(t, err)
	assert.Equal(t, provided, got)

	got, err = DefaultCIDRResolver(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}
