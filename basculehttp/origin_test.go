// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"maps"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOriginResolverInvalidProxy(t *testing.T) {
	r, err := NewOriginResolver(WithTrustedProxies(netip.Prefix{}))
	assert.Error(t, err)
	assert.Nil(t, r)
}

func TestOriginResolverOrigin(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8:ffff::/48"),
	}

	tests := []struct {
		name       string
		trusted    []netip.Prefix
		remoteAddr string
		headers    map[string][]string
		expected   string // empty means not ok
	}{
		{
			name:       "no trusted proxies, headers ignored",
			remoteAddr: "198.51.100.7:1234",
			headers: map[string][]string{
				"Forwarded":       {"for=192.0.2.60"},
				"X-Forwarded-For": {"192.0.2.61"},
			},
			expected: "198.51.100.7",
		},
		{
			name:       "untrusted peer, spoofed Forwarded ignored",
			trusted:    trusted,
			remoteAddr: "198.51.100.7:1234",
			headers:    map[string][]string{"Forwarded": {"for=192.0.2.60"}},
			expected:   "198.51.100.7",
		},
		{
			name:       "trusted peer, Forwarded",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers: map[string][]string{
				"Forwarded": {"for=192.0.2.60;proto=http, for=10.0.0.1"},
			},
			expected: "192.0.2.60",
		},
		{
			name:       "trusted peer, X-Forwarded-For",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers: map[string][]string{
				"X-Forwarded-For": {"192.0.2.60, 10.0.0.1"},
			},
			expected: "192.0.2.60",
		},
		{
			name:       "both headers, Forwarded wins",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers: map[string][]string{
				"Forwarded":       {"for=192.0.2.60"},
				"X-Forwarded-For": {"192.0.2.61"},
			},
			expected: "192.0.2.60",
		},
		{
			name:       "Forwarded without for=, falls back to X-Forwarded-For",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers: map[string][]string{
				"Forwarded":       {"proto=https"},
				"X-Forwarded-For": {"192.0.2.60"},
			},
			expected: "192.0.2.60",
		},
		{
			name:       "trusted peer, no forwarding headers",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
		},
		{
			name:       "trusted peer, Forwarded without for= and no X-Forwarded-For",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {"proto=https;host=example.com"}},
		},
		{
			name:       "quoted IPv6 with port",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {`for="[2001:db8::1]:4711"`}},
			expected:   "2001:db8::1",
		},
		{
			name:       "quoted IPv4 with port",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {`For="192.0.2.60:80"`}},
			expected:   "192.0.2.60",
		},
		{
			name:       "IPv6 zone stripped",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"X-Forwarded-For": {"fe80::1%eth0"}},
			expected:   "fe80::1",
		},
		{
			name:       "IPv4-mapped IPv6 hop",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"X-Forwarded-For": {"::ffff:192.0.2.1"}},
			expected:   "192.0.2.1",
		},
		{
			name:       "IPv4-mapped IPv6 peer",
			remoteAddr: "[::ffff:192.0.2.1]:1234",
			expected:   "192.0.2.1",
		},
		{
			name:       "IPv4-mapped IPv6 peer is trusted",
			trusted:    trusted,
			remoteAddr: "[::ffff:10.1.1.1]:1234",
			headers:    map[string][]string{"Forwarded": {"for=192.0.2.60"}},
			expected:   "192.0.2.60",
		},
		{
			name:       "trusted IPv6 peer",
			trusted:    trusted,
			remoteAddr: "[2001:db8:ffff::1]:1234",
			headers:    map[string][]string{"Forwarded": {`for="[2001:db8::1]"`}},
			expected:   "2001:db8::1",
		},
		{
			name:       "unknown in the walk",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {"for=192.0.2.60, for=unknown"}},
		},
		{
			name:       "obfuscated in the walk",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {"for=_hidden"}},
		},
		{
			name:       "unparseable hop beyond the walk is not needed",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {"for=unknown, for=192.0.2.60"}},
			expected:   "192.0.2.60",
		},
		{
			name:       "all hops trusted, left-most",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {"for=10.0.0.3, for=10.0.0.2"}},
			expected:   "10.0.0.3",
		},
		{
			name:       "multiple header lines concatenated in order",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers: map[string][]string{
				"X-Forwarded-For": {"192.0.2.60, 198.51.100.7", "10.0.0.2"},
			},
			expected: "198.51.100.7",
		},
		{
			name:       "comma inside a quoted string",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers: map[string][]string{
				"Forwarded": {`for=192.0.2.60;host="a,b", for=10.0.0.2`},
			},
			expected: "192.0.2.60",
		},
		{
			name:       "escaped quote and comma inside a quoted string",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers: map[string][]string{
				"Forwarded": {`for=192.0.2.60;host="a\",b", for=10.0.0.2`},
			},
			expected: "192.0.2.60",
		},
		{
			name:       "backslash escape inside a quoted for=",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {`for="192.0.2.\60"`}},
			expected:   "192.0.2.60",
		},
		{
			name:       "bare RemoteAddr",
			remoteAddr: "198.51.100.7",
			expected:   "198.51.100.7",
		},
		{
			name:       "unparseable RemoteAddr",
			remoteAddr: "garbage",
		},
		{
			name:       "unclosed bracket",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {`for="[2001:db8::1"`}},
		},
		{
			name:       "garbage after bracket",
			trusted:    trusted,
			remoteAddr: "10.1.1.1:1234",
			headers:    map[string][]string{"Forwarded": {`for="[2001:db8::1]x"`}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewOriginResolver(WithTrustedProxies(tc.trusted...))
			require.NoError(t, err)

			request := httptest.NewRequest("GET", "/", nil)
			request.RemoteAddr = tc.remoteAddr
			maps.Copy(request.Header, tc.headers)

			addr, ok := r.Origin(request)
			if tc.expected == "" {
				assert.False(t, ok)
				assert.False(t, addr.IsValid())
				return
			}

			assert.True(t, ok)
			assert.Equal(t, netip.MustParseAddr(tc.expected), addr)
		})
	}
}

func TestOriginResolverZeroValue(t *testing.T) {
	var r OriginResolver
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "198.51.100.7:1234"
	request.Header.Set("Forwarded", "for=192.0.2.60")

	addr, ok := r.Origin(request)
	assert.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("198.51.100.7"), addr)
}

func TestSplitQuoted(t *testing.T) {
	tests := []struct {
		in       string
		expected []string
	}{
		{in: "", expected: []string{""}},
		{in: "a,b", expected: []string{"a", "b"}},
		{in: `a,"b,c",d`, expected: []string{"a", `"b,c"`, "d"}},
		{in: `"a\",b",c`, expected: []string{`"a\",b"`, "c"}},
		{in: `a\,b`, expected: []string{`a\`, "b"}}, // backslash only escapes inside quotes
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.expected, splitQuoted(tc.in, ','))
		})
	}
}

func TestUnquote(t *testing.T) {
	tests := []struct {
		in, expected string
	}{
		{in: "", expected: ""},
		{in: `"`, expected: `"`},
		{in: "plain", expected: "plain"},
		{in: `"quoted"`, expected: "quoted"},
		{in: `""`, expected: ""},
		{in: `"a\"b"`, expected: `a"b`},
		{in: `"a\\b"`, expected: `a\b`},
		{in: `"a\"`, expected: `a\`}, // a trailing backslash is kept
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.expected, unquote(tc.in))
		})
	}
}

func TestNormalizePrefix(t *testing.T) {
	tests := []struct {
		in, expected string
	}{
		{in: "10.1.2.3/8", expected: "10.0.0.0/8"},
		{in: "::ffff:10.0.0.0/104", expected: "10.0.0.0/8"},
		{in: "::ffff:10.0.0.1/128", expected: "10.0.0.1/32"},
		{in: "::ffff:0.0.0.0/80", expected: "::/80"},
		{in: "2001:db8::1/32", expected: "2001:db8::/32"},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t,
				netip.MustParsePrefix(tc.expected),
				normalizePrefix(netip.MustParsePrefix(tc.in)),
			)
		})
	}
}
