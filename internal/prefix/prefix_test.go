// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package prefix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiteral(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		capability string
		rest       string
		ok         bool
	}{
		{name: "plain", prefix: "x1:webpa:api:", capability: "x1:webpa:api:/test:all", rest: "/test:all", ok: true},
		{name: "empty prefix", prefix: "", capability: "/test:all", rest: "/test:all", ok: true},
		{name: "exact", prefix: "x1:", capability: "x1:", rest: "", ok: true},
		{name: "not a prefix", prefix: "x1:", capability: "junk:x1:/test:all"},
		{name: "shorter capability", prefix: "x1:webpa:", capability: "x1:"},
		// regex metacharacters are taken as written
		{name: "alternation bar", prefix: "foo-bar|", capability: "foo-bar|/test:all", rest: "/test:all", ok: true},
		{name: "alternation bar is not an empty alternative", prefix: "foo-bar|", capability: "/test:all"},
		{name: "dot", prefix: "x1.webpa:", capability: "x1Xwebpa:/test:all"},
		{name: "paren", prefix: "x(1|2):", capability: "x(1|2):/test:all", rest: "/test:all", ok: true},
		{name: "unbalanced paren", prefix: "(a", capability: "(a/test:all", rest: "/test:all", ok: true},
		{name: "star", prefix: "*", capability: "*/test:all", rest: "/test:all", ok: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rest, ok := Literal(tc.prefix).Match(tc.capability)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.rest, rest)
		})
	}
}

func TestRegex(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		capability string
		rest       string
		ok         bool
	}{
		{name: "plain", prefix: "x1:webpa:api:", capability: "x1:webpa:api:/test:all", rest: "/test:all", ok: true},
		{name: "empty prefix", prefix: "", capability: "/test:all", rest: "/test:all", ok: true},
		{name: "not a prefix", prefix: "x1:", capability: "junk:x1:/test:all"},
		{name: "dot", prefix: "x1.webpa:", capability: "x1Xwebpa:/test:all", rest: "/test:all", ok: true},
		{name: "subexpression", prefix: "x(1|2):webpa:", capability: "x2:webpa:/test:all", rest: "/test:all", ok: true},
		{name: "subexpression no match", prefix: "x(1|2):webpa:", capability: "x3:webpa:/test:all"},
		{name: "top-level alternation first", prefix: "x1:|x2:", capability: "x1:/test:all", rest: "/test:all", ok: true},
		{name: "top-level alternation second", prefix: "x1:|x2:", capability: "x2:/test:all", rest: "/test:all", ok: true},
		// every alternative is anchored, not just the first
		{name: "top-level alternation stays anchored", prefix: "x1:|x2:", capability: "junk:x2:/test:all"},
		{name: "empty alternative matches everything", prefix: "foo-bar|", capability: "/test:all", rest: "/test:all", ok: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Regex(tc.prefix)
			require.NoError(t, err)

			rest, ok := m.Match(tc.capability)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.rest, rest)
		})
	}
}

func TestRegexInvalid(t *testing.T) {
	for _, invalid := range []string{
		"(?!foo)", // RE2 has no negative lookahead
		"(a",      // unbalanced
		"*",       // nothing to repeat
	} {
		t.Run(invalid, func(t *testing.T) {
			m, err := Regex(invalid)
			require.Error(t, err)
			assert.Nil(t, m)
		})
	}
}
