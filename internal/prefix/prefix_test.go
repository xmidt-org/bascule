// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package prefix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiteral(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		prefix     string
		capability string
		rest       string
		ok         bool
	}{
		{name: "plain", prefix: "webpa-prefix-api:", capability: "webpa-prefix-api:/test:all", rest: "/test:all", ok: true},
		{name: "empty prefix", prefix: "", capability: "/test:all", rest: "/test:all", ok: true},
		{name: "exact", prefix: "prefix:", capability: "prefix:", rest: "", ok: true},
		{name: "not a prefix", prefix: "prefix:", capability: "junk:prefix-a:/test:all"},
		{name: "shorter capability", prefix: "webpa-prefix:", capability: "prefix:"},
		// regex metacharacters are taken as written
		{name: "alternation bar", prefix: "foo-bar|", capability: "foo-bar|/test:all", rest: "/test:all", ok: true},
		{name: "alternation bar is not an empty alternative", prefix: "foo-bar|", capability: "/test:all"},
		{name: "dot", prefix: "webpa.prefix:", capability: "webpaXprefix:/test:all"},
		{name: "paren", prefix: "prefix-(a|b):", capability: "prefix-(a|b):/test:all", rest: "/test:all", ok: true},
		{name: "unbalanced paren", prefix: "(a", capability: "(a/test:all", rest: "/test:all", ok: true},
		{name: "star", prefix: "*", capability: "*/test:all", rest: "/test:all", ok: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rest, ok := Literal(tc.prefix).Match(tc.capability)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.rest, rest)
		})
	}
}

func TestRegex(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		prefix     string
		capability string
		rest       string
		ok         bool
	}{
		{name: "plain", prefix: "webpa-prefix-api:", capability: "webpa-prefix-api:/test:all", rest: "/test:all", ok: true},
		{name: "empty prefix", prefix: "", capability: "/test:all", rest: "/test:all", ok: true},
		{name: "not a prefix", prefix: "prefix:", capability: "junk:prefix-a:/test:all"},
		{name: "dot", prefix: "webpa.prefix:", capability: "webpaXprefix:/test:all", rest: "/test:all", ok: true},
		{name: "subexpression", prefix: "webpa-prefix-(a|b):", capability: "webpa-prefix-b:/test:all", rest: "/test:all", ok: true},
		{name: "subexpression no match", prefix: "webpa-prefix-(a|b):", capability: "webpa-prefix-c:/test:all"},
		{name: "top-level alternation first", prefix: "prefix-a:|prefix-b:", capability: "prefix-a:/test:all", rest: "/test:all", ok: true},
		{name: "top-level alternation second", prefix: "prefix-a:|prefix-b:", capability: "prefix-b:/test:all", rest: "/test:all", ok: true},
		// every alternative is anchored, not just the first
		{name: "top-level alternation stays anchored", prefix: "prefix-a:|prefix-b:", capability: "junk:prefix-b:/test:all"},
		{name: "empty alternative matches everything", prefix: "foo-bar|", capability: "/test:all", rest: "/test:all", ok: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := Regex(tc.prefix)
			require.NoError(t, err)

			rest, ok := m.Match(tc.capability)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.rest, rest)
		})
	}
}

func TestRegexInvalid(t *testing.T) {
	t.Parallel()
	for _, invalid := range []string{
		"(?!foo)", // RE2 has no negative lookahead
		"(a",      // unbalanced
		"*",       // nothing to repeat
	} {
		t.Run(invalid, func(t *testing.T) {
			t.Parallel()
			m, err := Regex(invalid)
			require.Error(t, err)
			assert.Nil(t, m)
		})
	}
}
