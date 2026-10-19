// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package prefix selects capabilities by a configured prefix.  Capabilities
// are flat strings shared by many services; the prefix decides which of a
// token's capabilities an approver honors.
package prefix

import (
	"fmt"
	"regexp"
	"strings"
)

// Matcher decides whether a capability carries a configured prefix.
type Matcher interface {
	// Match reports whether capability begins with the prefix.  When it does,
	// rest is the capability with the prefix removed.
	Match(capability string) (rest string, ok bool)
}

// Literal returns a Matcher that compares the prefix byte for byte.  Every
// character is taken as written; "foo-bar|" matches only capabilities that
// begin with "foo-bar|".  An empty prefix matches every capability.
func Literal(p string) Matcher {
	return literal(p)
}

type literal string

func (l literal) Match(capability string) (string, bool) {
	rest, ok := strings.CutPrefix(capability, string(l))
	if !ok {
		return "", false
	}

	return rest, true
}

// Regex returns a Matcher that treats the prefix as a regular expression
// anchored at the start of the capability.  The expression may contain
// subexpressions and top-level alternation; "x1:|x2:" matches either and
// nothing else.  An error is returned when the expression does not compile.
func Regex(p string) (Matcher, error) {
	// Group the expression so that a top-level alternation cannot escape the
	// anchor.
	re, err := regexp.Compile("^(?:" + p + ")")
	if err != nil {
		return nil, fmt.Errorf("Unable to compile capability prefix [%s]: %w", p, err)
	}

	return regex{re: re}, nil
}

type regex struct {
	re *regexp.Regexp
}

func (r regex) Match(capability string) (string, bool) {
	loc := r.re.FindStringIndex(capability)
	if loc == nil {
		return "", false
	}

	return capability[loc[1]:], true
}
