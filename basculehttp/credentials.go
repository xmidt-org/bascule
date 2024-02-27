// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"strings"

	"github.com/xmidt-org/bascule/v1"
)

// fastIsSpace tests an ASCII byte to see if it's whitespace.
// HTTP headers are restricted to US-ASCII, so we don't need
// the full unicode stack.
func fastIsSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

var defaultCredentialsParser bascule.CredentialsParser = bascule.CredentialsParserFunc(
	func(raw string) (c bascule.Credentials, err error) {
		before, after, found := strings.Cut(raw, " ")
		if found && len(before) > 0 && !fastIsSpace(after[0]) && !fastIsSpace(after[len(after)-1]) {
			c = bascule.Credentials{
				Scheme: bascule.Scheme(before),
				Value:  after,
			}
		} else {
			err = &bascule.InvalidCredentialsError{
				Raw: raw,
			}
		}

		return
	},
)

// DefaultCredentialsParser returns the default strategy for parsing credentials.  This
// builtin strategy is very strict on whitespace.  The format must correspond exactly
// to the format specified in https://www.rfc-editor.org/rfc/rfc7235.
func DefaultCredentialsParser() bascule.CredentialsParser {
	return defaultCredentialsParser
}
