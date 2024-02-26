// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"strings"

	"github.com/xmidt-org/bascule/v1"
)

var defaultCredentialsParser bascule.CredentialsParser = bascule.CredentialsParserFunc(
	func(raw string) (c bascule.Credentials, err error) {
		if before, after, found := strings.Cut(raw, " "); found {
			c = bascule.Credentials{
				Scheme: bascule.Scheme(strings.TrimSpace(before)),
				Value:  strings.TrimSpace(after),
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
// builtin strategy is tolerant of extra whitespace, and does not define any particular
// format for the value of the credentials.
//
// This parser assumes the format specified in https://www.rfc-editor.org/rfc/rfc7235.
func DefaultCredentialsParser() bascule.CredentialsParser {
	return defaultCredentialsParser
}
