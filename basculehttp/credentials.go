// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/xmidt-org/bascule/v1"
)

const (
	// DefaultAuthorizationHeader is the name of the header used by default to obtain
	// the raw credentials.
	DefaultAuthorizationHeader = "Authorization"
)

// DuplicateHeaderError indicates that an HTTP header had more than one value
// when only one value was expected.
type DuplicateHeaderError struct {
	// Header is the name of the duplicate header.
	Header string
}

func (err *DuplicateHeaderError) Error() string {
	var o strings.Builder
	o.WriteString(`Duplicate header: "`)
	o.WriteString(err.Header)
	o.WriteString(`"`)
	return o.String()
}

// MissingHeaderError indicates that an expected HTTP header is missing.
type MissingHeaderError struct {
	// Header is the name of the missing header.
	Header string
}

func (err *MissingHeaderError) Error() string {
	var o strings.Builder
	o.WriteString(`Missing header: "`)
	o.WriteString(err.Header)
	o.WriteString(`"`)
	return o.String()
}

// StatusCode returns http.StatusUnauthorized, as the request carries
// no authorization in it.
func (err *MissingHeaderError) StatusCode() int {
	return http.StatusUnauthorized
}

// fastIsSpace tests an ASCII byte to see if it's whitespace.
// HTTP headers are restricted to US-ASCII, so we don't need
// the full unicode stack.
func fastIsSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// DefaultCredentialsParser is the default algorithm used to produce HTTP credentials
// from a request.
type DefaultCredentialsParser struct {
	// HeaderName is the name of the authorization header.  If unset,
	// DefaultAuthorizationHeader is used.
	HeaderName string
}

func (dcp DefaultCredentialsParser) Parse(_ context.Context, source *http.Request) (bascule.Credentials, error) {
}

var defaultCredentialsParser CredentialsParser = bascule.CredentialsParserFunc[*http.Request](
	func(ctx context.Context, source *http.Request) (c bascule.Credentials, err error) {
		// format is <scheme><single space><credential value>
		// the code is strict:  it requires no leading or trailing space
		// and exactly one (1) space as a separator.
		scheme, value, found := strings.Cut(raw, " ")
		if found && len(scheme) > 0 && !fastIsSpace(value[0]) && !fastIsSpace(value[len(value)-1]) {
			c = bascule.Credentials{
				Scheme: bascule.Scheme(scheme),
				Value:  value,
			}
		} else {
			err = &bascule.BadCredentialsError{
				Raw: raw,
			}
		}

		return
	},
)

// DefaultCredentialsParser returns the default strategy for parsing credentials.  This
// builtin strategy is very strict on whitespace.  The format must correspond exactly
// to the format specified in https://www.rfc-editor.org/rfc/rfc7235.
func DefaultCredentialsParser() bascule.CredentialsParser[*http.Request] {
	return defaultCredentialsParser
}
