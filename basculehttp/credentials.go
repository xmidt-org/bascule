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

// DefaultCredentialsParser is the default algorithm used to produce HTTP credentials
// from a source request.
type DefaultCredentialsParser struct {
	// Header is the name of the authorization header.  If unset,
	// DefaultAuthorizationHeader is used.
	Header string

	// ErrorOnDuplicate controls whether an error is returned if more
	// than one Header is found in the request.  By default, this is false.
	ErrorOnDuplicate bool
}

func (dcp DefaultCredentialsParser) Parse(_ context.Context, source *http.Request) (c bascule.Credentials, err error) {
	header := dcp.Header
	if len(header) == 0 {
		header = DefaultAuthorizationHeader
	}

	var raw string
	values := source.Header.Values(header)
	switch {
	case len(values) == 0:
		err = &MissingHeaderError{
			Header: header,
		}

	case len(values) == 1 || !dcp.ErrorOnDuplicate:
		raw = values[0]

	default:
		err = &DuplicateHeaderError{
			Header: header,
		}
	}

	if err == nil {
		// format is <scheme><single space><credential value>
		// the code is strict:  it requires no leading or trailing space
		// and exactly one (1) space as a separator.
		scheme, credValue, found := strings.Cut(raw, " ")
		if found && len(scheme) > 0 && !fastIsSpace(credValue[0]) && !fastIsSpace(credValue[len(credValue)-1]) {
			c = bascule.Credentials{
				Scheme: bascule.Scheme(scheme),
				Value:  credValue,
			}
		} else {
			err = &bascule.BadCredentialsError{
				Raw: raw,
			}
		}
	}

	return
}
