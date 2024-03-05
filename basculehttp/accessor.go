// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"
	"strings"
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

// Accessor is the strategy for obtaining credentials from an HTTP request.
type Accessor interface {
	// GetCredentials returns the raw credentials from a request.
	GetCredentials(*http.Request) (string, error)
}

var defaultAccessor Accessor = HeaderAccessor{}

// DefaultAccessor returns the builtin default strategy for obtaining raw credentials
// from an HTTP request.  The returned Accessor simply retrieves the Authorization header
// value if it exists.
func DefaultAccessor() Accessor { return defaultAccessor }

// HeaderAccessor obtains the raw credentials from a specific header in
// an HTTP request.
type HeaderAccessor struct {
	// Header is the name of the HTTP header to use.  If not supplied,
	// DefaultAuthorizationHeader is used.
	//
	// If no authorization header can be found in an HTTP request,
	// MissingHeaderError is returned.
	Header string

	// ErrorOnDuplicate controls whether an error is returned if more
	// than one Header is found in the request.  By default, this is false.
	ErrorOnDuplicate bool
}

func (ha HeaderAccessor) GetCredentials(r *http.Request) (raw string, err error) {
	h := ha.Header
	if len(h) == 0 {
		h = DefaultAuthorizationHeader
	}

	values := r.Header.Values(h)
	switch {
	case len(values) == 0:
		err = &MissingHeaderError{
			Header: h,
		}

	case len(values) == 1 || !ha.ErrorOnDuplicate:
		raw = values[0]

	default:
		err = &DuplicateHeaderError{
			Header: h,
		}
	}

	return
}
