// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"
	"strings"
)

// Scheme is the authorization header scheme, e.g. Basic, Bearer, etc.
type Scheme string

const (
	// SchemeBasic is the Basic HTTP authorization scheme.
	SchemeBasic Scheme = "Basic"

	// SchemeBearer is the Bearer HTTP authorization scheme.
	SchemeBearer Scheme = "Bearer"
)

// lower returns a lowercased version of this Scheme.  Useful
// for ensuring case-insensitive matches.
func (s Scheme) lower() Scheme {
	return Scheme(
		strings.ToLower(string(s)),
	)
}

// UnsupportedSchemeError is used to indicate that a particular HTTP Authorization
// scheme is not supported by the server.
type UnsupportedSchemeError struct {
	Scheme Scheme
}

// StatusCode marks this error as using the http.StatusUnauthorized code.
// This is appropriate for almost all cases, as this error occurs because
// the server does not accept or understand the scheme that the
// HTTP client supplied.
func (use *UnsupportedSchemeError) StatusCode() int {
	return http.StatusUnauthorized
}

func (use *UnsupportedSchemeError) Error() string {
	var o strings.Builder
	o.WriteString("Unsupported authorization scheme: ")
	o.WriteString(string(use.Scheme))
	return o.String()
}
