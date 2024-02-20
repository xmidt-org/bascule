// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import "strings"

// MissingCredentialsError indicates that credentials could not be found.
// Typically, this error will be returned by code that extracts credentials
// from some other source, e.g. an HTTP request.
type MissingCredentialsError struct {
	// Cause represents the lower-level error that occurred, if any.
	Cause error

	// Reason contains any additional information about the missing credentials.
	Reason string
}

func (err *MissingCredentialsError) Unwrap() error { return err.Cause }

func (err *MissingCredentialsError) Error() string {
	var o strings.Builder
	o.WriteString("Missing credentials")
	if len(err.Reason) > 0 {
		o.WriteString(": ")
		o.WriteString(err.Reason)
	}

	return o.String()
}

// InvalidCredentialsError is returned typically by CredentialsParser.Parse
// to indicate that a raw, serialized credentials were badly formatted.
type InvalidCredentialsError struct {
	// Cause represents any lower-level error that occurred, if any.
	Cause error

	// Raw represents the raw credentials that couldn't be parsed.
	Raw string
}

func (err *InvalidCredentialsError) Unwrap() error { return err.Cause }

func (err *InvalidCredentialsError) Error() string {
	var o strings.Builder
	o.WriteString(`Invalid credentials: "`)
	o.WriteString(err.Raw)
	o.WriteString(`"`)
	return o.String()
}

// UnsupportedSchemeError indicates that a credential scheme was not
// supported via the particular way bascule was configured.
type UnsupportedSchemeError struct {
	Scheme Scheme
}

func (err *UnsupportedSchemeError) Error() string {
	var o strings.Builder
	o.WriteString(`Unsupported credential scheme: "`)
	o.WriteString(string(err.Scheme))
	o.WriteString(`"`)
	return o.String()
}

// Scheme represents how a security token should be parsed.  For HTTP, examples
// of a scheme are "Bearer" and "Basic".
type Scheme string

// Credentials holds the raw, unparsed token information.
type Credentials struct {
	// Scheme is the parsing scheme used for the credential value.
	Scheme Scheme

	// Value is the raw, unparsed credential information.
	Value string
}

// CredentialsParser produces Credentials from their serialized form.
type CredentialsParser interface {
	// Parse parses the raw, marshaled version of credentials and
	// returns the Credentials object.
	Parse(raw string) (Credentials, error)
}
