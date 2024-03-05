// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import "strings"

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
	o.WriteString(`Invalid credentials "`)
	o.WriteString(err.Raw)
	o.WriteString(`"`)

	if err.Cause != nil {
		o.WriteString(": ")
		o.WriteString(err.Cause.Error())
	}

	return o.String()
}

// UnsupportedSchemeError indicates that a credential scheme was not
// supported via the particular way bascule was configured.
type UnsupportedSchemeError struct {
	// Scheme is the authorization scheme that wasn't supported.
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

// CredentialsParserFunc is a function type that implements CredentialsParser.
type CredentialsParserFunc func(string) (Credentials, error)

func (cpf CredentialsParserFunc) Parse(raw string) (Credentials, error) {
	return cpf(raw)
}
