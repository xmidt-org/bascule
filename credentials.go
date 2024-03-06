// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

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
