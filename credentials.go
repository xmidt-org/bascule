// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import "context"

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

// CredentialsParser produces Credentials from a data source.
type CredentialsParser[S any] interface {
	// Parse extracts Credentials from a Source data object.
	Parse(ctx context.Context, source S) (Credentials, error)
}

// CredentialsParserFunc is a function type that implements CredentialsParser.
type CredentialsParserFunc[S any] func(context.Context, S) (Credentials, error)

func (cpf CredentialsParserFunc[S]) Parse(ctx context.Context, source S) (Credentials, error) {
	return cpf(ctx, source)
}
