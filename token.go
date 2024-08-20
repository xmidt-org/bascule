// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"reflect"
)

var (
	// ErrNoTokenParsers is returned by TokenParsers.Parse to indicate an empty array.
	// This distinguishes the absence of a token from a source from the absence of a token
	// because of configuration, possibly intentionally.
	ErrNoTokenParsers = errors.New("no token parsers")

	// ErrMissingCredentials indicates that a source object did not have any credentials
	// recognized by that parser.
	ErrMissingCredentials = errors.New("missing credentials")

	// ErrBadCredentials indicates that parseable credentials were present in the source,
	// but that the credentials did not match what the application expects.  For example,
	// a password mismatch should return this error.
	ErrBadCredentials = errors.New("bad credentials")

	// ErrInvalidCredentials indicates that a source did contain recognizable credentials,
	// but those credentials could not be parsed, possibly due to bad formatting.
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// Token is a runtime representation of credentials.  This interface will be further
// customized by infrastructure.
type Token interface {
	// Principal is the security subject of this token, e.g. the user name or other
	// user identifier.
	Principal() string
}

// TokenParser produces tokens from a source.  The original source S of the credentials
// are made available to the parser.
type TokenParser[S any] interface {
	// Parse extracts a Token from a source object, e.g. an HTTP request.
	//
	// If a particular source instance doesn't have the credentials expected by this
	// parser, this method must return an error with MissingCredentials in the returned
	// error's chain.
	//
	// If a source has credentials that failed to parse, this method must return an error
	// with InvalidCredentials in its error chain.
	//
	// If this method returns a nil Token, it must return a non-nil error.  Returning an
	// error with a non-nil Token is allowed but not required.
	Parse(ctx context.Context, source S) (Token, error)
}

// TokenParserFunc describes the closure signatures that are allowed as TokenParser instances.
type TokenParserFunc[S any] interface {
	~func(source S) (Token, error) |
		~func(ctx context.Context, source S) (Token, error)
}

// tokenParserFunc is the internal closure type that can be used to adapt
// a TokenParserFunc onto a TokenParser instance.
type tokenParserFunc[S any] func(context.Context, S) (Token, error)

func (tpf tokenParserFunc[S]) Parse(ctx context.Context, source S) (Token, error) {
	return tpf(ctx, source)
}

// AsTokenParser accepts a closure and turns it into a TokenParser instance.
// Custom types that are convertible to a TokenParserFunc are also supported.
func AsTokenParser[S any, F TokenParserFunc[S]](f F) TokenParser[S] {
	// first, try the simple cases
	switch ft := any(f).(type) {
	case func(S) (Token, error):
		return tokenParserFunc[S](func(_ context.Context, source S) (Token, error) {
			return ft(source) // curry away the context
		})

	case func(context.Context, S) (Token, error):
		return tokenParserFunc[S](ft)
	}

	// now handle user-defined types.  we have to look these up here, instead
	// of "caching" them, because of the way generics in golang work.
	fVal := reflect.ValueOf(f)
	if ft := reflect.TypeOf((func(S) (Token, error))(nil)); fVal.CanConvert(ft) {
		sourceOnly := fVal.Convert(ft).Interface().(func(S) (Token, error))
		return tokenParserFunc[S](func(_ context.Context, source S) (Token, error) {
			return sourceOnly(source) // curry away the context
		})
	} else {
		ft := reflect.TypeOf((func(context.Context, S) (Token, error))(nil))
		return tokenParserFunc[S](
			fVal.Convert(ft).Interface().(func(context.Context, S) (Token, error)),
		)
	}
}

// TokenParsers is an aggregate, ordered list of TokenParser implementations for
// a given type of source.
type TokenParsers[S any] []TokenParser[S]

// Len returns the number of parsers in this aggregate.
func (tps TokenParsers[S]) Len() int {
	return len(tps)
}

// Append adds one or more parsers to this aggregate TokenParsers.  The semantics
// of this method are the same as the built-in append.
func (tps TokenParsers[S]) Append(more ...TokenParser[S]) TokenParsers[S] {
	return append(tps, more...)
}

// Parse executes each TokenParser in turn.
//
// If this TokenParsers is empty, this method returns ErrNoTokenParsers.
//
// If a parser returns MissingCredentials, it is skipped.  If all parsers return
// MissingCredentials, the last error is returned.
//
// If a parser returns any other error, parsing is halted early and that error is returned.
//
// Otherwise, the token returned from the first successful parse is returned by
// this aggregate method.
func (tps TokenParsers[S]) Parse(ctx context.Context, source S) (t Token, err error) {
	if len(tps) == 0 {
		err = ErrNoTokenParsers
	}

	for i := 0; i < len(tps) && t == nil && (err == nil || errors.Is(err, ErrMissingCredentials)); i++ {
		t, err = tps[i].Parse(ctx, source)
	}

	return
}

// StubToken is a dummy token useful to configure a stubbed out workflow.  Useful
// in testing and in development.
type StubToken string

// Principal just returns this token's string value.
func (st StubToken) Principal() string { return string(st) }

// StubTokenParser is a parser that returns the same Token for all
// calls.  Useful in testing and in development.
type StubTokenParser[S any] struct {
	// Token is the constant token to return.  This could be a StubToken,
	// or any desired type.
	Token Token
}

// Parse always returns the configured Token and a nil error.
func (stp StubTokenParser[S]) Parse(context.Context, S) (Token, error) { return stp.Token, nil }
