// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"reflect"
)

// Validator represents a general strategy for validating tokens.  Token validation
// typically happens during authentication.
type Validator[S any] interface {
	// Validate validates a token.  If this validator needs to interact
	// with external systems, the supplied context can be passed to honor
	// cancelation semantics.  Additionally, the source object from which the
	// token was taken is made available.
	//
	// This method may be passed a token that it doesn't support, e.g. a Basic
	// validator can be passed a JWT token.  In that case, this method should
	// simply return a nil error.
	//
	// If this method returns a nil token, then the supplied token should be used
	// as is.  If this method returns a non-nil token, that new new token should be
	// used instead.  This allows a validator to augment a token with additional
	// data, possibly from an external system or database.
	Validate(ctx context.Context, source S, t Token) (Token, error)
}

// Validate applies several validators to the given token.  Although each individual
// validator may return a nil Token to indicate that there is no change in the token,
// this function will always return a non-nil Token.
//
// This function returns the validated Token and a nil error to indicate success.
// If any validator fails, this function halts further validation and returns
// the error.
func Validate[S any](ctx context.Context, source S, original Token, v ...Validator[S]) (validated Token, err error) {
	next := original
	for i, prev := 0, next; err == nil && i < len(v); i, prev = i+1, next {
		next, err = v[i].Validate(ctx, source, prev)
		if next == nil {
			// no change in the token
			next = prev
		}
	}

	if err == nil {
		validated = next
	}

	return
}

// Validators is an aggregate Validator that returns validity if and only if
// all of its contained validators return validity.
type Validators[S any] []Validator[S]

// Append tacks on more validators to this aggregate, returning the possibly new
// instance.  The semantics of this method are the same as the built-in append.
func (vs Validators[S]) Append(more ...Validator[S]) Validators[S] {
	return append(vs, more...)
}

// Validate executes each contained validator in order, returning validity only
// if all validators pass.  Any validation failure prevents subsequent validators
// from running.
func (vs Validators[S]) Validate(ctx context.Context, source S, t Token) (Token, error) {
	return Validate(ctx, source, t, vs...)
}

// ValidatorFunc defines the closure signatures that are allowed as Validator instances.
type ValidatorFunc[S any] interface {
	~func(Token) error |
		~func(S, Token) error |
		~func(Token) (Token, error) |
		~func(S, Token) (Token, error) |
		~func(context.Context, Token) error |
		~func(context.Context, S, Token) error |
		~func(context.Context, Token) (Token, error) |
		~func(context.Context, S, Token) (Token, error)
}

// validatorFunc is an internal type that implements Validator.  Used to normalize
// and uncurry a closure.
type validatorFunc[S any] func(context.Context, S, Token) (Token, error)

func (vf validatorFunc[S]) Validate(ctx context.Context, source S, t Token) (Token, error) {
	return vf(ctx, source, t)
}

var (
	tokenReturnsError             = reflect.TypeOf((func(Token) error)(nil))
	tokenReturnsTokenError        = reflect.TypeOf((func(Token) (Token, error))(nil))
	contextTokenReturnsError      = reflect.TypeOf((func(context.Context, Token) error)(nil))
	contextTokenReturnsTokenError = reflect.TypeOf((func(context.Context, Token) (Token, error))(nil))
)

// asValidatorSimple tries simple conversions on f.  This function will not catch
// user-defined types.
func asValidatorSimple[S any, F ValidatorFunc[S]](f F) (v Validator[S]) {
	switch vf := any(f).(type) {
	case func(Token) error:
		v = validatorFunc[S](
			func(ctx context.Context, source S, t Token) (Token, error) {
				return nil, vf(t)
			},
		)

	case func(S, Token) error:
		v = validatorFunc[S](
			func(ctx context.Context, source S, t Token) (Token, error) {
				return nil, vf(source, t)
			},
		)

	case func(Token) (Token, error):
		v = validatorFunc[S](
			func(ctx context.Context, source S, t Token) (next Token, err error) {
				next, err = vf(t)
				if next == nil {
					next = t
				}

				return
			},
		)

	case func(S, Token) (Token, error):
		v = validatorFunc[S](
			func(ctx context.Context, source S, t Token) (next Token, err error) {
				next, err = vf(source, t)
				if next == nil {
					next = t
				}

				return
			},
		)

	case func(context.Context, Token) error:
		v = validatorFunc[S](
			func(ctx context.Context, source S, t Token) (Token, error) {
				return nil, vf(ctx, t)
			},
		)

	case func(context.Context, S, Token) error:
		v = validatorFunc[S](
			func(ctx context.Context, source S, t Token) (Token, error) {
				return nil, vf(ctx, source, t)
			},
		)

	case func(context.Context, Token) (Token, error):
		v = validatorFunc[S](
			func(ctx context.Context, source S, t Token) (next Token, err error) {
				next, err = vf(ctx, t)
				if next == nil {
					next = t
				}

				return
			},
		)

	case func(context.Context, S, Token) (Token, error):
		v = validatorFunc[S](vf)
	}

	return
}

// AsValidator takes a ValidatorFunc closure and returns a Validator instance that
// executes that closure.
func AsValidator[S any, F ValidatorFunc[S]](f F) Validator[S] {
	// first, try the simple way:
	if v := asValidatorSimple[S](f); v != nil {
		return v
	}

	// next, support user-defined types that are closures that do not
	// require the source type.
	fVal := reflect.ValueOf(f)
	switch {
	case fVal.CanConvert(tokenReturnsError):
		return asValidatorSimple[S](
			fVal.Convert(tokenReturnsError).Interface().(func(Token) error),
		)

	case fVal.CanConvert(tokenReturnsTokenError):
		return asValidatorSimple[S](
			fVal.Convert(tokenReturnsError).Interface().(func(Token) (Token, error)),
		)

	case fVal.CanConvert(contextTokenReturnsError):
		return asValidatorSimple[S](
			fVal.Convert(contextTokenReturnsError).Interface().(func(context.Context, Token) error),
		)

	case fVal.CanConvert(contextTokenReturnsTokenError):
		return asValidatorSimple[S](
			fVal.Convert(contextTokenReturnsError).Interface().(func(context.Context, Token) (Token, error)),
		)
	}

	// finally: user-defined types that are closures involving the source type S.
	// we have to look these up here, due to the way generics in golang work.
	if ft := reflect.TypeOf((func(S, Token) error)(nil)); fVal.CanConvert(ft) {
		return asValidatorSimple[S](
			fVal.Convert(ft).Interface().(func(S, Token) error),
		)
	} else if ft := reflect.TypeOf((func(S, Token) (Token, error))(nil)); fVal.CanConvert(ft) {
		return asValidatorSimple[S](
			fVal.Convert(ft).Interface().(func(S, Token) (Token, error)),
		)
	} else if ft := reflect.TypeOf((func(context.Context, S, Token) error)(nil)); fVal.CanConvert(ft) {
		return asValidatorSimple[S](
			fVal.Convert(ft).Interface().(func(context.Context, S, Token) error),
		)
	} else {
		// we know this can be converted to this final type
		return asValidatorSimple[S](
			fVal.Convert(ft).Interface().(func(context.Context, S, Token) (Token, error)),
		)
	}
}
