// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/xmidt-org/bascule"
	"go.uber.org/fx"
)

var (
	ErrorMalformedValue    = errors.New("expected <user>:<password> in decoded value")
	ErrorPrincipalNotFound = errors.New("principal not found")
	ErrorInvalidPassword   = errors.New("invalid password")
)

type EncodedBasicKeys struct {
	Basic []string
}

// EncodedBasicKeysIn contains string representations of the basic auth allowed.
type EncodedBasicKeysIn struct {
	fx.In
	Keys EncodedBasicKeys
}

// TokenFactoryFunc makes it so any function that has the same signature as
// TokenFactory's ParseAndValidate function implements TokenFactory.
type TokenFactoryFunc func(context.Context, *http.Request, bascule.Authorization, string) (bascule.Token, error)

func (tff TokenFactoryFunc) ParseAndValidate(ctx context.Context, r *http.Request, a bascule.Authorization, v string) (bascule.Token, error) {
	return tff(ctx, r, a, v)
}

// BasicTokenFactory parses a basic auth and verifies it is in a map of valid
// basic auths.
type BasicTokenFactory map[string]string

// ParseAndValidate expects the given value to be a base64 encoded string with
// the username followed by a colon and then the password.  The function checks
// that the username password pair is in the map and returns a Token if it is.
func (btf BasicTokenFactory) ParseAndValidate(ctx context.Context, _ *http.Request, _ bascule.Authorization, value string) (bascule.Token, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("could not decode string: %v", err)
	}

	i := bytes.IndexByte(decoded, ':')
	if i <= 0 {
		return nil, ErrorMalformedValue
	}
	principal := string(decoded[:i])
	val, ok := btf[principal]
	if !ok {
		return nil, ErrorPrincipalNotFound
	}
	if val != string(decoded[i+1:]) {
		// failed authentication
		return nil, ErrorInvalidPassword
	}
	// "basic" is a placeholder here ... token types won't always map to the
	// Authorization header.  For example, a JWT should have a type of "jwt" or some such, not "bearer"
	return bascule.NewToken("basic", principal, bascule.NewAttributes(map[string]interface{}{})), nil
}

// NewBasicTokenFactoryFromList takes a list of base64 encoded basic auth keys,
// decodes them, and supplies that list in map form of username to password. If
// a username is encoded in two different auth keys, it will be overwritten by
// the last occurrence of that username with a password.  If anoth
func NewBasicTokenFactoryFromList(encodedBasicAuthKeys []string) (BasicTokenFactory, error) {
	btf := make(BasicTokenFactory)
	errs := bascule.Errors{}

	for _, encodedKey := range encodedBasicAuthKeys {
		decoded, err := base64.StdEncoding.DecodeString(encodedKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to base64-decode basic auth key [%v]: %v", encodedKey, err))
			continue
		}

		i := bytes.IndexByte(decoded, ':')
		if i <= 0 {
			errs = append(errs, fmt.Errorf("basic auth key [%v] is malformed", encodedKey))
			continue
		}

		btf[string(decoded[:i])] = string(decoded[i+1:])
	}

	if len(errs) != 0 {
		return btf, errs
	}

	// explicitly return nil so we don't have any empty error lists being returned.
	return btf, nil
}

// ProvideBasicTokenFactory uses configuration at the key given to build a basic
// token factory.  It provides a constructor option with the basic token
// factory.
func ProvideBasicTokenFactory() fx.Option {
	return fx.Provide(
		fx.Annotated{
			Group: "bascule_constructor_options",
			Target: func(in EncodedBasicKeysIn) (COption, error) {
				if len(in.Keys.Basic) == 0 {
					return nil, nil
				}
				tf, err := NewBasicTokenFactoryFromList(in.Keys.Basic)
				if err != nil {
					return nil, err
				}
				return WithTokenFactory(BasicAuthorization, tf), nil
			},
		},
	)
}
