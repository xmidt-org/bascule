/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package basculehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/key"
)

const (
	jwtPrincipalKey = "sub"
)

var (
	ErrorMalformedValue    = errors.New("expected <user>:<password> in decoded value")
	ErrorPrincipalNotFound = errors.New("principal not found")
	ErrorInvalidPassword   = errors.New("invalid password")
	ErrorNoProtectedHeader = errors.New("missing protected header")
	ErrorNoSigningMethod   = errors.New("signing method (alg) is missing or unrecognized")
	ErrorUnexpectedPayload = errors.New("payload isn't a map of strings to interfaces")
	ErrorInvalidPrincipal  = errors.New("invalid principal")
	ErrorInvalidToken      = errors.New("token isn't valid")
	ErrorUnexpectedClaims  = errors.New("claims wasn't MapClaims as expected")
)

// TokenFactory is a strategy interface responsible for creating and validating
// a secure Token.
type TokenFactory interface {
	ParseAndValidate(context.Context, *http.Request, bascule.Authorization, string) (bascule.Token, error)
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

// BearerTokenFactory parses and does basic validation for a JWT token.
type BearerTokenFactory struct {
	DefaultKeyId string
	Resolver     key.Resolver
	Parser       bascule.JWTParser
	Leeway       bascule.Leeway
}

// ParseAndValidate expects the given value to be a JWT with a kid header.  The
// kid should be resolvable by the Resolver and the JWT should be Parseable and
// pass any basic validation checks done by the Parser.  If everything goes
// well, a Token of type "jwt" is returned.
func (btf BearerTokenFactory) ParseAndValidate(ctx context.Context, _ *http.Request, _ bascule.Authorization, value string) (bascule.Token, error) {
	if len(value) == 0 {
		return nil, errors.New("empty value")
	}

	keyfunc := func(token *jwt.Token) (interface{}, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			keyID = btf.DefaultKeyId
		}

		pair, err := btf.Resolver.ResolveKey(ctx, keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve key: %v", err)
		}
		return pair.Public(), nil
	}

	leewayclaims := bascule.ClaimsWithLeeway{
		MapClaims: make(jwt.MapClaims),
		Leeway:    btf.Leeway,
	}

	jwsToken, err := btf.Parser.ParseJWT(value, &leewayclaims, keyfunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %v", err)
	}
	if !jwsToken.Valid {
		return nil, ErrorInvalidToken
	}

	claims, ok := jwsToken.Claims.(*bascule.ClaimsWithLeeway)

	if !ok {
		return nil, fmt.Errorf("failed to parse JWS: %w", ErrorUnexpectedClaims)
	}

	claimsMap, err := claims.GetMap()
	if err != nil {
		return nil, fmt.Errorf("failed to get map of claims with object [%v]: %v", claims, err)
	}

	jwtClaims := bascule.NewAttributes(claimsMap)

	principalVal, ok := jwtClaims.Get(jwtPrincipalKey)
	if !ok {
		return nil, fmt.Errorf("%w: principal value not found at key %v", ErrorInvalidPrincipal, jwtPrincipalKey)
	}
	principal, ok := principalVal.(string)
	if !ok {
		return nil, fmt.Errorf("%w: principal value [%v] not a string", ErrorInvalidPrincipal, principalVal)
	}

	return bascule.NewToken("jwt", principal, jwtClaims), nil
}
