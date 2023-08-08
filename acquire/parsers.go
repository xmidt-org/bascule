// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package acquire

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/spf13/cast"
)

var (
	errMissingExpClaim   = errors.New("missing exp claim in jwt")
	errUnexpectedCasting = errors.New("unexpected casting error")
)

// TokenParser defines the function signature of a bearer token extractor from a payload.
type TokenParser func([]byte) (string, error)

// ParseExpiration defines the function signature of a bearer token expiration date extractor.
type ParseExpiration func([]byte) (time.Time, error)

// DefaultTokenParser extracts a bearer token as defined by a SimpleBearer in a payload.
func DefaultTokenParser(data []byte) (string, error) {
	var bearer SimpleBearer

	if errUnmarshal := json.Unmarshal(data, &bearer); errUnmarshal != nil {
		return "", fmt.Errorf("unable to parse bearer token: %w", errUnmarshal)
	}
	return bearer.Token, nil
}

// DefaultExpirationParser extracts a bearer token expiration date as defined by a SimpleBearer in a payload.
func DefaultExpirationParser(data []byte) (time.Time, error) {
	var bearer SimpleBearer

	if errUnmarshal := json.Unmarshal(data, &bearer); errUnmarshal != nil {
		return time.Time{}, fmt.Errorf("unable to parse bearer token expiration: %w", errUnmarshal)
	}
	return time.Now().Add(time.Duration(bearer.ExpiresInSeconds) * time.Second), nil
}

func RawTokenParser(data []byte) (string, error) {
	return string(data), nil
}

func RawTokenExpirationParser(data []byte) (time.Time, error) {
	p := jwt.Parser{SkipClaimsValidation: true}
	token, _, err := p.ParseUnverified(string(data), jwt.MapClaims{})
	if err != nil {
		return time.Time{}, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return time.Time{}, errUnexpectedCasting
	}
	expVal, ok := claims["exp"]
	if !ok {
		return time.Time{}, errMissingExpClaim
	}

	exp, err := cast.ToInt64E(expVal)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(exp, 0), nil
}
