// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"encoding/json"
	"errors"

	"github.com/golang-jwt/jwt"
)

// JWTParser parses raw Tokens into JWT objects
type JWTParser interface {
	ParseJWT(string, jwt.Claims, jwt.Keyfunc) (*jwt.Token, error)
}

type defaultJWTParser struct{}

func (parser defaultJWTParser) ParseJWT(token string, claims jwt.Claims, parseFunc jwt.Keyfunc) (*jwt.Token, error) {
	if jwtToken, err := jwt.ParseWithClaims(token, claims, parseFunc); err == nil {
		return jwtToken, nil
	} else {
		return nil, err
	}
}

// DefaultJWTParser is the parser implementation that simply delegates to
// the jwt library's jws.ParseJWT function.
var DefaultJWTParser JWTParser = defaultJWTParser{}

type ClaimsWithLeeway struct {
	jwt.MapClaims
	Leeway Leeway
}

// Leeway is the amount of buffer to include with the time, to allow for clock
// skew.
type Leeway struct {
	EXP int64 `json:"expLeeway" yaml:"expLeeway"`
	NBF int64 `json:"nbfLeeway" yaml:"nbfLeeway"`
	IAT int64 `json:"iatLeeway" yaml:"iatLeeway"`
}

// Valid implements the jwt.Claims interface, ensuring that the token claism
// are valid.  This implementation checks the time based claims: exp, iat, nbf.
func (c *ClaimsWithLeeway) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()

	if !c.VerifyExpiresAt(now+c.Leeway.EXP, false) {
		vErr.Inner = errors.New("Token is expired")
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now-c.Leeway.IAT, false) {
		vErr.Inner = errors.New("Token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now-c.Leeway.NBF, false) {
		vErr.Inner = errors.New("Token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

func (c *ClaimsWithLeeway) UnmarshalJSON(data []byte) error {
	c.MapClaims = make(jwt.MapClaims) // just to be sure it's clean before each unmarshal
	return json.Unmarshal(data, &c.MapClaims)
}

// GetMap returns a map of string to interfaces of the values in the ClaimsWithLeeway
func (c *ClaimsWithLeeway) GetMap() (map[string]interface{}, error) {
	return c.MapClaims, nil
}
