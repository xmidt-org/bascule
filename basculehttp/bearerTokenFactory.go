// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/xmidt-org/arrange"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/clortho/clorthofx"
	"go.uber.org/fx"
)

const (
	jwtPrincipalKey = "sub"
)

var (
	ErrEmptyValue       = errors.New("empty value")
	ErrInvalidPrincipal = errors.New("invalid principal")
	ErrInvalidToken     = errors.New("token isn't valid")
	ErrUnexpectedClaims = errors.New("claims wasn't MapClaims as expected")

	ErrNilResolver = errors.New("resolver cannot be nil")
)

// BearerTokenFactory parses and does basic validation for a JWT token,
// converting it into a bascule Token.
type BearerTokenFactory struct {
	fx.In
	DefaultKeyID string `name:"default_key_id"`
	Resolver     clortho.Resolver
	Parser       bascule.JWTParser `optional:"true"`
	Leeway       bascule.Leeway    `name:"jwt_leeway" optional:"true"`
}

// ParseAndValidate expects the given value to be a JWT with a kid header.  The
// kid should be resolvable by the Resolver and the JWT should be Parseable and
// pass any basic validation checks done by the Parser.  If everything goes
// well, a Token of type "jwt" is returned.
func (btf BearerTokenFactory) ParseAndValidate(ctx context.Context, _ *http.Request, _ bascule.Authorization, value string) (bascule.Token, error) {
	if len(value) == 0 {
		return nil, ErrEmptyValue
	}

	keyfunc := func(token *jwt.Token) (interface{}, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			keyID = btf.DefaultKeyID
		}

		key, err := btf.Resolver.Resolve(ctx, keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve key: %v", err)
		}
		return key.Public(), nil
	}

	leewayclaims := bascule.ClaimsWithLeeway{
		MapClaims: make(jwt.MapClaims),
		Leeway:    btf.Leeway,
	}

	jwtToken, err := btf.Parser.ParseJWT(value, &leewayclaims, keyfunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %v", err)
	}
	if !jwtToken.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := jwtToken.Claims.(*bascule.ClaimsWithLeeway)
	if !ok {
		return nil, fmt.Errorf("failed to parse JWS: %w", ErrUnexpectedClaims)
	}
	claimsMap, err := claims.GetMap()
	if err != nil {
		return nil, fmt.Errorf("failed to get map of claims with object [%v]: %v", claims, err)
	}
	jwtClaims := bascule.NewAttributes(claimsMap)
	principalVal, ok := jwtClaims.Get(jwtPrincipalKey)
	if !ok {
		return nil, fmt.Errorf("%w: principal value not found at key %v", ErrInvalidPrincipal, jwtPrincipalKey)
	}
	principal, ok := principalVal.(string)
	if !ok {
		return nil, fmt.Errorf("%w: principal value [%v] not a string", ErrInvalidPrincipal, principalVal)
	}

	return bascule.NewToken("jwt", principal, jwtClaims), nil
}

// ProvideBearerTokenFactory uses the key given to unmarshal configuration
// needed to build a bearer token factory.  It provides a constructor option
// with the bearer token factory.
func ProvideBearerTokenFactory(configKey string, optional bool) fx.Option {
	return fx.Options(
		clorthofx.Provide(),
		fx.Provide(
			fx.Annotated{
				Name: "jwt_leeway",
				Target: arrange.UnmarshalKey(fmt.Sprintf("%s.leeway", configKey),
					bascule.Leeway{}),
			},
			fx.Annotated{
				Group: "bascule_constructor_options",
				Target: func(f BearerTokenFactory) (COption, error) {
					if f.Parser == nil {
						f.Parser = bascule.DefaultJWTParser
					}
					return WithTokenFactory(BearerAuthorization, f), nil
				},
			},
		),
	)
}
