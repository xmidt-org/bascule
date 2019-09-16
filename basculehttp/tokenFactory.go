package basculehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goph/emperror"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/key"
)

const (
	jwtPrincipalKey = "sub"
)

var (
	ErrorMalformedValue      = errors.New("expected <user>:<password> in decoded value")
	ErrorNotInMap            = errors.New("principal not found")
	ErrorInvalidPassword     = errors.New("invalid password")
	ErrorNoProtectedHeader   = errors.New("missing protected header")
	ErrorNoSigningMethod     = errors.New("signing method (alg) is missing or unrecognized")
	ErrorUnexpectedPayload   = errors.New("payload isn't a map of strings to interfaces")
	ErrorUnexpectedPrincipal = errors.New("principal isn't a string")
	ErrorInvalidToken        = errors.New("token isn't valid")
	ErrorUnexpectedClaims    = errors.New("claims wasn't MapClaims as expected")
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
		return nil, emperror.WrapWith(err, "could not decode string")
	}

	i := bytes.IndexByte(decoded, ':')
	if i <= 0 {
		return nil, ErrorMalformedValue
	}
	principal := string(decoded[:i])
	val, ok := btf[principal]
	if !ok {
		return nil, ErrorNotInMap
	}
	if val != string(decoded[i+1:]) {
		// failed authentication
		return nil, ErrorInvalidPassword
	}
	// "basic" is a placeholder here ... token types won't always map to the
	// Authorization header.  For example, a JWT should have a type of "jwt" or some such, not "bearer"
	return bascule.NewToken("basic", principal, bascule.Attributes{}), nil
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
			return nil, emperror.Wrap(err, "failed to resolve key")
		}
		return pair.Public(), nil
	}

	leewayclaims := bascule.ClaimsWithLeeway{
		MapClaims: make(jwt.MapClaims),
		Leeway:    btf.Leeway,
	}

	jwsToken, err := btf.Parser.ParseJWT(value, &leewayclaims, keyfunc)
	if err != nil {
		return nil, emperror.Wrap(err, "failed to parse JWS")
	}
	if !jwsToken.Valid {
		return nil, ErrorInvalidToken
	}

	claims, ok := jwsToken.Claims.(*bascule.ClaimsWithLeeway)
	if !ok {
		return nil, emperror.Wrap(ErrorUnexpectedClaims, "failed to parse JWS")
	}

	claimsMap, err := claims.GetMap()
	if err != nil {
		return nil, emperror.WrapWith(err, "failed to get map of claims", "claims struct", claims)
	}
	payload := bascule.Attributes(claimsMap)

	principal, ok := payload[jwtPrincipalKey].(string)
	if !ok {
		return nil, emperror.WrapWith(ErrorUnexpectedPrincipal, "failed to get and convert principal", "principal", payload[jwtPrincipalKey], "payload", payload)
	}

	return bascule.NewToken("jwt", principal, payload), nil
}
