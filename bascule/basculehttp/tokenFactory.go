package basculehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/Comcast/comcast-bascule/bascule"
	"github.com/Comcast/comcast-bascule/bascule/key"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goph/emperror"
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

// TokenFactory is a strategy interface responsible for creating and validating a secure token
type TokenFactory interface {
	ParseAndValidate(context.Context, *http.Request, bascule.Authorization, string) (bascule.Token, error)
}

type TokenFactoryFunc func(context.Context, *http.Request, bascule.Authorization, string) (bascule.Token, error)

func (tff TokenFactoryFunc) ParseAndValidate(ctx context.Context, r *http.Request, a bascule.Authorization, v string) (bascule.Token, error) {
	return tff(ctx, r, a, v)
}

// An example TokenFactory that this package should supply in some form.
// This type allows client code to simply use an in-memory map of users and passwords
// to authenticate against.  Other implementations might look things up in a database, etc.
type BasicTokenFactory map[string]string

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
	// "basic" is a placeholder here ... token types won't always map to the Authorization header.
	// For example, a JWT should have a type of "jwt" or some such, not "bearer"
	return bascule.NewToken("basic", principal, bascule.Attributes{}), nil
}

type BearerTokenFactory struct {
	DefaultKeyId string
	Resolver     key.Resolver
	Parser       bascule.JWTParser
	Leeway       bascule.Leeway
}

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
		Leeway: btf.Leeway,
	}

	jwsToken, err := btf.Parser.ParseJWT(value, &leewayclaims, keyfunc)
	if err != nil {
		return nil, emperror.Wrap(err, "failed to parse JWS")
	}
	if !jwsToken.Valid {
		return nil, ErrorInvalidToken
	}

	claims, ok := jwsToken.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, emperror.Wrap(ErrorUnexpectedClaims, "failed to parse JWS")
	}

	payload := bascule.Attributes(*claims)

	principal, ok := payload[jwtPrincipalKey].(string)
	if !ok {
		return nil, ErrorUnexpectedPrincipal
	}

	return bascule.NewToken("jwt", principal, payload), nil
}
