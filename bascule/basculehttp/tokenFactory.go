package basculehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/xmidt-org/bascule/bascule"
	"github.com/xmidt-org/bascule/bascule/key"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
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
	DefaultKeyId  string
	Resolver      key.Resolver
	Parser        bascule.JWSParser
	JWTValidators []*jwt.Validator
}

func (btf BearerTokenFactory) ParseAndValidate(ctx context.Context, _ *http.Request, _ bascule.Authorization, value string) (bascule.Token, error) {
	if len(value) == 0 {
		return nil, errors.New("empty value")
	}
	decoded := []byte(value)

	jwsToken, err := btf.Parser.ParseJWS(decoded)
	if err != nil {
		return nil, emperror.Wrap(err, "failed to parse JWS")
	}

	protected := jwsToken.Protected()
	if len(protected) == 0 {
		return nil, ErrorNoProtectedHeader
	}

	alg, _ := protected.Get("alg").(string)
	signingMethod := jws.GetSigningMethod(alg)
	if signingMethod == nil {
		return nil, ErrorNoSigningMethod
	}

	keyID, _ := protected.Get("kid").(string)
	if len(keyID) == 0 {
		keyID = btf.DefaultKeyId
	}

	pair, err := btf.Resolver.ResolveKey(ctx, keyID)
	if err != nil {
		return nil, emperror.Wrap(err, "failed to resolve key")
	}

	// validate the signature
	if len(btf.JWTValidators) > 0 {
		// all JWS implementations also implement jwt.JWT
		err = jwsToken.(jwt.JWT).Validate(pair.Public(), signingMethod, btf.JWTValidators...)
		if err != nil {
			return nil, emperror.Wrap(err, "failed to validate token")
		}
	} else {
		err = jwsToken.Verify(pair.Public(), signingMethod)
		if err != nil {
			return nil, emperror.Wrap(err, "failed to verify token")
		}
	}

	claims, ok := jwsToken.Payload().(jws.Claims)
	if !ok {
		return nil, ErrorUnexpectedPayload
	}
	payload := bascule.Attributes(claims)

	principal, ok := payload[jwtPrincipalKey].(string)
	if !ok {
		return nil, ErrorUnexpectedPrincipal
	}

	return bascule.NewToken("jwt", principal, payload), nil
}
