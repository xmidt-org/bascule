package basculehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/Comcast/comcast-bascule/bascule"
	"github.com/Comcast/comcast-bascule/bascule/key"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
)

const (
	jwtPrincipalKey = "sub"
)

var (
	ErrorNoProtectedHeader   = errors.New("Missing protected header")
	ErrorNoSigningMethod     = errors.New("Signing method (alg) is missing or unrecognized")
	ErrorUnexpectedPayload   = errors.New("Payload isn't a map of strings to interfaces")
	ErrorUnexpectedPrincipal = errors.New("Principal isn't a string")
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
		return nil, err
	}

	i := bytes.IndexByte(decoded, ':')
	if i > 0 {
		principal := string(decoded[:i])
		if btf[principal] == string(decoded[i+1:]) {
			// "basic" is a placeholder here ... token types won't always map to the Authorization header.
			// For example, a JWT should have a type of "jwt" or some such, not "bearer"
			return bascule.NewToken("basic", principal, bascule.Attributes{}), nil
		}
	}

	// failed authentication
	return nil, errors.New("TODO: Enrich this error with information")
}

type BearerTokenFactory struct {
	DefaultKeyId  string
	Resolver      key.Resolver
	Parser        bascule.JWSParser
	JWTValidators []*jwt.Validator
}

func (btf BearerTokenFactory) ParseAndValidate(ctx context.Context, request *http.Request, auth bascule.Authorization, value string) (bascule.Token, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	jwsToken, err := btf.Parser.ParseJWS(decoded)
	if err != nil {
		return nil, err
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

	pair, err := btf.Resolver.ResolveKey(keyID)
	if err != nil {
		return nil, err
	}

	// validate the signature
	if len(btf.JWTValidators) > 0 {
		// all JWS implementations also implement jwt.JWT
		err = jwsToken.(jwt.JWT).Validate(pair.Public(), signingMethod, btf.JWTValidators...)
	} else {
		err = jwsToken.Verify(pair.Public(), signingMethod)
	}

	if err != nil {
		// todo: add metrics to log the type of verification error
		return nil, err
	}

	payload, ok := jwsToken.Payload().(bascule.Attributes)
	if !ok {
		return nil, ErrorUnexpectedPayload
	}

	principal, ok := payload[jwtPrincipalKey].(string)
	if !ok {
		return nil, ErrorUnexpectedPrincipal
	}

	return bascule.NewToken("jwt", principal, jwsToken.Payload().(bascule.Attributes)), nil
}
