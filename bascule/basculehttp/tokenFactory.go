package basculehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/Comcast/comcast-bascule/bascule"
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
