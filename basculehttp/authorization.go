// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/xmidt-org/bascule/v1"
)

const (
	// DefaultAuthorizationHeader is the default HTTP header used for authorization
	// tokens in an HTTP request.
	DefaultAuthorizationHeader = "Authorization"
)

var (
	// ErrInvalidAuthorization indicates an authorization header value did not
	// correspond to the standard.
	ErrInvalidAuthorization = errors.New("invalid authorization")
)

// ParseAuthorization parses an authorization value typically passed in
// the Authorization HTTP header.
//
// The required format is <scheme><single space><credential value>.  This function
// is strict:  it requires no leading or trailing space and exactly (1) space as
// a separator.  If the raw value does not adhere to this format, ErrInvalidAuthorization
// is returned.
func ParseAuthorization(raw string) (s Scheme, v string, err error) {
	var scheme string
	var found bool
	scheme, v, found = strings.Cut(raw, " ")
	if found && len(scheme) > 0 && !fastIsSpace(v[0]) && !fastIsSpace(v[len(v)-1]) {
		s = Scheme(scheme)
	} else {
		err = ErrInvalidAuthorization
	}

	return
}

// AuthorizationParserOption is a configurable option for an AuthorizationParser.
type AuthorizationParserOption interface {
	apply(*AuthorizationParser) error
}

type authorizationParserOptionFunc func(*AuthorizationParser) error

func (apof authorizationParserOptionFunc) apply(ap *AuthorizationParser) error { return apof(ap) }

// WithAuthorizationHeader changes the name of the header holding the token.  By default,
// the header used is DefaultAuthorizationHeader.
func WithAuthorizationHeader(header string) AuthorizationParserOption {
	return authorizationParserOptionFunc(func(ap *AuthorizationParser) error {
		ap.header = header
		return nil
	})
}

// WithScheme registers a string-based token parser that handles a
// specific authorization scheme.  Invocations to this option are cumulative
// and will overwrite any existing registration.
func WithScheme(scheme Scheme, parser bascule.TokenParser[string]) AuthorizationParserOption {
	return authorizationParserOptionFunc(func(ap *AuthorizationParser) error {
		// we want case-insensitive matches, so lowercase everything
		ap.parsers[scheme.lower()] = parser
		return nil
	})
}

// WithBasic is a shorthand for WithScheme that registers basic token parsing using
// the default scheme.
func WithBasic() AuthorizationParserOption {
	return WithScheme(SchemeBasic, BasicTokenParser{})
}

// AuthorizationParsers is a bascule.TokenParser that handles the Authorization header.
//
// By default, this parser will use the standard Authorization header, which can be
// changed via with WithAuthorizationHeader option.
type AuthorizationParser struct {
	header  string
	parsers map[Scheme]bascule.TokenParser[string]
}

// NewAuthorizationParser constructs an Authorization parser from a set
// of configuration options.
func NewAuthorizationParser(opts ...AuthorizationParserOption) (*AuthorizationParser, error) {
	ap := &AuthorizationParser{
		parsers: make(map[Scheme]bascule.TokenParser[string]),
	}

	for _, o := range opts {
		if err := o.apply(ap); err != nil {
			return nil, err
		}
	}

	if len(ap.header) == 0 {
		ap.header = DefaultAuthorizationHeader
	}

	return ap, nil
}

// Parse extracts the appropriate header, Authorization by default, and parses the
// scheme and value.  Schemes are case-insensitive, e.g. BASIC and Basic are the same scheme.
//
// If no authorization header is found in the request, this method returns ErrMissingCredentials.
//
// If a token parser is registered for the given scheme, that token parser is invoked.
// Otherwise, UnsupportedSchemeError is returned, indicating the scheme in question.
func (ap *AuthorizationParser) Parse(ctx context.Context, source *http.Request) (bascule.Token, error) {
	authValue := source.Header.Get(ap.header)
	if len(authValue) == 0 {
		return nil, bascule.ErrMissingCredentials
	}

	scheme, value, err := ParseAuthorization(authValue)
	if err != nil {
		return nil, bascule.ErrInvalidCredentials
	}

	p, registered := ap.parsers[scheme.lower()]
	if !registered {
		return nil, &UnsupportedSchemeError{
			Scheme: scheme,
		}
	}

	return p.Parse(ctx, value)
}
