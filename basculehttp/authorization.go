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
	ErrInvalidAuthorization = errors.New("invalidation authorization")

	// ErrMissingAuthorization indicates that no authorization header was
	// present in the source HTTP request.
	ErrMissingAuthorization = errors.New("missing authorization")
)

// fastIsSpace tests an ASCII byte to see if it's whitespace.
// HTTP headers are restricted to US-ASCII, so we don't need
// the full unicode stack.
func fastIsSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

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

type AuthorizationParserOption interface {
	apply(*AuthorizationParser) error
}

type authorizationParserOptionFunc func(*AuthorizationParser) error

func (apof authorizationParserOptionFunc) apply(ap *AuthorizationParser) error { return apof(ap) }

func WithAuthorizationHeader(header string) AuthorizationParserOption {
	return authorizationParserOptionFunc(func(ap *AuthorizationParser) error {
		ap.header = header
		return nil
	})
}

func WithScheme(scheme Scheme, parser bascule.TokenParser[string]) AuthorizationParserOption {
	return authorizationParserOptionFunc(func(ap *AuthorizationParser) error {
		ap.parsers[scheme] = parser
		return nil
	})
}

type AuthorizationParser struct {
	header  string
	parsers map[Scheme]bascule.TokenParser[string]
}

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

func (ap *AuthorizationParser) Parse(_ context.Context, source *http.Request) (bascule.Token, error) {
	return nil, nil // TODO
}
