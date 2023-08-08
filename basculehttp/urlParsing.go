// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"errors"
	"net/url"
	"strings"

	"go.uber.org/fx"
)

// ParseURL is a function that modifies the url given then returns it.
type ParseURL func(*url.URL) (*url.URL, error)

// ParseURLIn is uber fx wiring allowing for ParseURL to be optional.
type ParseURLIn struct {
	fx.In
	P ParseURL `optional:"true"`
}

// DefaultParseURLFunc does nothing.  It returns the same url it received.
func DefaultParseURLFunc(u *url.URL) (*url.URL, error) {
	return u, nil
}

// CreateRemovePrefixURLFunc parses the URL by removing the prefix specified.
func CreateRemovePrefixURLFunc(prefix string, next ParseURL) ParseURL {
	return func(u *url.URL) (*url.URL, error) {
		escapedPath := u.EscapedPath()
		if !strings.HasPrefix(escapedPath, prefix) {
			return nil, errors.New("unexpected URL, did not start with expected prefix")
		}
		u.Path = escapedPath[len(prefix):]
		u.RawPath = escapedPath[len(prefix):]
		if next == nil {
			return u, nil
		}
		return next(u)
	}
}

// ProvideParseURL creates the constructor option to include a ParseURL function
// if it is provided.
func ProvideParseURL() fx.Option {
	return fx.Provide(
		fx.Annotated{
			Group: "bascule_constructor_options",
			Target: func(in ParseURLIn) COption {
				return WithParseURLFunc(in.P)
			},
		},
	)
}
