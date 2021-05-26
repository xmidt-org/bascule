/**
 * Copyright 2021 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
