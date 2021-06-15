/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
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

package key

import (
	"errors"
	"fmt"
	"time"

	"github.com/xmidt-org/arrange"
	"github.com/xmidt-org/webpa-common/resource"
	"go.uber.org/fx"
)

const (
	// KeyIdParameterName is the template parameter that must be present in URI templates
	// if there are any parameters.  URI templates accepted by this package have either no parameters
	// or exactly one (1) parameter with this name.
	KeyIdParameterName = "keyId"

	DefaultKeysUpdateInterval = 24 * time.Hour
)

var (
	// ErrorInvalidTemplate is the error returned when a URI template is invalid for a key resource
	ErrorInvalidTemplate = fmt.Errorf(
		"Key resource template must support either no parameters are the %s parameter",
		KeyIdParameterName,
	)

	ErrNoResolverFactory = errors.New("no resolver factory configuration found")
)

// ResolverFactory provides a JSON representation of a collection of keys together
// with a factory interface for creating distinct Resolver instances.
//
// This factory uses resource.NewExpander() to create a resource template used in resolving keys.
// This template can have no parameters, in which case the same resource is used regardless
// of the key id.  If the template has any parameters, it must have exactly (1) parameter
// and that parameter's name must be equal to KeyIdParameterName.
type ResolverFactory struct {
	resource.Factory

	// All keys resolved by this factory will have this purpose, which affects
	// how keys are parsed.
	Purpose Purpose `json:"purpose"`

	// UpdateInterval specifies how often keys should be refreshed.
	// If negative or zero, keys are never refreshed and are cached forever.
	UpdateInterval time.Duration `json:"updateInterval"`

	// Parser is a custom key parser.  If omitted, DefaultParser is used.
	Parser Parser `json:"-"`
}

type ResolverFactoryIn struct {
	fx.In
	R *ResolverFactory `name:"key_resolver_factory"`
}

func (factory *ResolverFactory) parser() Parser {
	if factory.Parser != nil {
		return factory.Parser
	}

	return DefaultParser
}

// NewResolver() creates a Resolver using this factory's configuration.  The
// returned Resolver always caches keys forever once they have been loaded.
func (factory *ResolverFactory) NewResolver() (Resolver, error) {
	expander, err := factory.NewExpander()
	if err != nil {
		return nil, err
	}

	names := expander.Names()
	nameCount := len(names)
	if nameCount == 0 {
		// the template had no parameters, so we can create a simpler object
		loader, err := factory.NewLoader()
		if err != nil {
			return nil, err
		}

		return &singleCache{
			basicCache{
				delegate: &singleResolver{
					basicResolver: basicResolver{
						parser:  factory.parser(),
						purpose: factory.Purpose,
					},
					loader: loader,
				},
			},
		}, nil
	} else if nameCount == 1 && names[0] == KeyIdParameterName {
		return &multiCache{
			basicCache{
				delegate: &multiResolver{
					basicResolver: basicResolver{
						parser:  factory.parser(),
						purpose: factory.Purpose,
					},
					expander: expander,
				},
			},
		}, nil
	}

	return nil, ErrorInvalidTemplate
}

func ProvideResolver(key string, optional bool) fx.Option {
	return fx.Provide(
		fx.Annotated{
			Name:   "key_resolver_factory",
			Target: arrange.UnmarshalKey(key, &ResolverFactory{}),
		},
		fx.Annotated{
			Name: "key_resolver",
			Target: func(in ResolverFactoryIn) (Resolver, error) {
				if in.R == nil || in.R.URI == "" {
					if optional {
						return nil, nil
					}
					return nil, fmt.Errorf("%w at key %s", ErrNoResolverFactory, key)
				}
				if in.R.UpdateInterval < 1 {
					in.R.UpdateInterval = DefaultKeysUpdateInterval
				}
				return in.R.NewResolver()
			},
		},
	)
}
