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
	"context"
	"fmt"

	"github.com/xmidt-org/webpa-common/resource"
)

// Resolver loads and parses keys associated with key identifiers.
type Resolver interface {
	// ResolveKey returns a key Pair associated with the given identifier.  The exact mechanics of resolving
	// a keyId into a Pair are implementation-specific.  Implementations are free
	// to ignore the keyId parameter altogether.
	ResolveKey(ctx context.Context, keyId string) (Pair, error)
}

// basicResolver contains common items for all resolvers.
type basicResolver struct {
	parser  Parser
	purpose Purpose
}

func (b *basicResolver) parseKey(ctx context.Context, data []byte) (Pair, error) {
	return b.parser.ParseKey(ctx, b.purpose, data)
}

// singleResolver is a Resolver which expects only (1) key for all key ids.
type singleResolver struct {
	basicResolver
	loader resource.Loader
}

func (r *singleResolver) String() string {
	return fmt.Sprintf(
		"singleResolver{parser: %v, purpose: %v, loader: %v}",
		r.parser,
		r.purpose,
		r.loader,
	)
}

func (r *singleResolver) ResolveKey(ctx context.Context, keyId string) (Pair, error) {
	data, err := resource.ReadAll(r.loader)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}

	return r.parseKey(ctx, data)
}

// multiResolver is a Resolver which uses the key id and will most likely return
// different keys for each key id value.
type multiResolver struct {
	basicResolver
	expander resource.Expander
}

func (r *multiResolver) String() string {
	return fmt.Sprintf(
		"multiResolver{parser: %v, purpose: %v, expander: %v}",
		r.parser,
		r.purpose,
		r.expander,
	)
}

func (r *multiResolver) ResolveKey(ctx context.Context, keyId string) (Pair, error) {
	values := map[string]interface{}{
		KeyIdParameterName: keyId,
	}

	loader, err := r.expander.Expand(values)
	if err != nil {
		return nil, err
	}

	data, err := resource.ReadAll(loader)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}

	return r.parseKey(ctx, data)
}
