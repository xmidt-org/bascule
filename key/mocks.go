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

	"github.com/stretchr/testify/mock"
)

var _ Resolver = (*MockResolver)(nil)
var _ Cache = (*MockCache)(nil)
var _ Parser = (*MockParser)(nil)

// MockResolver is a stretchr mock for Resolver.  It's exposed for other package tests.
type MockResolver struct {
	mock.Mock
}

func (resolver *MockResolver) ResolveKey(ctx context.Context, keyId string) (Pair, error) {
	arguments := resolver.Called(ctx, keyId)
	if pair, ok := arguments.Get(0).(Pair); ok {
		return pair, arguments.Error(1)
	} else {
		return nil, arguments.Error(1)
	}
}

// MockCache is a stretchr mock for Cache.  It's exposed for other package tests.
type MockCache struct {
	mock.Mock
}

func (cache *MockCache) ResolveKey(ctx context.Context, keyId string) (Pair, error) {
	arguments := cache.Called(ctx, keyId)
	if pair, ok := arguments.Get(0).(Pair); ok {
		return pair, arguments.Error(1)
	} else {
		return nil, arguments.Error(1)
	}
}

func (cache *MockCache) UpdateKeys(ctx context.Context) (int, []error) {
	arguments := cache.Called(ctx)
	if errors, ok := arguments.Get(1).([]error); ok {
		return arguments.Int(0), errors
	} else {
		return arguments.Int(0), nil
	}
}

// MockPair is a stretchr mock for Pair.  It's exposed for other package tests.
type MockPair struct {
	mock.Mock
}

func (pair *MockPair) Purpose() Purpose {
	arguments := pair.Called()
	return arguments.Get(0).(Purpose)
}

func (pair *MockPair) Public() interface{} {
	arguments := pair.Called()
	return arguments.Get(0)
}

func (pair *MockPair) HasPrivate() bool {
	arguments := pair.Called()
	return arguments.Bool(0)
}

func (pair *MockPair) Private() interface{} {
	arguments := pair.Called()
	return arguments.Get(0)
}

type MockParser struct {
	mock.Mock
}

func (parser *MockParser) ParseKey(ctx context.Context, purpose Purpose, data []byte) (Pair, error) {
	arguments := parser.Called(ctx, purpose, data)
	if pair, ok := arguments.Get(0).(Pair); ok {
		return pair, arguments.Error(1)
	}

	return nil, arguments.Error(1)
}
