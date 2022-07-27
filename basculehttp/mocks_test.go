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

package basculehttp

import (
	"github.com/stretchr/testify/mock"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/clortho"

	"context"

	"github.com/golang-jwt/jwt"
)

// mockListener
type mockListener struct {
	mock.Mock
}

func (l *mockListener) OnAuthenticated(a bascule.Authentication) {
	l.Called(a)
}

// mock JWT parser
type mockParser struct {
	mock.Mock
}

// we want to test the parseFunc so it needs to be called here.
func (p *mockParser) ParseJWT(token string, claims jwt.Claims, parseFunc jwt.Keyfunc) (*jwt.Token, error) {
	args := p.Called(token, claims, parseFunc)
	t := args.Get(0).(*jwt.Token)
	err := args.Error(1)
	if err != nil {
		return t, err
	}
	_, err = parseFunc(t)
	return t, err
}

// MockKey is a mock for key.
type MockKey struct {
	mock.Mock
}

func (key *MockKey) KeyID() string {
	arguments := key.Called()
	return arguments.String(0)
}
func (key *MockKey) KeyType() string {
	arguments := key.Called()
	return arguments.String(0)
}
func (key *MockKey) KeyUsage() string {
	arguments := key.Called()
	return arguments.String(0)
}

func (key *MockKey) Raw() interface{} {
	arguments := key.Called()
	return arguments.Get(0)
}

func (key *MockKey) String() string {
	arguments := key.Called()
	return arguments.String(0)
}

// MockResolver is a stretchr mock for Resolver.  It's exposed for other package tests.
type MockResolver struct {
	mock.Mock
}

func (resolver *MockResolver) Resolve(ctx context.Context, keyId string) (clortho.Key, error) {
	arguments := resolver.Called(ctx, keyId)
	if pair, ok := arguments.Get(0).(clortho.Key); ok {
		return pair, arguments.Error(1)
	} else {
		return nil, arguments.Error(1)
	}
}
func (resolver *MockResolver) AddListener(l clortho.ResolveListener) clortho.CancelListenerFunc {
	arguments := resolver.Called(l)
	return arguments.Get(0).(clortho.CancelListenerFunc)
}
