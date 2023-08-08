// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"crypto"

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

// mockKey is a mock for key.
type mockKey struct {
	mock.Mock
	clortho.Thumbprinter
}

func (key *mockKey) Public() crypto.PublicKey {
	arguments := key.Called()
	return arguments.Get(0)
}

func (key *mockKey) KeyType() string {
	arguments := key.Called()
	return arguments.String(0)
}

func (key *mockKey) KeyID() string {
	arguments := key.Called()
	return arguments.String(0)
}

func (key *mockKey) KeyUsage() string {
	arguments := key.Called()
	return arguments.String(0)
}

func (key *mockKey) Raw() interface{} {
	arguments := key.Called()
	return arguments.Get(0)
}

// MockResolver is a stretchr mock for Resolver.  It's exposed for other package tests.
type MockResolver struct {
	mock.Mock
}

func (resolver *MockResolver) Resolve(ctx context.Context, keyId string) (clortho.Key, error) {
	arguments := resolver.Called(ctx, keyId)
	if key, ok := arguments.Get(0).(clortho.Key); ok {
		return key, arguments.Error(1)
	} else {
		return nil, arguments.Error(1)
	}
}
func (resolver *MockResolver) AddListener(l clortho.ResolveListener) clortho.CancelListenerFunc {
	arguments := resolver.Called(l)
	return arguments.Get(0).(clortho.CancelListenerFunc)
}
