// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type mockToken struct {
	mock.Mock
}

func (m *mockToken) Principal() string {
	return m.Called().String(0)
}

func (m *mockToken) ExpectPrincipal(v string) *mock.Call {
	return m.On("Principal").Return(v)
}

type mockTokenWithCapabilities struct {
	mockToken
}

func (m *mockTokenWithCapabilities) Capabilities() []string {
	args := m.Called()
	caps, _ := args.Get(0).([]string)
	return caps
}

func (m *mockTokenWithCapabilities) ExpectCapabilities(caps ...string) *mock.Call {
	return m.On("Capabilities").Return(caps)
}

type mockValidator[S any] struct {
	mock.Mock
}

func (m *mockValidator[S]) Validate(ctx context.Context, source S, token Token) (Token, error) {
	args := m.Called(ctx, source, token)
	t, _ := args.Get(0).(Token)
	return t, args.Error(1)
}

func (m *mockValidator[S]) ExpectValidate(ctx context.Context, source S, token Token) *mock.Call {
	return m.On("Validate", ctx, source, token)
}

func assertValidators[S any](t mock.TestingT, vs ...Validator[S]) (passed bool) {
	for _, v := range vs {
		passed = v.(*mockValidator[S]).AssertExpectations(t) && passed
	}

	return
}

type mockTokenParser[S any] struct {
	mock.Mock
}

func (m *mockTokenParser[S]) Parse(ctx context.Context, source S) (Token, error) {
	args := m.Called(ctx, source)
	t, _ := args.Get(0).(Token)
	return t, args.Error(1)
}

func (m *mockTokenParser[S]) ExpectParse(ctx context.Context, source S) *mock.Call {
	return m.On("Parse", ctx, source)
}

func assertTokenParsers[S any](t mock.TestingT, tps ...TokenParser[S]) (passed bool) {
	for _, p := range tps {
		passed = p.(*mockTokenParser[S]).AssertExpectations(t) && passed
	}

	return
}

type mockApprover[R any] struct {
	mock.Mock
}

func (m *mockApprover[R]) Approve(ctx context.Context, resource R, token Token) error {
	return m.Called(ctx, resource, token).Error(0)
}

func (m *mockApprover[R]) ExpectApprove(ctx context.Context, resource R, token Token) *mock.Call {
	return m.On("Approve", ctx, resource, token)
}

type mockAuthenticateListener[E any] struct {
	mock.Mock
}

func (m *mockAuthenticateListener[E]) OnEvent(e AuthenticateEvent[E]) {
	m.Called(e)
}

func (m *mockAuthenticateListener[E]) ExpectOnEvent(expected AuthenticateEvent[E]) *mock.Call {
	return m.On("OnEvent", expected)
}

type mockAuthorizeListener[E any] struct {
	mock.Mock
}

func (m *mockAuthorizeListener[E]) OnEvent(e AuthorizeEvent[E]) {
	m.Called(e)
}

func (m *mockAuthorizeListener[E]) ExpectOnEvent(expected AuthorizeEvent[E]) *mock.Call {
	return m.On("OnEvent", expected)
}
