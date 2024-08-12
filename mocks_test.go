// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type testToken string

func (tt testToken) Principal() string { return string(tt) }

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
