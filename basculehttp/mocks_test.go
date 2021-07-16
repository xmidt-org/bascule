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
