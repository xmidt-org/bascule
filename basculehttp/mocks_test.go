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
	"github.com/SermoDigital/jose"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/stretchr/testify/mock"
	"github.com/xmidt-org/bascule"
)

type mockJWSParser struct {
	mock.Mock
}

func (parser *mockJWSParser) ParseJWS(token []byte) (jws.JWS, error) {
	arguments := parser.Called(token)
	jwsToken, _ := arguments.Get(0).(jws.JWS)
	return jwsToken, arguments.Error(1)
}

type mockJWS struct {
	mock.Mock
}

var _ jwt.JWT = (*mockJWS)(nil)
var _ jws.JWS = (*mockJWS)(nil)

func (j *mockJWS) Claims() jwt.Claims {
	arguments := j.Called()
	return arguments.Get(0).(jwt.Claims)
}

func (j *mockJWS) Validate(key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) error {
	arguments := j.Called(key, method, v)
	return arguments.Error(0)
}

func (j *mockJWS) Serialize(key interface{}) ([]byte, error) {
	arguments := j.Called(key)
	return arguments.Get(0).([]byte), arguments.Error(1)
}

func (j *mockJWS) Payload() interface{} {
	arguments := j.Called()
	return arguments.Get(0)
}

func (j *mockJWS) SetPayload(p interface{}) {
	j.Called(p)
}

func (j *mockJWS) Protected() jose.Protected {
	arguments := j.Called()
	protected, _ := arguments.Get(0).(jose.Protected)
	return protected
}

func (j *mockJWS) ProtectedAt(i int) jose.Protected {
	arguments := j.Called(i)
	return arguments.Get(0).(jose.Protected)
}

func (j *mockJWS) Header() jose.Header {
	arguments := j.Called()
	return arguments.Get(0).(jose.Header)
}

func (j *mockJWS) HeaderAt(i int) jose.Header {
	arguments := j.Called(i)
	return arguments.Get(0).(jose.Header)
}

func (j *mockJWS) Verify(key interface{}, method crypto.SigningMethod) error {
	arguments := j.Called(key, method)
	return arguments.Error(0)
}

func (j *mockJWS) VerifyMulti(keys []interface{}, methods []crypto.SigningMethod, o *jws.SigningOpts) error {
	arguments := j.Called(keys, methods, o)
	return arguments.Error(0)
}

func (j *mockJWS) VerifyCallback(fn jws.VerifyCallback, methods []crypto.SigningMethod, o *jws.SigningOpts) error {
	arguments := j.Called(fn, methods, o)
	return arguments.Error(0)
}

func (j *mockJWS) General(keys ...interface{}) ([]byte, error) {
	arguments := j.Called(keys)
	return arguments.Get(0).([]byte), arguments.Error(1)
}

func (j *mockJWS) Flat(key interface{}) ([]byte, error) {
	arguments := j.Called(key)
	return arguments.Get(0).([]byte), arguments.Error(1)
}

func (j *mockJWS) Compact(key interface{}) ([]byte, error) {
	arguments := j.Called(key)
	return arguments.Get(0).([]byte), arguments.Error(1)
}

func (j *mockJWS) IsJWT() bool {
	arguments := j.Called()
	return arguments.Bool(0)
}

// mockListener
type mockListener struct {
	mock.Mock
}

func (l *mockListener) OnAuthenticated(a bascule.Authentication) {
	l.Called(a)
}
