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
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xmidt-org/bascule"
)

var (
	next = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
)

func TestListenerDecorator(t *testing.T) {
	assert := assert.New(t)
	mockListener := new(mockListener)
	mockListener.On("OnAuthenticated", mock.Anything).Once()
	f := NewListenerDecorator(mockListener)
	handler := f(next)

	writer := httptest.NewRecorder()
	req := httptest.NewRequest("get", "/", nil)
	handler.ServeHTTP(writer, req)
	assert.Equal(http.StatusForbidden, writer.Code)

	u, err := url.ParseRequestURI("/")
	assert.NoError(err)

	ctx := bascule.WithAuthentication(context.Background(), bascule.Authentication{
		Authorization: "jwt",
		Token:         bascule.NewToken("", "", bascule.NewAttributes(map[string]interface{}{})),
		Request: bascule.Request{
			URL:    u,
			Method: "get",
		},
	})
	req = req.WithContext(ctx)
	writer = httptest.NewRecorder()
	handler.ServeHTTP(writer, req)
	assert.Equal(http.StatusOK, writer.Code)

}
