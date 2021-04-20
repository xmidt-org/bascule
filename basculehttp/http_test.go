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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorHeaderer(t *testing.T) {
	assert := assert.New(t)
	expectedErr := "test error"
	headers := map[string][]string{"test key": {"a", "b", "c", "d"}}
	eh := NewErrorHeaderer(errors.New(expectedErr), headers)
	var e headerer
	assert.True(errors.As(eh, &e))
	err := eh.Error()
	assert.Equal(expectedErr, err)
	h := e.Headers()
	assert.Equal(http.Header(headers), h)
}

type coder int

func (b coder) StatusCode() int {
	return int(b)
}

func TestWriteResponse(t *testing.T) {
	assert := assert.New(t)
	recorder := httptest.NewRecorder()
	err := errors.New("test error")
	headers := map[string][]string{"test key": {"a", "b", "c", "d"}}
	WriteResponse(recorder, http.StatusOK, NewErrorHeaderer(err, headers))
	assert.Equal(http.StatusOK, recorder.Code)
	assert.Equal(http.Header(headers), recorder.Header())
	recorder = httptest.NewRecorder()
	c := coder(http.StatusForbidden)
	WriteResponse(recorder, http.StatusBadRequest, c)
	assert.Equal(http.StatusForbidden, recorder.Code)
	assert.Equal(http.Header{}, recorder.Header())
}
