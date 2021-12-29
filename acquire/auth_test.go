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

package acquire

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"errors"

	"github.com/stretchr/testify/assert"
)

func TestAddAuth(t *testing.T) {
	fixedAcquirer, _ := NewFixedAuthAcquirer("Basic abc==")
	tests := []struct {
		name        string
		request     *http.Request
		acquirer    Acquirer
		shouldError bool
		authValue   string
	}{
		{
			name:        "RequestIsNil",
			acquirer:    &DefaultAcquirer{},
			shouldError: true,
		},
		{
			name:        "AcquirerIsNil",
			request:     httptest.NewRequest(http.MethodGet, "/", nil),
			shouldError: true,
		},
		{
			name:        "AcquirerFails",
			acquirer:    &failingAcquirer{},
			shouldError: true,
		},
		{
			name:        "HappyPath",
			request:     httptest.NewRequest(http.MethodGet, "/", nil),
			acquirer:    fixedAcquirer,
			shouldError: false,
			authValue:   "Basic abc==",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)

			if test.shouldError {
				assert.NotNil(AddAuth(test.request, test.acquirer))
			} else {
				assert.Nil(AddAuth(test.request, test.acquirer))
				assert.Equal(test.authValue, test.request.Header.Get("Authorization"))
			}
		})
	}
}

func TestFixedAuthAcquirer(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		assert := assert.New(t)

		acquirer, err := NewFixedAuthAcquirer("Basic xyz==")
		assert.NotNil(acquirer)
		assert.NoError(err)

		authValue, _ := acquirer.Acquire()
		assert.Equal("Basic xyz==", authValue)
	})

	t.Run("EmptyCredentials", func(t *testing.T) {
		assert := assert.New(t)

		acquirer, err := NewFixedAuthAcquirer("")
		assert.Equal(ErrEmptyCredentials, err)
		assert.Nil(acquirer)
	})
}

func TestDefaultAcquirer(t *testing.T) {
	assert := assert.New(t)
	acquirer := &DefaultAcquirer{}
	authValue, err := acquirer.Acquire()
	assert.Empty(authValue)
	assert.Empty(err)
}

type failingAcquirer struct{}

func (f *failingAcquirer) Acquire() (string, error) {
	return "", errors.New("always fails")
}
