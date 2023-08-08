// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package acquire

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
