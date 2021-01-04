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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRemoteBearerTokenAcquirer(t *testing.T) {
	goodAuth := SimpleBearer{
		Token: "test-token",
	}
	goodToken := "Bearer test-token"

	tests := []struct {
		description        string
		authToken          interface{}
		authURL            string
		returnUnauthorized bool
		expectedToken      string
		expectedErr        error
	}{
		{
			description:   "Success",
			authToken:     goodAuth,
			expectedToken: goodToken,
			expectedErr:   nil,
		},
		{
			description:   "HTTP Do Error",
			authToken:     goodAuth,
			expectedToken: "",
			authURL:       "/",
			expectedErr:   errors.New("error making request to '/' to acquire bearer"),
		},
		{
			description:   "HTTP Make Request Error",
			authToken:     goodAuth,
			expectedToken: "",
			authURL:       "/\b",
			expectedErr:   errors.New("failed to create new request"),
		},
		{
			description:        "HTTP Unauthorized Error",
			authToken:          goodAuth,
			returnUnauthorized: true,
			expectedToken:      "",
			expectedErr:        errors.New("received non 200 code"),
		},
		{
			description:   "Unmarshal Error",
			authToken:     []byte("{token:5555}"),
			expectedToken: "",
			expectedErr:   errors.New("unable to parse bearer token"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)

			// Start a local HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

				// Test optional headers
				assert.Equal("v0", req.Header.Get("k0"))
				assert.Equal("v1", req.Header.Get("k1"))

				// Send response to be tested
				if tc.returnUnauthorized {
					rw.WriteHeader(http.StatusUnauthorized)
					return
				}
				marshaledAuth, err := json.Marshal(tc.authToken)
				assert.NoError(err)
				rw.Write(marshaledAuth)
			}))
			// Close the server when test finishes
			defer server.Close()

			url := server.URL
			if tc.authURL != "" {
				url = tc.authURL
			}

			// Use Client & URL from our local test server
			auth, errConstructor := NewRemoteBearerTokenAcquirer(RemoteBearerTokenAcquirerOptions{
				AuthURL:        url,
				Timeout:        5 * time.Second,
				RequestHeaders: map[string]string{"k0": "v0", "k1": "v1"},
			})

			assert.NoError(errConstructor)

			token, err := auth.Acquire()

			if tc.expectedErr == nil || err == nil {
				assert.Equal(tc.expectedErr, err)
			} else {
				assert.Contains(err.Error(), tc.expectedErr.Error())
			}
			assert.Equal(tc.expectedToken, token)
		})
	}
}

func TestRemoteBearerTokenAcquirerCaching(t *testing.T) {
	assert := assert.New(t)

	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		auth := SimpleBearer{
			Token:            fmt.Sprintf("gopher%v", count),
			ExpiresInSeconds: 3600, //1 hour
		}
		count++

		marshaledAuth, err := json.Marshal(&auth)
		assert.NoError(err)
		rw.Write(marshaledAuth)
	}))
	defer server.Close()

	// Use Client & URL from our local test server
	auth, errConstructor := NewRemoteBearerTokenAcquirer(RemoteBearerTokenAcquirerOptions{
		AuthURL: server.URL,
		Timeout: time.Duration(5) * time.Second,
		Buffer:  time.Microsecond,
	})
	assert.NoError(errConstructor)
	token, err := auth.Acquire()
	assert.NoError(err)

	cachedToken, err := auth.Acquire()
	assert.NoError(err)
	assert.Equal(token, cachedToken)
	assert.Equal(1, count)
}

func TestRemoteBearerTokenAcquirerExiting(t *testing.T) {
	assert := assert.New(t)

	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		auth := SimpleBearer{
			Token:            fmt.Sprintf("gopher%v", count),
			ExpiresInSeconds: 1, //1 second
		}
		count++

		marshaledAuth, err := json.Marshal(&auth)
		assert.NoError(err)
		rw.Write(marshaledAuth)
	}))
	defer server.Close()

	// Use Client & URL from our local test server
	auth, errConstructor := NewRemoteBearerTokenAcquirer(RemoteBearerTokenAcquirerOptions{
		AuthURL: server.URL,
		Timeout: time.Duration(5) * time.Second,
		Buffer:  time.Second,
	})
	assert.NoError(errConstructor)
	token, err := auth.Acquire()
	assert.NoError(err)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			_, err := auth.Acquire()
			assert.NoError(err)
			wg.Done()
		}()
	}
	wg.Wait()
	cachedToken, err := auth.Acquire()
	assert.NoError(err)
	assert.NotEqual(token, cachedToken)
}
