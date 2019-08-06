package acquire

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
			description:   "HTTP Make Request Error",
			authToken:     goodAuth,
			expectedToken: "",
			authURL:       "/\b",
			expectedErr:   errors.New("failed to create new request for Bearer"),
		},
		{
			description:   "HTTP Do Error",
			authToken:     goodAuth,
			expectedToken: "",
			authURL:       "/",
			expectedErr:   errors.New("error acquiring bearer token"),
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
				assert.Nil(err)
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

			assert.Nil(errConstructor)

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
		assert.Nil(err)
		rw.Write(marshaledAuth)
	}))
	defer server.Close()

	// Use Client & URL from our local test server
	auth, errConstructor := NewRemoteBearerTokenAcquirer(RemoteBearerTokenAcquirerOptions{
		AuthURL: server.URL,
		Timeout: time.Duration(5) * time.Second,
		Buffer:  time.Microsecond,
	})
	assert.Nil(errConstructor)
	token, err := auth.Acquire()
	assert.Nil(err)

	cachedToken, err := auth.Acquire()
	assert.Nil(err)
	assert.Equal(token, cachedToken)
	assert.Equal(1, count)
}
