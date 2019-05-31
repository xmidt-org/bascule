package acquire

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthAcquireSuccess(t *testing.T) {
	goodAuth := JWTBasic{
		Token: "test token",
	}
	goodToken := "Bearer test token"

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
			expectedErr:   errors.New("failed to create new request for JWT"),
		},
		{
			description:   "HTTP Do Error",
			authToken:     goodAuth,
			expectedToken: "",
			authURL:       "/",
			expectedErr:   errors.New("error acquiring JWT token"),
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
			expectedErr:   errors.New("unable to read json"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)

			// Start a local HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
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
			auth := NewJWTAcquirer(JWTAcquirerOptions{
				AuthURL: url,
				Timeout: time.Duration(5) * time.Second,
			})
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

func TestAuthCaching(t *testing.T) {
	assert := assert.New(t)

	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		auth := JWTBasic{
			Token:      "gopher+" + string(count),
			Expiration: 1,
		}
		count++

		marshaledAuth, err := json.Marshal(&auth)
		assert.Nil(err)
		rw.Write(marshaledAuth)
	}))
	defer server.Close()

	// Use Client & URL from our local test server
	auth := NewJWTAcquirer(JWTAcquirerOptions{
		AuthURL: server.URL,
		Timeout: time.Duration(5) * time.Second,
		Buffer:  time.Microsecond,
	})
	token, err := auth.Acquire()
	assert.Nil(err)
	tokenA, err := auth.Acquire()
	assert.Nil(err)
	assert.Equal(token, tokenA)
	time.Sleep(time.Second)
	tokenA, err = auth.Acquire()
	assert.Nil(err)
	assert.NotEqual(token, tokenA)
}
