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

package acquire

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

// RemoteBearerTokenAcquirerOptions provides configuration for the RemoteBearerTokenAcquirer.
type RemoteBearerTokenAcquirerOptions struct {
	AuthURL        string            `json:"authURL"`
	Timeout        time.Duration     `json:"timeout"`
	Buffer         time.Duration     `json:"buffer"`
	RequestHeaders map[string]string `json:"requestHeaders"`

	GetToken      TokenParser
	GetExpiration ParseExpiration
}

// RemoteBearerTokenAcquirer implements Acquirer and fetches the tokens from a remote location with caching strategy.
type RemoteBearerTokenAcquirer struct {
	options                RemoteBearerTokenAcquirerOptions
	authValue              string
	authValueExpiration    time.Time
	httpClient             *http.Client
	nonExpiringSpecialCase time.Time
	lock                   sync.RWMutex
}

// SimpleBearer defines the field name mappings used by the default bearer token and expiration parsers.
type SimpleBearer struct {
	ExpiresInSeconds float64 `json:"expires_in"`
	Token            string  `json:"serviceAccessToken"`
}

// NewRemoteBearerTokenAcquirer returns a RemoteBearerTokenAcquirer configured with the given options.
func NewRemoteBearerTokenAcquirer(options RemoteBearerTokenAcquirerOptions) (*RemoteBearerTokenAcquirer, error) {
	if options.GetToken == nil {
		options.GetToken = DefaultTokenParser
	}

	if options.GetExpiration == nil {
		options.GetExpiration = DefaultExpirationParser
	}

	// TODO: we should inject timeout and buffer defaults values as well.

	return &RemoteBearerTokenAcquirer{
		options:             options,
		authValueExpiration: time.Now(),
		httpClient: &http.Client{
			Timeout: options.Timeout,
		},
		nonExpiringSpecialCase: time.Unix(0, 0),
	}, nil
}

// Acquire provides the cached token or, if it's near its expiry time, contacts
// the server for a new token to cache.
func (acquirer *RemoteBearerTokenAcquirer) Acquire() (string, error) {
	acquirer.lock.RLock()
	if time.Now().Add(acquirer.options.Buffer).Before(acquirer.authValueExpiration) {
		defer acquirer.lock.RUnlock()
		return acquirer.authValue, nil
	}
	acquirer.lock.RUnlock()
	acquirer.lock.Lock()
	defer acquirer.lock.Unlock()

	req, err := http.NewRequest("GET", acquirer.options.AuthURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create new request for Bearer: %v", err)
	}

	for key, value := range acquirer.options.RequestHeaders {
		req.Header.Set(key, value)
	}

	resp, errHTTP := acquirer.httpClient.Do(req)
	if errHTTP != nil {
		return "", fmt.Errorf("error making request to '%v' to acquire bearer token: %v",
			acquirer.options.AuthURL, errHTTP)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non 200 code acquiring Bearer: code %v", resp.Status)
	}

	respBody, errRead := ioutil.ReadAll(resp.Body)
	if errRead != nil {
		return "", fmt.Errorf("error reading HTTP response body: %v", errRead)
	}

	token, err := acquirer.options.GetToken(respBody)
	if err != nil {
		return "", fmt.Errorf("error parsing bearer token from http response body: %v", err)
	}
	expiration, err := acquirer.options.GetExpiration(respBody)
	if err != nil {
		return "", fmt.Errorf("error parsing bearer token expiration from http response body: %v", err)
	}

	acquirer.authValue, acquirer.authValueExpiration = "Bearer "+token, expiration
	return acquirer.authValue, nil
}
