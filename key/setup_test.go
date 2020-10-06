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

package key

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const (
	keyId = "testkey"
)

var (
	httpServer *httptest.Server

	publicKeyFilePath         string
	publicKeyFilePathTemplate string

	publicKeyURL         string
	publicKeyURLTemplate string

	privateKeyFilePath         string
	privateKeyFilePathTemplate string

	privateKeyURL         string
	privateKeyURLTemplate string
)

func TestMain(m *testing.M) {
	currentDirectory, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to obtain current working directory: %v\n", err)
		os.Exit(1)
	}

	httpServer = httptest.NewServer(http.FileServer(http.Dir(currentDirectory)))
	defer httpServer.Close()
	fmt.Printf("started test server at %s\n", httpServer.URL)

	publicKeyFilePath = fmt.Sprintf("%s/%s.pub", currentDirectory, keyId)
	publicKeyFilePathTemplate = fmt.Sprintf("%s/{%s}.pub", currentDirectory, KeyIdParameterName)

	publicKeyURL = fmt.Sprintf("%s/%s.pub", httpServer.URL, keyId)
	publicKeyURLTemplate = fmt.Sprintf("%s/{%s}.pub", httpServer.URL, KeyIdParameterName)

	privateKeyFilePath = fmt.Sprintf("%s/%s", currentDirectory, keyId)
	privateKeyFilePathTemplate = fmt.Sprintf("%s/{%s}", currentDirectory, KeyIdParameterName)

	privateKeyURL = fmt.Sprintf("%s/%s", httpServer.URL, keyId)
	privateKeyURLTemplate = fmt.Sprintf("%s/{%s}", httpServer.URL, KeyIdParameterName)

	os.Exit(m.Run())
}
