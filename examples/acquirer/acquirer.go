// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/xmidt-org/bascule/acquire"
)

func main() {
	// set up acquirer and add the auth to the request
	acquirer, err := acquire.NewFixedAuthAcquirer("Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create basic auth plain text acquirer: %v\n", err.Error())
		os.Exit(1)
	}

	request, err := http.NewRequest(http.MethodGet, "http://localhost:6000/test", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create request: %v\n", err.Error())
		os.Exit(1)
	}
	if err = acquire.AddAuth(request, acquirer); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add auth: %v\n", err.Error())
		os.Exit(1)
	}

	httpclient := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := httpclient.Do(request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to send request: %v\n", err.Error())
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.Body != nil {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read body: %v\n", err.Error())
			os.Exit(1)
		}
		// output the body if it's good
		fmt.Fprintf(os.Stdout, "Body: \n%s\n", respBody)
	}
	// output the code
	fmt.Fprintf(os.Stdout, "Status code received: %v\n", resp.StatusCode)
	os.Exit(0)
}
