// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"net/http"

	"github.com/xmidt-org/bascule/v1"
)

// BasicToken is a bascule.Token that results from Basic authorization.
type BasicToken struct {
	UserName string
	Password string
}

// Principal returns the user name from Basic auth.
func (bt BasicToken) Principal() string {
	return bt.UserName
}

// BasicTokenParser is a bascule.TokenParser expects Basic auth to
// be present.
type BasicTokenParser struct{}

// Parse extracts the Basic auth credentials from the source request.
// The net/http package is used to do this parsing.
//
// If no Basic auth credentials could be found, this method returns
// bascule.MissingCredentials.
func (btp BasicTokenParser) Parse(_ context.Context, source *http.Request) (t bascule.Token, err error) {
	if userName, password, ok := source.BasicAuth(); ok {
		t = BasicToken{
			UserName: userName,
			Password: password,
		}
	} else {
		err = bascule.MissingCredentials
	}

	return
}
