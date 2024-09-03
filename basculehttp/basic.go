// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"

	"github.com/xmidt-org/bascule"
)

// BasicToken is the interface that Basic Auth tokens implement.
type BasicToken interface {
	// UserName is the user name in the basic auth string and will
	// be e the same as Principal().
	UserName() string

	// Password returns the password from the basic auth string.
	// This also permits a BasicToken to be used with bascule.GetPassword.
	Password() string
}

// basicToken is the internal basic token struct that results from
// parsing a Basic Authorization header value.
type basicToken struct {
	userName string
	password string
}

func (bt basicToken) Principal() string {
	return bt.userName
}

func (bt basicToken) UserName() string {
	return bt.userName
}

func (bt basicToken) Password() string {
	return bt.password
}

// BasicTokenParser is a string-based bascule.TokenParser that produces
// BasicToken instances from strings.
type BasicTokenParser struct{}

// Parse assumes that value is of the format required by https://datatracker.ietf.org/doc/html/rfc7617.
// The returned Token will return the basic auth username from its Principal() method.
// The returned Token will also implement BasicToken.
func (BasicTokenParser) Parse(_ context.Context, value string) (bascule.Token, error) {
	// this mimics what the stdlib does at net/http.Request.BasicAuth()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, bascule.ErrInvalidCredentials
	}

	var (
		bt basicToken
		ok bool
	)

	bt.userName, bt.password, ok = strings.Cut(string(raw), ":")
	if ok {
		return bt, nil
	}

	return nil, bascule.ErrInvalidCredentials
}

// BasicAuth produces the basic authorization string described by RFC 2617.
func BasicAuth(userName, password string) string {
	var b bytes.Buffer
	b.WriteString(userName)
	b.WriteRune(':')
	b.WriteString(password)

	return base64.StdEncoding.EncodeToString(b.Bytes())
}
