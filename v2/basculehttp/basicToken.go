// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"encoding/base64"
	"strings"

	"github.com/xmidt-org/bascule/v2"
)

type basicToken struct {
	credentials bascule.Credentials
	userName    string
}

func (bt *basicToken) Credentials() bascule.Credentials { return bt.credentials }

func (bt *basicToken) Principal() string { return bt.userName }

type basicTokenParser struct{}

func (basicTokenParser) Parse(c bascule.Credentials) (t bascule.Token, err error) {
	var decoded []byte
	decoded, err = base64.StdEncoding.DecodeString(c.Value)
	if err == nil {
		if userName, _, ok := strings.Cut(string(decoded), ":"); ok {
			t = &basicToken{
				credentials: c,
				userName:    userName,
			}
		} else {
			err = &bascule.InvalidCredentialsError{
				Raw: c.Value,
			}
		}
	}

	return
}
