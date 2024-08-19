// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"

	"github.com/xmidt-org/bascule"
)

// NewAuthenticator is a convenient wrapper around bascule.NewAuthenticator.
// This function eases the syntactical pain of generics when creating Middleware.
func NewAuthenticator(opts ...bascule.AuthenticatorOption[*http.Request]) (*bascule.Authenticator[*http.Request], error) {
	return bascule.NewAuthenticator(opts...)
}
