// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"

	"github.com/xmidt-org/bascule"
)

// NewAuthorizer is a convenient wrapper around bascule.NewAuthorizer.
// This function eases the syntactical pain of generics when creating Middleware.
func NewAuthorizer(opts ...bascule.AuthorizerOption[*http.Request]) (*bascule.Authorizer[*http.Request], error) {
	return bascule.NewAuthorizer(opts...)
}
