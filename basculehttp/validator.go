// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"

	"github.com/xmidt-org/bascule"
)

// AsValidator an HTTP-specific version of bascule.AsValidator.  This function
// eases the syntactic pain of using golang's generics.
func AsValidator[F bascule.ValidatorFunc[*http.Request]](f F) bascule.Validator[*http.Request] {
	return bascule.AsValidator[*http.Request](f)
}
