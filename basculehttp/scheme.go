// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

// Scheme is the authorization header scheme, e.g. Basic, Bearer, etc.
type Scheme string

const (
	// SchemeBasic is the Basic HTTP authorization scheme.
	SchemeBasic Scheme = "Basic"

	// SchemeBearer is the Bearer HTTP authorization scheme.
	SchemeBearer Scheme = "Bearer"
)
