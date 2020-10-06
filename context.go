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

package bascule

import (
	"context"
	"net/url"
)

// Authorization represents the authorization mechanism performed on the token,
// e.g. "Basic", "Bearer", etc for HTTP security environments.
type Authorization string

// Authentication represents the output of a security pipeline.
type Authentication struct {
	Authorization Authorization
	Token         Token
	Request       Request
}

// Request holds request information that may be useful for validating the
// token.
type Request struct {
	URL    *url.URL
	Method string
}

type authenticationKey struct{}

// WithAuthentication adds the auth given to the context given, provided a way
// for other users of the context to get the authentication.
func WithAuthentication(ctx context.Context, auth Authentication) context.Context {
	return context.WithValue(ctx, authenticationKey{}, auth)
}

// FromContext gets the Authentication from the context provided.
func FromContext(ctx context.Context) (Authentication, bool) {
	auth, ok := ctx.Value(authenticationKey{}).(Authentication)
	return auth, ok
}
