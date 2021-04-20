/**
 * Copyright 2021 Comcast Cable Communications Management, LLC
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

// some factories to make common validation checks

package bascule

import (
	"context"
	"errors"
)

// CreateAllowAllCheck returns a Validator that never returns an error.
func CreateAllowAllCheck() ValidatorFunc {
	return func(_ context.Context, _ Token) error {
		return nil
	}
}

// CreateValidTypeCheck returns a Validator that checks that the token's type
// is one of the given valid types.
func CreateValidTypeCheck(validTypes []string) ValidatorFunc {
	return func(_ context.Context, token Token) error {
		tt := token.Type()
		for _, vt := range validTypes {
			if tt == vt {
				return nil
			}
		}
		return errors.New("invalid token type")
	}
}

// CreateNonEmptyTypeCheck returns a Validator that checks that the token's
// type isn't an empty string.
func CreateNonEmptyTypeCheck() ValidatorFunc {
	return func(_ context.Context, token Token) error {
		if token.Type() == "" {
			return errors.New("empty token type")
		}
		return nil
	}
}

// CreateNonEmptyPrincipalCheck returns a Validator that checks that the
// token's Principal isn't an empty string.
func CreateNonEmptyPrincipalCheck() ValidatorFunc {
	return func(_ context.Context, token Token) error {
		if token.Principal() == "" {
			return errors.New("empty token principal")
		}
		return nil
	}
}
