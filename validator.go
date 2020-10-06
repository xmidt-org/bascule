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

// Validator provides tools for validating authorization tokens. Validation is
// done through running the rules provided.  If a token is considered not valid,
// the validator will return an error.

package bascule

import "context"

// Validator is the rule type that determines if a Token is valid.  Each rule should do exactly
// (1) thing, and then be composed by application-layer code.  Validators are invoked for both
// authentication and authorization.  We may need to have different rule types for those two things,
// but for now this works.
type Validator interface {
	Check(context.Context, Token) error
}

// ValidatorFunc is the Check function that a Validator has.
type ValidatorFunc func(context.Context, Token) error

// Check runs the validatorFunc, making a ValidatorFunc also a Validator.
func (vf ValidatorFunc) Check(ctx context.Context, t Token) error {
	return vf(ctx, t)
}

// Validators are a list of objects that implement the Validator interface.
type Validators []Validator

// Check runs through the list of validator Checks and adds any errors returned
// to the list of errors, which is an Errors type.
func (v Validators) Check(ctx context.Context, t Token) error {
	// we want *all* rules to run, so we get a complete picture of the failure
	var all Errors
	for _, r := range v {
		if err := r.Check(ctx, t); err != nil {
			all = append(all, err)
		}
	}

	if len(all) > 0 {
		return all
	}

	return nil
}
