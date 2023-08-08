// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"context"
	"errors"
	"fmt"

	"github.com/xmidt-org/bascule"
)

// AllowAll returns a Validator that never returns an error.
func AllowAll() bascule.ValidatorFunc {
	return func(_ context.Context, _ bascule.Token) error {
		return nil
	}
}

// ValidType returns a Validator that checks that the token's type is one of the
// given valid types.
func ValidType(validTypes []string) bascule.ValidatorFunc {
	return func(_ context.Context, token bascule.Token) error {
		tt := token.Type()
		for _, vt := range validTypes {
			if tt == vt {
				return nil
			}
		}
		return errors.New("invalid token type")
	}
}

// NonEmptyType returns a Validator that checks that the token's type isn't an
// empty string.
func NonEmptyType() bascule.ValidatorFunc {
	return func(_ context.Context, token bascule.Token) error {
		if token.Type() == "" {
			return errors.New("empty token type")
		}
		return nil
	}
}

// NonEmptyPrincipal returns a Validator that checks that the token's Principal
// isn't an empty string.
func NonEmptyPrincipal() bascule.ValidatorFunc {
	return func(_ context.Context, token bascule.Token) error {
		if token.Principal() == "" {
			return errors.New("empty token principal")
		}
		return nil
	}
}

// AttributeList returns a Validator that runs checks against the content found
// in the key given.  It runs every check and returns all errors it finds.
func AttributeList(keys []string, checks ...func(context.Context, []interface{}) error) bascule.ValidatorFunc {
	return func(ctx context.Context, token bascule.Token) error {
		val, ok := bascule.GetNestedAttribute(token.Attributes(), keys...)
		if !ok {
			return fmt.Errorf("couldn't find attribute with keys %v", keys)
		}
		strVal, ok := val.([]interface{})
		if !ok {
			return fmt.Errorf("unexpected attribute value, expected []interface{} type but received: %T", val)
		}
		errs := bascule.Errors{}
		for _, check := range checks {
			err := check(ctx, strVal)
			if err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) == 0 {
			return nil
		}
		return fmt.Errorf("attribute checks of keys %v failed: %v", keys, errs)
	}
}
