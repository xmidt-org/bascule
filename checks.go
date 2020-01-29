// some factories to make common validation checks

package bascule

import (
	"context"
	"errors"
	"fmt"

	"github.com/goph/emperror"
)

const (
	capabilitiesKey = "capabilities"
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

// CreateListAttributeCheck returns a Validator that runs checks against the
// content found in the key given.  It runs every check and returns all errors
// it finds.
func CreateListAttributeCheck(key string, checks ...func(context.Context, []interface{}) error) ValidatorFunc {
	return func(ctx context.Context, token Token) error {
		val, ok := token.Attributes().Get(key)
		if !ok {
			return fmt.Errorf("couldn't find attribute with key %v", key)
		}
		strVal, ok := val.([]interface{})
		if !ok {
			return fmt.Errorf("unexpected attribute value, expected []interface{} type but received: %T", val)
		}
		errs := Errors{}
		for _, check := range checks {
			err := check(ctx, strVal)
			if err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) == 0 {
			return nil
		}
		return emperror.Wrap(errs, fmt.Sprintf("attribute checks of key %v failed", key))
	}
}

// NonEmptyStringListCheck checks that the list of values given are a list of
// one or more nonempty strings.
func NonEmptyStringListCheck(_ context.Context, vals []interface{}) error {
	if len(vals) == 0 {
		return errors.New("expected at least one value")
	}
	for _, val := range vals {
		str, ok := val.(string)
		if !ok {
			return errors.New("expected value to be a string")
		}
		if len(str) == 0 {
			return errors.New("expected string to be nonempty")
		}
	}
	return nil
}
