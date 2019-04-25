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

func CreateAllowAllCheck() ValidatorFunc {
	return func(_ context.Context, _ Token) error {
		return nil
	}
}

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

func CreateNonEmptyTypeCheck() ValidatorFunc {
	return func(_ context.Context, token Token) error {
		if token.Type() == "" {
			return errors.New("empty token type")
		}
		return nil
	}
}

func CreateNonEmptyPrincipalCheck() ValidatorFunc {
	return func(_ context.Context, token Token) error {
		if token.Principal() == "" {
			return errors.New("empty token principal")
		}
		return nil
	}
}

func CreateListAttributeCheck(key string, checks ...func(context.Context, []interface{}) error) ValidatorFunc {
	return func(ctx context.Context, token Token) error {
		val, ok := token.Attributes()[key]
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

func NonEmptyStringListCheck(ctx context.Context, vals []interface{}) error {
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
