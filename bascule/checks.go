// some factories to make common validation checks

package bascule

import (
	"context"
	"errors"
	"fmt"
)

const (
	capabilitiesKey = "capabilities"
)

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
			return errors.New("no capabilities found")
		}
		strVal, ok := val.([]interface{})
		if !ok {
			return fmt.Errorf("unexpected attribute value, expected []interface{} but received: %v", val)
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
		return errs
	}
}
