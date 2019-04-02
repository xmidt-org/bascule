// some factories to make common validation checks

package bascule

import (
	"context"
	"errors"
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

func CreateAttributeCheckByFunc(key string, check AttributeCheckFunc) ValidatorFunc {
	return func(ctx context.Context, token Token) error {
		val, ok := token.Attributes()[key]
		if !ok {
			return errors.New("no capabilities found")
		}
		return check(ctx, val)
	}
}

type AttributeCheckFunc func(context.Context, interface{}) error
