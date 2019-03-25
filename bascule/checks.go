// some factories to make common validation checks

package bascule

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
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

type capValidator struct {
	validFirstPiece    string
	validSecondPiece   string
	wildcardMethodType string
}

// capabilityValidation determines if a claim's capability is valid
func (c *capValidator) capabilityValidation(ctx context.Context, capability string) (valid_capabilities bool) {
	pieces := strings.Split(capability, ":")

	if len(pieces) == 5 &&
		pieces[0] == c.validFirstPiece &&
		pieces[1] == c.validSecondPiece {

		method_value, ok := ctx.Value("method").(string)
		if ok && (c.wildcardMethodType != "" && pieces[4] == c.wildcardMethodType ||
			strings.EqualFold(pieces[4], method_value)) {
			claimPath := fmt.Sprintf("/%s/[^/]+/%s", pieces[2], pieces[3])
			valid_capabilities, _ = regexp.MatchString(claimPath, ctx.Value("path").(string))
		}
	}

	return
}

func CreateCapabilitiesCheck(firstPiece string, secondPiece string, wildcard string) ValidatorFunc {
	return func(ctx context.Context, token Token) error {
		caps, ok := token.Attributes()[capabilitiesKey]
		if !ok {
			return errors.New("no capabilities found")
		}
		strCaps, ok := caps.([]string)
		if !ok {
			return errors.New("unexpected capabilities value")
		}

		c := capValidator{
			validFirstPiece:    firstPiece,
			validSecondPiece:   secondPiece,
			wildcardMethodType: wildcard,
		}

		for _, cap := range strCaps {
			if c.capabilityValidation(ctx, cap) {
				return nil
			}
		}
		return errors.New("invalid capabilities")
	}
}
