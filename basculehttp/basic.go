package basculehttp

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/xmidt-org/bascule/v1"
)

const (
	// BasicScheme is the bascule Scheme indicating basic authorization.
	BasicScheme bascule.Scheme = "Basic"
)

// InvalidBasicAuthError indicates that the Basic credentials were improperly
// encoded, either due to base64 issues or formatting.
type InvalidBasicAuthError struct {
	// Cause represents the lower level error that occurred, e.g. a base64
	// encoding error.
	Cause error
}

func (err *InvalidBasicAuthError) Unwrap() error { return err.Cause }

func (err *InvalidBasicAuthError) Error() string {
	var o strings.Builder
	o.WriteString("Basic auth string not encoded properly")

	if err.Cause != nil {
		o.WriteString(": ")
		o.WriteString(err.Cause.Error())
	}

	return o.String()
}

type basicTokenParser struct{}

func (btp basicTokenParser) Parse(_ context.Context, c bascule.Credentials) (t *Token, err error) {
	var decoded []byte
	decoded, err = base64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		err = &InvalidBasicAuthError{
			Cause: err,
		}

		return
	}

	username, _, found := strings.Cut(string(decoded), ":")
	if found {
		t = &Token{
			principal: username,
		}
	} else {
		err = &InvalidBasicAuthError{}
	}

	return
}
