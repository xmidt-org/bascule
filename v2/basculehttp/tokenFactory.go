package basculehttp

import (
	"strings"

	"github.com/xmidt-org/bascule/v2"
)

type defaultCredentialsParser struct{}

func (defaultCredentialsParser) Parse(serialized string) (c bascule.Credentials, err error) {
	parts := strings.Split(serialized, " ")
	if len(parts) != 2 {
		err = &bascule.InvalidCredentialsError{
			Raw: serialized,
		}
	} else {
		c.Scheme = bascule.Scheme(parts[0])
		c.Value = parts[1]
	}

	return
}

// NewTokenFactory builds a bascule.TokenFactory with useful defaults for an
// HTTP environment.
//
// A default CredentialParser and TokenParser schemes are prepended to the supplied
// option.  This function will not return an error if those options are omitted.
// Any options supplied explicitly to this function can override those defaults.
func NewTokenFactory(opts ...bascule.TokenFactoryOption) (bascule.TokenFactory, error) {
	opts = append(
		// prepend defaults, allowing subsequent options to override
		[]bascule.TokenFactoryOption{
			bascule.WithCredentialsParser(defaultCredentialsParser{}),
			bascule.WithTokenParser(BasicScheme, basicTokenParser{}),
			// TODO: add Bearer
		},
		opts...,
	)

	return bascule.NewTokenFactory(opts...)
}
