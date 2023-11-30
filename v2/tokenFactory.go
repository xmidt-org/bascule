package bascule

import (
	"errors"

	"go.uber.org/multierr"
)

// TokenFactoryOption is a configurable option for building a TokenFactory.
type TokenFactoryOption interface {
	apply(*tokenFactory) error
}

type tokenFactoryOptionFunc func(*tokenFactory) error

func (f tokenFactoryOptionFunc) apply(tf *tokenFactory) error { return f(tf) }

// WithCredentialsParser establishes the strategy for parsing credentials for
// the TokenFactory being built.  This option is required.
func WithCredentialsParser(cp CredentialsParser) TokenFactoryOption {
	return tokenFactoryOptionFunc(func(tf *tokenFactory) error {
		tf.credentialsParser = cp
		return nil
	})
}

// WithTokenParser registers a credential scheme with the TokenFactory.
// This option must be used at least once.
func WithTokenParser(scheme Scheme, tp TokenParser) TokenFactoryOption {
	return tokenFactoryOptionFunc(func(tf *tokenFactory) error {
		tf.tokenParsers.Register(scheme, tp)
		return nil
	})
}

// WithAuthenticators adds Authenticator rules to be used by the TokenFactory.
// Authenticator rules are optional.  If omitted, then the TokenFactory will
// not perform authentication.
func WithAuthenticators(auth ...Authenticator) TokenFactoryOption {
	return tokenFactoryOptionFunc(func(tf *tokenFactory) error {
		tf.authenticators = append(tf.authenticators, auth...)
		return nil
	})
}

// TokenFactory brings together the entire authentication workflow.  For typical
// code that uses bascule, this is the primary interface for obtaining Tokens.
type TokenFactory interface {
	// NewToken accepts a raw, serialized set of credentials and turns it
	// into a Token.  This method executes the workflow of:
	//
	// - parsing the serialized credentials into a Credentials
	// - parsing the Credentials into a Token
	// - executing any Authenticator rules against the Token
	NewToken(serialized string) (Token, error)
}

// NewTokenFactory creates a TokenFactory using the supplied option.
//
// A CredentialParser and at least one (1) TokenParser is required.  If
// either are not supplied, this function returns an error.
func NewTokenFactory(opts ...TokenFactoryOption) (TokenFactory, error) {
	tf := &tokenFactory{}

	var err error
	for _, o := range opts {
		err = multierr.Append(err, o.apply(tf))
	}

	if tf.credentialsParser == nil {
		err = multierr.Append(err, errors.New("A CredentialsParser is required"))
	}

	if len(tf.tokenParsers) == 0 {
		err = multierr.Append(err, errors.New("At least one (1) TokenParser is required"))
	}

	return tf, err
}

// tokenFactory is the internal implementation of TokenFactory.
type tokenFactory struct {
	credentialsParser CredentialsParser
	tokenParsers      TokenParsers
	authenticators    Authenticators
}

func (tf *tokenFactory) NewToken(serialized string) (t Token, err error) {
	var c Credentials
	c, err = tf.credentialsParser.Parse(serialized)
	if err == nil {
		t, err = tf.tokenParsers.Parse(c)
	}

	if err == nil {
		err = tf.authenticators.Authenticate(t)
	}

	return
}
