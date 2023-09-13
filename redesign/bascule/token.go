package bascule

import (
	"errors"
	"strings"
)

// InvalidCredentialsError is returned typically by CredentialsParser.Parse
// to indicate that a raw, serialized credentials were badly formatted.
type InvalidCredentialsError struct {
	// Cause represents any lower-level error that occurred.
	Cause error

	// Raw represents the raw credentials that couldn't be parsed.
	Raw string
}

func (err *InvalidCredentialsError) Unwrap() error { return err.Cause }

func (err *InvalidCredentialsError) Error() string {
	var o strings.Builder
	o.WriteString(`Invalid credentials: "`)
	o.WriteString(err.Raw)
	o.WriteString(`"`)
	return o.String()
}

// Scheme represents how a security token should be parsed.  For HTTP, examples
// of a scheme are "Bearer" and "Basic".
type Scheme string

// Credentials holds the raw, unparsed token information.
type Credentials struct {
	// Scheme is the parsing scheme used for the credential value.
	Scheme Scheme

	// Value is the raw, unparsed credential information.
	Value string
}

// CredentialsParser produces Credentials from their serialized form.
type CredentialsParser interface {
	// Parse parses the raw, marshaled version of credentials and
	// returns the Credentials object.
	Parse(raw string) (Credentials, error)
}

// Token is a runtime representation of credentials.  This interface will be further
// customized by infrastructure.
type Token interface {
	// Credentials returns the raw, unparsed information used to produce this Token.
	Credentials() Credentials

	// Principal is the security subject of this token, e.g. the user name or other
	// user identifier.
	Principal() string
}

// TokenParser produces tokens from credentials.
type TokenParser interface {
	// Parse turns a Credentials into a Token.  This method may validate parts
	// of the credential's value, but should not perform any authentication itself.
	Parse(Credentials) (Token, error)
}

// TokenParsers is a registry of parsers based on credential schemes.
// The zero value of this type is valid and ready to use.
type TokenParsers map[Scheme]TokenParser

// Register adds or replaces the parser associated with the given scheme.
func (tp *TokenParsers) Register(scheme Scheme, p TokenParser) {
	if *tp == nil {
		*tp = make(TokenParsers)
	}

	(*tp)[scheme] = p
}

// Parse chooses a TokenParser based on the Scheme and invokes that
// parser.  If the credential scheme is unsupported, an error is returned.
func (tp TokenParsers) Parse(c Credentials) (Token, error) {
	p, ok := tp[c.Scheme]
	if !ok {
		return nil, errors.New("TODO: unsupported credential scheme error")
	}

	return p.Parse(c)
}
