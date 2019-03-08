package bascule

type Attributes map[string]interface{}

// TODO: Add dotted path support and support for common concrete types, e.g. GetString
func (a Attributes) Get(key string) (interface{}, bool) {
	v, ok := a[key]
	return v, ok
}

// Token is the behavior supplied by all secure tokens
type Token interface {
	// Type is the custom token type assigned by plugin code
	Type() string

	// Principal is the security principal, e.g. the user name or client id
	Principal() string

	// Attributes are an arbitrary set of name/value pairs associated with the token.
	// Typically, these will be filled with information supplied by the user, e.g. the claims of a JWT.
	Attributes() Attributes
}

// simpleToken is a very basic token type that can serve as the Token for many types of secure pipelines
type simpleToken struct {
	tokenType  string
	principal  string
	attributes Attributes
}

func (st simpleToken) Type() string {
	return st.tokenType
}

func (st simpleToken) Principal() string {
	return st.principal
}

func (st simpleToken) Attributes() Attributes {
	return st.attributes
}

// NewToken creates a Token from basic information.  Many secure pipelines can use the returned value as
// their token.  Specialized pipelines can create additional interfaces and augment the returned Token
// as desired.  Alternatively, some pipelines can simply create their own Tokens out of whole cloth.
func NewToken(tokenType, principal string, attributes Attributes) Token {
	return simpleToken{tokenType, principal, attributes}
}
