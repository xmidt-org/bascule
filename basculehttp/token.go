package basculehttp

import "github.com/xmidt-org/bascule/v1"

// Token is bascule's default HTTP token.
type Token struct {
	principal string
}

func (t *Token) Principal() string {
	return t.principal
}

// DefaultTokenParsers returns the default suite of parsers supported by
// bascule.  This method returns a distinct instance each time it is called,
// thus allowing calling code to tailor it independently of other calls.
func DefaultTokenParsers() bascule.TokenParsers {
	return bascule.TokenParsers{
		BasicScheme: basicTokenParser{},
	}
}
