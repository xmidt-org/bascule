package basculehttp

import (
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/xmidt-org/bascule/v2"
)

type jwtToken struct {
	credentials bascule.Credentials
	token       jwt.Token
}

func (jt *jwtToken) Credentials() bascule.Credentials { return jt.credentials }

func (jt *jwtToken) Principal() string { return jt.token.Subject() }

type jwtTokenParser struct {
	options []jwt.ParseOption
}

func (jtp jwtTokenParser) Parse(c bascule.Credentials) (t bascule.Token, err error) {
	var token jwt.Token
	token, err = jwt.Parse([]byte(c.Value), jtp.options...)
	if err == nil {
		t = &jwtToken{
			token: token,
		}
	}

	return
}

func NewJwtTokenParser(opts ...jwt.ParseOption) (bascule.TokenParser, error) {
	return &jwtTokenParser{
		options: append([]jwt.ParseOption{}, opts...),
	}, nil
}
