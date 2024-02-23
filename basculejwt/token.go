package basculejwt

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/xmidt-org/bascule/v1"
)

type Token struct {
	jwtToken jwt.Token
}

func (t *Token) Principal() string {
	return t.jwtToken.Subject()
}

type TokenParser struct {
	options []jwt.ParseOption
}

func (tp *TokenParser) newBasculeToken(c bascule.Credentials) (*Token, error) {
	jwtToken, err := jwt.ParseString(c.Value, tp.options...)
	if err != nil {
		return nil, err
	}

	return &Token{
		jwtToken: jwtToken,
	}, nil
}

func (tp *TokenParser) Parse(_ context.Context, c bascule.Credentials) (bascule.Token, error) {
	token, err := tp.newBasculeToken(c)
	return token, err
}
