package bascule

import (
	"github.com/SermoDigital/jose/jws"
)

// JWSParser parses raw Tokens into JWS objects
type JWSParser interface {
	ParseJWS([]byte) (jws.JWS, error)
}

type defaultJWSParser struct{}

func (parser defaultJWSParser) ParseJWS(token []byte) (jws.JWS, error) {
	if jwtToken, err := jws.ParseJWT(token); err == nil {
		return jwtToken.(jws.JWS), nil
	} else {
		return nil, err
	}
}

// DefaultJWSParser is the parser implementation that simply delegates to
// the SermoDigital library's jws.ParseJWT function.
var DefaultJWSParser JWSParser = defaultJWSParser{}
