package bascule

import (
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestValid(t *testing.T) {
	assert := assert.New(t)
	claims := ClaimsWithLeeway{
		MapClaims: make(jwt.MapClaims),
		Leeway: Leeway{
			EXP: 5,
			NBF: 5,
			IAT: 5,
		},
	}
	err := claims.Valid()
	assert.Nil(err)
}
