package bascule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	attrs = map[string]interface{}{"testkey": "testval", "attr": 5}
)

func TestToken(t *testing.T) {
	assert := assert.New(t)
	tokenType := "test type"
	principal := "test principal"
	token := NewToken(tokenType, principal, attrs)
	assert.Equal(tokenType, token.Type())
	assert.Equal(principal, token.Principal())
	assert.Equal(Attributes(attrs), token.Attributes())
}

func TestGet(t *testing.T) {
	assert := assert.New(t)
	attributes := Attributes(attrs)

	val, ok := attributes.Get("testkey")
	assert.Equal("testval", val)
	assert.True(ok)

	val, ok = attributes.Get("noval")
	assert.Empty(val)
	assert.False(ok)
}
