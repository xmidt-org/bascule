package bascule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var attrs = NewAttributes(map[string]interface{}{"testkey": "testval", "attr": 5})

const (
	boolGetter = iota
	durationGetter
	float64Getter
	int64Getter
	intSliceGetter
	stringGetter
	stringMapGetter
	stringSliceGetter
	timeGetter
)

func TestToken(t *testing.T) {
	assert := assert.New(t)
	tokenType := "test type"
	principal := "test principal"
	token := NewToken(tokenType, principal, attrs)
	assert.Equal(tokenType, token.Type())
	assert.Equal(principal, token.Principal())
	assert.Equal(attrs, token.Attributes())
}
