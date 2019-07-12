package bascule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateAllowAllCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateAllowAllCheck()
	err := f(context.Background(), NewToken("", "", Attributes{}))
	assert.Nil(err)
}

func TestCreateValidTypeCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateValidTypeCheck([]string{"valid", "type"})
	err := f(context.Background(), NewToken("valid", "", Attributes{}))
	assert.Nil(err)
	err = f(context.Background(), NewToken("invalid", "", Attributes{}))
	assert.NotNil(err)
}

func TestCreateNonEmptyTypeCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateNonEmptyTypeCheck()
	err := f(context.Background(), NewToken("type", "", Attributes{}))
	assert.Nil(err)
	err = f(context.Background(), NewToken("", "", Attributes{}))
	assert.NotNil(err)
}

func TestCreateNonEmptyPrincipalCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateNonEmptyPrincipalCheck()
	err := f(context.Background(), NewToken("", "principal", Attributes{}))
	assert.Nil(err)
	err = f(context.Background(), NewToken("", "", Attributes{}))
	assert.NotNil(err)
}

func TestCreateListAttributeCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateListAttributeCheck("testkey", NonEmptyStringListCheck)
	err := f(context.Background(), NewToken("", "", map[string]interface{}{"testkey": []interface{}{"a", "b", "c"}}))
	assert.Nil(err)
	err = f(context.Background(), NewToken("", "", Attributes{}))
	assert.NotNil(err)
	err = f(context.Background(), NewToken("", "", map[string]interface{}{"testkey": ""}))
	assert.NotNil(err)
	err = f(context.Background(), NewToken("", "", map[string]interface{}{"testkey": []interface{}{}}))
	assert.NotNil(err)
	err = f(context.Background(), NewToken("", "", map[string]interface{}{"testkey": []interface{}{5, 7, 6}}))
	assert.NotNil(err)
	err = f(context.Background(), NewToken("", "", map[string]interface{}{"testkey": []interface{}{""}}))
	assert.NotNil(err)
}
