package bascule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateAllowAllCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateAllowAllCheck()
	err := f(context.Background(), NewToken("", "", NewAttributes()))
	assert.Nil(err)
}

func TestCreateValidTypeCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateValidTypeCheck([]string{"valid", "type"})
	err := f(context.Background(), NewToken("valid", "", NewAttributes()))
	assert.Nil(err)
	err = f(context.Background(), NewToken("invalid", "", NewAttributes()))
	assert.NotNil(err)
}

func TestCreateNonEmptyTypeCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateNonEmptyTypeCheck()
	err := f(context.Background(), NewToken("type", "", NewAttributes()))
	assert.Nil(err)
	err = f(context.Background(), NewToken("", "", NewAttributes()))
	assert.NotNil(err)
}

func TestCreateNonEmptyPrincipalCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateNonEmptyPrincipalCheck()
	err := f(context.Background(), NewToken("", "principal", NewAttributes()))
	assert.Nil(err)
	err = f(context.Background(), NewToken("", "", NewAttributes()))
	assert.NotNil(err)
}

func TestCreateListAttributeCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateListAttributeCheck("testkey.subkey", NonEmptyStringListCheck)

	err := f(context.Background(), NewToken("", "", NewAttributesFromMap(map[string]interface{}{
		"testkey": map[string]interface{}{"subkey": []interface{}{"a", "b", "c"}}})))
	assert.Nil(err)

	err = f(context.Background(), NewToken("", "", NewAttributes()))
	assert.NotNil(err)

	err = f(context.Background(), NewToken("", "", NewAttributesFromMap(map[string]interface{}{"testkey": ""})))
	assert.NotNil(err)

	err = f(context.Background(), NewToken("", "", NewAttributesFromMap(map[string]interface{}{"testkey": map[string]interface{}{
		"subkey": []interface{}{}}})))
	assert.NotNil(err)

	err = f(context.Background(), NewToken("", "", NewAttributesFromMap(map[string]interface{}{"testkey": map[string]interface{}{
		"subkey": []interface{}{5, 7, 6}}})))
	assert.NotNil(err)

	err = f(context.Background(), NewToken("", "", NewAttributesFromMap(map[string]interface{}{"testkey": map[string]interface{}{
		"subkey": []interface{}{""}}})))
	assert.NotNil(err)
}
