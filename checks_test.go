package bascule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateAllowAllCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateAllowAllCheck()
	err := f(context.Background(), NewToken("", "", NewAttributes(map[string]interface{}{})))
	assert.Nil(err)
}

func TestCreateValidTypeCheck(t *testing.T) {
	emptyAttributes := NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := CreateValidTypeCheck([]string{"valid", "type"})
	err := f(context.Background(), NewToken("valid", "", emptyAttributes))
	assert.Nil(err)
	err = f(context.Background(), NewToken("invalid", "", emptyAttributes))
	assert.NotNil(err)
}

func TestCreateNonEmptyTypeCheck(t *testing.T) {
	emptyAttributes := NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := CreateNonEmptyTypeCheck()
	err := f(context.Background(), NewToken("type", "", emptyAttributes))
	assert.Nil(err)
	err = f(context.Background(), NewToken("", "", emptyAttributes))
	assert.NotNil(err)
}

func TestCreateNonEmptyPrincipalCheck(t *testing.T) {
	emptyAttributes := NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := CreateNonEmptyPrincipalCheck()
	err := f(context.Background(), NewToken("", "principal", emptyAttributes))
	assert.Nil(err)
	err = f(context.Background(), NewToken("", "", emptyAttributes))
	assert.NotNil(err)
}

func TestCreateListAttributeCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateListAttributeCheck([]string{"testkey", "subkey"}, NonEmptyStringListCheck)

	err := f(context.Background(), NewToken("", "", NewAttributes(map[string]interface{}{
		"testkey": map[string]interface{}{"subkey": []interface{}{"a", "b", "c"}}})))
	assert.Nil(err)

	err = f(context.Background(), NewToken("", "", NewAttributes(map[string]interface{}{})))
	assert.NotNil(err)

	err = f(context.Background(), NewToken("", "", NewAttributes(map[string]interface{}{"testkey": ""})))
	assert.NotNil(err)

	err = f(context.Background(), NewToken("", "", NewAttributes(map[string]interface{}{"testkey": map[string]interface{}{
		"subkey": 5555}})))
	assert.NotNil(err)

	err = f(context.Background(), NewToken("", "", NewAttributes(map[string]interface{}{"testkey": map[string]interface{}{
		"subkey": []interface{}{}}})))
	assert.NotNil(err)

	err = f(context.Background(), NewToken("", "", NewAttributes(map[string]interface{}{"testkey": map[string]interface{}{
		"subkey": []interface{}{5, 7, 6}}})))
	assert.NotNil(err)

	err = f(context.Background(), NewToken("", "", NewAttributes(map[string]interface{}{"testkey": map[string]interface{}{
		"subkey": []interface{}{""}}})))
	assert.NotNil(err)
}
