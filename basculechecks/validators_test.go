// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
)

func TestAllowAll(t *testing.T) {
	assert := assert.New(t)
	f := AllowAll()
	err := f(context.Background(), bascule.NewToken("", "", bascule.NewAttributes(map[string]interface{}{})))
	assert.NoError(err)
}

func TestValidType(t *testing.T) {
	emptyAttributes := bascule.NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := ValidType([]string{"valid", "type"})
	err := f(context.Background(), bascule.NewToken("valid", "", emptyAttributes))
	assert.NoError(err)
	err = f(context.Background(), bascule.NewToken("invalid", "", emptyAttributes))
	assert.NotNil(err)
}

func TestNonEmptyType(t *testing.T) {
	emptyAttributes := bascule.NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := NonEmptyType()
	err := f(context.Background(), bascule.NewToken("type", "", emptyAttributes))
	assert.NoError(err)
	err = f(context.Background(), bascule.NewToken("", "", emptyAttributes))
	assert.NotNil(err)
}

func TestNonEmptyPrincipal(t *testing.T) {
	emptyAttributes := bascule.NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := NonEmptyPrincipal()
	err := f(context.Background(), bascule.NewToken("", "principal", emptyAttributes))
	assert.NoError(err)
	err = f(context.Background(), bascule.NewToken("", "", emptyAttributes))
	assert.NotNil(err)
}

func TestAttributeList(t *testing.T) {
	testErr := errors.New("test err")
	failFunc := func(_ context.Context, _ []interface{}) error {
		return testErr
	}
	successFunc := func(_ context.Context, _ []interface{}) error {
		return nil
	}

	assert := assert.New(t)
	fGood := AttributeList([]string{"testkey", "subkey"}, successFunc)
	f := AttributeList([]string{"testkey", "subkey"}, successFunc, failFunc)

	err := fGood(context.Background(), bascule.NewToken("", "", bascule.NewAttributes(map[string]interface{}{
		"testkey": map[string]interface{}{"subkey": []interface{}{"a", "b", "c"}}})))
	assert.NoError(err)

	err = fGood(context.Background(), bascule.NewToken("", "", bascule.NewAttributes(map[string]interface{}{})))
	assert.Error(err)

	err = fGood(context.Background(), bascule.NewToken("", "", bascule.NewAttributes(map[string]interface{}{"testkey": ""})))
	assert.Error(err)

	err = fGood(context.Background(), bascule.NewToken("", "", bascule.NewAttributes(map[string]interface{}{"testkey": map[string]interface{}{
		"subkey": 5555}})))
	assert.Error(err)

	err = f(context.Background(), bascule.NewToken("", "", bascule.NewAttributes(map[string]interface{}{"testkey": map[string]interface{}{
		"subkey": []interface{}{}}})))
	assert.Error(err)
}
