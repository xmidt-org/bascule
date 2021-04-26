/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package basculechecks

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
)

func TestCreateAllowAllCheck(t *testing.T) {
	assert := assert.New(t)
	f := CreateAllowAllCheck()
	err := f(context.Background(), bascule.NewToken("", "", bascule.NewAttributes(map[string]interface{}{})))
	assert.NoError(err)
}

func TestCreateValidTypeCheck(t *testing.T) {
	emptyAttributes := bascule.NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := CreateValidTypeCheck([]string{"valid", "type"})
	err := f(context.Background(), bascule.NewToken("valid", "", emptyAttributes))
	assert.NoError(err)
	err = f(context.Background(), bascule.NewToken("invalid", "", emptyAttributes))
	assert.NotNil(err)
}

func TestCreateNonEmptyTypeCheck(t *testing.T) {
	emptyAttributes := bascule.NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := CreateNonEmptyTypeCheck()
	err := f(context.Background(), bascule.NewToken("type", "", emptyAttributes))
	assert.NoError(err)
	err = f(context.Background(), bascule.NewToken("", "", emptyAttributes))
	assert.NotNil(err)
}

func TestCreateNonEmptyPrincipalCheck(t *testing.T) {
	emptyAttributes := bascule.NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := CreateNonEmptyPrincipalCheck()
	err := f(context.Background(), bascule.NewToken("", "principal", emptyAttributes))
	assert.NoError(err)
	err = f(context.Background(), bascule.NewToken("", "", emptyAttributes))
	assert.NotNil(err)
}

func TestCreateListAttributeCheck(t *testing.T) {
	testErr := errors.New("test err")
	failFunc := func(_ context.Context, _ []interface{}) error {
		return testErr
	}
	successFunc := func(_ context.Context, _ []interface{}) error {
		return nil
	}

	assert := assert.New(t)
	fGood := CreateListAttributeCheck([]string{"testkey", "subkey"}, successFunc)
	f := CreateListAttributeCheck([]string{"testkey", "subkey"}, successFunc, failFunc)

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
