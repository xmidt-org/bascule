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
	assert.NoError(err)
}

func TestCreateValidTypeCheck(t *testing.T) {
	emptyAttributes := NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := CreateValidTypeCheck([]string{"valid", "type"})
	err := f(context.Background(), NewToken("valid", "", emptyAttributes))
	assert.NoError(err)
	err = f(context.Background(), NewToken("invalid", "", emptyAttributes))
	assert.NotNil(err)
}

func TestCreateNonEmptyTypeCheck(t *testing.T) {
	emptyAttributes := NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := CreateNonEmptyTypeCheck()
	err := f(context.Background(), NewToken("type", "", emptyAttributes))
	assert.NoError(err)
	err = f(context.Background(), NewToken("", "", emptyAttributes))
	assert.NotNil(err)
}

func TestCreateNonEmptyPrincipalCheck(t *testing.T) {
	emptyAttributes := NewAttributes(map[string]interface{}{})
	assert := assert.New(t)
	f := CreateNonEmptyPrincipalCheck()
	err := f(context.Background(), NewToken("", "principal", emptyAttributes))
	assert.NoError(err)
	err = f(context.Background(), NewToken("", "", emptyAttributes))
	assert.NotNil(err)
}
