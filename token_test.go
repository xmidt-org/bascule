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
	"testing"

	"github.com/stretchr/testify/assert"
)

var attrs = NewAttributes(map[string]interface{}{"testkey": "testval", "attr": 5})

func TestToken(t *testing.T) {
	assert := assert.New(t)
	tokenType := "test type"
	principal := "test principal"
	token := NewToken(tokenType, principal, attrs)
	assert.Equal(tokenType, token.Type())
	assert.Equal(principal, token.Principal())
	assert.Equal(attrs, token.Attributes())
}
