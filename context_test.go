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
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContext(t *testing.T) {
	assert := assert.New(t)
	u, err := url.ParseRequestURI("/a/b/c")
	assert.Nil(err)
	expectedAuth := Authentication{
		Authorization: "authorization string",
		Token: simpleToken{
			tokenType:  "test",
			principal:  "test principal",
			attributes: NewAttributes(map[string]interface{}{"testkey": "testval", "attr": 5}),
		},
		Request: Request{
			URL:    u,
			Method: "GET",
		},
	}
	ctx := context.Background()
	newCtx := WithAuthentication(ctx, expectedAuth)
	assert.NotNil(newCtx)
	auth, ok := FromContext(newCtx)
	assert.True(ok)
	assert.Equal(expectedAuth, auth)
}
