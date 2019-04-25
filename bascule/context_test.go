package bascule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContext(t *testing.T) {
	assert := assert.New(t)
	expectedAuth := Authentication{
		Authorization: "authorization string",
		Token: simpleToken{
			tokenType:  "test",
			principal:  "test principal",
			attributes: map[string]interface{}{"testkey": "testval", "attr": 5},
		},
		Request: Request{
			URL:    "/a/b/c",
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
