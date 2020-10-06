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
