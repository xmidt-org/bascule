// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule/v1"
)

type BasicTestSuite struct {
	suite.Suite
}

func (suite *BasicTestSuite) TestBasicAuth() {
	encoded := BasicAuth("Aladdin", "open sesame")

	// ripped right from RFC 2617 ...
	suite.Equal("QWxhZGRpbjpvcGVuIHNlc2FtZQ==", encoded)
}

func (suite *BasicTestSuite) TestBasicTokenParser() {
	suite.Run("Invalid", func() {
		p := BasicTokenParser{}
		token, err := p.Parse(context.Background(), "^%$@!()$kldfj34729$(&fhd") // hopelessly invalid ...

		suite.ErrorIs(err, bascule.ErrInvalidCredentials)
		suite.Nil(token)
	})

	suite.Run("ImproperlyFormatted", func() {
		p := BasicTokenParser{}
		token, err := p.Parse(
			context.Background(),
			base64.StdEncoding.EncodeToString([]byte("missing colon")),
		)

		suite.ErrorIs(err, bascule.ErrInvalidCredentials)
		suite.Nil(token)
	})

	suite.Run("Success", func() {
		p := BasicTokenParser{}
		token, err := p.Parse(context.Background(), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==")

		suite.NoError(err)
		suite.Require().NotNil(token)
		suite.Equal("Aladdin", token.Principal())

		suite.Require().Implements((*BasicToken)(nil), token)
		suite.Equal("Aladdin", token.(BasicToken).UserName())
		suite.Equal("open sesame", token.(BasicToken).Password())
	})
}

func TestBasic(t *testing.T) {
	suite.Run(t, new(BasicTestSuite))
}
