// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type CredentialsTestSuite struct {
	suite.Suite
}

func (suite *CredentialsTestSuite) TestCredentialsParserFunc() {
	const expectedRaw = "expected raw credentials"
	expectedErr := errors.New("expected error")
	var c CredentialsParser[string] = CredentialsParserFunc[string](func(_ context.Context, raw string) (Credentials, error) {
		suite.Equal(expectedRaw, raw)
		return Credentials{
			Scheme: Scheme("test"),
			Value:  "value",
		}, expectedErr
	})

	creds, err := c.Parse(context.Background(), expectedRaw)
	suite.Equal(
		Credentials{
			Scheme: Scheme("test"),
			Value:  "value",
		},
		creds,
	)

	suite.Same(expectedErr, err)
}

func TestCredentials(t *testing.T) {
	suite.Run(t, new(CredentialsTestSuite))
}
