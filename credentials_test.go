package bascule

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type CredentialsTestSuite struct {
	suite.Suite
}

func (suite *CredentialsTestSuite) TestInvalidCredentialsError() {
	suite.Run("WithCause", func() {
		cause := errors.New("cause")
		err := InvalidCredentialsError{
			Cause: cause,
			Raw:   "raw",
		}

		suite.Same(err.Unwrap(), cause)
		suite.Contains(err.Error(), "cause")
		suite.Contains(err.Error(), "raw")
	})

	suite.Run("NoCause", func() {
		err := InvalidCredentialsError{
			Raw: "raw",
		}

		suite.Nil(err.Unwrap())
		suite.Contains(err.Error(), "raw")
	})
}

func (suite *CredentialsTestSuite) TestUnsupportedSchemeError() {
	err := UnsupportedSchemeError{
		Scheme: Scheme("scheme"),
	}

	suite.Contains(err.Error(), "scheme")
}

func (suite *CredentialsTestSuite) TestCredentialsParserFunc() {
	const expectedRaw = "expected raw credentials"
	expectedErr := errors.New("expected error")
	var c CredentialsParser = CredentialsParserFunc(func(raw string) (Credentials, error) {
		suite.Equal(expectedRaw, raw)
		return Credentials{
			Scheme: Scheme("test"),
			Value:  "value",
		}, expectedErr
	})

	creds, err := c.Parse(expectedRaw)
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
