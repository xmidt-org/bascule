package bascule

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ErrorSuite struct {
	suite.Suite
}

func (suite *ErrorSuite) TestUnsupportedSchemeError() {
	err := UnsupportedSchemeError{
		Scheme: Scheme("scheme"),
	}

	suite.Contains(err.Error(), "scheme")
	suite.Equal(ErrorTypeBadCredentials, err.Type())
}

func (suite *ErrorSuite) TestBadCredentialsError() {
	err := BadCredentialsError{
		Raw: "these are an unparseable, raw credentials",
	}

	suite.Contains(err.Error(), "these are an unparseable, raw credentials")
	suite.Equal(ErrorTypeBadCredentials, err.Type())
}

func (suite *ErrorSuite) TestGetErrorType() {
	suite.Run("Unknown", func() {
		suite.Equal(
			ErrorTypeUnknown,
			GetErrorType(errors.New("this is an error that is unknown to bascule")),
		)
	})

	suite.Run("ImplementsError", func() {
		suite.Equal(
			ErrorTypeBadCredentials,
			GetErrorType(new(BadCredentialsError)),
		)
	})
}

func TestError(t *testing.T) {
	suite.Run(t, new(ErrorSuite))
}
