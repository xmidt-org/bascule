// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"errors"
	"mime"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule"
)

type ErrorTestSuite struct {
	suite.Suite
}

func (suite *ErrorTestSuite) TestDefaultErrorStatusCoder() {
	suite.Run("ErrMissingCredentials", func() {
		suite.Equal(
			http.StatusUnauthorized,
			DefaultErrorStatusCoder(nil, bascule.ErrMissingCredentials),
		)
	})

	suite.Run("ErrInvalidCredentials", func() {
		suite.Equal(
			http.StatusBadRequest,
			DefaultErrorStatusCoder(nil, bascule.ErrInvalidCredentials),
		)
	})

	suite.Run("StatusCoder", func() {
		suite.Equal(
			317,
			DefaultErrorStatusCoder(
				nil,
				UseStatusCode(317, errors.New("unrecognized")),
			),
		)
	})

	suite.Run("OverrideStatusCode", func() {
		suite.Equal(
			http.StatusNotFound,
			DefaultErrorStatusCoder(
				nil,
				UseStatusCode(http.StatusNotFound, bascule.ErrMissingCredentials),
			),
		)
	})

	suite.Run("Unrecognized", func() {
		suite.Equal(
			0,
			DefaultErrorStatusCoder(nil, errors.New("unrecognized error")),
		)
	})
}

func (suite *ErrorTestSuite) TestDefaultErrorMarshaler() {
	contentType, content, marshalErr := DefaultErrorMarshaler(
		nil,
		bascule.ErrMissingCredentials,
	)

	suite.Require().NoError(marshalErr)
	suite.Equal(bascule.ErrMissingCredentials.Error(), string(content))

	mediaType, _, err := mime.ParseMediaType(contentType)
	suite.Require().NoError(err)
	suite.Equal("text/plain", mediaType)
}

func (suite *ErrorTestSuite) TestUseStatusCode() {
	var (
		err        = errors.New("an error")
		wrapperErr = UseStatusCode(511, err)
	)

	suite.Error(wrapperErr)
	suite.ErrorIs(wrapperErr, err)

	type statusCoder interface {
		StatusCode() int
	}

	var sc statusCoder
	suite.Require().ErrorAs(wrapperErr, &sc)
	suite.Equal(511, sc.StatusCode())
}

func TestError(t *testing.T) {
	suite.Run(t, new(ErrorTestSuite))
}
