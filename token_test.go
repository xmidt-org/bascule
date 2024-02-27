package bascule

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type TokenParsersSuite struct {
	suite.Suite
}

func TestTokenParsers(t *testing.T) {
	suite.Run(t, new(TokenParsersSuite))
}
