package basculehash

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type PrincipalsTestSuite struct {
	TestSuite

	hasher Hasher
}

func TestPrincipals(t *testing.T) {
	suite.Run(t, new(PrincipalsTestSuite))
}
