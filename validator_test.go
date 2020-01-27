package bascule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidators(t *testing.T) {
	assert := assert.New(t)
	validatorList := Validators([]Validator{CreateNonEmptyTypeCheck(), CreateNonEmptyPrincipalCheck()})
	err := validatorList.Check(context.Background(), NewToken("type", "principal", NewAttributes()))
	assert.Nil(err)
	errs := validatorList.Check(context.Background(), NewToken("", "", NewAttributes()))
	assert.NotNil(errs)
	_, ok := errs.(Errors)
	assert.True(ok)
}
