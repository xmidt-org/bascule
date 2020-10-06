package bascule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGet(t *testing.T) {
	assert := assert.New(t)
	attributes := Attributes(attrs)

	val, ok := attributes.Get("testkey")
	assert.Equal("testval", val)
	assert.True(ok)

	val, ok = attributes.Get("noval")
	assert.Empty(val)
	assert.False(ok)

	emptyAttributes := NewAttributes(map[string]interface{}{})
	val, ok = emptyAttributes.Get("test")
	assert.Nil(val)
	assert.False(ok)
}

func TestGetNestedAttribute(t *testing.T) {
	attributes := NewAttributes(map[string]interface{}{
		"a":         map[string]interface{}{"b": map[string]interface{}{"c": "answer"}},
		"one level": "yay",
		"bad":       nil,
	})
	tests := []struct {
		description    string
		keys           []string
		expectedResult interface{}
		expectedOK     bool
	}{
		// Success test is failing. ): getting nil, false
		{
			description:    "Success",
			keys:           []string{"a", "b", "c"},
			expectedResult: "answer",
			expectedOK:     true,
		},
		{
			description:    "Success single key",
			keys:           []string{"one level"},
			expectedResult: "yay",
			expectedOK:     true,
		},
		{
			description:    "Success nil",
			keys:           []string{"bad"},
			expectedResult: nil,
			expectedOK:     true,
		},
		{
			description: "Nil Keys Error",
			keys:        nil,
		},
		{
			description: "No Keys Error",
			keys:        []string{},
		},
		{
			description: "Non Attribute Value Error",
			keys:        []string{"one level", "test"},
		},
		{
			description: "Nil Attributes Error",
			keys:        []string{"bad", "more bad"},
		},
		{
			description: "Missing Key Error",
			keys:        []string{"c", "b", "a"},
		},
		{
			description: "Wrong Key Case Error",
			keys:        []string{"A", "B", "C"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			val, ok := GetNestedAttribute(attributes, tc.keys...)
			assert.Equal(tc.expectedResult, val)
			assert.Equal(tc.expectedOK, ok)
		})
	}
}
