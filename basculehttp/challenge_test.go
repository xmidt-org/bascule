// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ChallengeTestSuite struct {
	suite.Suite
}

// newValidParameters creates a test set of parameters and asserts
// that they're value.
func (suite *ChallengeTestSuite) newValidParameters(s ...string) ChallengeParameters {
	cp, err := NewChallengeParameters(s...)
	suite.Require().NoError(err)
	return cp
}

func (suite *ChallengeTestSuite) testChallengeParametersInvalid() {
	testCases := []struct {
		name, value string
	}{
		{}, // both blank
		{"valid", ""},
		{"", "valid"},
		{"token68", "value"}, // reserved
		{"embedded whitespace", "value"},
		{"name", "embedded whitespace"},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			var cp ChallengeParameters
			suite.Error(cp.Set(testCase.name, testCase.value))
		})
	}
}

func (suite *ChallengeTestSuite) testChallengeParametersEmpty() {
	var cp ChallengeParameters
	suite.Zero(cp.Len())

	var o strings.Builder
	cp.Write(&o)
	suite.Empty(o.String())
	suite.Empty(cp.String())
}

func (suite *ChallengeTestSuite) testChallengeParametersValid() {
	testCases := []struct {
		namesAndValues []string
		expectedFormat string
	}{
		{
			namesAndValues: []string{"realm", "test"},
			expectedFormat: `realm="test"`,
		},
		{
			namesAndValues: []string{"nonce", "this_is_a_nonce", "qos", "a,b,c"},
			expectedFormat: `nonce="this_is_a_nonce", qos="a,b,c"`,
		},
		{
			namesAndValues: []string{"nonce", "this_is_a_nonce", "realm", "test@example.com", "qos", "a,b,c"},
			expectedFormat: `realm="test@example.com", nonce="this_is_a_nonce", qos="a,b,c"`, // realm is always first
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			cp, err := NewChallengeParameters(testCase.namesAndValues...)
			suite.Require().NoError(err)
			suite.Equal(len(testCase.namesAndValues)/2, cp.Len())

			var o strings.Builder
			cp.Write(&o)
			suite.Equal(testCase.expectedFormat, o.String())
			suite.Equal(testCase.expectedFormat, cp.String())
		})
	}
}

func (suite *ChallengeTestSuite) testChallengeParametersDuplicate() {
	var cp ChallengeParameters
	suite.NoError(cp.Set("name", "value1"))
	suite.NoError(cp.Set("another", "somevalue"))
	suite.NoError(cp.Set("name", "value2"))

	var o strings.Builder
	cp.Write(&o)
	suite.Equal(
		`name="value2", another="somevalue"`,
		o.String(),
	)

	suite.Equal(
		`name="value2", another="somevalue"`,
		cp.String(),
	)

	suite.Equal(2, cp.Len())
}

func (suite *ChallengeTestSuite) testChallengeParametersSetRealm() {
	suite.Run("Invalid", func() {
		var cp ChallengeParameters
		suite.Error(cp.SetRealm("embedded whitespace"))
		suite.Zero(cp.Len())

		var o strings.Builder
		cp.Write(&o)
		suite.Empty(o.String())
		suite.Empty(cp.String())
	})

	suite.Run("Valid", func() {
		var cp ChallengeParameters
		suite.NoError(cp.SetRealm("myrealm"))
		suite.Equal(1, cp.Len())

		var o strings.Builder
		cp.Write(&o)
		suite.Equal(`realm="myrealm"`, o.String())
		suite.Equal(`realm="myrealm"`, cp.String())
	})
}

func (suite *ChallengeTestSuite) testChallengeParametersSetCharset() {
	suite.Run("Invalid", func() {
		var cp ChallengeParameters
		suite.Error(cp.SetCharset("embedded whitespace"))
		suite.Zero(cp.Len())

		var o strings.Builder
		cp.Write(&o)
		suite.Empty(o.String())
		suite.Empty(cp.String())
	})

	suite.Run("Valid", func() {
		var cp ChallengeParameters
		suite.NoError(cp.SetCharset("UTF-8"))
		suite.Equal(1, cp.Len())

		var o strings.Builder
		cp.Write(&o)
		suite.Equal(`charset="UTF-8"`, o.String())
		suite.Equal(`charset="UTF-8"`, cp.String())
	})
}

func (suite *ChallengeTestSuite) testChallengeParametersOddParameterCount() {
	cp, err := NewChallengeParameters("1", "2", "3")
	suite.Error(err)
	suite.Zero(cp.Len())
}

func (suite *ChallengeTestSuite) TestChallengeParameters() {
	suite.Run("Invalid", suite.testChallengeParametersInvalid)
	suite.Run("Empty", suite.testChallengeParametersEmpty)
	suite.Run("Valid", suite.testChallengeParametersValid)
	suite.Run("Duplicate", suite.testChallengeParametersDuplicate)
	suite.Run("SetRealm", suite.testChallengeParametersSetRealm)
	suite.Run("SetCharset", suite.testChallengeParametersSetCharset)
	suite.Run("OddParameterCount", suite.testChallengeParametersOddParameterCount)
}

func (suite *ChallengeTestSuite) testChallengeValid() {
	testCases := []struct {
		challenge      Challenge
		expectedFormat string
	}{
		{
			challenge: Challenge{
				Scheme: SchemeBasic,
			},
			expectedFormat: `Basic`,
		},
		{
			challenge: Challenge{
				Scheme:     SchemeBasic,
				Parameters: suite.newValidParameters(RealmParameter, "test"),
			},
			expectedFormat: `Basic realm="test"`,
		},
		{
			challenge:      NewBasicChallenge("", false),
			expectedFormat: `Basic`,
		},
		{
			challenge:      NewBasicChallenge("test", false),
			expectedFormat: `Basic realm="test"`,
		},
		{
			challenge:      NewBasicChallenge("test@example.com", true),
			expectedFormat: `Basic realm="test@example.com", charset="UTF-8"`,
		},
		{
			challenge: Challenge{
				Scheme: Scheme("Custom"),
				Parameters: suite.newValidParameters(
					"nonce", "this_is_a_nonce",
					"qop", "a,b,c",
					RealmParameter, "test@example.com", // this will get placed first
					"custom", "1234",
				),
			},
			expectedFormat: `Custom realm="test@example.com", nonce="this_is_a_nonce", qop="a,b,c", custom="1234"`,
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			var o strings.Builder
			suite.NoError(testCase.challenge.Write(&o))
			suite.Equal(testCase.expectedFormat, o.String())
		})
	}
}

func (suite *ChallengeTestSuite) testChallengeInvalid() {
	badChallenges := []Challenge{
		Challenge{}, // blank scheme
		Challenge{
			Scheme: Scheme("this is not a valid scheme"),
		},
	}

	for i, bad := range badChallenges {
		suite.Run(strconv.Itoa(i), func() {
			var o strings.Builder
			suite.Error(bad.Write(&o))
		})
	}
}

func (suite *ChallengeTestSuite) TestChallenge() {
	suite.Run("Valid", suite.testChallengeValid)
	suite.Run("Invalid", suite.testChallengeInvalid)
}

func (suite *ChallengeTestSuite) testChallengesValid() {
	testCases := []struct {
		challenges Challenges
		expected   []string
	}{
		{
			challenges: Challenges{}, // empty is always valid and should do nothing
			expected:   nil,
		},
		{
			challenges: Challenges{}.
				Append(
					NewBasicChallenge("test@server.com", true),
				),
			expected: []string{
				`Basic realm="test@server.com", charset="UTF-8"`,
			},
		},
		{
			challenges: Challenges{}.
				Append(Challenge{
					Scheme: Scheme("Bearer"),
					Parameters: suite.newValidParameters(
						RealmParameter, "myrealm",
						"foo", "bar",
					),
				}).
				Append(Challenge{
					Scheme: Scheme("Custom"),
					Parameters: suite.newValidParameters(
						"nonce", "this_is_a_nonce",
						RealmParameter, "anotherrealm@somewhere.net",
						"age", "123",
					),
				}),
			expected: []string{
				`Bearer realm="myrealm", foo="bar"`,
				`Custom realm="anotherrealm@somewhere.net", nonce="this_is_a_nonce", age="123"`,
			},
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			suite.Run("DefaultHeader", func() {
				header := make(http.Header)
				suite.NoError(testCase.challenges.WriteHeader(header))
				suite.ElementsMatch(testCase.expected, header.Values(WWWAuthenticateHeader))
			})

			suite.Run("CustomHeader", func() {
				header := make(http.Header)
				suite.NoError(testCase.challenges.WriteHeaderCustom(header, "Custom"))
				suite.ElementsMatch(testCase.expected, header.Values("Custom"))
			})
		})
	}
}

func (suite *ChallengeTestSuite) testChallengesInvalid() {
	badChallenges := []Challenges{
		Challenges{}.Append(Challenge{
			Scheme: Scheme("bad scheme"),
		}),
		Challenges{}.Append(Challenge{
			Scheme: Scheme("Good"),
		}).
			Append(Challenge{
				Scheme: Scheme("bad scheme"),
			}),
	}

	for i, bad := range badChallenges {
		suite.Run(strconv.Itoa(i), func() {
			header := make(http.Header)
			suite.Error(bad.WriteHeader(header))
			suite.Error(bad.WriteHeaderCustom(header, "Custom"))
		})
	}
}

func (suite *ChallengeTestSuite) TestChallenges() {
	suite.Run("Valid", suite.testChallengesValid)
	suite.Run("Invalid", suite.testChallengesInvalid)
}

func TestChallenge(t *testing.T) {
	suite.Run(t, new(ChallengeTestSuite))
}
