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

// newValidBasic uses NewBasicChallenge to create a Challenge and asserts
// that no error occurred.
func (suite *ChallengeTestSuite) newValidBasic(realm string, UTF8 bool) Challenge {
	c, err := NewBasicChallenge(realm, UTF8)
	suite.Require().NoError(err)
	return c
}

func (suite *ChallengeTestSuite) TestChallengeParameters() {
	suite.Run("Invalid", func() {
		badParameterNames := []string{
			"",
			"  ",
			"this is not ok",
			"neither\tis\bthis",
			"token68", // reserved
			"realm",   // reserved
		}

		for i, bad := range badParameterNames {
			suite.Run(strconv.Itoa(i), func() {
				var cp ChallengeParameters
				suite.Error(cp.Set(bad, "value"))
			})
		}
	})

	suite.Run("Duplicate", func() {
		var cp ChallengeParameters
		suite.NoError(cp.Set("name", "value1"))
		suite.NoError(cp.Set("another", "somevalue"))
		suite.NoError(cp.Set("name", "value2"))
		suite.Equal(
			`name="value2", another="somevalue"`,
			cp.String(),
		)
	})
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
				Scheme: SchemeBasic,
				Realm:  "test",
			},
			expectedFormat: `Basic realm="test"`,
		},
		{
			challenge:      suite.newValidBasic("", false),
			expectedFormat: `Basic`,
		},
		{
			challenge:      suite.newValidBasic("test", false),
			expectedFormat: `Basic realm="test"`,
		},
		{
			challenge:      suite.newValidBasic("test@example.com", true),
			expectedFormat: `Basic realm="test@example.com" charset="UTF-8"`,
		},
		{
			challenge: Challenge{
				Scheme: Scheme("Custom"),
				Realm:  "test@example.com",
				Parameters: suite.newValidParameters(
					"nonce", "this is a nonce",
					"qop", "a, b, c",
					"custom", "1234",
				),
			},
			expectedFormat: `Custom realm="test@example.com" nonce="this is a nonce", qop="a, b, c", custom="1234"`,
		},
		{
			challenge: Challenge{
				Scheme:  Scheme("Bearer"),
				Realm:   "my realm",
				Token68: true,
				Parameters: suite.newValidParameters(
					"nonce", "this is a nonce",
					"blank",
				),
			},
			expectedFormat: `Bearer realm="my realm" token68 nonce="this is a nonce", blank=""`,
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
					suite.newValidBasic("test@server.com", true),
				),
			expected: []string{
				`Basic realm="test@server.com" charset="UTF-8"`,
			},
		},
		{
			challenges: Challenges{}.
				Append(Challenge{
					Scheme:     Scheme("Bearer"),
					Realm:      "my realm",
					Parameters: suite.newValidParameters("foo", "bar"),
				}).
				Append(Challenge{
					Scheme:     Scheme("Custom"),
					Realm:      "another realm@somewhere.net",
					Token68:    true,
					Parameters: suite.newValidParameters("nonce", "this is a nonce", "age", "123"),
				}),
			expected: []string{
				`Bearer realm="my realm" foo="bar"`,
				`Custom realm="another realm@somewhere.net" token68 nonce="this is a nonce", age="123"`,
			},
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			suite.Run("DefaultHeader", func() {
				header := make(http.Header)
				suite.NoError(testCase.challenges.WriteHeader("", header))
				suite.ElementsMatch(testCase.expected, header.Values(WWWAuthenticateHeader))
			})

			suite.Run("CustomHeader", func() {
				header := make(http.Header)
				suite.NoError(testCase.challenges.WriteHeader("Custom", header))
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
			suite.Error(bad.WriteHeader("", header))
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
