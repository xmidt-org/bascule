// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

type RunTestSuite struct {
	suite.Suite

	kongOptions []kong.Option

	stdout   bytes.Buffer
	stderr   bytes.Buffer
	exitCode int
}

func (suite *RunTestSuite) exitFunc(code int) {
	suite.exitCode = code
}

func (suite *RunTestSuite) SetupSuite() {
	suite.kongOptions = []kong.Option{
		kong.Writers(&suite.stdout, &suite.stderr),
		kong.Exit(suite.exitFunc),
	}
}

func (suite *RunTestSuite) SetupTest() {
	suite.stdout.Reset()
	suite.stderr.Reset()
	suite.exitCode = 0
}

func (suite *RunTestSuite) SetupSubTest() {
	suite.SetupTest()
}

func (suite *RunTestSuite) testBcryptSubcommandInvalidParameters() {
	testCases := []struct {
		args []string
	}{
		{
			args: []string{"bcrypt"},
		},
		{
			args: []string{"bcrypt", "--cost", "123", "plaintext"},
		},
		{
			args: []string{"bcrypt", "-c", "123", "plaintext"},
		},
		{
			args: []string{"bcrypt", "--cost", "1", "plaintext"},
		},
		{
			args: []string{"bcrypt", "-c", "1", "plaintext"},
		},
		{
			args: []string{"bcrypt", "this plaintext is way to long ... asdfoiuwelrkjhsldkjfp983yu5pkljheflkajsodifuypwieuyrtplkahjsdflkajhsdf"},
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			run(testCase.args, suite.kongOptions...)

			suite.NotEqual(0, suite.exitCode)
			suite.Greater(suite.stdout.Len(), 0) // the usage on error goes to stdout
			suite.Greater(suite.stderr.Len(), 0)
		})
	}
}

func (suite *RunTestSuite) testBcryptSubcommandSuccess() {
	const plaintext string = "plaintext"

	testCases := []struct {
		args []string
	}{
		{
			args: []string{"bcrypt", plaintext},
		},
		{
			args: []string{"bcrypt", "-c", "5", plaintext},
		},
		{
			args: []string{"bcrypt", "--cost", "9", plaintext},
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			run(testCase.args, suite.kongOptions...)

			suite.Zero(suite.exitCode)
			suite.Greater(suite.stdout.Len(), 0)
			suite.Zero(suite.stderr.Len())

			// what's written to stdout should be parseable as a bcrypt hash
			suite.NoError(
				bcrypt.CompareHashAndPassword(
					suite.stdout.Bytes(),
					[]byte(plaintext),
				),
			)
		})
	}
}

func (suite *RunTestSuite) TestBcryptSubcommand() {
	suite.Run("InvalidParameters", suite.testBcryptSubcommandInvalidParameters)
	suite.Run("Success", suite.testBcryptSubcommandSuccess)
}

func TestRun(t *testing.T) {
	suite.Run(t, new(RunTestSuite))
}
