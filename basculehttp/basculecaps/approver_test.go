// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule"
)

type testToken struct {
	principal    string
	capabilities []string
}

func (tt *testToken) Principal() string {
	return tt.principal
}

func (tt *testToken) Capabilities() []string {
	return tt.capabilities
}

type ApproverTestSuite struct {
	suite.Suite
}

// newRequest creates an HTTP request with an empty body, since these
// tests do not need to use any entity bodies.
func (suite *ApproverTestSuite) newRequest(method, url string) *http.Request {
	return httptest.NewRequest(method, url, nil)
}

// newToken creates a stub token that has the given capabilities.
func (suite *ApproverTestSuite) newToken(capabilities ...string) bascule.Token {
	return &testToken{
		principal:    "test",
		capabilities: append([]string{}, capabilities...),
	}
}

// newApprover creates a Approver from a set of options that
// must be valid.
func (suite *ApproverTestSuite) newApprover(opts ...ApproverOption) *Approver {
	ca, err := NewApprover(opts...)
	suite.Require().NoError(err)
	suite.Require().NotNil(ca)
	return ca
}

func (suite *ApproverTestSuite) TestInvalidPrefix() {
	invalidPrefixes := []string{
		"(?!foo)", // RE2 has no negative lookahead
		"(a",      // unbalanced
		"*",       // nothing to repeat
	}

	for i, invalid := range invalidPrefixes {
		suite.Run(strconv.Itoa(i), func() {
			ca, err := NewApprover(
				WithPrefixes(invalid),
			)

			suite.Error(err)
			suite.Nil(ca)
		})
	}
}

func (suite *ApproverTestSuite) TestInvalidAllMethod() {
	ca, err := NewApprover(
		WithAllMethod(""), // blanks aren't allowed
	)

	suite.Error(err)
	suite.Nil(ca)
}

func (suite *ApproverTestSuite) testApproveMissingCapabilities() {
	ca := suite.newApprover() // don't need any options for this case
	err := ca.Approve(context.Background(), suite.newRequest("GET", "/test"), new(testToken))
	suite.ErrorIs(err, bascule.ErrUnauthorized)
}

func (suite *ApproverTestSuite) testApproveSuccess() {
	testCases := []struct {
		capabilities []string
		request      *http.Request
		options      []ApproverOption
	}{
		{
			capabilities: []string{"x1:webpa:api:.*:all"},
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixes("x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:device/.*/config:all"},
			request:      suite.newRequest("GET", "/device/DEADBEEF/config"),
			options: []ApproverOption{
				WithPrefixes("x1:xmidt:api:", "x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:/test/.*:put"},
			request:      suite.newRequest("PUT", "/test/foo"),
			options: []ApproverOption{
				WithPrefixes("x1:xmidt:api:", "x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{
				"x1:xmidt:api:/device/.*/config:all",
				"x1:webpa:api:/something/else:get",
				"x1:doesnot:apply:.*:all",
				"x1:webpa:api:/test/.*:put", // this should match
			},
			request: suite.newRequest("PUT", "/test/foo"),
			options: []ApproverOption{
				WithPrefixes("x1:xmidt:api:", "x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:/test/.*:custom"},
			request:      suite.newRequest("PATCH", "/test/foo"),
			options: []ApproverOption{
				WithPrefixes("x1:xmidt:api:", "x1:webpa:api:"),
				WithAllMethod("custom"),
			},
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			var (
				token = suite.newToken(testCase.capabilities...)
				ca    = suite.newApprover(testCase.options...)
			)

			suite.NoError(
				ca.Approve(context.Background(), testCase.request, token),
			)
		})
	}
}

func (suite *ApproverTestSuite) testApproveUnauthorized() {
	testCases := []struct {
		capabilities []string
		request      *http.Request
		options      []ApproverOption
	}{
		{
			capabilities: []string{"x1:xmidt:api:.*:all"},
			request:      suite.newRequest("GET", "/"),
			options:      nil, // will reject all tokens
		},
		{
			capabilities: []string{"x1:webpa:api:.*:put"},
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixes("x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:/doesnotmatch:get"},
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixes("x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:(?!foo):put"}, // bad expression
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixes("x1:webpa:api:"),
			},
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			var (
				token = suite.newToken(testCase.capabilities...)
				ca    = suite.newApprover(testCase.options...)
			)

			err := ca.Approve(context.Background(), testCase.request, token)
			suite.ErrorIs(err, bascule.ErrUnauthorized)
		})
	}
}

// testApproveCapabilityURL documents how the url pattern carried by a token's
// capability is matched against a request.  The prefix is the only thing
// configured; the capability itself decides what the token may reach.
func (suite *ApproverTestSuite) testApproveCapabilityURL() {
	const prefix = "x1:webpa:api:"

	testCases := []struct {
		capability string
		target     string
		approved   bool
	}{
		{
			// a pattern need not be rooted
			capability: "x1:webpa:api:device/.*/config:all",
			target:     "/device/mac:112233/config",
			approved:   true,
		}, {
			capability: "x1:webpa:api:device/.*/config:all",
			target:     "/mistake/device/mac:112233/config",
			approved:   false,
		}, {
			// a doubled leading slash is not absorbed
			capability: "x1:webpa:api:device/.*/config:all",
			target:     "//device/mac:112233/config",
			approved:   false,
		}, {
			capability: "x1:webpa:api:/device/.*/config:all",
			target:     "/device/mac:112233/config",
			approved:   true,
		}, {
			capability: "x1:webpa:api:/device/.*/config:all",
			target:     "/mistake/device/mac:112233/config",
			approved:   false,
		}, {
			capability: "x1:webpa:api:/device/.*/config:all",
			target:     "//device/mac:112233/config",
			approved:   false,
		}, {
			// a capability is a prefix grant, not an exact match
			capability: "x1:webpa:api:/device/.*/config:all",
			target:     "/device/mac:112233/config/ignored",
			approved:   true,
		}, {
			capability: "x1:webpa:api:test:all",
			target:     "/test",
			approved:   true,
		}, {
			capability: "x1:webpa:api:test:all",
			target:     "/mistake/test",
			approved:   false,
		}, {
			capability: "x1:webpa:api:test:all",
			target:     "/test/foo",
			approved:   true,
		}, {
			// a leading .* may match nothing at all
			capability: "x1:webpa:api:.*/device/.*/config:all",
			target:     "/device/mac:112233/config",
			approved:   true,
		}, {
			capability: "x1:webpa:api:.*/device/.*/config:all",
			target:     "/api/device/mac:112233/config",
			approved:   true,
		}, {
			// every alternative is rooted, not just the first
			capability: "x1:webpa:api:test|dir:all",
			target:     "/test",
			approved:   true,
		}, {
			capability: "x1:webpa:api:test|dir:all",
			target:     "/dir",
			approved:   true,
		}, {
			capability: "x1:webpa:api:test|dir:all",
			target:     "/invalid/test",
			approved:   false,
		}, {
			capability: "x1:webpa:api:test|dir:all",
			target:     "/invalid/dir",
			approved:   false,
		}, {
			// a token reaches only what its own capability grants
			capability: "x1:webpa:api:/device/alice/config:all",
			target:     "/device/alice/config",
			approved:   true,
		}, {
			capability: "x1:webpa:api:/device/alice/config:all",
			target:     "/device/bob/config",
			approved:   false,
		}, {
			// neither alternative is rooted, both must match
			capability: "x1:webpa:api:foo|bar:all",
			target:     "/foo",
			approved:   true,
		}, {
			capability: "x1:webpa:api:foo|bar:all",
			target:     "/bar",
			approved:   true,
		}, {
			capability: "x1:webpa:api:foo|bar:all",
			target:     "/xxx/bar",
			approved:   false,
		}, {
			// both alternatives rooted
			capability: "x1:webpa:api:/foo|/bar:all",
			target:     "/bar",
			approved:   true,
		}, {
			// alternatives may disagree about the leading '/'
			capability: "x1:webpa:api:foo|/bar:all",
			target:     "/foo",
			approved:   true,
		}, {
			capability: "x1:webpa:api:foo|/bar:all",
			target:     "/bar",
			approved:   true,
		}, {
			capability: "x1:webpa:api:/foo|bar:all",
			target:     "/foo",
			approved:   true,
		}, {
			capability: "x1:webpa:api:/foo|bar:all",
			target:     "/bar",
			approved:   true,
		}, {
			// alternation may be nested
			capability: "x1:webpa:api:(x|/y)|z:all",
			target:     "/y",
			approved:   true,
		}, {
			capability: "x1:webpa:api:(x|/y)|z:all",
			target:     "/z",
			approved:   true,
		}, {
			capability: "x1:webpa:api:(x|/y)|z:all",
			target:     "/a/y",
			approved:   false,
		}, {
			// single character alternatives parse as a character class
			capability: "x1:webpa:api:a|b|c:all",
			target:     "/b",
			approved:   true,
		}, {
			capability: "x1:webpa:api:a|b|c:all",
			target:     "/d",
			approved:   false,
		}, {
			// a doubled slash is not a way to reach /admin
			capability: "x1:webpa:api:/admin:all",
			target:     "/admin",
			approved:   true,
		}, {
			capability: "x1:webpa:api:/admin:all",
			target:     "//admin",
			approved:   false,
		}, {
			capability: "x1:webpa:api:/admin:all",
			target:     "///admin",
			approved:   false,
		}, {
			capability: "x1:webpa:api:/admin:all",
			target:     "/admin/sub",
			approved:   true,
		}, {
			// an unrooted pattern is still confined to one leading slash
			capability: "x1:webpa:api:admin:all",
			target:     "/admin",
			approved:   true,
		}, {
			capability: "x1:webpa:api:admin:all",
			target:     "//admin",
			approved:   false,
		}, {
			capability: "x1:webpa:api:admin:all",
			target:     "///admin",
			approved:   false,
		}, {
			// a pattern that asks for a doubled slash still gets it
			capability: "x1:webpa:api://admin:all",
			target:     "//admin",
			approved:   true,
		}, {
			capability: "x1:webpa:api://admin:all",
			target:     "/admin",
			approved:   false,
		}, {
			// a trailing slash is inside the grant
			capability: "x1:webpa:api:/admin:all",
			target:     "/admin/",
			approved:   true,
		}, {
			// a doubled slash anywhere is not collapsed
			capability: "x1:webpa:api:/x/admin:all",
			target:     "/x//admin",
			approved:   false,
		}, {
			// a wildcard still covers a doubled slash
			capability: "x1:webpa:api:.*:all",
			target:     "//admin",
			approved:   true,
		}, {
			// the doubled slash guard applies to alternations too
			capability: "x1:webpa:api:test|dir:all",
			target:     "//dir",
			approved:   false,
		}, {
			// a request with no path at all
			capability: "x1:webpa:api:.*:all",
			target:     "http://foo.com",
			approved:   true,
		}, {
			capability: "x1:webpa:api:/test:all",
			target:     "http://foo.com",
			approved:   false,
		}, {
			capability: "x1:webpa:api:/test:all",
			target:     "http://foo.com/test",
			approved:   true,
		}, {
			capability: "x1:webpa:api:.*:all",
			target:     "http://foo.com/",
			approved:   true,
		},
	}

	for _, testCase := range testCases {
		suite.Run(fmt.Sprintf("'%s' + '%s' -> %t", testCase.capability, testCase.target, testCase.approved), func() {
			err := suite.newApprover(WithPrefixes(prefix)).Approve(
				context.Background(),
				suite.newRequest("GET", testCase.target),
				suite.newToken(testCase.capability),
			)

			if testCase.approved {
				suite.NoError(err)
			} else {
				suite.ErrorIs(err, bascule.ErrUnauthorized)
			}
		})
	}
}

// testApproveConfiguredPrefix documents how the configured prefix selects which
// of a token's capabilities are honored.
func (suite *ApproverTestSuite) testApproveConfiguredPrefix() {
	testCases := []struct {
		prefix     string
		capability string
		target     string
		approved   bool
	}{
		{
			// a plain literal prefix
			prefix:     "x1:webpa:api:",
			capability: "x1:webpa:api:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			// every alternative of a prefix is anchored, not just the first
			prefix:     "x1:webpa:|x2:webpa:",
			capability: "x1:webpa:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			prefix:     "x1:webpa:|x2:webpa:",
			capability: "x2:webpa:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			prefix:     "x1:webpa:|x2:webpa:",
			capability: "x3:webpa:/test:all",
			target:     "/test",
			approved:   false,
		}, {
			// a prefix may contain subexpressions of its own
			prefix:     "x(1|2):webpa:",
			capability: "x1:webpa:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			prefix:     "x(1|2):webpa:",
			capability: "x2:webpa:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			prefix:     "x(1|2):webpa:",
			capability: "x3:webpa:/test:all",
			target:     "/test",
			approved:   false,
		}, {
			// nested and repeated subexpressions shift the url and method too
			prefix:     "(a)(b)((c)):",
			capability: "abc:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			// a prefix may be empty
			prefix:     "",
			capability: "/test:all",
			target:     "/test",
			approved:   true,
		},
	}

	for _, testCase := range testCases {
		suite.Run(fmt.Sprintf("'%s' + '%s' -> %t", testCase.prefix, testCase.capability, testCase.approved), func() {
			ca, err := NewApprover(WithPrefixes(testCase.prefix))
			if err != nil {
				suite.False(testCase.approved, "prefix was rejected: %s", err)
				return
			}

			err = ca.Approve(
				context.Background(),
				suite.newRequest("GET", testCase.target),
				suite.newToken(testCase.capability),
			)

			if testCase.approved {
				suite.NoError(err)
			} else {
				suite.ErrorIs(err, bascule.ErrUnauthorized)
			}
		})
	}
}

func (suite *ApproverTestSuite) TestApprove() {
	suite.Run("MissingCapabilities", suite.testApproveMissingCapabilities)
	suite.Run("Success", suite.testApproveSuccess)
	suite.Run("Unauthorized", suite.testApproveUnauthorized)
	suite.Run("CapabilityURL", suite.testApproveCapabilityURL)
	suite.Run("ConfiguredPrefix", suite.testApproveConfiguredPrefix)
}

func TestApprover(t *testing.T) {
	suite.Run(t, new(ApproverTestSuite))
}
