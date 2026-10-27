// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
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

// stripAPIVersion removes a leading /api/vN from a request's path, so that
// capabilities may be written without it.
var apiVersion = regexp.MustCompile(`^/api/v[0-9]+`)

func stripAPIVersion(u url.URL) url.URL {
	u.Path = apiVersion.ReplaceAllString(u.Path, "")
	u.RawPath = ""

	return u
}

func (suite *ApproverTestSuite) TestInvalidPrefixRegex() {
	invalidPrefixes := []string{
		"(?!foo)", // RE2 has no negative lookahead
		"(a",      // unbalanced
		"*",       // nothing to repeat
	}

	for i, invalid := range invalidPrefixes {
		suite.Run(strconv.Itoa(i), func() {
			for _, option := range []func(...string) ApproverOption{WithPrefixRegexes, WithPrefixes} {
				ca, err := NewApprover(option(invalid))
				suite.Require().Error(err)
				suite.Nil(ca)
			}
		})
	}
}

func (suite *ApproverTestSuite) TestInvalidAllMethod() {
	ca, err := NewApprover(
		WithAllMethod(""), // blanks aren't allowed
	)

	suite.Require().Error(err)
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
			capabilities: []string{"webpa-prefix-api:.*:all"},
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixLiterals("webpa-prefix-api:"),
			},
		},
		{
			capabilities: []string{"webpa-prefix-api:device/.*/config:all"},
			request:      suite.newRequest("GET", "/device/DEADBEEF/config"),
			options: []ApproverOption{
				WithPrefixLiterals("xmidt-prefix-api:", "webpa-prefix-api:"),
			},
		},
		{
			capabilities: []string{"webpa-prefix-api:/test/.*:put"},
			request:      suite.newRequest("PUT", "/test/foo"),
			options: []ApproverOption{
				WithPrefixLiterals("xmidt-prefix-api:", "webpa-prefix-api:"),
			},
		},
		{
			capabilities: []string{
				"xmidt-prefix-api:/device/.*/config:all",
				"webpa-prefix-api:/something/else:get",
				"doesnot-prefix-apply:.*:all",
				"webpa-prefix-api:/test/.*:put", // this should match
			},
			request: suite.newRequest("PUT", "/test/foo"),
			options: []ApproverOption{
				WithPrefixLiterals("xmidt-prefix-api:", "webpa-prefix-api:"),
			},
		},
		{
			capabilities: []string{"webpa-prefix-api:/test/.*:custom"},
			request:      suite.newRequest("PATCH", "/test/foo"),
			options: []ApproverOption{
				WithPrefixLiterals("xmidt-prefix-api:", "webpa-prefix-api:"),
				WithAllMethod("custom"),
			},
		},
		{
			// a capability written without the api version, matched against a
			// versioned path by normalizing the version away first
			capabilities: []string{
				"webpa-prefix-api:test/.*:put",
			},
			request: suite.newRequest("PUT", "/api/v1/test/foo"),
			options: []ApproverOption{
				WithPrefixLiterals("xmidt-prefix-api:", "webpa-prefix-api:"),
				WithURLNormalizeFunc(stripAPIVersion),
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
			capabilities: []string{"xmidt-prefix-api:.*:all"},
			request:      suite.newRequest("GET", "/"),
			options:      nil, // will reject all tokens
		},
		{
			capabilities: []string{"webpa-prefix-api:.*:put"},
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixLiterals("webpa-prefix-api:"),
			},
		},
		{
			capabilities: []string{"webpa-prefix-api:/doesnotmatch:get"},
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixLiterals("webpa-prefix-api:"),
			},
		},
		{
			capabilities: []string{"webpa-prefix-api:(?!foo):put"}, // bad expression
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixLiterals("webpa-prefix-api:"),
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
	const prefix = "webpa-prefix-api:"

	testCases := []struct {
		capability string
		target     string
		approved   bool
	}{
		{
			// a pattern need not be rooted
			capability: "webpa-prefix-api:device/.*/config:all",
			target:     "/device/mac:112233/config",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:device/.*/config:all",
			target:     "/mistake/device/mac:112233/config",
			approved:   false,
		}, {
			// a doubled leading slash is not absorbed
			capability: "webpa-prefix-api:device/.*/config:all",
			target:     "//device/mac:112233/config",
			approved:   false,
		}, {
			capability: "webpa-prefix-api:/device/.*/config:all",
			target:     "/device/mac:112233/config",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:/device/.*/config:all",
			target:     "/mistake/device/mac:112233/config",
			approved:   false,
		}, {
			capability: "webpa-prefix-api:/device/.*/config:all",
			target:     "//device/mac:112233/config",
			approved:   false,
		}, {
			// a capability is a prefix grant, not an exact match
			capability: "webpa-prefix-api:/device/.*/config:all",
			target:     "/device/mac:112233/config/ignored",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:test:all",
			target:     "/test",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:test:all",
			target:     "/mistake/test",
			approved:   false,
		}, {
			capability: "webpa-prefix-api:test:all",
			target:     "/test/foo",
			approved:   true,
		}, {
			// a leading .* may match nothing at all
			capability: "webpa-prefix-api:.*/device/.*/config:all",
			target:     "/device/mac:112233/config",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:.*/device/.*/config:all",
			target:     "/api/device/mac:112233/config",
			approved:   true,
		}, {
			// every alternative is rooted, not just the first
			capability: "webpa-prefix-api:test|dir:all",
			target:     "/test",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:test|dir:all",
			target:     "/dir",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:test|dir:all",
			target:     "/invalid/test",
			approved:   false,
		}, {
			capability: "webpa-prefix-api:test|dir:all",
			target:     "/invalid/dir",
			approved:   false,
		}, {
			// a token reaches only what its own capability grants
			capability: "webpa-prefix-api:/device/alice/config:all",
			target:     "/device/alice/config",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:/device/alice/config:all",
			target:     "/device/bob/config",
			approved:   false,
		}, {
			// neither alternative is rooted, both must match
			capability: "webpa-prefix-api:foo|bar:all",
			target:     "/foo",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:foo|bar:all",
			target:     "/bar",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:foo|bar:all",
			target:     "/xxx/bar",
			approved:   false,
		}, {
			// both alternatives rooted
			capability: "webpa-prefix-api:/foo|/bar:all",
			target:     "/bar",
			approved:   true,
		}, {
			// alternatives may disagree about the leading '/'
			capability: "webpa-prefix-api:foo|/bar:all",
			target:     "/foo",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:foo|/bar:all",
			target:     "/bar",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:/foo|bar:all",
			target:     "/foo",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:/foo|bar:all",
			target:     "/bar",
			approved:   true,
		}, {
			// alternation may be nested
			capability: "webpa-prefix-api:(x|/y)|z:all",
			target:     "/y",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:(x|/y)|z:all",
			target:     "/z",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:(x|/y)|z:all",
			target:     "/a/y",
			approved:   false,
		}, {
			// single character alternatives parse as a character class
			capability: "webpa-prefix-api:a|b|c:all",
			target:     "/b",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:a|b|c:all",
			target:     "/d",
			approved:   false,
		}, {
			// a doubled slash is not a way to reach /admin
			capability: "webpa-prefix-api:/admin:all",
			target:     "/admin",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:/admin:all",
			target:     "//admin",
			approved:   false,
		}, {
			capability: "webpa-prefix-api:/admin:all",
			target:     "///admin",
			approved:   false,
		}, {
			capability: "webpa-prefix-api:/admin:all",
			target:     "/admin/sub",
			approved:   true,
		}, {
			// an unrooted pattern is still confined to one leading slash
			capability: "webpa-prefix-api:admin:all",
			target:     "/admin",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:admin:all",
			target:     "//admin",
			approved:   false,
		}, {
			capability: "webpa-prefix-api:admin:all",
			target:     "///admin",
			approved:   false,
		}, {
			// a pattern that asks for a doubled slash still gets it
			capability: "webpa-prefix-api://admin:all",
			target:     "//admin",
			approved:   true,
		}, {
			capability: "webpa-prefix-api://admin:all",
			target:     "/admin",
			approved:   false,
		}, {
			// a trailing slash is inside the grant
			capability: "webpa-prefix-api:/admin:all",
			target:     "/admin/",
			approved:   true,
		}, {
			// a doubled slash anywhere is not collapsed
			capability: "webpa-prefix-api:/x/admin:all",
			target:     "/x//admin",
			approved:   false,
		}, {
			// a wildcard still covers a doubled slash
			capability: "webpa-prefix-api:.*:all",
			target:     "//admin",
			approved:   true,
		}, {
			// the doubled slash guard applies to alternations too
			capability: "webpa-prefix-api:test|dir:all",
			target:     "//dir",
			approved:   false,
		}, {
			// a request with no path at all
			capability: "webpa-prefix-api:.*:all",
			target:     "http://example.com",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:/test:all",
			target:     "http://example.com",
			approved:   false,
		}, {
			capability: "webpa-prefix-api:/test:all",
			target:     "http://example.com/test",
			approved:   true,
		}, {
			capability: "webpa-prefix-api:.*:all",
			target:     "http://example.com/",
			approved:   true,
		},
	}

	for _, testCase := range testCases {
		suite.Run(fmt.Sprintf("'%s' + '%s' -> %t", testCase.capability, testCase.target, testCase.approved), func() {
			err := suite.newApprover(WithPrefixLiterals(prefix)).Approve(
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
// of a token's capabilities are honored, and how the literal and regex options
// read the same prefix differently.
func (suite *ApproverTestSuite) testApproveConfiguredPrefix() {
	testCases := []struct {
		option     func(...string) ApproverOption
		prefix     string
		capability string
		target     string
		approved   bool
	}{
		// literal prefixes
		{
			option:     WithPrefixLiterals,
			prefix:     "webpa-prefix-api:",
			capability: "webpa-prefix-api:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			// a literal prefix may be empty
			option:     WithPrefixLiterals,
			prefix:     "",
			capability: "/test:all",
			target:     "/test",
			approved:   true,
		}, {
			// a selected capability still needs a url pattern and a method
			option:     WithPrefixLiterals,
			prefix:     "webpa-prefix-api:",
			capability: "webpa-prefix-api:/test",
			target:     "/test",
			approved:   false,
		}, {
			// a literal prefix must appear in full
			option:     WithPrefixLiterals,
			prefix:     "webpa-prefix-api:",
			capability: "xmidt-prefix-api:/test:all",
			target:     "/test",
			approved:   false,
		}, {
			// regex metacharacters are taken as written
			option:     WithPrefixLiterals,
			prefix:     "foo-bar|",
			capability: "foo-bar|/test:all",
			target:     "/test",
			approved:   true,
		}, {
			// ... so a trailing '|' is not an empty alternative that matches everything
			option:     WithPrefixLiterals,
			prefix:     "foo-bar|",
			capability: "/test:all",
			target:     "/test",
			approved:   false,
		}, {
			// ... a '.' is not a wildcard
			option:     WithPrefixLiterals,
			prefix:     "webpa.prefix:",
			capability: "webpaXprefix:/test:all",
			target:     "/test",
			approved:   false,
		}, {
			// ... and what would not compile as a regex is a fine literal
			option:     WithPrefixLiterals,
			prefix:     "(a",
			capability: "(a/test:all",
			target:     "/test",
			approved:   true,
		},

		// regex prefixes
		{
			option:     WithPrefixRegexes,
			prefix:     "webpa-prefix-api:",
			capability: "webpa-prefix-api:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			// every alternative of a prefix is anchored, not just the first
			option:     WithPrefixRegexes,
			prefix:     "webpa-prefix-a:|webpa-prefix-b:",
			capability: "webpa-prefix-a:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			option:     WithPrefixRegexes,
			prefix:     "webpa-prefix-a:|webpa-prefix-b:",
			capability: "webpa-prefix-b:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			option:     WithPrefixRegexes,
			prefix:     "webpa-prefix-a:|webpa-prefix-b:",
			capability: "webpa-prefix-c:/test:all",
			target:     "/test",
			approved:   false,
		}, {
			// a prefix may contain subexpressions of its own
			option:     WithPrefixRegexes,
			prefix:     "webpa-prefix-(a|b):",
			capability: "webpa-prefix-a:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			option:     WithPrefixRegexes,
			prefix:     "webpa-prefix-(a|b):",
			capability: "webpa-prefix-b:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			option:     WithPrefixRegexes,
			prefix:     "webpa-prefix-(a|b):",
			capability: "webpa-prefix-c:/test:all",
			target:     "/test",
			approved:   false,
		}, {
			// nested and repeated subexpressions do not disturb the url and method
			option:     WithPrefixRegexes,
			prefix:     "(a)(b)((c)):",
			capability: "abc:/test:all",
			target:     "/test",
			approved:   true,
		}, {
			// a regex prefix may be empty
			option:     WithPrefixRegexes,
			prefix:     "",
			capability: "/test:all",
			target:     "/test",
			approved:   true,
		}, {
			// a trailing '|' is an empty alternative, which selects everything
			option:     WithPrefixRegexes,
			prefix:     "foo-bar|",
			capability: "/test:all",
			target:     "/test",
			approved:   true,
		},

		// the deprecated option reads its prefixes as regexes
		{
			option:     WithPrefixes,
			prefix:     "webpa-prefix-(a|b):",
			capability: "webpa-prefix-b:/test:all",
			target:     "/test",
			approved:   true,
		},
	}

	for _, testCase := range testCases {
		suite.Run(fmt.Sprintf("'%s' + '%s' -> %t", testCase.prefix, testCase.capability, testCase.approved), func() {
			ca, err := NewApprover(testCase.option(testCase.prefix))
			suite.Require().NoError(err)

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

// testApproveURLNormalizeFunc covers the option itself: that it is consulted,
// that it cannot alter the request, and how it fails.
func (suite *ApproverTestSuite) testApproveURLNormalizeFunc() {
	const capability = "webpa-prefix-api:test/.*:put"

	suite.Run("Normalized", func() {
		request := suite.newRequest("PUT", "/api/v2/test/foo")
		ca := suite.newApprover(
			WithPrefixLiterals("webpa-prefix-api:"),
			WithURLNormalizeFunc(stripAPIVersion),
		)

		suite.Require().NoError(ca.Approve(context.Background(), request, suite.newToken(capability)))

		suite.Equal("/api/v2/test/foo", request.URL.Path,
			"the request's own URL must not have been modified")
	})

	suite.Run("WithoutTheOption", func() {
		ca := suite.newApprover(WithPrefixLiterals("webpa-prefix-api:"))

		suite.ErrorIs(
			ca.Approve(context.Background(),
				suite.newRequest("PUT", "/api/v2/test/foo"),
				suite.newToken(capability)),
			bascule.ErrUnauthorized,
			"without normalization the version is part of the path")
	})

	suite.Run("Nil", func() {
		_, err := NewApprover(WithPrefixLiterals("webpa-prefix-api:"), WithURLNormalizeFunc(nil))
		suite.Error(err)
	})
}

func (suite *ApproverTestSuite) TestApprove() {
	suite.Run("MissingCapabilities", suite.testApproveMissingCapabilities)
	suite.Run("Success", suite.testApproveSuccess)
	suite.Run("Unauthorized", suite.testApproveUnauthorized)
	suite.Run("CapabilityURL", suite.testApproveCapabilityURL)
	suite.Run("ConfiguredPrefix", suite.testApproveConfiguredPrefix)
	suite.Run("URLNormalizeFunc", suite.testApproveURLNormalizeFunc)
}

func TestApprover(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(ApproverTestSuite))
}

func TestSplitCapability(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rest   string
		url    string
		method string
		ok     bool
	}{
		{rest: "/test:all", url: "/test", method: "all", ok: true},
		{rest: "/test:get", url: "/test", method: "get", ok: true},
		// the url pattern may contain colons; the split is at the last one
		{rest: "/a:b/c:get", url: "/a:b/c", method: "get", ok: true},
		// a trailing colon belongs to the method, which is never empty
		{rest: "/test:get:", url: "/test", method: "get:", ok: true},
		{rest: ""},
		{rest: ":"},
		{rest: "/test"},
		{rest: "/test:"},
		{rest: ":get"},
	}

	for _, tc := range tests {
		t.Run(tc.rest, func(t *testing.T) {
			t.Parallel()
			url, method, ok := splitCapability(tc.rest)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.url, url)
			assert.Equal(t, tc.method, method)
		})
	}
}
