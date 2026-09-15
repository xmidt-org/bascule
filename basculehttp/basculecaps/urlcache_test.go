// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule"
)

type URLCacheTestSuite struct {
	suite.Suite
}

// TestCompiled verifies that a pattern is compiled correctly and that the
// anchoring applied by the cache is what approveURL relies on.
func (suite *URLCacheTestSuite) TestCompiled() {
	c := newURLCache(DefaultCacheSize)

	re, err := c.compile("test|dir")
	suite.Require().NoError(err)
	suite.Equal("^(?:test|dir)", re.String())
}

// TestReuse verifies that a repeated pattern is not recompiled.
func (suite *URLCacheTestSuite) TestReuse() {
	c := newURLCache(DefaultCacheSize)

	first, err := c.compile("/device/.*/config")
	suite.Require().NoError(err)

	second, err := c.compile("/device/.*/config")
	suite.Require().NoError(err)

	suite.Same(first, second, "the same compiled regexp should be returned")
	suite.Equal(1, c.len())
}

// TestBounded verifies that the cache never exceeds its size, and that the
// least recently used entry is the one evicted.
func (suite *URLCacheTestSuite) TestBounded() {
	const maxSize = 4
	c := newURLCache(maxSize)

	for i := 0; i < 100; i++ {
		_, err := c.compile("/path/" + strconv.Itoa(i))
		suite.Require().NoError(err)
		suite.LessOrEqual(c.len(), maxSize)
	}

	suite.Equal(maxSize, c.len())
}

// TestEvictsOldest verifies that once full, the entry added longest ago is the
// one dropped.  Reading an entry does not make it any safer; the hit path takes
// only a read lock and deliberately does not reorder.
func (suite *URLCacheTestSuite) TestEvictsOldest() {
	c := newURLCache(2)

	first, err := c.compile("/first")
	suite.Require().NoError(err)
	_, err = c.compile("/second")
	suite.Require().NoError(err)

	// reading /first does not protect it
	again, err := c.compile("/first")
	suite.Require().NoError(err)
	suite.Same(first, again)

	_, err = c.compile("/third")
	suite.Require().NoError(err)

	suite.Equal(2, c.len())

	// /first was added longest ago, so it is the one that went
	replaced, err := c.compile("/first")
	suite.Require().NoError(err)
	suite.NotSame(first, replaced, "/first should have been evicted and recompiled")
}

// TestCachesFailures verifies that a pattern which cannot compile is retained,
// so that a malformed capability does not recompile on every request.
func (suite *URLCacheTestSuite) TestCachesFailures() {
	c := newURLCache(DefaultCacheSize)

	re, err := c.compile("(?!foo)")
	suite.Error(err)
	suite.Nil(re)
	suite.Equal(1, c.len())

	re, err = c.compile("(?!foo)")
	suite.Error(err)
	suite.Nil(re)
	suite.Equal(1, c.len())
}

// TestConcurrent exercises the cache from several goroutines.  Run with -race.
func (suite *URLCacheTestSuite) TestConcurrent() {
	const (
		workers = 8
		rounds  = 200
	)

	c := newURLCache(16)

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if _, err := c.compile("/path/" + strconv.Itoa(i%32)); err != nil {
					suite.NoError(err)
				}
			}
		}(w)
	}

	wg.Wait()
	suite.LessOrEqual(c.len(), 16)
}

func TestURLCache(t *testing.T) {
	suite.Run(t, new(URLCacheTestSuite))
}

// TestApproverURLCacheSize covers the option and its validation.
func TestApproverURLCacheSize(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		for _, size := range []int{0, -1} {
			if _, err := NewApprover(WithPrefixes("x1:webpa:"), WithCacheSize(size)); err == nil {
				t.Errorf("expected an error for size %d", size)
			}
		}
	})

	t.Run("bounded", func(t *testing.T) {
		a, err := NewApprover(WithPrefixes("x1:webpa:"), WithCacheSize(2))
		if err != nil {
			t.Fatal(err)
		}

		// approve against several distinct capability urls
		for i := 0; i < 10; i++ {
			path := "/path/" + strconv.Itoa(i)
			_ = a.Approve(context.Background(),
				(&ApproverTestSuite{}).newRequest("GET", path),
				&testToken{principal: "t", capabilities: []string{"x1:webpa:" + path + ":all"}})
		}

		if got := a.urlCache.len(); got > 2 {
			t.Errorf("cache grew to %d, want <= 2", got)
		}
	})
}

var _ bascule.Token = (*testToken)(nil)
