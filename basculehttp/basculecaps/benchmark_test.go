// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"context"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
)

// benchPattern is a capability url pattern of the shape a deployment actually
// uses: a couple of character classes and a wildcard tail.
const benchPattern = "/device/[0-9a-f]+/config/.*"

// benchPatterns returns n distinct patterns, standing in for the set of
// capabilities a fleet of tokens presents.
func benchPatterns(n int) []string {
	patterns := make([]string, n)
	for i := range patterns {
		patterns[i] = benchPattern + strconv.Itoa(i)
	}

	return patterns
}

// BenchmarkCompileUncached is the cost the cache exists to avoid: compiling a
// capability's pattern on every request.
func BenchmarkCompileUncached(b *testing.B) {
	for b.Loop() {
		regexp.MustCompile("^(?:" + benchPattern + ")")
	}
}

// BenchmarkCacheHit is the cost when the pattern has been seen before, which is
// what a deployment does almost all of the time.
func BenchmarkCacheHit(b *testing.B) {
	c := newURLCache(DefaultCacheSize)
	c.compile(benchPattern)

	b.ResetTimer()
	for b.Loop() {
		c.compile(benchPattern)
	}
}

// BenchmarkCacheHitParallel measures the same hit path under contention.  The
// hit path takes only a read lock, so this is the number that would regress if
// it ever started mutating on read.
func BenchmarkCacheHitParallel(b *testing.B) {
	const distinct = 64

	c := newURLCache(DefaultCacheSize)
	patterns := benchPatterns(distinct)
	for _, p := range patterns {
		c.compile(p)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i int
		for pb.Next() {
			c.compile(patterns[i%distinct])
			i++
		}
	})
}

// BenchmarkCacheMiss measures a full cache taking a pattern it has never seen,
// which is compile plus insert plus an eviction.  This is also the cost a token
// presenting endlessly varied patterns imposes.
func BenchmarkCacheMiss(b *testing.B) {
	c := newURLCache(DefaultCacheSize)
	for _, p := range benchPatterns(DefaultCacheSize) {
		c.compile(p)
	}

	b.ResetTimer()
	var i int
	for b.Loop() {
		c.compile(benchPattern + "miss" + strconv.Itoa(i))
		i++
	}
}

// BenchmarkApprove measures an entire authorization, so that the cache can be
// kept in proportion to what surrounds it.
func BenchmarkApprove(b *testing.B) {
	a, err := NewApprover(WithPrefixes("x1:webpa:api:"))
	if err != nil {
		b.Fatal(err)
	}

	var (
		token = &testToken{
			principal:    "benchmark",
			capabilities: []string{"x1:webpa:api:" + benchPattern + ":all"},
		}

		request = httptest.NewRequest("GET", "/device/deadbeef/config/wifi", nil)
		ctx     = context.Background()
	)

	b.ResetTimer()
	for b.Loop() {
		if err := a.Approve(ctx, request, token); err != nil {
			b.Fatal(err)
		}
	}
}
