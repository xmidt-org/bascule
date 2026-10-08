// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"regexp"

	"github.com/xmidt-org/bascule/internal/boundedcache"
)

// DefaultCacheSize is the number of compiled capability URL patterns an
// Approver retains by default.
const DefaultCacheSize = 1024

// urlCacheEntry is one compiled capability URL pattern.  A pattern that failed
// to compile is retained as well, so that a malformed capability is not
// recompiled on every request.
type urlCacheEntry struct {
	regex *regexp.Regexp
	err   error
}

// urlCache is a bounded cache of compiled capability URL patterns.  Patterns
// arrive on tokens, so the set of them is not under this package's control and
// the cache must not be allowed to grow without limit.
//
// A urlCache is safe for concurrent use.
type urlCache struct {
	entries *boundedcache.Cache[urlCacheEntry]
}

func newURLCache(maxSize int) *urlCache {
	return &urlCache{
		entries: boundedcache.New[urlCacheEntry](maxSize),
	}
}

// compile returns the anchored regular expression for a capability's url
// pattern, compiling it only if it is not already cached.
func (c *urlCache) compile(pattern string) (*regexp.Regexp, error) {
	if entry, ok := c.entries.Get(pattern); ok {
		return entry.regex, entry.err
	}

	// Compiled outside the lock.  Two goroutines may compile the same pattern
	// concurrently, which wastes a little work but is otherwise harmless.
	regex, err := regexp.Compile("^(?:" + pattern + ")")

	entry := c.entries.Add(pattern, urlCacheEntry{regex: regex, err: err})
	return entry.regex, entry.err
}

// len returns the number of cached entries.  Used by tests.
func (c *urlCache) len() int {
	return c.entries.Len()
}
