// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"regexp"
	"sync"
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
// the cache must not be allowed to grow without limit.  Once full, the entry
// added longest ago is evicted.
//
// The hit path takes only a read lock, so requests that find their pattern
// already compiled do not contend with one another.  That is what a deployment
// does almost all of the time: the set of capability patterns in use is small
// and stable, and eviction is reached only when something is presenting an
// unusual variety of them.
//
// A urlCache is safe for concurrent use.
type urlCache struct {
	lock sync.RWMutex

	// maxSize is the largest number of entries retained.  It is always positive.
	maxSize int

	entries map[string]urlCacheEntry

	// added holds the keys of entries in the order they were added, oldest
	// first.  It is only touched when an entry is added.
	added []string
}

func newURLCache(maxSize int) *urlCache {
	return &urlCache{
		maxSize: maxSize,
		entries: make(map[string]urlCacheEntry, maxSize),
		added:   make([]string, 0, maxSize),
	}
}

// compile returns the anchored regular expression for a capability's url
// pattern, compiling it only if it is not already cached.
func (c *urlCache) compile(pattern string) (*regexp.Regexp, error) {
	c.lock.RLock()
	entry, ok := c.entries[pattern]
	c.lock.RUnlock()

	if ok {
		return entry.regex, entry.err
	}

	// Compiled outside the lock.  Two goroutines may compile the same pattern
	// concurrently, which wastes a little work but is otherwise harmless.
	regex, err := regexp.Compile("^(?:" + pattern + ")")

	return c.add(pattern, urlCacheEntry{regex: regex, err: err})
}

// add stores an entry, evicting the oldest entries as needed.  If another
// goroutine stored this pattern first, that entry is returned instead.
func (c *urlCache) add(pattern string, entry urlCacheEntry) (*regexp.Regexp, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if existing, ok := c.entries[pattern]; ok {
		return existing.regex, existing.err
	}

	c.entries[pattern] = entry
	c.added = append(c.added, pattern)

	for len(c.added) > c.maxSize {
		delete(c.entries, c.added[0])
		c.added = c.added[1:]
	}

	return entry.regex, entry.err
}

// len returns the number of cached entries.  Used by tests.
func (c *urlCache) len() int {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return len(c.entries)
}
