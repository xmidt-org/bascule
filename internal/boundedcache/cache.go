// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package boundedcache provides a size-limited cache for values derived from
// token contents, which are not under the caller's control and so must not be
// allowed to grow a cache without limit.
package boundedcache

import "sync"

// Cache is a bounded cache of values keyed by string.  Once full, the entry
// added longest ago is evicted.
//
// The hit path takes only a read lock, so lookups that find their entry do not
// contend with one another.  That is what a deployment does almost all of the
// time: the set of keys in use is small and stable, and eviction is reached
// only when something is presenting an unusual variety of them.  Reading an
// entry does not protect it from eviction.
//
// A Cache is safe for concurrent use.
type Cache[V any] struct {
	lock sync.RWMutex

	// maxSize is the largest number of entries retained.  It is always positive.
	maxSize int

	entries map[string]V

	// added holds the keys of entries in the order they were added, oldest
	// first.  It is only touched when an entry is added.
	added []string
}

// New creates a Cache that retains at most maxSize entries.  It panics if
// maxSize is not positive; callers validate the size when it is configured.
func New[V any](maxSize int) *Cache[V] {
	if maxSize < 1 {
		panic("boundedcache: maxSize must be positive")
	}

	return &Cache[V]{
		maxSize: maxSize,
		entries: make(map[string]V, maxSize),
		added:   make([]string, 0, maxSize),
	}
}

// Get returns the value stored for key, if any.
func (c *Cache[V]) Get(key string) (v V, ok bool) {
	c.lock.RLock()
	v, ok = c.entries[key]
	c.lock.RUnlock()
	return
}

// Add stores a value, evicting the oldest entries as needed, and returns the
// value now cached for key.  If another goroutine stored key first, that value
// is kept and returned instead, so concurrent callers agree on one value.
func (c *Cache[V]) Add(key string, v V) V {
	c.lock.Lock()
	defer c.lock.Unlock()

	if existing, ok := c.entries[key]; ok {
		return existing
	}

	c.entries[key] = v
	c.added = append(c.added, key)

	for len(c.added) > c.maxSize {
		delete(c.entries, c.added[0])
		c.added = c.added[1:]
	}

	return v
}

// Len returns the number of cached entries.
func (c *Cache[V]) Len() int {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return len(c.entries)
}
