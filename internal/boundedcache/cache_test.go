// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package boundedcache

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewInvalidSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		assert.Panics(t, func() { New[int](size) })
	}
}

func TestGetAdd(t *testing.T) {
	c := New[int](4)

	_, ok := c.Get("a")
	assert.False(t, ok)

	assert.Equal(t, 1, c.Add("a", 1))
	v, ok := c.Get("a")
	assert.True(t, ok)
	assert.Equal(t, 1, v)

	// the first value stored wins
	assert.Equal(t, 1, c.Add("a", 2))
	v, _ = c.Get("a")
	assert.Equal(t, 1, v)
	assert.Equal(t, 1, c.Len())
}

func TestBounded(t *testing.T) {
	const maxSize = 4
	c := New[int](maxSize)

	for i := range 100 {
		c.Add(strconv.Itoa(i), i)
		assert.LessOrEqual(t, c.Len(), maxSize)
	}

	assert.Equal(t, maxSize, c.Len())
}

// TestEvictsOldest verifies that once full, the entry added longest ago is the
// one dropped, even if it was read recently.
func TestEvictsOldest(t *testing.T) {
	c := New[string](2)
	c.Add("first", "1")
	c.Add("second", "2")

	// reading first does not protect it
	_, ok := c.Get("first")
	assert.True(t, ok)

	c.Add("third", "3")
	assert.Equal(t, 2, c.Len())

	_, ok = c.Get("first")
	assert.False(t, ok)

	_, ok = c.Get("second")
	assert.True(t, ok)

	_, ok = c.Get("third")
	assert.True(t, ok)
}

// TestConcurrent exercises the cache from several goroutines.  Run with -race.
func TestConcurrent(t *testing.T) {
	const (
		workers = 8
		rounds  = 200
	)

	c := New[int](16)

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range rounds {
				key := strconv.Itoa(i % 32)
				if _, ok := c.Get(key); !ok {
					c.Add(key, i)
				}
			}
		})
	}

	wg.Wait()
	assert.LessOrEqual(t, c.Len(), 16)
}
