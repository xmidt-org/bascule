package key

import (
	"context"
	"sync"
	"sync/atomic"
)

const (
	// dummyKeyId is used when no actual keyID is necessary.
	dummyKeyId = ""
)

// Cache is a Resolver type which provides caching for keys based on keyID.
//
// All implementations will block the first time a particular key is accessed
// and will initialize the value for that key.  Thereafter, all updates happen
// in a separate goroutine.  This allows HTTP transactions to avoid paying
// the cost of loading a key after the initial fetch.
type Cache interface {
	Resolver

	// UpdateKeys updates all keys known to this cache.  This method makes
	// a best-effort to avoid blocking other goroutines which use ResolveKey,
	// which may mean copy-on-write semantics.
	//
	// The first return value is the count of keys for which attempts were
	// made to update.
	//
	// UpdateKeys may run multiple I/O operations.  The second return value is a slice of
	// errors that occurred while it attempted to update each key.  Exactly one (1)
	// attempt will be made to update each key present in the cache, regardless
	// of any update errors for each individual key.  This slice may be nil if no
	// errors occurred.
	UpdateKeys(ctx context.Context) (int, []error)
}

// basicCache contains the internal members common to all cache implementations
type basicCache struct {
	delegate   Resolver
	value      atomic.Value
	updateLock sync.Mutex
}

func (b *basicCache) load() interface{} {
	return b.value.Load()
}

func (b *basicCache) store(newValue interface{}) {
	b.value.Store(newValue)
}

// update provides a critical section for an update operation
func (b *basicCache) update(operation func()) {
	b.updateLock.Lock()
	defer b.updateLock.Unlock()
	operation()
}

// singleCache assumes that the delegate Resolver
// only returns (1) key.
type singleCache struct {
	basicCache
}

func (cache *singleCache) ResolveKey(ctx context.Context, keyID string) (pair Pair, err error) {
	var ok bool
	pair, ok = cache.load().(Pair)
	if !ok {
		cache.update(func() {
			pair, ok = cache.load().(Pair)
			if ctx.Err() != nil {
				err = ctx.Err()
				return
			}
			if !ok {
				pair, err = cache.delegate.ResolveKey(ctx, keyID)
				if err == nil {
					cache.store(pair)
				}
			}
		})
	}

	return
}

func (cache *singleCache) UpdateKeys(ctx context.Context) (count int, errors []error) {
	count = 1
	cache.update(func() {
		// this type of cache is specifically for resolvers which don't use the keyID,
		// so just pass an empty string in
		pair, err := cache.delegate.ResolveKey(ctx, dummyKeyId)

		if err == nil {
			cache.store(pair)
		} else {
			errors = []error{err}
		}
	})

	return
}

// multiCache uses an atomic map reference to store keys.
// Once created, each internal map instance will never be written
// to again, thus removing the need to lock for reads.  This approach
// does consume more memory, however.  The updateLock ensures that only
// (1) goroutine will ever be updating the map at anytime.
type multiCache struct {
	basicCache
}

// fetchPair uses the atomic reference to the keys map and attempts
// to fetch the key from the cache.
func (cache *multiCache) fetchPair(keyID string) (pair Pair, ok bool) {
	pairs, ok := cache.load().(map[string]Pair)
	if ok {
		pair, ok = pairs[keyID]
	}

	return
}

// copyPairs creates a copy of the current key cache.  If no keys are present
// yet, this method returns a non-nil empty map.
func (cache *multiCache) copyPairs() map[string]Pair {
	pairs, _ := cache.load().(map[string]Pair)

	// make the capacity 1 larger, since this method is almost always
	// going to be invoked prior to doing a copy-on-write update.
	newPairs := make(map[string]Pair, len(pairs)+1)

	for keyID, pair := range pairs {
		newPairs[keyID] = pair
	}

	return newPairs
}

func (cache *multiCache) ResolveKey(ctx context.Context, keyID string) (pair Pair, err error) {
	var ok bool
	pair, ok = cache.fetchPair(keyID)
	if !ok {
		cache.update(func() {
			pair, ok = cache.fetchPair(keyID)
			if ctx.Err() != nil {
				err = ctx.Err()
				return
			}

			if !ok {
				pair, err = cache.delegate.ResolveKey(ctx, keyID)

				if err == nil {
					newPairs := cache.copyPairs()
					newPairs[keyID] = pair
					cache.store(newPairs)
				}
			}
		})
	}

	return
}

func (cache *multiCache) UpdateKeys(ctx context.Context) (count int, errors []error) {
	if existingPairs, ok := cache.load().(map[string]Pair); ok {
		count = len(existingPairs)
		cache.update(func() {
			newCount := 0
			newPairs := make(map[string]Pair, len(existingPairs))
			for keyID, oldPair := range existingPairs {
				if ctx.Err() != nil {
					errors = append(errors, ctx.Err())
					return
				}
				newPair, err := cache.delegate.ResolveKey(ctx, keyID)
				if err == nil {
					newCount++
					newPairs[keyID] = newPair
				} else {
					// keep the old key in the event of an error
					newPairs[keyID] = oldPair
					errors = append(errors, err)
				}
			}

			// small optimization: don't bother doing the atomic swap
			// if every key operation failed
			if newCount > 0 {
				cache.store(newPairs)
			}
		})
	}

	return
}
