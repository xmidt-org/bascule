package key

import (
	"context"
	"time"
)

// UpdateOptions cleans up the signature of WithUpdate.  When you have a lot of function
// parameters, it starts getting hard to read.
type UpdateOptions struct {
	// Ctx is the required context.  If the caller doesn't have a context, she should
	// use context.Background() here explicitly.  Not permitting nil here is a common pattern,
	// and makes client code self-documenting.
	Ctx context.Context

	// Resolver is the required key resolver that optionally implements Cache.  If this member
	// does not implement cache, no updating is done.
	Resolver Resolver

	// OpTimeout is the amount of time to wait before timing out an UpdateKeys() operation.  If
	// this is 0, then there is no timeout.
	OpTimeout time.Duration

	// Interval is the options time interval for updating.  If unset, no update should occur.
	// This allows client code to turn off updates via configuration without having to do a lot
	// of branching.
	Interval time.Duration

	// NewTicker is the factory function for a ticker.  If nil, the default is used.
	// Injecting a closure here makes testing easier, as unit tests can simply supply
	// their own factory function.
	NewTicker func(time.Duration) (<-chan time.Time, func())
}

func defaultNewTicker(i time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(i)
	return t.C, t.Stop
}

// noop is just that ... a no-op.  Using a declared function instead of a closure is a bit
// easier on the garbage collector.
func noop() {
}

// update is the goroutine that updates the cache.  Pulling this function out allows intermediate objects
// inside WithUpdate to be cleaned up, since it's not a closure.
func update(ctx context.Context, cache Cache, updateKeysTimeout time.Duration, updateInterval time.Duration, newTicker func(time.Duration) (<-chan time.Time, func())) {
	var (
		updateKeysCtx context.Context
		cancel        context.CancelFunc
	)
	t, stop := newTicker(updateInterval)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t:
			if updateKeysTimeout < 1 {
				updateKeysCtx, cancel = context.WithCancel(ctx)
			} else {
				updateKeysCtx, cancel = context.WithTimeout(ctx, updateKeysTimeout)
			}
			_, errs := cache.UpdateKeys(updateKeysCtx)
			if len(errs) != 0 {
				// todo: log errors
			}
			cancel()
		}
	}
}

// WithUpdate (conditionally) spawns a goroutine and returns the child context and cancelation the
// updater runs within.  This also follows the pattern of context.WithCancel, context.WithTimeout, etc.
func WithUpdate(o UpdateOptions) (context.Context, func()) {
	if o.Interval < 1 {
		return o.Ctx, noop
	}

	cache, ok := o.Resolver.(Cache)
	if !ok {
		// if resolver isn't a cache, just return no-op
		// this allows client code to avoid caring about whether a resolver is actually a cache
		return o.Ctx, noop
	}

	var (
		updateCtx, cancel = context.WithCancel(o.Ctx)
		newTicker         = o.NewTicker
	)

	if newTicker == nil {
		newTicker = defaultNewTicker
	}

	go update(updateCtx, cache, o.OpTimeout, o.Interval, newTicker)

	// returning the child context allows further child contexts to be created, e.g. if the caller has
	// goroutines that should end if the updater ends.  it also is more flexible, since if downstream code
	// just wants a <-chan struct{} the caller can use updateCtx.Done().
	return updateCtx, cancel
}
