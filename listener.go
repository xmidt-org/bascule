// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// Listener is a sink for bascule events.
type Listener[E any] interface {
	// OnEvent receives a bascule event.  This method must not block or panic.
	OnEvent(E)
}

// ListenerFunc is a closure that can act as a Listener.
type ListenerFunc[E any] func(E)

// OnEvent satisfies the Listener interface.
func (lf ListenerFunc[E]) OnEvent(e E) { lf(e) }

// Listeners is an aggregate Listener.
type Listeners[E any] []Listener[E]

// Append adds more listeners to this aggregate.  The (possibly new)
// aggregate Listeners is returned.  This method has the same
// semantics as the built-in append.
func (ls Listeners[E]) Append(more ...Listener[E]) Listeners[E] {
	return append(ls, more...)
}

// AppendFunc is a more convenient version of Append when using
// closures as listeners.
func (ls Listeners[E]) AppendFunc(more ...ListenerFunc[E]) Listeners[E] {
	for _, lf := range more {
		if lf != nil { // handle the nil interface case
			ls = ls.Append(lf)
		}
	}

	return ls
}

// OnEvent dispatches the given event to all listeners
// contained by this aggregate.
func (ls Listeners[E]) OnEvent(e E) {
	for _, l := range ls {
		l.OnEvent(e)
	}
}
