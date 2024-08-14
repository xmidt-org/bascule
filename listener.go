// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// Listener is a consumer of bascule events.
type Listener[E any] interface {
	// OnEvent accepts an event from the bascule workflow.
	// This method must not block or panic.
	OnEvent(E)
}

// ListenerFunc is a closure that can act as a Listener.
type ListenerFunc[E any] func(E)

func (lf ListenerFunc[E]) OnEvent(event E) { lf(event) }

// Listeners is an aggregate bascule Listener that dispatches
// events to each of its component listeners in order.
type Listeners[E any] []Listener[E]

// Append adds several listeners to this aggregate.  The semantics of
// this method are the same as the built-in append.
func (ls Listeners[E]) Append(more ...Listener[E]) Listeners[E] {
	return append(ls, more...)
}

// AppendFunc is like Append, but is more convenient when closures
// are being used as listeners.
func (ls Listeners[E]) AppendFunc(more ...ListenerFunc[E]) Listeners[E] {
	for _, m := range more {
		ls = append(ls, m)
	}

	return ls
}

// OnEvent dispatches the given event to each listener contained
// by this collection.
func (ls Listeners[E]) OnEvent(event E) {
	for _, l := range ls {
		l.OnEvent(event)
	}
}
