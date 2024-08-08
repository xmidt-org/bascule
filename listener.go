// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

//go:generate stringer -type=EventType -trimprefix=EventType -output=eventType_string.go

// EventType describes the kind of event bascule has dispatched.
type EventType int

const (
	// EventTypeSuccess represents a completely successful authorization.
	// The event's Token field will be set to resulting token.
	EventTypeSuccess EventType = iota

	// EventTypeMissingCredentials represents a source that missing any
	// kind of credentials that are recognizable to the way bascule
	// has been configured.
	EventTypeMissingCredentials

	// EventTypeInvalidCredentials indicates that credentials were present
	// in the source, but were unparseable.
	EventTypeInvalidCredentials

	// EventTypeFailedAuthentication indicates that valid, parseable credentials
	// were present in the source, but the token failed authentication.
	//
	// The Token field will be set in the Event.
	EventTypeFailedAuthentication

	// EventTypeFailedAuthorization indicates that valid, parseable credentials
	// were present in the source and that the resulting token was authentic.
	// However, the token did not have access to the resource(s) being requested.
	//
	// The Token field will be set in the Event.
	EventTypeFailedAuthorization
)

// Event holds information about the result of a attempting to obtain a token.
type Event[S any] struct {
	// Type is the kind of event.  This field is always set.
	Type EventType

	// Source is the source of credentials.  This field is always set.
	Source S

	// Token is the parsed token from the source.  This field will always be set
	// if the token successfully parsed, even if it wasn't authentic or authorized.
	Token Token

	// Err is any error that occurred from the bascule infrastructure.  This will
	// always be nil for a successful Event.  This field MAY BE set if the
	// configured infrastructure gave more information about why the attempt to
	// get a token failed.
	Err error
}

// Success is a convenience for checking if the event's Type field represents
// a successful token. Using this method ensures that client code will work
// in future versions.
func (e Event[S]) Success() bool {
	return e.Type == EventTypeSuccess
}

// Listener is a sink for bascule events.
type Listener[S any] interface {
	// OnEvent receives a bascule event.  This method must not block or panic.
	OnEvent(Event[S])
}

// ListenerFunc is a closure that can act as a Listener.
type ListenerFunc[S any] func(Event[S])

// OnEvent satisfies the Listener interface.
func (lf ListenerFunc[S]) OnEvent(e Event[S]) { lf(e) }

// Listeners is an aggregate Listener.
type Listeners[S any] []Listener[S]

// Append adds more listeners to this aggregate.  The (possibly new)
// aggregate Listeners is returned.  This method has the same
// semantics as the built-in append.
func (ls Listeners[S]) Append(more ...Listener[S]) Listeners[S] {
	return append(ls, more...)
}

// AppendFunc is a more convenient version of Append when using
// closures as listeners.
func (ls Listeners[S]) AppendFunc(more ...ListenerFunc[S]) Listeners[S] {
	for _, lf := range more {
		if lf != nil { // handle the nil interface case
			ls = ls.Append(lf)
		}
	}

	return ls
}

// OnEvent dispatches the given event to all listeners
// contained by this aggregate.
func (ls Listeners[S]) OnEvent(e Event[S]) {
	for _, l := range ls {
		l.OnEvent(e)
	}
}

// filteredListener is the internal type returned by FilterEvents.
type filteredListener[S any] struct {
	next  Listener[S]
	types map[EventType]bool
}

func (fl filteredListener[S]) OnEvent(e Event[S]) {
	if fl.types[e.Type] {
		fl.next.OnEvent(e)
	}
}

// FilterEvents decorates a given Listener so that it only receives events of
// certain types.  The decorated Listener is returned.  This method simplifies
// client code by removing the need for if/else or switch/case blocks to check
// the event's Type field in certain situations.
//
// If types is empty, the Listener is returned as is.
func FilterEvents[S any](l Listener[S], types ...EventType) Listener[S] {
	if len(types) == 0 {
		return l
	}

	fl := filteredListener[S]{
		next:  l,
		types: make(map[EventType]bool, len(types)),
	}

	for _, t := range types {
		fl.types[t] = true
	}

	return fl
}
