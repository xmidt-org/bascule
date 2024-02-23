// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// Attributes is an optional interface that a Token may implement
// that provides access to arbitrary key/value pairs.
type Attributes interface {
	// Get returns the value of an attribute, if it exists.
	Get(key string) (any, bool)
}

// GetAttribute provides a typesafe way of obtaining attribute values.
// This function will return false if either the attribute doesn't exist
// or if the attribute's value of not of type T.
//
// If any additional keys are supplied after the first, this function will
// attempt to traverse maps and Attributes to find the nested key.  Traversal
// halts early with a false return if it reaches a value that is not a set
// of attributes.
func GetAttribute[T any](a Attributes, first string, rest ...string) (v T, ok bool) {
	var raw any
	raw, ok = a.Get(first)
	for i := 0; ok && i < len(rest); i++ {
		var m map[string]any
		if m, ok = raw.(map[string]any); ok {
			raw, ok = m[rest[i]]
			continue
		}

		var a Attributes
		if a, ok = raw.(Attributes); ok {
			raw, ok = a.Get(rest[i])
		}
	}

	if ok {
		v, ok = raw.(T)
	}

	return
}
