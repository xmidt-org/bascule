// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// AttributesAccessor is an optional interface that a Token may implement
// that provides access to arbitrary key/value pairs.
type AttributesAccessor interface {
	// Get returns the value of an attribute, if it exists.
	Get(key string) (any, bool)
}

// GetAttribute provides a typesafe way of obtaining attribute values.
// This function will return false if either the attribute doesn't exist
// or if the attribute's value of not of type T.
//
// Multiple keys may be passed to this function, in which case the keys will
// be traversed to find the nested key.  If any intervening keys are not of
// type map[string]any or Attributes, this function will return false.
//
// If no keys are supplied, this function returns the zero value for T and false.
func GetAttribute[T any](a AttributesAccessor, keys ...string) (v T, ok bool) {
	if len(keys) == 0 {
		return
	}

	var raw any
	raw, ok = a.Get(keys[0])
	for i := 1; ok && i < len(keys); i++ {
		var m map[string]any
		if m, ok = raw.(map[string]any); ok {
			raw, ok = m[keys[i]]
			continue
		}

		var a AttributesAccessor
		if a, ok = raw.(AttributesAccessor); ok {
			raw, ok = a.Get(keys[i])
		}
	}

	if ok {
		v, ok = raw.(T)
	}

	return
}
