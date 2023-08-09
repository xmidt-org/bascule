// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

type BasicAttributes map[string]interface{}

func (a BasicAttributes) Get(key string) (interface{}, bool) {
	v, ok := a[key]
	return v, ok
}

// NewAttributes builds an Attributes instance with
// the given map as datasource.
func NewAttributes(m map[string]interface{}) Attributes {
	return BasicAttributes(m)
}

// GetNestedAttribute uses multiple keys in order to obtain an attribute.
func GetNestedAttribute(attributes Attributes, keys ...string) (interface{}, bool) {
	// need at least one key.
	if len(keys) == 0 {
		return nil, false
	}

	var (
		result interface{}
		ok     bool
	)
	result = attributes
	for _, k := range keys {
		var a Attributes
		if result == nil {
			return nil, false
		}

		switch t := result.(type) {
		case map[string]interface{}:
			a = BasicAttributes(t)
		case Attributes:
			a = result.(Attributes)
		default:
			return nil, false
		}

		result, ok = a.Get(k)
		if !ok {
			return nil, false
		}
	}
	return result, ok
}
