package bascule

import (
	"time"
)

var nilTime = time.Time{}

type attributes map[string]interface{}

func (a attributes) Get(key string) (interface{}, bool) {
	v, ok := a[key]
	return v, ok
}

//NewAttributes builds an Attributes instance with
//the given map as datasource. Default AttributeOptions are used.
func NewAttributes(m map[string]interface{}) Attributes {
	return attributes(m)
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
		a, ok := result.(Attributes)
		if !ok {
			return nil, false
		}
		result, ok = a.Get(k)
		if !ok {
			return nil, false
		}
	}
	return result, ok
}
