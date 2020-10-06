package bascule

import (
	"time"

	"github.com/xmidt-org/arrange"
)

var nilTime = time.Time{}

type BasicAttributes map[string]interface{}

func (a BasicAttributes) Get(key string) (interface{}, bool) {
	v, ok := a[key]
	return v, ok
}

//NewAttributes builds an Attributes instance with
//the given map as datasource.
func NewAttributes(m map[string]interface{}) Attributes {
	return BasicAttributes(m)
}

// GetNestedAttribute uses multiple keys in order to obtain an attribute.
func GetNestedAttribute(attributes Attributes, keys ...string) (interface{}, bool) {
	// need at least one key.
	if keys == nil || len(keys) == 0 {
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
		ok = arrange.TryConvert(result,
			func(attr Attributes) { a = attr },
			func(m map[string]interface{}) { a = BasicAttributes(m) },
		)
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
