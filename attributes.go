/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package bascule

import (
	"github.com/xmidt-org/arrange"
)

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
