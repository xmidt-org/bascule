/**
 * Copyright 2021 Comcast Cable Communications Management, LLC
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

package basculechecks

// Reasoner is an error that provides a failure reason to use as a value for a
// metric label.
type Reasoner interface {
	Reason() string
}

type errWithReason struct {
	err    error
	reason string
}

// Error returns the error string.
func (e errWithReason) Error() string {
	return e.err.Error()
}

// Reason returns the reason string for the error.  This is intended to be used
// in a metric label.
func (e errWithReason) Reason() string {
	return e.reason
}

// Unwrap returns the error stored.
func (e errWithReason) Unwrap() error {
	return e.err
}
