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
	"context"

	"github.com/go-kit/kit/log"
)

var (
	defaultLogger = log.NewNopLogger()

	ErrorKey interface{} = "error"
)

// logger we expect for the decorators
type Logger interface {
	Log(keyvals ...interface{}) error
}

// NewDefaultLogger returns the default logger, which doesn't do anything.
func NewDefaultLogger() Logger {
	return defaultLogger
}

// GetDefaultLoggerFunc a function that returns the default logger, which
// doesn't do anything
func GetDefaultLoggerFunc(ctx context.Context) Logger {
	return NewDefaultLogger()
}
