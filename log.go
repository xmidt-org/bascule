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
