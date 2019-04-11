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

func NewDefaultLogger() Logger {
	return defaultLogger
}

func GetDefaultLoggerFunc(ctx context.Context) Logger {
	return NewDefaultLogger()
}
