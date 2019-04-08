package basculehttp

import (
	"context"
	"os"

	"github.com/go-kit/kit/log"
)

var (
	defaultLogger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))

	callerKey    interface{} = "caller"
	messageKey   interface{} = "msg"
	errorKey     interface{} = "error"
	timestampKey interface{} = "ts"
)

// logger we expect for the decorators
type Logger interface {
	Log(keyvals ...interface{}) error
}

type DefaultLogger struct {
	log.Logger
}

func NewDefaultLogger() Logger {
	return DefaultLogger{log.NewNopLogger()}
}

func getDefaultLoggerFunc(ctx context.Context) Logger {
	return NewDefaultLogger()
}
