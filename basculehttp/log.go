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

package basculehttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/justinas/alice"
	"github.com/xmidt-org/sallust"
	"github.com/xmidt-org/sallust/sallustkit"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var (
	defaultLogger = log.NewNopLogger()

	errorKey interface{} = "error"
)

// defaultGetLoggerFunc returns the default logger, which doesn't do anything.
func defaultGetLoggerFunc(_ context.Context) log.Logger {
	return defaultLogger
}

// getZapLogger converts a zap logger to a go-kit logger. This won't be needed
// when basculehttp starts using the zap logger directly.
func getZapLogger(f func(context.Context) *zap.Logger) func(context.Context) log.Logger {
	return func(ctx context.Context) log.Logger {
		return sallustkit.Logger{
			Zap: f(ctx),
		}
	}
}

func sanitizeHeaders(headers http.Header) (filtered http.Header) {
	filtered = headers.Clone()
	if authHeader := filtered.Get("Authorization"); authHeader != "" {
		filtered.Del("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 {
			filtered.Set("Authorization-Type", parts[0])
		}
	}
	return
}

// SetLogger creates an alice constructor that sets up a zap logger that can be
// used for all logging related to the current request.  The logger is added to
// the request's context.
func SetLogger(logger *zap.Logger) alice.Constructor {
	return func(delegate http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(sallust.With(r.Context(),
				logger.With(
					zap.Reflect("requestHeaders", sanitizeHeaders(r.Header)), //lgtm [go/clear-text-logging]
					zap.String("requestURL", r.URL.EscapedPath()),
					zap.String("method", r.Method))))
			delegate.ServeHTTP(w, r)
		})
	}
}

// ProvideLogger provides functions that use zap loggers, getting from and
// setting to a context.  The zap logger is translated into a go-kit logger for
// compatibility with the alice middleware.  Options are also provided for the
// middleware so they can use the context logger.
func ProvideLogger() fx.Option {
	return fx.Options(
		fx.Supply(sallust.Get),
		fx.Provide(
			// set up middleware to add request-specific logger to context
			fx.Annotated{
				Name:   "alice_set_logger",
				Target: SetLogger,
			},

			// add logger constructor option
			fx.Annotated{
				Group: "bascule_constructor_options",
				Target: func(getLogger func(context.Context) *zap.Logger) COption {
					return WithCLogger(getZapLogger(getLogger))
				},
			},

			// add logger enforcer option
			fx.Annotated{
				Group: "bascule_enforcer_options",
				Target: func(getLogger func(context.Context) *zap.Logger) EOption {
					return WithELogger(getZapLogger(getLogger))
				},
			},
		),
	)
}
