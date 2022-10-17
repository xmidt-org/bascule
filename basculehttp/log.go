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
	"net"
	"net/http"
	"strings"

	"github.com/justinas/alice"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/candlelight"
	"github.com/xmidt-org/sallust"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var (
	errorKey interface{} = "error"
)

// defaultGetLoggerFunc returns the default logger, which doesn't do anything.
func defaultGetLoggerFunc(_ context.Context) *zap.Logger {
	return sallust.Default()
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
			tid := r.Header.Get(candlelight.HeaderWPATIDKeyName)
			if tid == "" {
				tid = candlelight.GenTID()
			}

			var source string
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				source = r.RemoteAddr
			} else {
				source = host
			}

			logger = logger.With(
				zap.Any("request.Headers", sanitizeHeaders(r.Header)), //lgtm [go/clear-text-logging]
				zap.String("request.URL", r.URL.EscapedPath()),
				zap.String("request.method", r.Method),
				zap.String("request.address", source),
				zap.String("request.path", r.URL.Path),
				zap.String("request.query", r.URL.RawQuery),
				zap.String("request.tid", tid),
			)
			traceID, spanID, ok := candlelight.ExtractTraceInfo(r.Context())
			if ok {
				logger = logger.With(
					zap.String(candlelight.TraceIdLogKeyName, traceID),
					zap.String(candlelight.SpanIDLogKeyName, spanID),
				)
			}
			r = r.WithContext(sallust.With(r.Context(), logger))
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
					return WithCLogger(getLogger)
				},
			},

			// add logger enforcer option
			fx.Annotated{
				Group: "bascule_enforcer_options",
				Target: func(getLogger func(context.Context) *zap.Logger) EOption {
					return WithELogger(getLogger)
				},
			},

			// add info to logger
			fx.Annotated{
				Name:   "alice_set_logger_info",
				Target: SetBasculeInfo,
			},
		),
	)
}

// SetBasculeInfo creates an alice constructor that takes
// the logger and bascule Auth and adds
// relevant bascule information to the logger before putting the logger
// back in the context.
func SetBasculeInfo() alice.Constructor {
	return func(delegate http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			logger := sallust.Get(ctx)

			var satClientID = "N/A"
			// retrieve satClientID from request context
			if auth, ok := bascule.FromContext(r.Context()); ok {
				satClientID = auth.Token.Principal()
			}

			logger.With(zap.String("satClientID", satClientID))

			r = r.WithContext(sallust.With(ctx, logger))

			delegate.ServeHTTP(w, r)
		})
	}
}
