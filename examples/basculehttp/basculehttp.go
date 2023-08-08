// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/sallust"
	"github.com/xmidt-org/webpa-common/logging"
	"go.uber.org/zap"
)

func SetLogger(logger *zap.Logger) func(delegate http.Handler) http.Handler {
	return func(delegate http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ctx := r.WithContext(logging.WithLogger(r.Context(),
					logger.With(zap.Any("requestHeaders", r.Header), zap.String("requestURL", r.URL.EscapedPath()), zap.String("method", r.Method))))
				delegate.ServeHTTP(w, ctx)
			})
	}
}

// currently only sets up basic auth
func authChain(logger *zap.Logger) alice.Chain {
	basicAllowed := map[string]string{
		"testuser": "testpass",
		"pls":      "letmein",
	}
	options := []basculehttp.COption{
		basculehttp.WithCLogger(sallust.Get),
		basculehttp.WithTokenFactory("Basic", basculehttp.BasicTokenFactory(basicAllowed)),
	}

	authConstructor := basculehttp.NewConstructor(options...)

	basicRules := bascule.Validators{
		bascule.CreateNonEmptyPrincipalCheck(),
		bascule.CreateNonEmptyTypeCheck(),
		bascule.CreateValidTypeCheck([]string{"basic"}),
	}

	authEnforcer := basculehttp.NewEnforcer(
		basculehttp.WithELogger(sallust.Get),
		basculehttp.WithRules("Basic", basicRules),
	)

	return alice.New(SetLogger(logger), authConstructor, authEnforcer)
}

func simpleResponse(writer http.ResponseWriter, request *http.Request) {
	writer.Write([]byte("good auth!"))
	writer.WriteHeader(200)
	return
}

func main() {
	router := mux.NewRouter()
	authFuncs := authChain(sallust.Default())
	router.Handle("/test", authFuncs.ThenFunc(simpleResponse))
	http.ListenAndServe(":6000", router)
}
