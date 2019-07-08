package main

import (
	"context"
	"net/http"
	"os"

	"github.com/Comcast/comcast-bascule/bascule"
	"github.com/Comcast/comcast-bascule/bascule/basculehttp"
	"github.com/Comcast/webpa-common/logging"
	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
)

func SetLogger(logger log.Logger) func(delegate http.Handler) http.Handler {
	return func(delegate http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ctx := r.WithContext(logging.WithLogger(r.Context(),
					log.With(logger, "requestHeaders", r.Header, "requestURL", r.URL.EscapedPath(), "method", r.Method)))
				delegate.ServeHTTP(w, ctx)
			})
	}
}

func GetLogger(ctx context.Context) bascule.Logger {
	return log.With(logging.GetLogger(ctx), "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
}

// currently only sets up basic auth
func authChain(logger log.Logger) alice.Chain {
	basicAllowed := map[string]string{
		"testuser": "testpass",
		"pls":      "letmein",
	}
	options := []basculehttp.COption{
		basculehttp.WithCLogger(GetLogger),
		basculehttp.WithTokenFactory("Basic", basculehttp.BasicTokenFactory(basicAllowed)),
	}

	authConstructor := basculehttp.NewConstructor(options...)

	basicRules := bascule.Validators{
		bascule.CreateNonEmptyPrincipalCheck(),
		bascule.CreateNonEmptyTypeCheck(),
		bascule.CreateValidTypeCheck([]string{"basic"}),
	}

	authEnforcer := basculehttp.NewEnforcer(
		basculehttp.WithELogger(GetLogger),
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
	logger := log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	router := mux.NewRouter()
	authFuncs := authChain(logger)
	router.Handle("/test", authFuncs.ThenFunc(simpleResponse))
	http.ListenAndServe(":6000", router)
}
