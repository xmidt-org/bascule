module github.com/xmidt-org/bascule

go 1.27.1

require (
	github.com/alecthomas/kong v1.16.1
	github.com/lestrrat-go/jwx/v4 v4.5.0
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.57.0
)

require (
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
)

// Versions v1.3.0 through v1.3.5 carry breaking changes that were not
// intended, in the API and in what a token is authorized to reach:
//
//   - the WithPrefixes and WithAllMethod options were removed.
//   - capability url patterns that do not begin with a '/' stopped matching
//     any request, silently denying traffic that was previously approved.
//   - a request is matched against the capability pattern supplied by
//     configuration rather than the one carried by the token, so a token
//     scoped to a single resource is authorized for every resource the
//     configuration allows.
retract [v1.3.0, v1.3.5]
