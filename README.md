# bascule

A library for authentication and authorization workflows.

[![Build Status](https://github.com/xmidt-org/bascule/actions/workflows/ci.yml/badge.svg)](https://github.com/xmidt-org/bascule/actions/workflows/ci.yml)
[![codecov.io](http://codecov.io/github/xmidt-org/bascule/coverage.svg?branch=main)](http://codecov.io/github/xmidt-org/bascule?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/xmidt-org/bascule)](https://goreportcard.com/report/github.com/xmidt-org/bascule)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/bascule/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/release/xmidt-org/bascule.svg)](CHANGELOG.md)
[![GoDoc](https://pkg.go.dev/badge/github.com/xmidt-org/bascule)](https://pkg.go.dev/github.com/xmidt-org/bascule)

## Summary

Bascule provides authentication and authorization workflows, particularly focused on the needs of an HTTP server.

## Table of Contents
- [Usage](#usage)
- [Code of Conduct](#code-of-conduct)
- [Install](#install)
- [Contributing](#contributing)


## Usage

### Create Basic Auth Middleware For Http Requests

> tp, err := basculehttp.NewAuthorizationParser(
		basculehttp.WithBasic(),
	)
	if err != nil {
		fmt.Prrintln(err)
	}

	m, err := basculehttp.NewMiddleware(
		basculehttp.UseAuthenticator(

			basculehttp.NewAuthenticator(
				bascule.WithTokenParsers(tp),
				bascule.WithValidators(
					bascule.AsValidator[*http.Request](
						func(token bascule.Token) error {
							if basic, ok := token.(basculehttp.BasicToken); ok && basic.UserName() == "some-username" && basic.Password() == "some-password" {
								return nil
							}

							return bascule.ErrBadCredentials
						},
					),
				),
			),
		),
	)

### Create JWT Auth Middleware For Http Requests

> // get public keys with automatic refresh
	keyUrl := "http://localhost/keys"
	cache := jwk.NewCache(context.Background())
	err := cache.Register(keyUrl, jwk.WithRefreshInterval(time.Duration(p.refreshIntervalHours)*time.Hour))
	keys, err := jwk.NewCachedSet(cache, keyUrl), err
	if err != nil {
		fmt.Println("error getting public keys")
	}

	// create token parser

	jwtp, err := basculejwt.NewTokenParser(jwt.WithKeySet(keys))
	if err != nil {
		fmt.Println("error creating token parser")
	}

	tp, err := basculehttp.NewAuthorizationParser(
		basculehttp.WithScheme(basculehttp.SchemeBearer, jwtp),
	)
	if err != nil {
		fmt.Println("error creating authoritization parser")
	}


	// create middleware

	m, err = basculehttp.NewMiddleware(
		basculehttp.UseAuthenticator(
			basculehttp.NewAuthenticator(
				bascule.WithTokenParsers(tp),
				bascule.WithValidators(
					bascule.AsValidator[*http.Request](
						func(token bascule.Token) error {
							_, ok := token.(basculejwt.Claims)
							if !ok {
								return bascule.ErrBadCredentials
							}

							capabilities, _ := bascule.GetCapabilities(token)

							// perform capability and other validation checks here

							fmt.Println(capabilities)

							return nil
						},
					),
				),
			),
		),
	)

	if (err != nil) {
		fmt.Println("error creating middleware")
	}


### Use Middleware To Intercept Http Requests

> func getHandlers(m *basculehttp.Middleware, next http.Handler) http.Handler {
	return m.ThenFunc(
		next.ServeHTTP,
	)
}



## Code of Conduct

This project and everyone participating in it are governed by the [XMiDT Code Of Conduct](https://xmidt.io/code_of_conduct/). 
By participating, you agree to this Code.

## Install
This repo is a library of packages used for authentication and authorization.

## Contributing
Refer to [CONTRIBUTING.md](CONTRIBUTING.md).
