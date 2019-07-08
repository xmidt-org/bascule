# comcast-bascule

The library for authorization: both acquiring and validating.

[![Build Status](https://travis-ci.org/Comcast/comcast-bascule.svg?branch=master)](https://travis-ci.org/Comcast/comcast-bascule)
[![codecov.io](http://codecov.io/github/Comcast/comcast-bascule/coverage.svg?branch=master)](http://codecov.io/github/Comcast/comcast-bascule?branch=master)
[![Code Climate](https://codeclimate.com/github/Comcast/comcast-bascule/badges/gpa.svg)](https://codeclimate.com/github/Comcast/comcast-bascule)
[![Issue Count](https://codeclimate.com/github/Comcast/comcast-bascule/badges/issue_count.svg)](https://codeclimate.com/github/Comcast/comcast-bascule)
[![Go Report Card](https://goreportcard.com/badge/github.com/Comcast/comcast-bascule)](https://goreportcard.com/report/github.com/Comcast/comcast-bascule)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/Comcast/comcast-bascule/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/Comcast/comcast-bascule.svg)](CHANGELOG.md)
[![GoDoc](https://godoc.org/github.com/Comcast/comcast-bascule/bascule?status.svg)](https://godoc.org/github.com/Comcast/comcast-bascule/bascule)

## Summary

This library provides validation of Tokens used for authorization as well as a 
way to acquire Authorization header values.  Tokens can be parsed and validated 
from http requests. Bascule provides a generic framework that can be configured, 
but currently can support basic and jwt authorization.

## Acquiring Authorization

The `acquire` subpackage handles getting the value for an Authorization header of
an http request.  The JWT acquirer gets a JWT from a configurable endpoint, 
caches it, and will get a new JWT at a configurable time before the current JWT 
expires.

## Validating Authorization

Validation of Tokens happens once an authorization value has been parsed into 
something that implements the [Token interface](https://godoc.org/github.com/Comcast/comcast-bascule/bascule#Token).  
The `basculehttp` subpackage provides http decorators/middleware that will parse an http 
request into a Token and validate it with configurable rules.

Read more about the `basculehttp` subpackage in its [README](bascule/basculehttp/README.md).

## Install
This repo is a library of packages used for the authorization.  There is no 
installation.

## Contributing
Refer to [CONTRIBUTING.md](CONTRIBUTING.md).