# comcast-bascule

The library for authorization: both acquiring and validating.

[![Build Status](https://travis-ci.com/xmidt-org/bascule.svg?branch=master)](https://travis-ci.com/xmidt-org/bascule)
[![codecov.io](http://codecov.io/github/xmidt-org/bascule/coverage.svg?branch=master)](http://codecov.io/github/xmidt-org/bascule?branch=master)
[![Code Climate](https://codeclimate.com/github/xmidt-org/bascule/badges/gpa.svg)](https://codeclimate.com/github/xmidt-org/bascule)
[![Issue Count](https://codeclimate.com/github/xmidt-org/bascule/badges/issue_count.svg)](https://codeclimate.com/github/xmidt-org/bascule)
[![Go Report Card](https://goreportcard.com/badge/github.com/xmidt-org/bascule)](https://goreportcard.com/report/github.com/xmidt-org/bascule)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/bascule/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/xmidt-org/bascule.svg)](CHANGELOG.md)
[![GoDoc](https://godoc.org/github.com/xmidt-org/bascule?status.svg)](https://godoc.org/github.com/xmidt-org/bascule)

## Summary

This library provides validation of Tokens used for authorization as well as a 
way to acquire Authorization header values.  Tokens can be parsed and validated 
from http requests. Bascule provides a generic framework that can be configured, 
but currently can support basic and jwt authorization.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Acquiring Authorization](#acquiring-authorization)
- [Validating Authorization](#validating-authorization)
- [Install](#install)
- [Contributing](#contributing)

## Code of Conduct

This project and everyone participating in it are governed by the [XMiDT Code Of Conduct](https://xmidt.io/code_of_conduct/). 
By participating, you agree to this Code.

## Acquiring Authorization

The `acquire` subpackage handles getting the value for an Authorization header of
an http request.  The JWT acquirer gets a JWT from a configurable endpoint, 
caches it, and will get a new JWT at a configurable time before the current JWT 
expires.

## Validating Authorization

Validation of Tokens happens once an authorization value has been parsed into 
something that implements the [Token interface](https://godoc.org/github.com/xmidt-org/bascule#Token).  
The `basculehttp` subpackage provides http decorators/middleware that will parse an http 
request into a Token and validate it with configurable rules.

Read more about the `basculehttp` subpackage in its [README](basculehttp/README.md).

## Install
This repo is a library of packages used for the authorization.  There is no 
installation.

## Contributing
Refer to [CONTRIBUTING.md](CONTRIBUTING.md).