# bascule

The library for authorization: both acquiring and validating.

[![Build Status](https://github.com/xmidt-org/bascule/actions/workflows/ci.yml/badge.svg)](https://github.com/xmidt-org/bascule/actions/workflows/ci.yml)
[![Dependency Updateer](https://github.com/xmidt-org/bascule/actions/workflows/updater.yml/badge.svg)](https://github.com/xmidt-org/bascule/actions/workflows/updater.yml)
[![codecov.io](http://codecov.io/github/xmidt-org/bascule/coverage.svg?branch=main)](http://codecov.io/github/xmidt-org/bascule?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/xmidt-org/bascule)](https://goreportcard.com/report/github.com/xmidt-org/bascule)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=xmidt-org_bascule&metric=alert_status)](https://sonarcloud.io/dashboard?id=xmidt-org_bascule)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/bascule/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/release/xmidt-org/bascule.svg)](CHANGELOG.md)
[![GoDoc](https://pkg.go.dev/badge/github.com/xmidt-org/bascule)](https://pkg.go.dev/github.com/xmidt-org/bascule)

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
