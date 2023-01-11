# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.11.3]
- [Remove deprecated sallust code #167](https://github.com/xmidt-org/bascule/pull/167)

## [v0.11.2]
- [SetLogger Bug: Shared logger among requests creates repeating logging context #159](https://github.com/xmidt-org/bascule/issues/159)
- [Enable & Fix Linter #149](https://github.com/xmidt-org/bascule/issues/149)
- [Remove go-kit/kit/log & go-kit/log #148](https://github.com/xmidt-org/bascule/issues/148)
- [Move to zap logger #103](https://github.com/xmidt-org/bascule/issues/103)
- Security patch, remove debug logged token

## [v0.11.1]
- [SetLogger Bug: Shared logger among requests creates repeating logging context #159](https://github.com/xmidt-org/bascule/issues/159)
- [CVE-2022-32149 (High) detected in golang.org/x/text-v0.3.7 #153](https://github.com/xmidt-org/bascule/issues/153)

## [v0.11.0]
- Refactored basculehttp to use Clortho instead of key package [135](https://github.com/xmidt-org/bascule/pull/135)
- Update dependencies. [131](https://github.com/xmidt-org/bascule/pull/131)
    -  [github.com/gorilla/sessions v1.2.1 cwe-613 no patch available](https://ossindex.sonatype.org/vulnerability/sonatype-2021-4899)
- Update dependencies. [130](https://github.com/xmidt-org/bascule/pull/130)
- Update CI system. [129](https://github.com/xmidt-org/bascule/pull/129)
- Add new middleware for specifying the logger. [126](https://github.com/xmidt-org/bascule/pull/126)
- Added fields to SetLoggerLogger func and bumped cast, viper, arrange, and zap packages. [122](https://github.com/xmidt-org/bascule/pull/122)
- Removed "github.com/pkg/errors" dependency for "errors". [#116](https://github.com/xmidt-org/bascule/pull/116)

## [v0.10.2]
- Update setLogger Authorization header filtering logic. [#111](https://github.com/xmidt-org/bascule/pull/111)
- Switched to github.com/golang-jwt/jwt to address a security vulnerability. [#112](https://github.com/xmidt-org/bascule/pull/112)
- Fix goconst linting warning [#113](https://github.com/xmidt-org/bascule/pull/113)


## [v0.10.1]
- Added raw parsers for bearer acquirer. [#110](https://github.com/xmidt-org/bascule/pull/110)
- Added default keys update interval value. [#110](https://github.com/xmidt-org/bascule/pull/110)

## [v0.10.0]
- fixed Authorization keys in the constructor to be case sensitive. [#74](https://github.com/xmidt-org/bascule/pull/74)
- Removed unused check. [#79](https://github.com/xmidt-org/bascule/pull/79)
- Removed Logger interface in favor of the go-kit one. [#79](https://github.com/xmidt-org/bascule/pull/79)
- Moved log.go to basculehttp and simplified code, with nothing exported. [#79](https://github.com/xmidt-org/bascule/pull/79)
- Added constructor option for letting users decide what gets written on the HTTP response on errors. [#84](https://github.com/xmidt-org/bascule/pull/84)
- Added metric listener for auth validation outcome. [#81](https://github.com/xmidt-org/bascule/pull/81)
- Moved checks to their own package and added capability checks. [#85](https://github.com/xmidt-org/bascule/pull/85)
- Removed emperror package dependency. [#94](https://github.com/xmidt-org/bascule/pull/94)
- Converted basculechecks to use touchstone metrics. [#95](https://github.com/xmidt-org/bascule/pull/95)
- Added method label to metric validator. [#96](https://github.com/xmidt-org/bascule/pull/96)
- Update errors to include reason used by metric validator. [#97](https://github.com/xmidt-org/bascule/pull/97)
- Made Capability Key configurable for CapabilitiesValidator and CapabilitiesMap. [#98](https://github.com/xmidt-org/bascule/pull/98)
- Updated MetricValidator with a New function and options. [#99](https://github.com/xmidt-org/bascule/pull/99)
- Removed Partner from ParsedValues. [#99](https://github.com/xmidt-org/bascule/pull/99)
- Fixed ProvideMetricValidator() so it works. [#100](https://github.com/xmidt-org/bascule/pull/100)
- Updated error response reason's string representation to be snake case. [#102](https://github.com/xmidt-org/bascule/pull/102)
- Updated objects created with options to ignore nils. [#104](https://github.com/xmidt-org/bascule/pull/104)
- Added Provide() functions in basculehttp and basculechecks for easier setup. [#104](https://github.com/xmidt-org/bascule/pull/104)

## [v0.9.0]
- added helper function for building basic auth map [#59](https://github.com/xmidt-org/bascule/pull/59)
- fixed references to the main branch [#61](https://github.com/xmidt-org/bascule/pull/61)
- fixed attributes to be case sensitive and simplified the Attributes interface [#64](https://github.com/xmidt-org/bascule/pull/64)

## [v0.8.1]
- fixed data race in RemoteBearerTokenAcquirer [#55](https://github.com/xmidt-org/bascule/pull/55)

## [v0.8.0]
- Add support for key paths in token attribute getters [#52](https://github.com/xmidt-org/bascule/pull/52)

## [v0.7.0]
- Modified URL in context to be a *url.URL [#47](https://github.com/xmidt-org/bascule/pull/47)
- Added a ParseURL function into the basculehttp constructor [#47](https://github.com/xmidt-org/bascule/pull/47)
- Added automated release using travis [#49](https://github.com/xmidt-org/bascule/pull/49)

## [v0.6.0] 
- Prune use of unnecessary custom time.Duration

## [v0.5.0]
- Fixed panic in jws parser
- Fixed ClaimsWithLeeway to be unmarshaled into correctly
- Updated basculehttp logs to provide more information

## [v0.4.0]
- Refactored acquirer code to be more flexible/extendable
- Gave examples their own go.mod files so the library doesn't have unnecessary dependencies.

## [v0.3.1]
- Fix travis yaml
- Added delimiter option for constructor

## [v0.3.0]
- Added Auth for outgoing requests
- Added jwt Validator
- Removed SermoDigital dependency
- Added documentation and examples
- Moved all packages up one folder

## [v0.2.5]
- Added Error Response Reason

## [v0.2.4]
- Removed tip builds from travis
- Added unit tests
- Added more descriptive errors
- Changed StatusUnauthorized to StatusForbidden

## [v0.2.3]
- Fixed Errors `Error()` function

## [v0.2.2]
- Updated Errors `Error()` function
- Added request URL and method to context

## [v0.2.1]
- Removed request from logging statements

## [v0.2.0]
 - Added checks
 - Added configurable behavior on a key not found in `enforcer`
 - Fixed error message in a check
 - Added logging to `constructor` and `enforcer`

## [v0.1.1]
 - Changed a check to be more generic
 - Fixed byte-ifying the value for Bearer parsing

## [v0.1.0]
- Initial creation
- Added constructor, enforcer, and listener alice decorators
- Basic code and structure established

[Unreleased]: https://github.com/xmidt-org/bascule/compare/v0.11.3...HEAD
[v0.11.3]: https://github.com/xmidt-org/bascule/compare/v0.11.2...v0.11.3
[v0.11.2]: https://github.com/xmidt-org/bascule/compare/v0.11.1...v0.11.2
[v0.11.1]: https://github.com/xmidt-org/bascule/compare/v0.11.0...v0.11.1
[v0.11.0]: https://github.com/xmidt-org/bascule/compare/v0.10.2...v0.11.0
[v0.10.2]: https://github.com/xmidt-org/bascule/compare/v0.10.1...v0.10.2
[v0.10.1]: https://github.com/xmidt-org/bascule/compare/v0.10.0...v0.10.1
[v0.10.0]: https://github.com/xmidt-org/bascule/compare/v0.9.0...v0.10.0
[v0.9.0]: https://github.com/xmidt-org/bascule/compare/v0.8.1...v0.9.0
[v0.8.1]: https://github.com/xmidt-org/bascule/compare/v0.8.0...v0.8.1
[v0.8.0]: https://github.com/xmidt-org/bascule/compare/v0.7.0...v0.8.0
[v0.7.0]: https://github.com/xmidt-org/bascule/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/xmidt-org/bascule/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/xmidt-org/bascule/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/xmidt-org/bascule/compare/v0.3.1...v0.4.0
[v0.3.1]: https://github.com/xmidt-org/bascule/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/xmidt-org/bascule/compare/v0.2.5...v0.3.0
[v0.2.5]: https://github.com/xmidt-org/bascule/compare/v0.2.4...v0.2.5
[v0.2.4]: https://github.com/xmidt-org/bascule/compare/v0.2.3...v0.2.4
[v0.2.3]: https://github.com/xmidt-org/bascule/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/xmidt-org/bascule/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/xmidt-org/bascule/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/xmidt-org/bascule/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/xmidt-org/bascule/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/xmidt-org/bascule/compare/v0.0.0...v0.1.0
