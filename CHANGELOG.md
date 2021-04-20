# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
- fixed Authorization keys in the constructor to be case sensitive. [#74](https://github.com/xmidt-org/bascule/pull/74)
- Removed unused checks. []()
- Removed Logger interface in favor of the go-kit one. []()
- Moved log.go to basculehttp and simplified code, with nothing exported. []()

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

[Unreleased]: https://github.com/xmidt-org/bascule/compare/v0.9.0...HEAD
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
