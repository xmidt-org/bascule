// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package basculecaps provide a standard format for token capabilities in the
// context of HTTP-based workflow.  Capabilities handled by this package are
// expected to be of the format {prefix}{url pattern}:{method}.
//
// The prefix decides which of a token's capabilities this package honors.  It
// can be a string literal or a regular expression, and it may contain
// subexpressions.  A prefix may also be the empty string.
//
// The url pattern is carried by the token and describes the request URLs that
// the token is authorized to access.  It is a regular expression, though it may
// also be a string literal, and it cannot be blank.  It is matched against the
// beginning of the request's path and is tried both with and without a leading
// '/', so device/.*/config and /device/.*/config each authorize
// /device/DEADBEEF/config.  A pattern is not anchored at its end, so /test also
// authorizes /test/foo.  A path that begins with '//' is matched only as
// written, so /admin does not authorize //admin.
//
// The method portion of the capability is a string literal that matches the
// request's method, and it must be lowercase.  The special token "all" is used
// to designate any method.  This special "all" token may be altered through
// configuration, but it cannot be an empty string.
package basculecaps
