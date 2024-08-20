// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

/*
Package basculecaps provide a standard format for token capabilities in the
context of HTTP-based workflow.  Capabilities handled by this package are
expected to be of the format {prefix}{url pattern}:{method}.

The prefix can be a string literal or a regular expression.  If it is a regular
expression, it must not contain subexpressions.  A prefix may also be the empty string.

The url pattern is expected to be a regular expression that matches request URLs
that the token is authorized to access.  This pattern may also be a string literal,
but it cannot be blank and cannot contain subexpressions.

The method portion of the capability is a string literal that matches the request's
method.  The special token "all" is used to designate any regular expression.  This
special "all" token may be altered through configuration, but it cannot be an
empty string.
*/
package basculecaps
