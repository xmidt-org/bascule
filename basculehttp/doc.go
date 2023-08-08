// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

/*
Package basculehttp provides Alice-style http middleware that parses a Token
from an http header, validates the Token, and allows for the consumer to add
additional logs or metrics upon an error or a valid Token. The package contains
listener middleware that tracks if requests were authorized or not.
*/
package basculehttp
