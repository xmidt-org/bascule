// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"strings"
	"sync"
)

// WarningAttr is one key/value pair that describes a Warning.
type WarningAttr struct {
	Key   string
	Value string
}

// Warning is a note for the caller describing a problem with their token or
// request, e.g. a malformed capability or a check that would have rejected the
// request had it been enforcing.  A Warning does not, by itself, block a request.
type Warning struct {
	// Reason is a short, machine-readable reason, e.g. "malformed".
	Reason string

	// Attrs further describe the warning, in order.
	Attrs []WarningAttr
}

// String formats this warning as <reason>; key=value; ...
//
// A value that is a valid HTTP token is written as is.  Any other value is
// written as a quoted string, with '"' and '\' escaped by a backslash.
func (w Warning) String() string {
	var o strings.Builder
	o.WriteString(w.Reason)
	for _, attr := range w.Attrs {
		o.WriteString("; ")
		o.WriteString(attr.Key)
		o.WriteByte('=')
		writeWarningValue(&o, attr.Value)
	}

	return o.String()
}

func writeWarningValue(o *strings.Builder, v string) {
	if isToken(v) {
		o.WriteString(v)
		return
	}

	o.WriteByte('"')
	for i := 0; i < len(v); i++ {
		if v[i] == '"' || v[i] == '\\' {
			o.WriteByte('\\')
		}

		o.WriteByte(v[i])
	}

	o.WriteByte('"')
}

// isToken reports whether v is a non-empty RFC 9110 token.
func isToken(v string) bool {
	if len(v) == 0 {
		return false
	}

	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}

	return true
}

// warningCollector accumulates the warnings raised while handling one request.
// It is safe for concurrent use.
type warningCollector struct {
	lock     sync.Mutex
	warnings []Warning
}

type warningsContextKey struct{}

// WithWarnings returns a context that collects warnings added with AddWarning.
// Any warnings collected by ctx are not carried over.
func WithWarnings(ctx context.Context) context.Context {
	return context.WithValue(ctx, warningsContextKey{}, new(warningCollector))
}

// AddWarning records a warning with the collector in ctx.  If ctx has no
// collector, i.e. WithWarnings was not used, this function does nothing, so
// approvers may call it unconditionally.
func AddWarning(ctx context.Context, w Warning) {
	if c, ok := ctx.Value(warningsContextKey{}).(*warningCollector); ok {
		c.lock.Lock()
		c.warnings = append(c.warnings, w)
		c.lock.Unlock()
	}
}

// GetWarnings returns a copy of the warnings collected so far in ctx, in the
// order they were added.  It returns nil if there are none or ctx has no
// collector.
func GetWarnings(ctx context.Context) []Warning {
	c, ok := ctx.Value(warningsContextKey{}).(*warningCollector)
	if !ok {
		return nil
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if len(c.warnings) == 0 {
		return nil
	}

	return append([]Warning(nil), c.warnings...)
}
