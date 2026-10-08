// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWarningString(t *testing.T) {
	tests := []struct {
		name     string
		warning  Warning
		expected string
	}{
		{
			name:     "reason only",
			warning:  Warning{Reason: "malformed"},
			expected: "malformed",
		},
		{
			name: "token and quoted values",
			warning: Warning{
				Reason: "malformed",
				Attrs: []WarningAttr{
					{Key: "kind", Value: "cidr"},
					{Key: "cap", Value: "x1:webpa:cidr:10.0.0.0/33"},
				},
			},
			expected: `malformed; kind=cidr; cap="x1:webpa:cidr:10.0.0.0/33"`,
		},
		{
			name: "empty value",
			warning: Warning{
				Reason: "would-reject",
				Attrs:  []WarningAttr{{Key: "origin", Value: ""}},
			},
			expected: `would-reject; origin=""`,
		},
		{
			name: "quote and backslash escaped",
			warning: Warning{
				Reason: "malformed",
				Attrs:  []WarningAttr{{Key: "cap", Value: `a"b\c`}},
			},
			expected: `malformed; cap="a\"b\\c"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.warning.String())
		})
	}
}

func TestAddWarningNoCollector(t *testing.T) {
	ctx := context.Background()
	assert.NotPanics(t, func() {
		AddWarning(ctx, Warning{Reason: "ignored"})
	})

	assert.Nil(t, GetWarnings(ctx))
}

func TestWarnings(t *testing.T) {
	ctx := WithWarnings(context.Background())
	assert.Nil(t, GetWarnings(ctx))

	first := Warning{Reason: "first"}
	second := Warning{Reason: "second"}
	AddWarning(ctx, first)
	AddWarning(ctx, second)

	warnings := GetWarnings(ctx)
	assert.Equal(t, []Warning{first, second}, warnings)

	// the result is a copy
	warnings[0] = Warning{Reason: "changed"}
	assert.Equal(t, []Warning{first, second}, GetWarnings(ctx))

	// a fresh collector does not see the old warnings
	assert.Nil(t, GetWarnings(WithWarnings(ctx)))
}

func TestAddWarningConcurrent(t *testing.T) {
	ctx := WithWarnings(context.Background())

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			AddWarning(ctx, Warning{Reason: "concurrent"})
		})
	}

	wg.Wait()
	assert.Len(t, GetWarnings(ctx), 10)
}

func TestAuthorizeEventWarnings(t *testing.T) {
	expected := Warning{Reason: "would-reject"}

	var events []AuthorizeEvent[string]
	a, err := NewAuthorizer(
		WithApproverFuncs(func(ctx context.Context, _ string, _ Token) error {
			AddWarning(ctx, expected)
			return nil
		}),
		WithAuthorizeListenerFuncs(func(e AuthorizeEvent[string]) {
			events = append(events, e)
		}),
	)
	assert.NoError(t, err)

	ctx := WithWarnings(context.Background())
	assert.NoError(t, a.Authorize(ctx, "resource", StubToken("test")))

	if assert.Len(t, events, 1) {
		assert.NoError(t, events[0].Err)
		assert.Equal(t, []Warning{expected}, events[0].Warnings)
	}
}
