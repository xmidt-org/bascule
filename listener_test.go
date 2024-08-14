// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

// testEvent is the event type used for testing below.
// the listeners behave the same regardless of the event type,
// so testing with just (1) type is all that's needed.
type testEvent NoCredentialsEvent[int]

type ListenerTestSuite struct {
	suite.Suite
}

func (suite *ListenerTestSuite) newTestEvent() testEvent {
	return testEvent{
		Source: 239471231,
		Err:    errors.New("expected"),
	}
}

func (suite *ListenerTestSuite) TestListenerFunc() {
	var (
		called bool

		expectedEvent = suite.newTestEvent()

		l Listener[testEvent] = ListenerFunc[testEvent](func(actualEvent testEvent) {
			suite.Equal(expectedEvent, actualEvent)
			called = true
		})
	)

	l.OnEvent(expectedEvent)
	suite.True(called)
}

func (suite *ListenerTestSuite) TestListeners() {
	suite.Run("Empty", func() {
		var ls Listeners[testEvent]
		ls.OnEvent(suite.newTestEvent()) // should be fine
	})

	suite.Run("Append", func() {
		for _, count := range []int{1, 2, 5} {
			suite.Run(fmt.Sprintf("count=%d", count), func() {
				var (
					called        int
					expectedEvent = suite.newTestEvent()
					ls            Listeners[testEvent]
				)

				for i := 0; i < count; i++ {
					var l Listener[testEvent] = ListenerFunc[testEvent](func(actualEvent testEvent) {
						suite.Equal(expectedEvent, actualEvent)
						called++
					})

					ls = ls.Append(l)
				}

				ls.OnEvent(expectedEvent)
				suite.Equal(count, called)
			})
		}
	})

	suite.Run("AppendFunc", func() {
		for _, count := range []int{1, 2, 5} {
			suite.Run(fmt.Sprintf("count=%d", count), func() {
				var (
					called        int
					expectedEvent = suite.newTestEvent()

					ls Listeners[testEvent]
				)

				for i := 0; i < count; i++ {
					ls = ls.AppendFunc(func(actualEvent testEvent) {
						suite.Equal(expectedEvent, actualEvent)
						called++
					})
				}

				ls.OnEvent(expectedEvent)
				suite.Equal(count, called)
			})
		}
	})
}

func TestListener(t *testing.T) {
	suite.Run(t, new(ListenerTestSuite))
}
