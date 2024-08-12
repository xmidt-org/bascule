// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ListenerTestSuite struct {
	suite.Suite
}

func (suite *ListenerTestSuite) TestEvent() {
	suite.Run("Success", func() {
		testCases := []struct {
			name     string
			event    Event[int]
			expected bool
		}{
			{
				name: "type success",
				event: Event[int]{
					Type: EventTypeSuccess,
				},
				expected: true,
			},
			{
				name: "type missing credentials",
				event: Event[int]{
					Type: EventTypeMissingCredentials,
				},
				expected: false,
			},
		}

		for _, testCase := range testCases {
			suite.Run(testCase.name, func() {
				suite.Equal(
					testCase.expected,
					testCase.event.Success(),
				)
			})
		}
	})

	// just check that strings are unique
	suite.Run("String", func() {
		var (
			eventTypes = []EventType{
				EventTypeSuccess,
				EventTypeMissingCredentials,
				EventTypeInvalidCredentials,
				EventTypeFailedAuthentication,
				EventTypeFailedAuthorization,
				EventType(256), // random weird value should still work
			}

			strings = make(map[string]bool)
		)

		for _, et := range eventTypes {
			strings[et.String()] = true
		}

		suite.Equal(len(eventTypes), len(strings))
	})
}

func (suite *ListenerTestSuite) TestListenerFunc() {
	var (
		called bool

		l Listener[int] = ListenerFunc[int](func(e Event[int]) {
			suite.Equal(EventTypeMissingCredentials, e.Type)
			called = true
		})
	)

	l.OnEvent(Event[int]{
		Type: EventTypeMissingCredentials,
	})

	suite.True(called)
}

func (suite *ListenerTestSuite) TestListeners() {
	suite.Run("Empty", func() {
		var ls Listeners[int]
		ls.OnEvent(Event[int]{}) // should be fine
	})

	suite.Run("Append", func() {
		for _, count := range []int{1, 2, 5} {
			suite.Run(fmt.Sprintf("count=%d", count), func() {
				var (
					called        int
					expectedEvent = Event[int]{
						Type:   EventTypeInvalidCredentials,
						Source: 1234,
						Err:    errors.New("expected"),
					}

					ls Listeners[int]
				)

				for i := 0; i < count; i++ {
					var l Listener[int] = ListenerFunc[int](func(e Event[int]) {
						suite.Equal(expectedEvent, e)
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
					expectedEvent = Event[int]{
						Type:   EventTypeInvalidCredentials,
						Source: 1234,
						Err:    errors.New("expected"),
					}

					ls Listeners[int]
				)

				for i := 0; i < count; i++ {
					ls = ls.AppendFunc(func(e Event[int]) {
						suite.Equal(expectedEvent, e)
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
