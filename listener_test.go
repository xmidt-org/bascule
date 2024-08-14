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

func (suite *ListenerTestSuite) newTestEvent() AuthenticateEvent[int] {
	return AuthenticateEvent[int]{
		Source: 2349732,
		Token:  stubToken("test token"),
		Err:    errors.New("expected"),
	}
}

func (suite *ListenerTestSuite) TestListenerFunc() {
	var (
		called bool

		expectedEvent = suite.newTestEvent()

		l Listener[AuthenticateEvent[int]] = ListenerFunc[AuthenticateEvent[int]](
			func(actualEvent AuthenticateEvent[int]) {
				suite.Equal(expectedEvent, actualEvent)
				called = true
			},
		)
	)

	l.OnEvent(expectedEvent)
	suite.True(called)
}

func (suite *ListenerTestSuite) TestListeners() {
	suite.Run("Empty", func() {
		var ls Listeners[AuthenticateEvent[int]]
		ls.OnEvent(AuthenticateEvent[int]{}) // should be fine
	})

	suite.Run("Append", func() {
		for _, count := range []int{1, 2, 5} {
			suite.Run(fmt.Sprintf("count=%d", count), func() {
				var (
					called        int
					expectedEvent = suite.newTestEvent()

					ls Listeners[AuthenticateEvent[int]]
				)

				for i := 0; i < count; i++ {
					var l Listener[AuthenticateEvent[int]] = ListenerFunc[AuthenticateEvent[int]](
						func(actualEvent AuthenticateEvent[int]) {
							suite.Equal(expectedEvent, actualEvent)
							called++
						},
					)

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

					ls Listeners[AuthenticateEvent[int]]
				)

				for i := 0; i < count; i++ {
					ls = ls.AppendFunc(func(e AuthenticateEvent[int]) {
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
