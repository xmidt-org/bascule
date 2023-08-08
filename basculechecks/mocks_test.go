// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"github.com/stretchr/testify/mock"
	"github.com/xmidt-org/bascule"
)

type mockCapabilitiesChecker struct {
	mock.Mock
}

func (m *mockCapabilitiesChecker) CheckAuthentication(auth bascule.Authentication, v ParsedValues) error {
	args := m.Called(auth, v)
	return args.Error(0)
}
