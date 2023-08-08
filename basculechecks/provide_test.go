// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/fx"
)

func TestProvideMetricValidator(t *testing.T) {
	type In struct {
		fx.In
		V bascule.Validator `name:"bascule_validator_capabilities"`
	}
	tests := []struct {
		description string
		optional    bool
		expectedErr error
	}{
		{
			description: "Optional Success",
			optional:    true,
			expectedErr: nil,
		},
		{
			description: "Required Failure",
			optional:    false,
			expectedErr: ErrNilChecker,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			var result bascule.Validator
			app := fx.New(
				touchstone.Provide(),
				ProvideMetrics(),
				fx.Provide(
					func() CapabilitiesChecker {
						return nil
					},
				),
				ProvideMetricValidator(tc.optional),
				fx.Invoke(
					func(in In) {
						result = in.V
					},
				),
			)
			app.Start(context.Background())
			defer app.Stop(context.Background())
			err := app.Err()
			assert.Nil(result)
			if tc.expectedErr == nil {
				assert.NoError(err)
				return
			}
			require.Error(err)
			assert.True(strings.Contains(err.Error(), tc.expectedErr.Error()),
				fmt.Errorf("error [%v] doesn't contain error [%v]",
					err, tc.expectedErr),
			)
		})
	}
}
