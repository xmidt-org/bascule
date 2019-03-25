package bascule

import (
	"github.com/Comcast/webpa-common/xmetrics"
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/provider"
)

const (
	TokenCounter = "token_count"
)

const (
	TokenTypeLabel = "type"
)

func Metrics() []xmetrics.Metric {
	return []xmetrics.Metric{
		{
			Name:       TokenCounter,
			Help:       "The total number of tokens received",
			Type:       "counter",
			LabelNames: []string{TokenTypeLabel},
		},
	}
}

type Measures struct {
	TokenCount metrics.Counter
}

func NewMeasures(p provider.Provider, customMeasures []interface{}) *Measures {
	return &Measures{
		TokenCount: p.NewCounter(TokenCounter),
	}
}
