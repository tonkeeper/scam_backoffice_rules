package scam_backoffice_rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func getTestJetton() *JettonEvaluate {
	testKnownJettons := []jetton{
		{
			Name:   "First jetton",
			Symbol: "First Symbol",
		},
		{
			Name:   "Second jetton",
			Symbol: "Second Symbol",
		},
	}
	for idx, item := range testKnownJettons {
		item.NormalizedSymbol = strings.ToLower(normalizeReg.ReplaceAllString(item.Symbol, ""))
		testKnownJettons[idx] = item
	}

	return &JettonEvaluate{
		Jettons: testKnownJettons,
	}
}

func TestEvaluateJettons(t *testing.T) {
	tests := []struct {
		name   string
		symbol string
		want   TypeOfAction
	}{
		{
			symbol: "First Symbol",
			want:   Drop,
		},
		{
			symbol: "Second Symbol",
			want:   Drop,
		},
		{
			symbol: "Blah-blah",
			want:   Accept,
		},
		{
			symbol: "Blah-blah-blah",
			want:   Accept,
		},
	}
	knownJettons := getTestJetton()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := knownJettons.SearchAction(tt.symbol)
			require.Equal(t, tt.want, got)
		})
	}
}
