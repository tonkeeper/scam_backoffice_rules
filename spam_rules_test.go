package scam_backoffice_rules

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tonkeeper/tongo"
)

func getTestJetton() *JettonEvaluate {
	testKnownJettons := []jetton{
		{
			Name:    "Cock Fights Token",
			Symbol:  "CFT",
			Address: tongo.MustParseAccountID("0:a6e0456ba1ca77e0915e94760f1b1fc3e292aa43e812ebfc45650cc8c3003e58"),
		},
		{
			Name:    "jUSDT",
			Symbol:  "jUSDT",
			Address: tongo.MustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
		},
	}
	j := &JettonEvaluate{}
	j.updateJettons(testKnownJettons)
	return j
}

func TestEvaluateJettons(t *testing.T) {
	tests := []struct {
		name    string
		symbol  string
		address tongo.AccountID
		want    TypeOfAction
	}{
		{
			symbol:  "jUSDT",
			address: tongo.MustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
			want:    Accept,
		},
		{
			symbol:  "CFT",
			address: tongo.MustParseAccountID("0:a6e0456ba1ca77e0915e94760f1b1fc3e292aa43e812ebfc45650cc8c3003e58"),
			want:    Accept,
		},
		{
			symbol:  "jUSDT",
			address: tongo.AccountID{}, // emulate different address
			want:    Drop,
		},
		{
			symbol:  "CFT",
			address: tongo.AccountID{}, // emulate different address
			want:    Drop,
		},
		{
			symbol:  "Random Symbol",
			address: tongo.AccountID{},
			want:    Accept,
		},
	}
	knownJettons := getTestJetton()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := knownJettons.SearchAction(tt.address, tt.symbol)
			require.Equal(t, tt.want, got)
		})
	}
}
