package scam_backoffice_rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tonkeeper/tongo"
	"github.com/tonkeeper/tongo/ton"
)

var (
	testKnownJettons = []jetton{
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
		{
			Name:    "Valid duplicate of jUSDT",
			Symbol:  "jUSDT",
			Address: tongo.MustParseAccountID("-1:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
		},
		{
			Name:    "Ambra",
			Symbol:  "AMBR",
			Address: tongo.MustParseAccountID("0:9c2c05b9dfb2a7460fda48fae7409a32623399933a98a7a15599152f37572b49"),
		},
		{
			// this is a fake token added to the well-known jettons list to ban scam tokens
			Address: tongo.MustParseAccountID("0:ca9006bd3fb03d355daeeff93b24be90afaa6e3ca0073ff5720f8a852c933278"),
			Name:    "Tether USD",
			Symbol:  "USDT",
		},
	}
)

func TestJettonVerifier_IsSimilarToWellKnownSymbol(t *testing.T) {
	tests := []struct {
		name            string
		tokenName       string
		symbol          string
		address         ton.AccountID
		wantBlacklisted bool
	}{
		{
			name:            "similar to TON",
			symbol:          "ton",
			wantBlacklisted: true,
		},
		{
			name:            "similar to TON",
			symbol:          "$TON",
			wantBlacklisted: true,
		},
		{
			name:            "similar to TON2",
			symbol:          "TON.",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdt",
			symbol:          "jUSDT ",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdt",
			symbol:          "USD₮",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdt",
			symbol:          "$USD₮",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdt",
			symbol:          "USD₮$",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdt",
			symbol:          "U$DT",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdt",
			symbol:          "$U$DT",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdt",
			symbol:          "$USD₮",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdt",
			tokenName:       "$USDT",
			symbol:          "Teher USD",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdt",
			symbol:          "jU⁣SDT",
			wantBlacklisted: true,
		},
		{
			name:            "fake usdc",
			symbol:          "USĐC",
			wantBlacklisted: true,
		},
		{
			name:            "similar to TON, first letter is cyrillic",
			symbol:          "ТОN",
			wantBlacklisted: true,
		},
		{
			name:            "similar to TON, last letter is cyrillic",
			symbol:          "jUSDТ",
			wantBlacklisted: true,
		},
		{
			name:            "original jUSDC",
			symbol:          "jUSDC",
			address:         ton.MustParseAccountID("0:7e30fc2b7751ba58a3642f3fd59d5e96a810ddd78d8a310bfe8353bef10500df"),
			wantBlacklisted: false,
		},
		{
			name:            "original jUSDT",
			symbol:          "jUSDT",
			address:         ton.MustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
			wantBlacklisted: false,
		},
		{
			name:            "valid duplicate of jUSDT",
			symbol:          "jUSDT",
			address:         ton.MustParseAccountID("-1:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
			wantBlacklisted: false,
		},
		{
			name:            "jUSDT but with different address",
			symbol:          "jUSDT",
			address:         ton.MustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a1700"),
			wantBlacklisted: true,
		},
		{
			name:            "jUSDT but with different address and non ascii symbols",
			symbol:          "jUЅDT",
			address:         ton.MustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a1700"),
			wantBlacklisted: true,
		},
		{
			symbol:          "jUSDT",
			address:         ton.MustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
			wantBlacklisted: false,
		},
		{
			symbol:          "CFT",
			address:         tongo.MustParseAccountID("0:a6e0456ba1ca77e0915e94760f1b1fc3e292aa43e812ebfc45650cc8c3003e58"),
			wantBlacklisted: false,
		},
		{
			symbol:          "CFT",
			address:         tongo.AccountID{}, // emulate different address
			wantBlacklisted: true,
		},
		{
			symbol:          "Random Symbol",
			address:         tongo.AccountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid cyrillic symbol",
			symbol:          "Токен",
			address:         tongo.AccountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid German symbol",
			symbol:          "genießen",
			address:         tongo.AccountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid Hindi symbol",
			symbol:          "टोकन",
			address:         tongo.AccountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid Marathi symbol",
			symbol:          "टोकन",
			address:         tongo.AccountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid Telugu symbol",
			symbol:          "టోకెన్",
			address:         tongo.AccountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid symbol with typographic apostrophe",
			symbol:          "Juli\u2019s Cat",
			address:         tongo.AccountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid symbol with left single quotation mark",
			symbol:          "\u2018Token\u2019",
			address:         tongo.AccountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid symbol with typographic double quotes",
			symbol:          "\u201CSmart\u201D",
			address:         tongo.AccountID{},
			wantBlacklisted: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &JettonVerifier{}
			verifier.updateJettons(testKnownJettons)
			similar := verifier.IsBlacklisted(tt.address, tt.symbol)
			if tt.tokenName != "" {
				similar = similar || verifier.IsBlacklisted(tt.address, tt.tokenName)
			}
			require.Equal(t, tt.wantBlacklisted, similar)

		})
	}
}

func TestJettonVerifier_run(t *testing.T) {
	verifier := &JettonVerifier{
		jettons: map[string]map[tongo.AccountID]jetton{},
	}
	knownJettons, err := downloadJettons()
	require.Nil(t, err)
	verifier.updateJettons(knownJettons)

	jettons := verifier.jettons[""]
	for _, jetton := range jettons {
		fmt.Printf("jetton %v simplified to an empty string\n", jetton.Name)
	}
	require.Equal(t, 0, len(jettons))
}
