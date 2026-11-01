package scam_backoffice_rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testKnownJettons = []jetton{
		{
			Name:    "Cock Fights Token",
			Symbol:  "CFT",
			Address: mustParseAccountID("0:a6e0456ba1ca77e0915e94760f1b1fc3e292aa43e812ebfc45650cc8c3003e58"),
		},
		{
			Name:    "jUSDT",
			Symbol:  "jUSDT",
			Address: mustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
		},
		{
			Name:    "Valid duplicate of jUSDT",
			Symbol:  "jUSDT",
			Address: mustParseAccountID("-1:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
		},
		{
			Name:    "Ambra",
			Symbol:  "AMBR",
			Address: mustParseAccountID("0:9c2c05b9dfb2a7460fda48fae7409a32623399933a98a7a15599152f37572b49"),
		},
		{
			// this is a fake token added to the well-known jettons list to ban scam tokens
			Address: mustParseAccountID("0:ca9006bd3fb03d355daeeff93b24be90afaa6e3ca0073ff5720f8a852c933278"),
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
		address         accountID
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
			address:         mustParseAccountID("0:7e30fc2b7751ba58a3642f3fd59d5e96a810ddd78d8a310bfe8353bef10500df"),
			wantBlacklisted: false,
		},
		{
			name:            "original jUSDT",
			symbol:          "jUSDT",
			address:         mustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
			wantBlacklisted: false,
		},
		{
			name:            "valid duplicate of jUSDT",
			symbol:          "jUSDT",
			address:         mustParseAccountID("-1:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
			wantBlacklisted: false,
		},
		{
			name:            "jUSDT but with different address",
			symbol:          "jUSDT",
			address:         mustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a1700"),
			wantBlacklisted: true,
		},
		{
			name:            "jUSDT but with different address and non ascii symbols",
			symbol:          "jUЅDT",
			address:         mustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a1700"),
			wantBlacklisted: true,
		},
		{
			symbol:          "jUSDT",
			address:         mustParseAccountID("0:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2"),
			wantBlacklisted: false,
		},
		{
			symbol:          "CFT",
			address:         mustParseAccountID("0:a6e0456ba1ca77e0915e94760f1b1fc3e292aa43e812ebfc45650cc8c3003e58"),
			wantBlacklisted: false,
		},
		{
			symbol:          "CFT",
			address:         accountID{}, // emulate different address
			wantBlacklisted: true,
		},
		{
			symbol:          "Random Symbol",
			address:         accountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid cyrillic symbol",
			symbol:          "Токен",
			address:         accountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid German symbol",
			symbol:          "genießen",
			address:         accountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid Hindi symbol",
			symbol:          "टोकन",
			address:         accountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid Marathi symbol",
			symbol:          "टोकन",
			address:         accountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid Telugu symbol",
			symbol:          "టోకెన్",
			address:         accountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid symbol with typographic apostrophe",
			symbol:          "Juli\u2019s Cat",
			address:         accountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid symbol with left single quotation mark",
			symbol:          "\u2018Token\u2019",
			address:         accountID{},
			wantBlacklisted: false,
		},
		{
			name:            "valid symbol with typographic double quotes",
			symbol:          "\u201CSmart\u201D",
			address:         accountID{},
			wantBlacklisted: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &JettonVerifier{}
			verifier.updateJettons(testKnownJettons)
			similar := verifier.IsBlacklisted(tt.address.workchain, tt.address.address, tt.symbol)
			if tt.tokenName != "" {
				similar = similar || verifier.IsBlacklisted(tt.address.workchain, tt.address.address, tt.tokenName)
			}
			require.Equal(t, tt.wantBlacklisted, similar)

		})
	}
}

func TestJettonVerifier_run(t *testing.T) {
	verifier := &JettonVerifier{
		jettons: map[string]map[accountID]jetton{},
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

func TestParseAccountID(t *testing.T) {
	raw := mustParseAccountID("0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe")
	for _, s := range []string{
		"EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs",
		"EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id/sDs",
		"UQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_p0p",
	} {
		id, err := parseAccountID(s)
		require.NoError(t, err, s)
		require.Equal(t, raw, id, s)
	}
	_, err := parseAccountID("EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDt")
	require.Error(t, err)
	_, err = parseAccountID("0:b113")
	require.Error(t, err)
	masterchain := mustParseAccountID("-1:729c13b6df2c07cbf0a06ab63d34af454f3d320ec1bcd8fb5c6d24d0806a17c2")
	require.Equal(t, int32(-1), masterchain.workchain)
}

func mustParseAccountID(s string) accountID {
	id, err := parseAccountID(s)
	if err != nil {
		panic(err)
	}
	return id
}
