package scam_backoffice_rules

import (
	"encoding/json"
	"fmt"
	"golang.org/x/exp/slices"
	"net/http"
	"sync"
	"time"
	"unicode"

	"github.com/avast/retry-go"
	"github.com/labstack/gommon/log"
	"github.com/tonkeeper/tongo"
)

const jettonPath = "https://raw.githubusercontent.com/tonkeeper/ton-assets/main/jettons.json"

// JettonVerifier helps to blacklist jettons based on their similarity to well-known jettons.
// The list of well-known jettons is maintained by the community and can be found there:
// https://raw.githubusercontent.com/tonkeeper/ton-assets/main/jettons.json
type JettonVerifier struct {
	// mu protects Jettons
	mu      sync.RWMutex
	jettons map[string]map[tongo.AccountID]jetton
}

type jetton struct {
	Name    string          `json:"name"`
	Address tongo.AccountID `json:"address"`
	Symbol  string          `json:"symbol"`
}

// hardcodedBlacklistedSymbols contains symbols that are known to be used by scam jettons.
var hardcodedBlacklistedSymbols = []string{
	"ton",
	"$ton",
	"toncoin",
	"$usdt",
	"usdt$",
	"$usdt$",
	"usdc",
	"$usdc",
	"usdc$",
	"$usdc$",
	"usd",
	"$usd",
	"usd$",
	"tetherusd",
	"usdtether",
}

// allowedRanges specifies what unicode characters are safe to be used in jetton symbols.
// Unicode is so powerful that it is easy to trick a human into thinking that a scam jetton is a well-known one.
// So blacklisting is kind of challenging.
//
// An ideal jetton should probably have a plain-English symbol, like "jUSDT".
//
// If you feel that some unicode range should be added to this list,
// please create an issue or open a request.
var allowedRanges = []*unicode.RangeTable{ //ordered by popularity
	unicode.Latin,
	unicode.ASCII_Hex_Digit,
	unicode.Space,
	unicode.Mark,
	unicode.Dash,
	simplePunct,
	unicode.Cyrillic,
	manuallyWhitelisted,
	unicode.Hyphen,
	unicode.Telugu,
	unicode.Devanagari,
	unicode.Katakana,
}

var simplePunct = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x0021, 0x0023, 1},
		{0x0025, 0x002a, 1},
		{0x002c, 0x002f, 1},
		{0x003a, 0x003b, 1},
		{0x003f, 0x0040, 1},
		{0x005b, 0x005d, 1},
		{0x005f, 0x007b, 28},
		{0x007d, 0x00a1, 36},
	},
}

var manuallyWhitelisted = &unicode.RangeTable{
	R16: []unicode.Range16{
		{36, 36, 1},   //$
		{43, 43, 1},   //+
		{61, 61, 1},   //=
		{126, 126, 1}, //~
		{8366, 8366, 1},
	},
	R32: []unicode.Range32{
		{0x2764, 0x2764, 1},   //❤
		{0x4eba, 0x4eba, 1},   //
		{0x56fd, 0x56fd, 1},   //国人
		{0x5e01, 0x5e01, 1},   //币
		{0x9fb1, 0x9fb1, 1},   //龱
		{0x1f48e, 0x1f48e, 1}, //💎

	},
}

func NewJettonVerifier() *JettonVerifier {
	verifier := JettonVerifier{
		// we have valid jettons sharing the same symbol
		jettons: map[string]map[tongo.AccountID]jetton{},
	}
	go verifier.run()
	return &verifier
}

func (verifier *JettonVerifier) run() {
	for {
		_ = retry.Do(func() error {
			knownJettons, err := downloadJettons()
			if err != nil {
				log.Errorf("failed to download jettons: %v", err)
				return err
			}
			verifier.updateJettons(knownJettons)
			return nil
		}, retry.Attempts(3), retry.Delay(5*time.Second))

		time.Sleep(time.Hour * 1)
	}
}

func (verifier *JettonVerifier) updateJettons(knownJettons []jetton) {
	jettons := make(map[string]map[tongo.AccountID]jetton, len(knownJettons))
	for _, item := range knownJettons {
		normalized := NormalizeString(item.Symbol)
		if _, ok := jettons[normalized]; !ok {
			jettons[normalized] = make(map[tongo.AccountID]jetton)
		}
		jettons[normalized][item.Address] = item
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.jettons = jettons
}

// IsBlacklisted returns true if the jetton SYMBOL is similar to any of the well-known jettons.
func (verifier *JettonVerifier) IsBlacklisted(address tongo.AccountID, symbol string) bool {
	for _, s := range symbol {
		// if the symbol contains non-printable characters,
		// we consider it a scam.
		if !unicode.IsGraphic(s) {
			return true
		}
	}
	for _, s := range symbol {
		if !unicode.In(s, allowedRanges...) {
			return true
		}
	}
	symbol = NormalizeString(symbol)
	if slices.Contains(hardcodedBlacklistedSymbols, symbol) {
		return true
	}
	verifier.mu.RLock()
	defer verifier.mu.RUnlock()

	jettons, ok := verifier.jettons[symbol]
	if !ok {
		// no jettons with such symbol
		return false
	}
	if _, ok := jettons[address]; ok {
		// this jetton is in our list of well-known jettons
		return false
	}
	return true
}

func downloadJettons() ([]jetton, error) {
	resp, err := http.Get(jettonPath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("invalid status code %v", resp.StatusCode)
	}
	var jettons []jetton
	if err = json.NewDecoder(resp.Body).Decode(&jettons); err != nil {
		return nil, err
	}
	return jettons, nil
}
