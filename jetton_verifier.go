package scam_backoffice_rules

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/exp/slices"

	"github.com/avast/retry-go"
	"github.com/labstack/gommon/log"
)

const jettonPath = "https://raw.githubusercontent.com/tonkeeper/ton-assets/main/jettons.json"

// JettonVerifier helps to blacklist jettons based on their similarity to well-known jettons.
// The list of well-known jettons is maintained by the community and can be found there:
// https://raw.githubusercontent.com/tonkeeper/ton-assets/main/jettons.json
type JettonVerifier struct {
	// mu protects Jettons
	mu      sync.RWMutex
	jettons map[string]map[accountID]jetton
}

type jetton struct {
	Name    string    `json:"name"`
	Address accountID `json:"address"`
	Symbol  string    `json:"symbol"`
}

type accountID struct {
	workchain int32
	address   [32]byte
}

// hardcodedBlacklistedSymbols contains symbols that are known to be used by scam jettons.
var hardcodedBlacklistedSymbolsMutex sync.RWMutex
var hardcodedBlacklistedSymbols = []string{
	"ton",
	"$ton",
	"toncoin",
	"toncoins",
	"$usdt",
	"usdt$",
	"$usdt$",
	"u$dt",
	"$u$dt",
	"u$dt$",
	"$u$dt$",
	"usdc",
	"$usdc",
	"usdc$",
	"$usdc$",
	"u$dc",
	"$u$dc",
	"u$dc$",
	"$u$dc$",
	"usd",
	"$usd",
	"usd$",
	"$usd$",
	"u$d",
	"$u$d",
	"u$d$",
	"$u$d$",
	"tetherusd",
	"tetheru$d",
	"usdtether",
	"u$dtether",
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

// simplePunct contains basic ASCII punctuation allowed in jetton symbols.
var simplePunct = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x0021, 0x0023, 1},  // ! " #
		{0x0025, 0x002a, 1},  // % & ' ( ) *
		{0x002c, 0x002f, 1},  // , - . /
		{0x003a, 0x003b, 1},  // : ;
		{0x003f, 0x0040, 1},  // ? @
		{0x005b, 0x005d, 1},  // [ \ ]
		{0x005f, 0x007b, 28}, // _ {
		{0x007d, 0x00a1, 36}, // } ¡
	},
}

var manuallyWhitelisted = &unicode.RangeTable{
	R16: []unicode.Range16{
		{34, 34, 1},     // "
		{36, 36, 1},     // $
		{39, 39, 1},     // '
		{43, 43, 1},     // +
		{61, 61, 1},     // =
		{96, 96, 1},     // `
		{126, 126, 1},   // ~
		{8216, 8217, 1}, // ''
		{8220, 8221, 1}, // ""
		{8366, 8366, 1}, // ₮
	},
	R32: []unicode.Range32{
		{0x2764, 0x2764, 1},   // ❤
		{0x4eba, 0x4eba, 1},   // 人
		{0x56fd, 0x56fd, 1},   // 国
		{0x5e01, 0x5e01, 1},   // 币
		{0x9fb1, 0x9fb1, 1},   // 龱
		{0x1f48e, 0x1f48e, 1}, // 💎

	},
}

func NewJettonVerifier() *JettonVerifier {
	verifier := JettonVerifier{
		// we have valid jettons sharing the same symbol
		jettons: map[string]map[accountID]jetton{},
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
	jettons := make(map[string]map[accountID]jetton, len(knownJettons))
	for _, item := range knownJettons {
		normalized := NormalizeString(item.Symbol)
		if _, ok := jettons[normalized]; !ok {
			jettons[normalized] = make(map[accountID]jetton)
		}
		jettons[normalized][item.Address] = item
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.jettons = jettons
}

// IsBlacklisted returns true if the jetton SYMBOL is similar to any of the well-known jettons.
func (verifier *JettonVerifier) IsBlacklisted(workchain int32, address [32]byte, symbol string) bool {
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
	hardcodedBlacklistedSymbolsMutex.RLock()
	copyHardcodedBlacklistedSymbols := hardcodedBlacklistedSymbols
	hardcodedBlacklistedSymbolsMutex.RUnlock()
	if slices.Contains(copyHardcodedBlacklistedSymbols, symbol) {
		return true
	}
	verifier.mu.RLock()
	defer verifier.mu.RUnlock()

	jettons, ok := verifier.jettons[symbol]
	if !ok {
		// no jettons with such symbol
		return false
	}
	if _, ok := jettons[accountID{workchain: workchain, address: address}]; ok {
		// this jetton is in our list of well-known jettons
		return false
	}
	return true
}

func (id *accountID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := parseAccountID(s)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func SetBlacklistedSymbols(blacklistedSymbols []string) {
	hardcodedBlacklistedSymbolsMutex.Lock()
	hardcodedBlacklistedSymbols = blacklistedSymbols
	hardcodedBlacklistedSymbolsMutex.Unlock()
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

// parseAccountID accepts the raw form "workchain:hex" and the base64 user-friendly form.
func parseAccountID(s string) (accountID, error) {
	s = strings.TrimSpace(s)
	if workchain, hash, ok := strings.Cut(s, ":"); ok {
		return parseRawAccountID(workchain, hash)
	}
	return parseFriendlyAccountID(s)
}

func parseRawAccountID(workchain, hash string) (accountID, error) {
	var id accountID
	wc, err := strconv.ParseInt(workchain, 10, 32)
	if err != nil {
		return accountID{}, fmt.Errorf("invalid workchain %q: %w", workchain, err)
	}
	id.workchain = int32(wc)
	b, err := hex.DecodeString(hash)
	if err != nil || len(b) != len(id.address) {
		return accountID{}, fmt.Errorf("invalid account hash %q", hash)
	}
	copy(id.address[:], b)
	return id, nil
}

func parseFriendlyAccountID(s string) (accountID, error) {
	var id accountID
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(s)
	}
	if err != nil || len(b) != 36 {
		return accountID{}, fmt.Errorf("invalid account address %q", s)
	}
	if crc16(b[:34]) != binary.BigEndian.Uint16(b[34:]) {
		return accountID{}, fmt.Errorf("invalid account address %q: checksum mismatch", s)
	}
	id.workchain = int32(int8(b[1]))
	copy(id.address[:], b[2:34])
	return id, nil
}

// crc16 is CRC-16/XMODEM, the checksum of user-friendly addresses.
func crc16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
