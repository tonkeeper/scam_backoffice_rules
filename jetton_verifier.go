package scam_backoffice_rules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

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
	jettons map[string]jetton
}

type jetton struct {
	Name    string          `json:"name"`
	Address tongo.AccountID `json:"address"`
	Symbol  string          `json:"symbol"`
}

func NewJettonVerifier() *JettonVerifier {
	verifier := JettonVerifier{
		jettons: map[string]jetton{},
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
	jettons := make(map[string]jetton, len(knownJettons))
	for _, item := range knownJettons {
		normalized := normalizeString(item.Symbol)
		jettons[normalized] = item
	}

	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.jettons = jettons
}

// IsBlacklisted returns true if the jetton SYMBOL is similar to any of the well-known jettons.
func (verifier *JettonVerifier) IsBlacklisted(address tongo.AccountID, symbol string) bool {
	symbol = normalizeString(symbol)
	if symbol == "ton" {
		return true
	}
	verifier.mu.RLock()
	defer verifier.mu.RUnlock()
	for normalizedSymbol, jetton := range verifier.jettons {
		if jetton.Address == address && normalizedSymbol == symbol {
			return false
		}
		if normalizedSymbol == symbol {
			return true
		}
	}
	return false
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
