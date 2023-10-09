package scam_backoffice_rules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/labstack/gommon/log"
	"github.com/tonkeeper/tongo"
)

var normalizeReg = regexp.MustCompile("[^\\p{L}\\p{N}]")

const jettonPath = "https://raw.githubusercontent.com/tonkeeper/ton-assets/main/jettons.json"

type JettonEvaluate struct {
	mu      sync.RWMutex
	Jettons map[string]jetton
}

type jetton struct {
	Name             string          `json:"name"`
	Address          tongo.AccountID `json:"address"`
	Symbol           string          `json:"symbol"`
	NormalizedSymbol string          `json:"normalized_symbol"`
}

func NewJettonEvaluate() *JettonEvaluate {
	jettonEvaluate := JettonEvaluate{
		Jettons: map[string]jetton{},
	}
	go func() {
		for {
			for attempt := 0; attempt <= 3; attempt++ {
				time.Sleep(time.Second * 5)
				if err := jettonEvaluate.refresh(); err == nil {
					break
				}
				log.Errorf("next attempt for load known jettons...")
			}
			time.Sleep(time.Hour * 1)
		}
	}()
	return &jettonEvaluate
}

func (jr *JettonEvaluate) refresh() error {
	knownJettons, err := downloadJettons()
	if err != nil {
		log.Errorf("failed to download jettons: %v", err)
		return err
	}
	jr.updateJettons(knownJettons)
	return nil
}

func (jr *JettonEvaluate) updateJettons(knownJettons []jetton) {
	jettons := make(map[string]jetton, len(knownJettons))
	for _, item := range knownJettons {
		item.NormalizedSymbol = strings.ToLower(normalizeReg.ReplaceAllString(item.Symbol, ""))
		jettons[item.NormalizedSymbol] = item
	}

	jr.mu.Lock()
	defer jr.mu.Unlock()
	jr.Jettons = jettons
}

func (jr *JettonEvaluate) SearchAction(address tongo.AccountID, symbol string) TypeOfAction {
	jr.mu.RLock()
	defer jr.mu.RUnlock()

	symbol = strings.ToLower(normalizeReg.ReplaceAllString(symbol, ""))
	if jetton, ok := jr.Jettons[symbol]; ok && jetton.Address != address {
		return Drop
	}
	return Accept
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
