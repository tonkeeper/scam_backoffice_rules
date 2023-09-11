package scam_backoffice_rules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
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
	Jettons []jetton
}

type jetton struct {
	Name             string          `json:"name"`
	Address          tongo.AccountID `json:"address"`
	Symbol           string          `json:"symbol"`
	NormalizedSymbol string          `json:"normalized_symbol"`
}

func NewJettonEvaluate() *JettonEvaluate {
	jettonEvaluate := JettonEvaluate{
		Jettons: []jetton{},
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
	for idx, item := range knownJettons {
		item.NormalizedSymbol = strings.ToLower(normalizeReg.ReplaceAllString(item.Symbol, ""))
		knownJettons[idx] = item
	}

	sort.Slice(knownJettons, func(i, j int) bool {
		return knownJettons[i].NormalizedSymbol < knownJettons[j].NormalizedSymbol
	})

	jr.mu.Lock()
	defer jr.mu.Unlock()
	jr.Jettons = knownJettons

	return nil
}

func (jr *JettonEvaluate) SearchAction(address tongo.AccountID, symbol string) TypeOfAction {
	jr.mu.RLock()
	knownJettons := jr.Jettons
	jr.mu.RUnlock()

	symbol = strings.ToLower(normalizeReg.ReplaceAllString(symbol, ""))

	left, right := 0, len(knownJettons)-1
	for left <= right {
		mid := left + (right-left)/2

		if knownJettons[mid].NormalizedSymbol == symbol && knownJettons[mid].Address != address {
			return Drop
		} else if knownJettons[mid].NormalizedSymbol < symbol {
			left = mid + 1
		} else {
			right = mid - 1
		}
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
