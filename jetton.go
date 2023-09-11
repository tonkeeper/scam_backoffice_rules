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
	Name             string `json:"name"`
	Address          string `json:"address"`
	Symbol           string `json:"symbol"`
	NormalizedSymbol string `json:"normalized_symbol"`
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

func (jr *JettonEvaluate) SortJettons() {
	sort.SliceStable(jr.Jettons, func(i, j int) bool {
		return jr.Jettons[i].NormalizedSymbol < jr.Jettons[j].NormalizedSymbol
	})
}

func (jr *JettonEvaluate) refresh() error {
	knownJettons, err := downloadJettons()
	if err != nil {
		log.Errorf("failed to download jettons: %v", err)
		return err
	}
	for idx, item := range knownJettons {
		accountID, err := tongo.ParseAccountID(item.Address)
		if err != nil {
			continue
		}
		item.Address = accountID.ToRaw()
		item.NormalizedSymbol = strings.ToLower(normalizeReg.ReplaceAllString(item.Symbol, ""))
		knownJettons[idx] = item
	}

	jr.mu.Lock()
	defer jr.mu.Unlock()
	jr.Jettons = knownJettons

	return nil
}

func (jr *JettonEvaluate) SearchAction(symbol string) TypeOfAction {
	jr.mu.RLock()
	knownJettons := jr.Jettons
	jr.mu.RUnlock()

	symbol = strings.ToLower(normalizeReg.ReplaceAllString(symbol, ""))

	index := sort.Search(len(knownJettons), func(i int) bool {
		return jr.Jettons[i].NormalizedSymbol >= symbol
	})
	if index < len(knownJettons) && knownJettons[index].NormalizedSymbol == symbol {
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
