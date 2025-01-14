package scam_backoffice_rules

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"github.com/labstack/gommon/log"
	"gopkg.in/yaml.v3"
)

//go:embed default_rules.yaml
var defaultRules []byte

type TypeOfAction string
type TypeOfPattern string

const (
	Accept   TypeOfAction = "accept"
	Drop     TypeOfAction = "drop"
	MarkScam TypeOfAction = "mark_scam"
	UnKnown  TypeOfAction = "unknown"
)

const (
	Comment TypeOfPattern = "comment"
	Nft     TypeOfPattern = "nft"
)

type ConvertedRules struct {
	Rules []struct {
		Pattern string          `yaml:"pattern" json:"pattern"`
		Action  TypeOfAction    `yaml:"action" json:"action"`
		Type    []TypeOfPattern `yaml:"type" json:"type"`
	} `yaml:"rules" json:"rules"`
}

type Rule struct {
	Evaluate func(comment string) TypeOfAction
	Type     []TypeOfPattern
}

type Rules []Rule

func LoadRules(bytesOfRules []byte, yamlConverted bool) Rules {
	var rules Rules
	var convertedRules ConvertedRules
	var err error

	if yamlConverted {
		err = yaml.Unmarshal(bytesOfRules, &convertedRules)
	} else {
		err = json.Unmarshal(bytesOfRules, &convertedRules)
	}
	if err != nil {
		log.Panicf("Failed to parse rules: %v", err)
	}

	for _, inputRule := range convertedRules.Rules {
		compiledRegexp, err := regexp.Compile(inputRule.Pattern)
		if err != nil {
			fmt.Printf("Failed to compile regexp for pattern %s: %v", inputRule.Pattern, err)
			continue
		}

		var rule Rule
		action := inputRule.Action
		rule.Evaluate = func(text string) TypeOfAction {
			match := compiledRegexp.MatchString(text)
			if !match {
				return UnKnown
			}
			return action
		}
		rule.Type = inputRule.Type
		rules = append(rules, rule)
	}

	return rules
}

func CheckAction(rules Rules, comment string) TypeOfAction {
	var err error
	comment, err = NormalizeComment(comment)
	if err != nil {
		return Drop
	}
	action := UnKnown
	for _, rule := range rules {
		action = rule.Evaluate(comment)
		if action != UnKnown {
			break
		}
	}
	return action
}

func CheckActionOfType(rules Rules, text string, patternType TypeOfPattern) TypeOfAction {
	var err error
	text, err = NormalizeComment(text)
	if err != nil {
		return Drop
	}
	action := UnKnown
	for _, rule := range rules {
		if slices.Contains(rule.Type, patternType) {
			action = rule.Evaluate(text)
			if action != UnKnown {
				break
			}
		}
	}
	return action
}

func GetDefaultRules() Rules {
	return LoadRules(defaultRules, true)
}
