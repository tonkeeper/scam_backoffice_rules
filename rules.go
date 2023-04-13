package scam_backoffice_rules

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/labstack/gommon/log"
	"gopkg.in/yaml.v3"
	"regexp"
)

//go:embed default_rules.yaml
var defaultRules []byte

type TypeOfAction string

const (
	Accept  TypeOfAction = "accept"
	Drop    TypeOfAction = "drop"
	UnKnown TypeOfAction = "unknown"
)

type ConvertedRules struct {
	Rules []struct {
		Pattern string       `yaml:"pattern" json:"pattern"`
		Action  TypeOfAction `yaml:"action" json:"action"`
	} `yaml:"rules" json:"rules"`
}

type Rule struct {
	Evaluate func(comment string) TypeOfAction
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
		rule.Evaluate = func(comment string) TypeOfAction {
			match := compiledRegexp.MatchString(comment)
			if !match {
				return UnKnown
			}
			return action
		}

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

func GetDefaultRules() []byte {
	return defaultRules
}
