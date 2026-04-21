package key

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Id      string `yaml:"id"`
	Enabled bool   `yaml:"enabled"`
	Pattern string `yaml:"pattern"`
}

type Rules struct {
	Rules []Rule `yaml:"rules"`
}

// defaultRulesYAML 内置去重后的默认规则集。
//
// 规则来源：
// 1. 旧版 config/rule.yaml
// 2. internal/key/800+ 规则.yml
//
// 合并时按 pattern 去重，优先保留旧版 config/rule.yaml 中已有规则，
// 从而维持现有 rule_id 与分类映射的稳定性。
//
//go:embed default_rules.yaml
var defaultRulesYAML []byte

func resolveRuleFilePath() string {
	return filepath.Join("config", "rule.yaml")
}

func ReadRuleFile() (*Rules, error) {
	configFile := resolveRuleFilePath()
	file, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return loadEmbeddedRules()
		}
		return nil, fmt.Errorf("error reading rule file: %v", err)
	}

	return parseRules(file)
}

func parseRules(data []byte) (*Rules, error) {
	var rules Rules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("error unmarshalling rule file: %v", err)
	}
	return &rules, nil
}

func loadEmbeddedRules() (*Rules, error) {
	if len(defaultRulesYAML) == 0 {
		return nil, fmt.Errorf("embedded default rules are empty")
	}
	return parseRules(defaultRulesYAML)
}

func CreateConfigFile() error {
	configFile := resolveRuleFilePath()
	if err := os.MkdirAll(filepath.Dir(configFile), 0755); err != nil {
		return fmt.Errorf("error creating config directory: %v", err)
	}

	rules, err := loadEmbeddedRules()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(rules)
	if err != nil {
		return fmt.Errorf("error marshalling default rules: %v", err)
	}

	if err := os.WriteFile(configFile, data, 0755); err != nil {
		return fmt.Errorf("error writing default rule file: %v", err)
	}

	return nil
}
