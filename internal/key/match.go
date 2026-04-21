package key

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/25smoking/Gwxapkg/internal/scanner"
)

var (
	rulesInstance   *Rules
	once            sync.Once
	jsonMutex       sync.Mutex
	globalCollector *scanner.DataCollector
	collectorMutex  sync.Mutex
)

func getRulesInstance() (*Rules, error) {
	var err error
	once.Do(func() {
		rulesInstance, err = ReadRuleFile()
	})
	return rulesInstance, err
}

func MatchRules(input string) error {
	rules, err := getRulesInstance()
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	for _, rule := range rules.Rules {
		if rule.Enabled {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return fmt.Errorf("failed to compile regex for rule %s: %v", rule.Id, err)
			}
			matches := re.FindAllStringSubmatch(input, -1)
			for _, match := range matches {
				if len(match) > 0 {
					if strings.TrimSpace(match[0]) == "" {
						continue
					}
					err := appendToJSON(rule.Id, match[0])
					if err != nil {
						return fmt.Errorf("failed to append to JSON: %v", err)
					}
				}
			}
		}
	}

	return nil
}

func appendToJSON(ruleId, matchedContent string) error {
	jsonMutex.Lock()
	defer jsonMutex.Unlock()

	file, err := os.OpenFile("sensitive_data.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open JSON file: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("failed to close JSON file: %v", err)
		}
	}(file)

	record := map[string]string{
		"rule_id": ruleId,
		"content": matchedContent,
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("failed to write to JSON file: %v", err)
	}

	return nil
}

// InitCollector 初始化全局收集器
func InitCollector(appID string) {
	collectorMutex.Lock()
	defer collectorMutex.Unlock()
	globalCollector = scanner.NewCollector(appID)
}

// GetCollector 获取全局收集器
func GetCollector() *scanner.DataCollector {
	collectorMutex.Lock()
	defer collectorMutex.Unlock()
	return globalCollector
}

// ResetCollector 重置收集器
func ResetCollector() {
	collectorMutex.Lock()
	defer collectorMutex.Unlock()
	globalCollector = nil
}

// InitRules 初始化规则（预编译）
func InitRules() error {
	rules, err := ReadRuleFile()
	if err != nil {
		return fmt.Errorf("读取规则文件失败: %w", err)
	}

	compiledRules := make([]*scanner.CompiledRule, 0)
	for _, rule := range rules.Rules {
		if !rule.Enabled {
			continue
		}

		pattern, e := regexp.Compile(rule.Pattern)
		if e != nil {
			fmt.Printf("警告: 规则 %s 编译失败: %v\n", rule.Id, e)
			continue
		}

		compiledRules = append(compiledRules, &scanner.CompiledRule{
			ID:         rule.Id,
			Pattern:    pattern,
			Category:   scanner.GetCategoryKey(rule.Id),
			Confidence: scanner.GetConfidence(rule.Id),
		})
	}

	scanner.CompiledRules = compiledRules
	return nil
}
