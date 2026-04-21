package scanner

import (
	"bufio"
	"regexp"
	"strings"
	"time"
)

// CompiledRule 编译后的规则
type CompiledRule struct {
	ID         string
	Pattern    *regexp.Regexp
	Category   string
	Confidence string
}

// CompiledRules 全局编译后的规则 (由 key 包设置)
var CompiledRules []*CompiledRule

// ScanFile 扫描单个文件
func ScanFile(filePath string, content []byte, collector *DataCollector) error {
	// 转换为字符串
	text := string(content)

	if collector != nil {
		for _, endpoint := range ExtractAPIEndpoints(filePath, content) {
			collector.AddAPIEndpoint(endpoint)
		}
	}

	// 按行扫描以获取行号
	scanner := bufio.NewScanner(strings.NewReader(text))
	// 设置更大的缓冲区以支持压缩后的超长行（默认 64KB，这里设置为 10MB）
	const maxScanTokenSize = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)
	lineNumber := 1

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			lineNumber++
			continue
		}

		// 使用所有规则扫描这一行
		for _, rule := range CompiledRules {
			matches := rule.Pattern.FindAllString(line, -1)
			for _, match := range matches {
				if strings.TrimSpace(match) == "" {
					continue
				}

				item := SensitiveItem{
					RuleID:     rule.ID,
					RuleName:   GetRuleName(rule.ID),
					Category:   rule.Category,
					Content:    match,
					FilePath:   filePath,
					LineNumber: lineNumber,
					Context:    line,
					Confidence: rule.Confidence,
					Timestamp:  time.Now().Format("2006-01-02 15:04:05"),
				}

				collector.Add(item)
			}
		}

		lineNumber++
	}

	return scanner.Err()
}
