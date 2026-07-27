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
	Tier       string
}

// CompiledRules 全局编译后的规则 (由 key 包设置)
var CompiledRules []*CompiledRule

// ScanFile 使用全局扫描选项扫描单个文件。
func ScanFile(filePath string, content []byte, collector *DataCollector) error {
	return ScanFileWithOptions(filePath, content, collector, GetGlobalScanOptions())
}

// ScanFileWithOptions 按选项扫描单个文件。
func ScanFileWithOptions(filePath string, content []byte, collector *DataCollector, opts ScanOptions) error {
	if collector == nil {
		return nil
	}
	if !ShouldScanPath(filePath) {
		return nil
	}

	if opts.MaxLineBytes <= 0 {
		opts.MaxLineBytes = DefaultMaxLineBytes
	}

	// 复用一次 string 转换
	text := string(content)
	if strings.TrimSpace(text) == "" {
		return nil
	}

	extractAPI := opts.ExtractAPI && !opts.DisableExtractAPI
	if extractAPI && looksLikeAPIContent(text) {
		// 正则 + AST 互补；AST 失败不影响正则结果
		merged := mergeAPIEndpoints(
			ExtractAPIEndpointsFromText(filePath, text),
			ExtractAPIEndpointsAST(filePath, text),
		)
		for _, endpoint := range merged {
			collector.AddAPIEndpoint(endpoint)
		}
	}

	rules := activeRulesForOptions(opts)
	if len(rules) == 0 {
		return nil
	}

	// 按行扫描以获取行号
	lineScanner := bufio.NewScanner(strings.NewReader(text))
	// 设置更大的缓冲区以支持压缩后的超长行（默认 64KB，这里设置为 10MB）
	const maxScanTokenSize = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxScanTokenSize)
	lineScanner.Buffer(buf, maxScanTokenSize)
	lineNumber := 1
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	for lineScanner.Scan() {
		line := lineScanner.Text()
		if strings.TrimSpace(line) == "" {
			lineNumber++
			continue
		}

		lineRules := rules
		// 超长行：仅跑 high/critical，并对内容分块匹配，避免 920 条规则扫整块
		if len(line) > opts.MaxLineBytes {
			lineRules = highPriorityRules(rules)
			if len(lineRules) == 0 {
				lineNumber++
				continue
			}
			scanLineChunks(filePath, line, lineNumber, lineRules, collector, timestamp, opts.MaxLineBytes)
			lineNumber++
			continue
		}

		scanLineWithRules(filePath, line, lineNumber, lineRules, collector, timestamp)
		lineNumber++
	}

	return lineScanner.Err()
}

func scanLineWithRules(filePath, line string, lineNumber int, rules []*CompiledRule, collector *DataCollector, timestamp string) {
	// 截断 context，避免把整段压缩 JS 写进报告
	context := line
	if len(context) > 2000 {
		context = context[:2000] + "..."
	}

	for _, rule := range rules {
		if rule == nil || rule.Pattern == nil {
			continue
		}
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
				Context:    context,
				Confidence: rule.Confidence,
				Timestamp:  timestamp,
			}
			collector.Add(item)
		}
	}
}

func scanLineChunks(filePath, line string, lineNumber int, rules []*CompiledRule, collector *DataCollector, timestamp string, chunkSize int) {
	if chunkSize <= 0 {
		chunkSize = DefaultMaxLineBytes
	}
	// 轻微重叠，减少跨块截断
	overlap := 256
	if overlap >= chunkSize {
		overlap = chunkSize / 8
	}
	for start := 0; start < len(line); {
		end := start + chunkSize
		if end > len(line) {
			end = len(line)
		}
		chunk := line[start:end]
		scanLineWithRules(filePath, chunk, lineNumber, rules, collector, timestamp)
		if end >= len(line) {
			break
		}
		start = end - overlap
	}
}
