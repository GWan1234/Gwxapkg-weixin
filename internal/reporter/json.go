package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/25smoking/Gwxapkg/internal/scanner"
)

// JSONReporter 生成适合自动化和 LLM 审计读取的结构化扫描报告。
type JSONReporter struct{}

// NewJSONReporter 创建 JSON 报告生成器。
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// Generate 将敏感信息扫描报告写出为 JSON。
func (r *JSONReporter) Generate(report *scanner.ScanReport, filename string) error {
	if report == nil {
		return fmt.Errorf("报告为空")
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 JSON 报告失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("写入 JSON 报告失败: %w", err)
	}
	return nil
}
