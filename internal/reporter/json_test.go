package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/25smoking/Gwxapkg/internal/scanner"
)

func TestJSONReporterGeneratesMachineReadableReport(t *testing.T) {
	report := &scanner.ScanReport{
		AppID:      "wx-test",
		ScanTime:   "2026-05-15 12:00:00",
		TotalFiles: 2,
		Items: []scanner.SensitiveItem{
			{
				RuleID:     "api",
				RuleName:   "接口地址",
				Category:   "url",
				Content:    "https://example.com/api",
				FilePath:   "app.js",
				LineNumber: 7,
				Confidence: "high",
			},
		},
		APIEndpoints: []scanner.APIEndpoint{
			{
				Name:       "GetECert",
				Method:     "GET",
				FilePath:   "api/cert.js",
				LineNumber: 12,
			},
		},
		Summary: scanner.ReportSummary{
			TotalMatches:  1,
			UniqueMatches: 1,
			HighRisk:      1,
			CategoryStats: map[string]int{"url": 1},
		},
	}

	output := filepath.Join(t.TempDir(), "nested", "sensitive_report.json")
	if err := NewJSONReporter().Generate(report, output); err != nil {
		t.Fatalf("Generate 返回错误: %v", err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("读取 JSON 报告失败: %v", err)
	}

	var decoded scanner.ScanReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("生成内容不是合法 JSON: %v", err)
	}
	if decoded.AppID != "wx-test" || len(decoded.APIEndpoints) != 1 || decoded.Summary.HighRisk != 1 {
		t.Fatalf("JSON 报告字段不完整: %+v", decoded)
	}
}
