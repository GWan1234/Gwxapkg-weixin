package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/25smoking/Gwxapkg/internal/scanner"
)

func TestHTMLReporterKeepsHighRiskVisible(t *testing.T) {
	report := &scanner.ScanReport{
		AppID:      "wx-test",
		ScanTime:   "2026-05-15 16:00:00",
		TotalFiles: 1,
		Categories: map[string]*scanner.CategoryData{
			"wechat": {
				Name:        "微信生态",
				Count:       1,
				UniqueCount: 1,
				Items: map[string][]scanner.LocationInfo{
					`"WECHAT_APPID_FIXTURE"`: {
						{FilePath: "app-service.js", LineNumber: 45072},
					},
				},
			},
		},
		Items: []scanner.SensitiveItem{
			{
				RuleID:     "wechat_appid",
				RuleName:   "微信 AppID",
				Category:   "wechat",
				Content:    `"WECHAT_APPID_FIXTURE"`,
				FilePath:   "app-service.js",
				LineNumber: 45072,
				Context:    `WEAPP: "WECHAT_APPID_FIXTURE"`,
				Confidence: "high",
			},
		},
		Summary: scanner.ReportSummary{
			TotalMatches:  1,
			UniqueMatches: 1,
			HighRisk:      1,
			CategoryStats: map[string]int{"wechat": 1},
		},
	}

	output := filepath.Join(t.TempDir(), "sensitive_report.html")
	if err := NewHTMLReporter().Generate(report, output); err != nil {
		t.Fatalf("Generate 返回错误: %v", err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("读取 HTML 失败: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, `id="panel-risk-high"`) {
		t.Fatalf("应生成高风险筛选面板")
	}
	if !strings.Contains(html, `risk-badge risk-high`) {
		t.Fatalf("高危项应显示为 risk-high，而不是默认低危")
	}
	if strings.Contains(html, `risk-badge risk-low">低</span></td>`) {
		t.Fatalf("唯一高危样本不应被渲染成低危")
	}
}
