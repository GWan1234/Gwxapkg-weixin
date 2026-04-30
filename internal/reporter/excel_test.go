package reporter

import (
	"path/filepath"
	"testing"

	"github.com/25smoking/Gwxapkg/internal/scanner"
	"github.com/xuri/excelize/v2"
)

func TestSafeExcelSheetName(t *testing.T) {
	used := map[string]struct{}{"Sheet1": {}}

	first := safeExcelSheetName("URL/API", "url", used)
	if first != "URL_API" {
		t.Fatalf("非法字符应被替换，got %q", first)
	}

	second := safeExcelSheetName("URL?API", "url2", used)
	if second != "URL_API_1" {
		t.Fatalf("重名 sheet 应追加后缀，got %q", second)
	}

	long := safeExcelSheetName("这是一个非常非常非常非常非常长的分类名称/with/slash", "long", used)
	if len([]rune(long)) > 31 {
		t.Fatalf("sheet 名不能超过 31 个字符，got %q", long)
	}
}

func TestExcelReporterGeneratesWithIllegalCategoryName(t *testing.T) {
	report := &scanner.ScanReport{
		AppID:      "wx-test",
		ScanTime:   "2026-04-30 12:00:00",
		TotalFiles: 1,
		Categories: map[string]*scanner.CategoryData{
			"url": {
				Name:        "URL/API",
				Count:       1,
				UniqueCount: 1,
				Items: map[string][]scanner.LocationInfo{
					"https://example.com": {
						{FilePath: "app.js", LineNumber: 1},
					},
				},
			},
		},
		Summary: scanner.ReportSummary{
			TotalMatches:  1,
			UniqueMatches: 1,
			LowRisk:       1,
			CategoryStats: map[string]int{"url": 1},
		},
	}

	output := filepath.Join(t.TempDir(), "report.xlsx")
	if err := NewExcelReporter().Generate(report, output); err != nil {
		t.Fatalf("Generate 返回错误: %v", err)
	}

	file, err := excelize.OpenFile(output)
	if err != nil {
		t.Fatalf("打开生成的 Excel 失败: %v", err)
	}
	defer file.Close()

	if index, err := file.GetSheetIndex("URL_API"); err != nil || index == -1 {
		t.Fatalf("应生成清洗后的 URL_API sheet，index=%d err=%v sheets=%v", index, err, file.GetSheetList())
	}
}
