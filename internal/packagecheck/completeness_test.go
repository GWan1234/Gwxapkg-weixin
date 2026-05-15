package packagecheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeDetectsMissingSubpackagesAndPlaceholders(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.json"), `{
  "pages": ["pages/home/index"],
  "subPackages": [
    {"root": "sub-pages/real", "pages": ["index/index"]},
    {"root": "sub-pages/missing", "pages": ["index/index"]}
  ]
}`)
	writeFile(t, filepath.Join(root, "pages/home/index.js"), "Page({})")
	writeFile(t, filepath.Join(root, "pages/home/index.wxml"), "<view />")
	writeFile(t, filepath.Join(root, "sub-pages/real/index/index.js"), "Page({onLoad:function(){}})")
	writeFile(t, filepath.Join(root, "sub-pages/real/index/index.wxml"), `<import src="../../../base.wxml" />`)
	writeFile(t, filepath.Join(root, "sub-pages/missing/index/index.js"), placeholderJS("sub-pages/missing/index/index"))
	writeFile(t, filepath.Join(root, "sub-pages/missing/index/index.wxml"), placeholderWXML("sub-pages/missing/index/index"))

	report, err := Analyze(root, "wx123", []string{
		filepath.Join(root, "__APP__.wxapkg"),
		filepath.Join(root, "_sub-pages_real_.wxapkg"),
	})
	if err != nil {
		t.Fatalf("Analyze 失败: %v", err)
	}

	if report.Status != StatusPartial {
		t.Fatalf("应标记为 partial，实际: %s", report.Status)
	}
	if report.DeclaredSubpackageCount != 2 || report.FoundSubpackageCount != 1 || report.MissingSubpackageCount != 1 {
		t.Fatalf("分包统计不正确: %#v", report)
	}
	if report.DeclaredPageCount != 3 || report.RealPageCount != 2 || report.PlaceholderPageCount != 1 {
		t.Fatalf("页面统计不正确: %#v", report)
	}
	if len(report.MissingSubpackages) != 1 || report.MissingSubpackages[0] != "sub-pages/missing" {
		t.Fatalf("缺失分包不正确: %#v", report.MissingSubpackages)
	}
}

func TestAnalyzeFullWhenAllPagesAreReal(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.json"), `{
  "pages": ["pages/home/index"],
  "subPackages": [
    {"root": "sub-pages/real", "pages": ["index/index"]}
  ]
}`)
	writeFile(t, filepath.Join(root, "pages/home/index.js"), "Page({})")
	writeFile(t, filepath.Join(root, "pages/home/index.wxml"), "<view />")
	writeFile(t, filepath.Join(root, "sub-pages/real/index/index.js"), "Page({})")
	writeFile(t, filepath.Join(root, "sub-pages/real/index/index.wxml"), "<view />")

	report, err := Analyze(root, "wx123", []string{
		filepath.Join(root, "__APP__.wxapkg"),
		filepath.Join(root, "_sub-pages_real_.wxapkg"),
	})
	if err != nil {
		t.Fatalf("Analyze 失败: %v", err)
	}
	if report.Status != StatusFull {
		t.Fatalf("应标记为 full，实际: %#v", report)
	}
}

func TestWriteAndReadReport(t *testing.T) {
	root := t.TempDir()
	report := &Report{
		AppID:                   "wx123",
		Status:                  StatusPartial,
		DeclaredSubpackageCount: 2,
		FoundSubpackageCount:    1,
		MissingSubpackageCount:  1,
	}
	if err := WriteReport(root, report); err != nil {
		t.Fatalf("WriteReport 失败: %v", err)
	}
	loaded, err := ReadReport(root)
	if err != nil {
		t.Fatalf("ReadReport 失败: %v", err)
	}
	if loaded.AppID != "wx123" || loaded.Status != StatusPartial {
		t.Fatalf("读取报告不正确: %#v", loaded)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
}
