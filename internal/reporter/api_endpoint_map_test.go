package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/25smoking/Gwxapkg/internal/scanner"
)

func TestAPIEndpointMapReporterGeneratesFallbackMapWithoutRedaction(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "api.js")
	if err := os.WriteFile(sourcePath, []byte(`request({url:"/api/token",method:"POST",client_secret:"secret-value"})`), 0644); err != nil {
		t.Fatalf("写入测试源码失败: %v", err)
	}

	report := &scanner.ScanReport{
		AppID: "wx-test",
		APIEndpoints: []scanner.APIEndpoint{
			{
				Name:       "POST /api/token",
				Method:     "POST",
				RawURL:     "/api/token",
				FilePath:   "api.js",
				LineNumber: 1,
				SourceRule: "object-request",
				Context:    `request({url:"/api/token",method:"POST",client_secret:"secret-value"})`,
			},
			{
				Name:       "GET /missing",
				Method:     "GET",
				RawURL:     "/missing",
				FilePath:   "app-service.js",
				LineNumber: 9,
				SourceRule: "url-field",
				Context:    `url:"/missing"`,
			},
		},
	}

	artifacts, err := NewAPIEndpointMapReporter().Generate(report, root, root)
	if err != nil {
		t.Fatalf("Generate 返回错误: %v", err)
	}

	data, err := os.ReadFile(artifacts.JSONPath)
	if err != nil {
		t.Fatalf("读取 JSON 失败: %v", err)
	}
	if !strings.Contains(string(data), "secret-value") {
		t.Fatalf("通用 endpoint map 不应脱敏原始上下文: %s", string(data))
	}

	var decoded APIEndpointMapReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON 无法解析: %v", err)
	}
	if decoded.EndpointCount != 2 || decoded.ExistingSourceCount != 1 || decoded.MissingSourceCount != 1 {
		t.Fatalf("统计不正确: %+v", decoded)
	}
	if !decoded.NoRedaction || decoded.RedactionPolicy == "" {
		t.Fatalf("应明确标记不脱敏策略: %+v", decoded)
	}
	if decoded.Endpoints[0].Context == "" {
		t.Fatalf("应保留 endpoint 上下文")
	}

	md, err := os.ReadFile(artifacts.MarkdownPath)
	if err != nil {
		t.Fatalf("读取 Markdown 失败: %v", err)
	}
	if !strings.Contains(string(md), "不脱敏") || !strings.Contains(string(md), "/api/token") {
		t.Fatalf("Markdown 内容不完整: %s", string(md))
	}
}
