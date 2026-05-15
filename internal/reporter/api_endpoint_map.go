package reporter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/25smoking/Gwxapkg/internal/scanner"
)

const (
	apiEndpointMapJSONFileName = "api_endpoint_map.json"
	apiEndpointMapMDFileName   = "api_endpoint_map.md"
)

// APIEndpointMapReporter 输出通用 API endpoint 地图，作为语义 api_map 覆盖不足时的 fallback。
type APIEndpointMapReporter struct{}

// APIEndpointMapArtifacts 记录通用 API 地图产物路径。
type APIEndpointMapArtifacts struct {
	JSONPath     string
	MarkdownPath string
}

// APIEndpointMapReport 描述扫描器提取到的通用请求端点。
type APIEndpointMapReport struct {
	GeneratedAt             string                `json:"generated_at"`
	AppID                   string                `json:"app_id"`
	EndpointCount           int                   `json:"endpoint_count"`
	ExistingSourceCount     int                   `json:"existing_source_count"`
	MissingSourceCount      int                   `json:"missing_source_count"`
	SourceRoot              string                `json:"source_root"`
	CoverageNotes           []string              `json:"coverage_notes,omitempty"`
	Endpoints               []APIEndpointMapEntry `json:"endpoints"`
	NoRedaction             bool                  `json:"no_redaction"`
	RedactionPolicy         string                `json:"redaction_policy"`
	GeneratedFromScanReport bool                  `json:"generated_from_scan_report"`
}

// APIEndpointMapEntry 是一个可追溯的通用 API endpoint 线索。
type APIEndpointMapEntry struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Method               string `json:"method"`
	RawURL               string `json:"raw_url"`
	Path                 string `json:"path,omitempty"`
	Query                string `json:"query,omitempty"`
	FilePath             string `json:"file_path"`
	LineNumber           int    `json:"line_number"`
	SourceRule           string `json:"source_rule"`
	Context              string `json:"context,omitempty"`
	SourceArtifactExists bool   `json:"source_artifact_exists"`
	ExistingSourcePath   string `json:"existing_source_path,omitempty"`
	EvidenceNote         string `json:"evidence_note,omitempty"`
}

// NewAPIEndpointMapReporter 创建通用 API endpoint 地图生成器。
func NewAPIEndpointMapReporter() *APIEndpointMapReporter {
	return &APIEndpointMapReporter{}
}

// Generate 写出 .gwxapkg/api_endpoint_map.json 和 .gwxapkg/api_endpoint_map.md。
func (r *APIEndpointMapReporter) Generate(report *scanner.ScanReport, sourceRoot string, outputRoot string) (*APIEndpointMapArtifacts, error) {
	if report == nil {
		return nil, fmt.Errorf("报告为空")
	}
	if outputRoot == "" {
		outputRoot = sourceRoot
	}
	reportDir := filepath.Join(outputRoot, ".gwxapkg")
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return nil, fmt.Errorf("创建 API endpoint 地图目录失败: %w", err)
	}

	endpoints := make([]APIEndpointMapEntry, 0, len(report.APIEndpoints))
	existingCount := 0
	for i, endpoint := range report.APIEndpoints {
		exists, existingPath := resolveEndpointSource(sourceRoot, endpoint.FilePath)
		if exists {
			existingCount++
		}
		entry := APIEndpointMapEntry{
			ID:                   fmt.Sprintf("endpoint-%04d", i+1),
			Name:                 endpoint.Name,
			Method:               normalizeEndpointMethod(endpoint.Method),
			RawURL:               endpoint.RawURL,
			FilePath:             filepath.ToSlash(endpoint.FilePath),
			LineNumber:           endpoint.LineNumber,
			SourceRule:           endpoint.SourceRule,
			Context:              endpoint.Context,
			SourceArtifactExists: exists,
			ExistingSourcePath:   existingPath,
		}
		entry.Path, entry.Query = splitEndpointURL(endpoint.RawURL)
		if !exists {
			entry.EvidenceNote = "扫描阶段记录的原始打包文件在当前还原目录中不可直接回读，请优先使用 context 字段和已还原源码二次定位。"
		}
		endpoints = append(endpoints, entry)
	}

	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].RawURL != endpoints[j].RawURL {
			return endpoints[i].RawURL < endpoints[j].RawURL
		}
		if endpoints[i].FilePath != endpoints[j].FilePath {
			return endpoints[i].FilePath < endpoints[j].FilePath
		}
		return endpoints[i].LineNumber < endpoints[j].LineNumber
	})

	mapReport := APIEndpointMapReport{
		GeneratedAt:             time.Now().Format("2006-01-02 15:04:05"),
		AppID:                   report.AppID,
		EndpointCount:           len(endpoints),
		ExistingSourceCount:     existingCount,
		MissingSourceCount:      len(endpoints) - existingCount,
		SourceRoot:              filepath.Clean(sourceRoot),
		Endpoints:               endpoints,
		NoRedaction:             true,
		RedactionPolicy:         "本地授权审计产物默认不脱敏，保留原始 URL、上下文和参数线索；仅在用户明确要求对外脱敏版时再处理。",
		GeneratedFromScanReport: true,
	}
	if mapReport.EndpointCount == 0 {
		mapReport.CoverageNotes = append(mapReport.CoverageNotes, "敏感扫描器未提取到通用 API endpoint。")
	}
	if mapReport.MissingSourceCount > 0 {
		mapReport.CoverageNotes = append(mapReport.CoverageNotes, "部分 endpoint 的 file_path 指向扫描阶段的原始打包文件，当前还原目录中不存在；context 字段仍可作为回溯线索。")
	}

	jsonPath := filepath.Join(reportDir, apiEndpointMapJSONFileName)
	data, err := json.MarshalIndent(mapReport, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化 API endpoint 地图失败: %w", err)
	}
	if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		return nil, fmt.Errorf("写入 API endpoint 地图失败: %w", err)
	}

	mdPath := filepath.Join(reportDir, apiEndpointMapMDFileName)
	if err := os.WriteFile(mdPath, []byte(buildAPIEndpointMapMarkdown(mapReport)), 0644); err != nil {
		return nil, fmt.Errorf("写入 API endpoint 地图 Markdown 失败: %w", err)
	}

	return &APIEndpointMapArtifacts{JSONPath: jsonPath, MarkdownPath: mdPath}, nil
}

func normalizeEndpointMethod(method string) string {
	value := strings.ToUpper(strings.TrimSpace(method))
	if value == "" {
		return "UNKNOWN"
	}
	return value
}

func resolveEndpointSource(sourceRoot string, relPath string) (bool, string) {
	if strings.TrimSpace(relPath) == "" {
		return false, ""
	}
	candidate := relPath
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(sourceRoot, filepath.FromSlash(relPath))
	}
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return true, candidate
	}
	return false, ""
}

func splitEndpointURL(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw, ""
	}
	if parsed.Path == "" {
		return raw, parsed.RawQuery
	}
	return parsed.Path, parsed.RawQuery
}

func buildAPIEndpointMapMarkdown(report APIEndpointMapReport) string {
	var builder strings.Builder
	builder.WriteString("# API Endpoint Map\n\n")
	builder.WriteString(fmt.Sprintf("- AppID: `%s`\n", report.AppID))
	builder.WriteString(fmt.Sprintf("- 端点数: `%d`\n", report.EndpointCount))
	builder.WriteString(fmt.Sprintf("- 可直接回读源码: `%d`\n", report.ExistingSourceCount))
	builder.WriteString(fmt.Sprintf("- 原始打包路径缺失: `%d`\n", report.MissingSourceCount))
	builder.WriteString("- 脱敏策略: `不脱敏，本地授权审计保留原始证据`\n\n")

	if len(report.CoverageNotes) > 0 {
		builder.WriteString("## 覆盖说明\n\n")
		for _, note := range report.CoverageNotes {
			builder.WriteString("- ")
			builder.WriteString(note)
			builder.WriteByte('\n')
		}
		builder.WriteByte('\n')
	}

	builder.WriteString("## Endpoints\n\n")
	builder.WriteString("| ID | Method | URL | 文件 | 行号 | 规则 | 源文件存在 | Context |\n")
	builder.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, endpoint := range report.Endpoints {
		builder.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | `%d` | `%s` | `%t` | %s |\n",
			endpoint.ID,
			escapeTableCell(endpoint.Method),
			escapeTableCell(endpoint.RawURL),
			escapeTableCell(path.Clean(endpoint.FilePath)),
			endpoint.LineNumber,
			escapeTableCell(endpoint.SourceRule),
			endpoint.SourceArtifactExists,
			escapeTableCell(endpoint.Context),
		))
	}
	return builder.String()
}

func escapeTableCell(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return value
}
