package reporter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/25smoking/Gwxapkg/internal/scanner"
	"github.com/25smoking/Gwxapkg/internal/semantic"
)

const (
	unifiedAPIMapJSONFileName = "api_unified_map.json"
	unifiedAPIMapMDFileName   = "api_unified_map.md"
)

// UnifiedAPIMapArtifacts 统一 API 地图产物路径。
type UnifiedAPIMapArtifacts struct {
	JSONPath       string
	MarkdownPath   string
	EndpointCount  int
	SemanticCount  int
	HTTPCount      int
	MergedCount    int
}

// UnifiedAPIMapReport 合并 semantic api_map 与通用 endpoint map。
type UnifiedAPIMapReport struct {
	GeneratedAt string               `json:"generated_at"`
	Sources     UnifiedAPIMapSources `json:"sources"`
	Endpoints   []UnifiedAPIEndpoint `json:"endpoints"`
	Notes       []string             `json:"notes,omitempty"`
	NoRedaction bool                 `json:"no_redaction"`
}

// UnifiedAPIMapSources 记录各来源数量。
type UnifiedAPIMapSources struct {
	SemanticCount int `json:"semantic_count"`
	EndpointCount int `json:"endpoint_count"`
	MergedCount   int `json:"merged_count"`
}

// UnifiedAPIEndpoint 统一端点条目。
type UnifiedAPIEndpoint struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"` // semantic | http | both
	Method         string   `json:"method,omitempty"`
	URL            string   `json:"url,omitempty"`
	ControllerName string   `json:"controller_name,omitempty"`
	MethodsName    string   `json:"methods_name,omitempty"`
	FunctionName   string   `json:"function_name,omitempty"`
	FilePath       string   `json:"file_path,omitempty"`
	LineNumber     int      `json:"line_number,omitempty"`
	ParamFields    []string `json:"param_fields,omitempty"`
	SourceRules    []string `json:"source_rules,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	Context        string   `json:"context,omitempty"`
}

// GenerateUnifiedAPIMap 写出 .gwxapkg/api_unified_map.{json,md}。
// semanticReport 可为 nil；此时尝试从 sourceRoot/.gwxapkg/api_map.json 读取。
func GenerateUnifiedAPIMap(sourceRoot, outputRoot string, scanReport *scanner.ScanReport, semanticReport *semantic.APIMapReport) (*UnifiedAPIMapArtifacts, error) {
	if outputRoot == "" {
		outputRoot = sourceRoot
	}
	if semanticReport == nil && sourceRoot != "" {
		if loaded, err := loadSemanticAPIMap(sourceRoot); err == nil {
			semanticReport = loaded
		}
	}

	var httpEndpoints []scanner.APIEndpoint
	if scanReport != nil {
		httpEndpoints = scanReport.APIEndpoints
	}

	if (semanticReport == nil || len(semanticReport.Endpoints) == 0) && len(httpEndpoints) == 0 {
		return nil, nil
	}

	report := buildUnifiedAPIMapReport(semanticReport, httpEndpoints)
	reportDir := filepath.Join(outputRoot, ".gwxapkg")
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return nil, fmt.Errorf("创建统一 API 地图目录失败: %w", err)
	}

	jsonPath := filepath.Join(reportDir, unifiedAPIMapJSONFileName)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化统一 API 地图失败: %w", err)
	}
	if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		return nil, fmt.Errorf("写入统一 API 地图 JSON 失败: %w", err)
	}

	mdPath := filepath.Join(reportDir, unifiedAPIMapMDFileName)
	if err := os.WriteFile(mdPath, []byte(buildUnifiedAPIMapMarkdown(report)), 0644); err != nil {
		return nil, fmt.Errorf("写入统一 API 地图 Markdown 失败: %w", err)
	}

	return &UnifiedAPIMapArtifacts{
		JSONPath:      jsonPath,
		MarkdownPath:  mdPath,
		EndpointCount: len(report.Endpoints),
		SemanticCount: report.Sources.SemanticCount,
		HTTPCount:     report.Sources.EndpointCount,
		MergedCount:   report.Sources.MergedCount,
	}, nil
}

// LoadUnifiedAPIMap 读取已存在的统一 API 地图。
func LoadUnifiedAPIMap(rootDir string) (*UnifiedAPIMapReport, error) {
	data, err := os.ReadFile(filepath.Join(rootDir, ".gwxapkg", unifiedAPIMapJSONFileName))
	if err != nil {
		return nil, err
	}
	var report UnifiedAPIMapReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

func loadSemanticAPIMap(rootDir string) (*semantic.APIMapReport, error) {
	data, err := os.ReadFile(filepath.Join(rootDir, ".gwxapkg", "api_map.json"))
	if err != nil {
		return nil, err
	}
	var report semantic.APIMapReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

func buildUnifiedAPIMapReport(semanticReport *semantic.APIMapReport, httpEndpoints []scanner.APIEndpoint) *UnifiedAPIMapReport {
	report := &UnifiedAPIMapReport{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Endpoints:   make([]UnifiedAPIEndpoint, 0),
		NoRedaction: true,
	}

	semanticCount := 0
	if semanticReport != nil {
		semanticCount = len(semanticReport.Endpoints)
	}
	report.Sources.SemanticCount = semanticCount
	report.Sources.EndpointCount = len(httpEndpoints)

	// 先放入 semantic 端点
	type mergeKey struct {
		url    string
		method string
	}
	indexByKey := make(map[mergeKey]int)
	indexByController := make(map[string]int)

	if semanticReport != nil {
		for _, ep := range semanticReport.Endpoints {
			entry := UnifiedAPIEndpoint{
				Kind:           "semantic",
				Method:         strings.ToUpper(strings.TrimSpace(ep.HTTPMethod)),
				URL:            strings.TrimSpace(ep.URL),
				ControllerName: ep.ControllerName,
				MethodsName:    ep.MethodsName,
				FunctionName:   ep.FunctionName,
				FilePath:       filepath.ToSlash(ep.FilePath),
				ParamFields:    ep.ParamFields,
				SourceRules:    []string{"semantic"},
				Confidence:     "high",
			}
			if entry.Method == "" {
				entry.Method = "UNKNOWN"
			}
			if len(ep.CallSites) > 0 {
				entry.LineNumber = ep.CallSites[0].LineNumber
				if entry.FilePath == "" {
					entry.FilePath = filepath.ToSlash(ep.CallSites[0].FilePath)
				}
			}
			report.Endpoints = append(report.Endpoints, entry)
			idx := len(report.Endpoints) - 1
			if entry.URL != "" {
				indexByKey[mergeKey{url: normalizeUnifiedURL(entry.URL), method: entry.Method}] = idx
			}
			if entry.ControllerName != "" && entry.MethodsName != "" {
				indexByController[strings.ToLower(entry.ControllerName+"/"+entry.MethodsName)] = idx
			}
		}
	}

	merged := 0
	for _, ep := range httpEndpoints {
		method := strings.ToUpper(strings.TrimSpace(ep.Method))
		if method == "" {
			method = "UNKNOWN"
		}
		rawURL := strings.TrimSpace(ep.RawURL)
		key := mergeKey{url: normalizeUnifiedURL(rawURL), method: method}

		if idx, ok := indexByKey[key]; ok && key.url != "" {
			// 合并到已有 semantic 条目
			report.Endpoints[idx].Kind = "both"
			report.Endpoints[idx].SourceRules = appendUnique(report.Endpoints[idx].SourceRules, ep.SourceRule, "http")
			if report.Endpoints[idx].Context == "" {
				report.Endpoints[idx].Context = ep.Context
			}
			if report.Endpoints[idx].LineNumber == 0 {
				report.Endpoints[idx].LineNumber = ep.LineNumber
			}
			if report.Endpoints[idx].FilePath == "" {
				report.Endpoints[idx].FilePath = filepath.ToSlash(ep.FilePath)
			}
			merged++
			continue
		}

		// 尝试 controller/method 出现在 context 中的弱关联（不做强合并）
		entry := UnifiedAPIEndpoint{
			Kind:        "http",
			Method:      method,
			URL:         rawURL,
			FilePath:    filepath.ToSlash(ep.FilePath),
			LineNumber:  ep.LineNumber,
			SourceRules: []string{ep.SourceRule},
			Confidence:  "medium",
			Context:     ep.Context,
		}
		if entry.SourceRules[0] == "" {
			entry.SourceRules = []string{"http"}
		}
		report.Endpoints = append(report.Endpoints, entry)
	}
	report.Sources.MergedCount = merged

	// 分配稳定 ID 并排序
	sort.SliceStable(report.Endpoints, func(i, j int) bool {
		if report.Endpoints[i].URL != report.Endpoints[j].URL {
			return report.Endpoints[i].URL < report.Endpoints[j].URL
		}
		if report.Endpoints[i].Method != report.Endpoints[j].Method {
			return report.Endpoints[i].Method < report.Endpoints[j].Method
		}
		return report.Endpoints[i].FilePath < report.Endpoints[j].FilePath
	})
	for i := range report.Endpoints {
		report.Endpoints[i].ID = fmt.Sprintf("ep_%04d", i+1)
	}

	if report.Sources.SemanticCount == 0 && report.Sources.EndpointCount > 0 {
		report.Notes = append(report.Notes, "语义 API 地图为空，当前统一地图主要来自通用 HTTP endpoint 提取。")
	}
	if report.Sources.EndpointCount == 0 && report.Sources.SemanticCount > 0 {
		report.Notes = append(report.Notes, "通用 endpoint 提取为空，当前统一地图主要来自 controllerName/methodsName 语义地图。")
	}
	if merged > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf("成功合并 %d 个同时具备语义与 HTTP 证据的端点。", merged))
	}

	return report
}

func normalizeUnifiedURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil {
		if parsed.Path != "" || parsed.Host != "" {
			path := parsed.Path
			if path == "" {
				path = "/"
			}
			if parsed.RawQuery != "" {
				return strings.ToLower(path) + "?" + parsed.RawQuery
			}
			return strings.ToLower(path)
		}
	}
	return strings.ToLower(raw)
}

func appendUnique(values []string, items ...string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		seen[v] = struct{}{}
	}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		values = append(values, item)
	}
	return values
}

func buildUnifiedAPIMapMarkdown(report *UnifiedAPIMapReport) string {
	var b strings.Builder
	b.WriteString("# 统一 API 地图\n\n")
	b.WriteString(fmt.Sprintf("- 生成时间: %s\n", report.GeneratedAt))
	b.WriteString(fmt.Sprintf("- 语义端点: %d\n", report.Sources.SemanticCount))
	b.WriteString(fmt.Sprintf("- HTTP 端点: %d\n", report.Sources.EndpointCount))
	b.WriteString(fmt.Sprintf("- 合并端点: %d\n", report.Sources.MergedCount))
	b.WriteString(fmt.Sprintf("- 统一条目: %d\n\n", len(report.Endpoints)))
	if len(report.Notes) > 0 {
		b.WriteString("## 备注\n\n")
		for _, note := range report.Notes {
			b.WriteString("- " + note + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("| ID | Kind | Method | URL / Controller | File | Confidence |\n")
	b.WriteString("|----|------|--------|------------------|------|------------|\n")
	for _, ep := range report.Endpoints {
		target := ep.URL
		if target == "" && ep.ControllerName != "" {
			target = ep.ControllerName + "." + ep.MethodsName
		}
		target = strings.ReplaceAll(target, "|", "\\|")
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			ep.ID, ep.Kind, ep.Method, target, ep.FilePath, ep.Confidence))
	}
	return b.String()
}
