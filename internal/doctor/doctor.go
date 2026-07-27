package doctor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	reportDirName = ".gwxapkg"
	jsonFileName  = "doctor_report.json"
	mdFileName    = "doctor_report.md"
)

// Analyze 检查已解包目录的产物健康度与覆盖缺口。
func Analyze(rootDir string) (*HealthReport, error) {
	if rootDir == "" {
		return nil, fmt.Errorf("目录为空")
	}
	info, err := os.Stat(rootDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("不是目录: %s", rootDir)
	}

	report := &HealthReport{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		SourceDir:   rootDir,
		Status:      StatusOK,
		Artifacts:   make([]ArtifactStatus, 0),
		Gaps:        make([]string, 0),
		Suggestions: make([]string, 0),
	}

	// 基础目录形态
	hasAppJSON := fileExists(filepath.Join(rootDir, "app.json"))
	hasJS := hasAnyExt(rootDir, ".js")
	report.LooksLikeMiniProgram = hasAppJSON || hasJS
	if !report.LooksLikeMiniProgram {
		report.Status = StatusPoor
		report.Gaps = append(report.Gaps, "目录不像已解包小程序（缺少 app.json 与 JS 文件）")
		report.Suggestions = append(report.Suggestions, "请先运行: gwxapkg all -id=<AppID> 或 gwxapkg -id=<AppID> -in=<wxapkg>")
	}

	// 完整性
	completenessPath := filepath.Join(rootDir, reportDirName, "package_completeness.json")
	if data, err := os.ReadFile(completenessPath); err == nil {
		var completeness packageCompletenessLite
		if json.Unmarshal(data, &completeness) == nil {
			report.PackageStatus = completeness.Status
			report.MissingSubpackages = completeness.MissingSubpackageCount
			report.PlaceholderPages = completeness.PlaceholderPageCount
			if completeness.Status == "partial" {
				report.Status = worse(report.Status, StatusWarn)
				report.Gaps = append(report.Gaps, fmt.Sprintf("分包不完整: missing=%d placeholder_pages=%d",
					completeness.MissingSubpackageCount, completeness.PlaceholderPageCount))
				report.Suggestions = append(report.Suggestions,
					"在微信中打开缺失页面后运行: gwxapkg all -id=<AppID> -watch=auto 或普通 all/scan")
			}
		}
	} else {
		report.Gaps = append(report.Gaps, "缺少 package_completeness 报告")
		report.Suggestions = append(report.Suggestions, "运行 scan-only 或完整 all 生成分包完整性报告")
	}

	// 关键清单
	checks := []struct {
		Name string
		Path string
		Key  bool
	}{
		{"semantic_module_map", filepath.Join(reportDirName, "semantic_module_map.json"), true},
		{"api_map", filepath.Join(reportDirName, "api_map.json"), true},
		{"api_endpoint_map", filepath.Join(reportDirName, "api_endpoint_map.json"), false},
		{"api_unified_map", filepath.Join(reportDirName, "api_unified_map.json"), true},
		{"business_surface", filepath.Join(reportDirName, "business_surface.json"), true},
		{"api_call_chain", filepath.Join(reportDirName, "api_call_chain.json"), false},
		{"ast_rename_map", filepath.Join(reportDirName, "ast_rename_map.json"), false},
		{"package_completeness", filepath.Join(reportDirName, "package_completeness.json"), false},
		{"doctor_report", filepath.Join(reportDirName, "doctor_report.json"), false},
		{"sensitive_report", "sensitive_report.json", true},
		{"route_manifest", "route_manifest.json", false},
	}

	for _, check := range checks {
		full := filepath.Join(rootDir, check.Path)
		st := ArtifactStatus{Name: check.Name, Path: check.Path, Required: check.Key}
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			st.Exists = true
			st.Size = fi.Size()
		} else {
			st.Exists = false
			if check.Key {
				report.Status = worse(report.Status, StatusWarn)
				report.Gaps = append(report.Gaps, "缺少关键产物: "+check.Name)
			}
		}
		report.Artifacts = append(report.Artifacts, st)
	}

	// 数量对比
	report.SemanticEndpointCount = countJSONArray(filepath.Join(rootDir, reportDirName, "api_map.json"), "endpoints")
	report.HTTPEndpointCount = countJSONArray(filepath.Join(rootDir, reportDirName, "api_endpoint_map.json"), "endpoints")
	report.UnifiedEndpointCount = countJSONArray(filepath.Join(rootDir, reportDirName, "api_unified_map.json"), "endpoints")
	report.SensitiveMatchCount = countSensitiveMatches(filepath.Join(rootDir, "sensitive_report.json"))
	report.ASTSkippedFiles = countASTSkipped(filepath.Join(rootDir, reportDirName, "ast_rename_map.json"))

	if report.SemanticEndpointCount == 0 && report.HTTPEndpointCount > 0 {
		report.Gaps = append(report.Gaps, "语义 API 地图为空，但通用 endpoint 地图有数据（可用 unified/fallback）")
		report.Suggestions = append(report.Suggestions, "可运行: gwxapkg semantic -dir="+rootDir)
	}
	if report.SemanticEndpointCount == 0 && report.HTTPEndpointCount == 0 {
		report.Status = worse(report.Status, StatusWarn)
		report.Gaps = append(report.Gaps, "未发现 API 地图证据（semantic 与 http endpoint 均为 0）")
	}
	if !artifactExists(report, "sensitive_report") {
		report.Suggestions = append(report.Suggestions, "运行: gwxapkg scan-only -dir="+rootDir+" -format=both")
	}
	if !artifactExists(report, "api_unified_map") && (report.SemanticEndpointCount > 0 || report.HTTPEndpointCount > 0) {
		report.Suggestions = append(report.Suggestions, "重新运行 scan-only 或 all 以生成 api_unified_map")
	}
	if report.ASTSkippedFiles > 0 {
		report.Gaps = append(report.Gaps, fmt.Sprintf("AST 重命名跳过 %d 个文件", report.ASTSkippedFiles))
	}

	// 建议去重
	report.Suggestions = uniqueStrings(report.Suggestions)
	report.Gaps = uniqueStrings(report.Gaps)

	if len(report.Gaps) == 0 && report.LooksLikeMiniProgram {
		report.Status = StatusOK
	} else if report.Status == StatusOK && len(report.Gaps) > 0 {
		report.Status = StatusWarn
	}

	return report, nil
}

// AnalyzeAndWrite 分析并写入 doctor 报告。
func AnalyzeAndWrite(rootDir string) (*HealthReport, error) {
	report, err := Analyze(rootDir)
	if err != nil {
		return nil, err
	}
	if err := WriteReport(rootDir, report); err != nil {
		return report, err
	}
	return report, nil
}

// WriteReport 写出 doctor_report.json / .md
func WriteReport(rootDir string, report *HealthReport) error {
	if report == nil {
		return fmt.Errorf("报告为空")
	}
	dir := filepath.Join(rootDir, reportDirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	report.JSONPath = filepath.Join(dir, jsonFileName)
	report.MarkdownPath = filepath.Join(dir, mdFileName)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(report.JSONPath, data, 0644); err != nil {
		return err
	}
	return os.WriteFile(report.MarkdownPath, []byte(BuildMarkdown(report)), 0644)
}

// BuildMarkdown 生成可读的 doctor 报告。
func BuildMarkdown(report *HealthReport) string {
	var b strings.Builder
	b.WriteString("# Gwxapkg Doctor 报告\n\n")
	b.WriteString(fmt.Sprintf("- 时间: %s\n", report.GeneratedAt))
	b.WriteString(fmt.Sprintf("- 目录: %s\n", report.SourceDir))
	b.WriteString(fmt.Sprintf("- 状态: **%s**\n", report.Status))
	b.WriteString(fmt.Sprintf("- 像小程序目录: %v\n", report.LooksLikeMiniProgram))
	b.WriteString(fmt.Sprintf("- 分包状态: %s (missing=%d placeholder=%d)\n",
		valueOr(report.PackageStatus, "unknown"), report.MissingSubpackages, report.PlaceholderPages))
	b.WriteString(fmt.Sprintf("- Semantic API: %d | HTTP API: %d | Unified: %d | Sensitive matches: %d | AST skipped: %d\n\n",
		report.SemanticEndpointCount, report.HTTPEndpointCount, report.UnifiedEndpointCount,
		report.SensitiveMatchCount, report.ASTSkippedFiles))

	b.WriteString("## 产物\n\n")
	b.WriteString("| 名称 | 存在 | 路径 | 大小 |\n|----|----|----|----|\n")
	for _, a := range report.Artifacts {
		b.WriteString(fmt.Sprintf("| %s | %v | %s | %d |\n", a.Name, a.Exists, a.Path, a.Size))
	}

	if len(report.Gaps) > 0 {
		b.WriteString("\n## 覆盖缺口\n\n")
		for _, g := range report.Gaps {
			b.WriteString("- " + g + "\n")
		}
	}
	if len(report.Suggestions) > 0 {
		b.WriteString("\n## 建议命令\n\n")
		for _, s := range report.Suggestions {
			b.WriteString("- `" + s + "`\n")
		}
	}
	return b.String()
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

func hasAnyExt(root, ext string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".gwxapkg" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ext) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func countJSONArray(path, field string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return 0
	}
	arr, ok := raw[field]
	if !ok {
		return 0
	}
	var items []json.RawMessage
	if json.Unmarshal(arr, &items) != nil {
		return 0
	}
	return len(items)
}

func countSensitiveMatches(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return 0
	}
	if summary, ok := raw["summary"]; ok {
		var s struct {
			UniqueMatches int `json:"unique_matches"`
			TotalMatches  int `json:"total_matches"`
		}
		if json.Unmarshal(summary, &s) == nil {
			if s.UniqueMatches > 0 {
				return s.UniqueMatches
			}
			return s.TotalMatches
		}
	}
	return 0
}

func countASTSkipped(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var raw struct {
		Files []struct {
			Status string `json:"status"`
		} `json:"files"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return 0
	}
	n := 0
	for _, f := range raw.Files {
		if strings.EqualFold(f.Status, "skipped") {
			n++
		}
	}
	return n
}

func artifactExists(report *HealthReport, name string) bool {
	for _, a := range report.Artifacts {
		if a.Name == name {
			return a.Exists
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func worse(current, candidate string) string {
	rank := map[string]int{StatusOK: 0, StatusWarn: 1, StatusPoor: 2}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}

type packageCompletenessLite struct {
	Status                  string `json:"status"`
	MissingSubpackageCount  int    `json:"missing_subpackages"`
	PlaceholderPageCount    int    `json:"placeholder_pages"`
}
