package dataflow

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	reportDirName = ".gwxapkg"
	jsonFileName  = "dataflow_hints.json"
)

// Hint 是一条轻量静态数据流线索（非完整污点分析）。
type Hint struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	FilePath   string `json:"file_path"`
	LineNumber int    `json:"line_number"`
	Summary    string `json:"summary"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"`
}

// Report 数据流线索报告。
type Report struct {
	GeneratedAt string `json:"generated_at"`
	SourceDir   string `json:"source_dir"`
	HintCount   int    `json:"hint_count"`
	Hints       []Hint `json:"hints"`
	JSONPath    string `json:"json_path,omitempty"`
}

var (
	storageTokenPattern = regexp.MustCompile(`(?i)(getStorageSync|setStorageSync|getStorage|setStorage).{0,120}(token|openid|session|Authorization|access_token|refresh_token)`)
	cryptoRequestPattern = regexp.MustCompile(`(?is)(CryptoJS|sm2|sm4|encrypt|btoa|atob).{0,200}(request\s*\(|wx\.request|uni\.request|fetch\s*\()`)
	tokenRequestPattern  = regexp.MustCompile(`(?is)(Authorization|Bearer|token|openid).{0,160}(request\s*\(|wx\.request|uni\.request|header\s*:)`)
)

// AnalyzeAndWrite 扫描目录并写出 dataflow_hints.json。
func AnalyzeAndWrite(rootDir string) (*Report, error) {
	report, err := Analyze(rootDir)
	if err != nil {
		return nil, err
	}
	if err := WriteReport(rootDir, report); err != nil {
		return report, err
	}
	return report, nil
}

// Analyze 提取轻量数据流线索。
func Analyze(rootDir string) (*Report, error) {
	report := &Report{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		SourceDir:   rootDir,
		Hints:       make([]Hint, 0),
	}

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".gwxapkg" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(d.Name()), ".js") {
			return nil
		}
		rel, _ := filepath.Rel(rootDir, path)
		rel = filepath.ToSlash(rel)
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(content)
		report.Hints = append(report.Hints, findHintsInFile(rel, text)...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	for i := range report.Hints {
		report.Hints[i].ID = fmt.Sprintf("df_%04d", i+1)
	}
	report.HintCount = len(report.Hints)
	return report, nil
}

// WriteReport 写出 JSON。
func WriteReport(rootDir string, report *Report) error {
	dir := filepath.Join(rootDir, reportDirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	path := filepath.Join(dir, jsonFileName)
	report.JSONPath = path
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func findHintsInFile(relPath, text string) []Hint {
	hints := make([]Hint, 0)
	for _, match := range storageTokenPattern.FindAllStringIndex(text, -1) {
		snippet := compact(text[match[0]:match[1]])
		hints = append(hints, Hint{
			Kind:       "storage_token",
			FilePath:   relPath,
			LineNumber: lineAt(text, match[0]),
			Summary:    "本地存储与 token/openid 等敏感字段共现",
			Evidence:   snippet,
			Confidence: "medium",
		})
	}
	for _, match := range cryptoRequestPattern.FindAllStringIndex(text, -1) {
		snippet := compact(text[match[0]:match[1]])
		hints = append(hints, Hint{
			Kind:       "crypto_to_request",
			FilePath:   relPath,
			LineNumber: lineAt(text, match[0]),
			Summary:    "加密/编码逻辑与请求调用邻近共现",
			Evidence:   snippet,
			Confidence: "low",
		})
	}
	for _, match := range tokenRequestPattern.FindAllStringIndex(text, -1) {
		snippet := compact(text[match[0]:match[1]])
		hints = append(hints, Hint{
			Kind:       "token_to_request",
			FilePath:   relPath,
			LineNumber: lineAt(text, match[0]),
			Summary:    "鉴权字段与请求/header 构造邻近共现",
			Evidence:   snippet,
			Confidence: "medium",
		})
	}
	return hints
}

func lineAt(text string, offset int) int {
	if offset <= 0 {
		return 1
	}
	if offset > len(text) {
		offset = len(text)
	}
	return strings.Count(text[:offset], "\n") + 1
}

func compact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 220 {
		return s[:220] + "..."
	}
	return s
}
