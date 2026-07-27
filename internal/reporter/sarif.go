package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/25smoking/Gwxapkg/internal/scanner"
)

// GenerateSARIF 将敏感扫描报告导出为 SARIF 2.1.0。
func GenerateSARIF(report *scanner.ScanReport, filename string) error {
	if report == nil {
		return fmt.Errorf("报告为空")
	}

	rules := make([]sarifRule, 0)
	ruleIndex := make(map[string]int)
	results := make([]sarifResult, 0, len(report.Items))

	for _, item := range report.Items {
		idx, ok := ruleIndex[item.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[item.RuleID] = idx
			rules = append(rules, sarifRule{
				ID:   item.RuleID,
				Name: item.RuleName,
				ShortDescription: sarifMessage{
					Text: item.RuleName,
				},
				FullDescription: sarifMessage{
					Text: fmt.Sprintf("category=%s confidence=%s", item.Category, item.Confidence),
				},
				DefaultConfiguration: sarifReportingConfig{
					Level: confidenceToSARIFLevel(item.Confidence),
				},
			})
		}

		results = append(results, sarifResult{
			RuleID:    item.RuleID,
			RuleIndex: idx,
			Level:     confidenceToSARIFLevel(item.Confidence),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s: %s", item.RuleName, item.Content),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: filepath.ToSlash(item.FilePath),
						},
						Region: sarifRegion{
							StartLine:   maxInt(item.LineNumber, 1),
							Snippet:     sarifMessage{Text: truncate(item.Context, 240)},
						},
					},
				},
			},
		})
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Gwxapkg",
						InformationURI: "https://github.com/25smoking/Gwxapkg",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 SARIF 失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("写入 SARIF 失败: %w", err)
	}
	return nil
}

func confidenceToSARIFLevel(confidence string) string {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name,omitempty"`
	ShortDescription     sarifMessage          `json:"shortDescription,omitempty"`
	FullDescription      sarifMessage          `json:"fullDescription,omitempty"`
	DefaultConfiguration sarifReportingConfig  `json:"defaultConfiguration,omitempty"`
}

type sarifReportingConfig struct {
	Level string `json:"level,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level,omitempty"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int          `json:"startLine"`
	Snippet   sarifMessage `json:"snippet,omitempty"`
}
