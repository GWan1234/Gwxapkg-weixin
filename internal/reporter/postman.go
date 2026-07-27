package reporter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/25smoking/Gwxapkg/internal/scanner"
)

// PostmanReporter Postman Collection 生成器
type PostmanReporter struct{}

// NewPostmanReporter 创建 Postman 报告生成器
func NewPostmanReporter() *PostmanReporter {
	return &PostmanReporter{}
}

type postmanCollection struct {
	Info postmanInfo   `json:"info"`
	Item []postmanItem `json:"item"`
}

type postmanInfo struct {
	PostmanID   string `json:"_postman_id,omitempty"`
	Name        string `json:"name"`
	Schema      string `json:"schema"`
	Description string `json:"description,omitempty"`
}

type postmanItem struct {
	Name    string         `json:"name"`
	Request postmanRequest `json:"request"`
	Event   []postmanEvent `json:"event,omitempty"`
}

type postmanEvent struct {
	Listen string        `json:"listen"`
	Script postmanScript `json:"script"`
}

type postmanScript struct {
	Type string   `json:"type"`
	Exec []string `json:"exec"`
}

type postmanRequest struct {
	Method string            `json:"method"`
	Header []postmanHeader   `json:"header"`
	URL    postmanRequestURL `json:"url"`
}

type postmanHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type postmanRequestURL struct {
	Raw   string         `json:"raw"`
	Host  []string       `json:"host,omitempty"`
	Path  []string       `json:"path,omitempty"`
	Query []postmanQuery `json:"query,omitempty"`
}

type postmanQuery struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// PostmanOptions 控制 Postman 导出细节。
type PostmanOptions struct {
	BaseURL string
}

// Generate 生成 Postman Collection v2.1
func (r *PostmanReporter) Generate(report *scanner.ScanReport, filename string) error {
	return r.GenerateWithOptions(report, filename, PostmanOptions{})
}

// GenerateWithOptions 支持 base URL 拼接。
func (r *PostmanReporter) GenerateWithOptions(report *scanner.ScanReport, filename string, opts PostmanOptions) error {
	if report == nil {
		return fmt.Errorf("报告为空")
	}

	collection := postmanCollection{
		Info: postmanInfo{
			Name:   report.AppID + " - API Collection",
			Schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
		},
		Item: make([]postmanItem, 0, len(report.APIEndpoints)),
	}

	for _, endpoint := range report.APIEndpoints {
		collection.Item = append(collection.Item, buildPostmanItem(endpoint, opts.BaseURL))
	}

	data, err := json.MarshalIndent(collection, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 Postman Collection 失败: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("写入 Postman Collection 失败: %w", err)
	}

	return nil
}

func buildPostmanItem(endpoint scanner.APIEndpoint, baseURL string) postmanItem {
	raw := endpoint.RawURL
	if baseURL != "" && isRelativeAPIURL(raw) {
		raw = joinBaseURL(baseURL, raw)
	}

	requestURL := postmanRequestURL{
		Raw: raw,
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Scheme != "" {
		if parsed.Host != "" {
			requestURL.Host = []string{parsed.Host}
		}
		if parsed.Path != "" {
			parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
			if len(parts) == 1 && parts[0] == "" {
				requestURL.Path = []string{}
			} else {
				requestURL.Path = parts
			}
		}
		if parsed.RawQuery != "" {
			for _, pair := range strings.Split(parsed.RawQuery, "&") {
				if pair == "" {
					continue
				}
				kv := strings.SplitN(pair, "=", 2)
				q := postmanQuery{Key: kv[0]}
				if len(kv) > 1 {
					q.Value = kv[1]
				}
				requestURL.Query = append(requestURL.Query, q)
			}
		}
	}

	return postmanItem{
		Name: endpoint.Name,
		Request: postmanRequest{
			Method: endpoint.Method,
			Header: []postmanHeader{},
			URL:    requestURL,
		},
	}
}

func isRelativeAPIURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	return !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://")
}

func joinBaseURL(base, path string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	path = strings.TrimSpace(path)
	if path == "" {
		return base
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}
