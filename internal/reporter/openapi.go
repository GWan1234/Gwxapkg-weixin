package reporter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// GenerateOpenAPIFromDir 优先读取 api_unified_map.json，生成 OpenAPI 3 文档。
func GenerateOpenAPIFromDir(rootDir, filename, baseURL string) error {
	unified, err := LoadUnifiedAPIMap(rootDir)
	if err != nil {
		// fallback: endpoint map only
		return generateOpenAPIFromEndpointMap(rootDir, filename, baseURL)
	}
	return GenerateOpenAPI(unified, filename, baseURL)
}

// GenerateOpenAPI 从统一 API 地图生成 OpenAPI 3.0。
func GenerateOpenAPI(report *UnifiedAPIMapReport, filename, baseURL string) error {
	if report == nil {
		return fmt.Errorf("统一 API 地图为空")
	}

	doc := openAPIDoc{
		OpenAPI: "3.0.3",
		Info: openAPIInfo{
			Title:       "Gwxapkg Mini Program APIs",
			Description: "Generated from Gwxapkg api_unified_map (static extraction, not live traffic).",
			Version:     "1.0.0",
		},
		Paths: make(map[string]map[string]openAPIOperation),
	}
	if strings.TrimSpace(baseURL) != "" {
		doc.Servers = []openAPIServer{{URL: strings.TrimRight(baseURL, "/")}}
	}

	for _, ep := range report.Endpoints {
		pathKey := openAPIPath(ep.URL, ep.ControllerName, ep.MethodsName)
		if pathKey == "" {
			continue
		}
		method := strings.ToLower(strings.TrimSpace(ep.Method))
		if method == "" || method == "unknown" {
			method = "post"
		}
		if doc.Paths[pathKey] == nil {
			doc.Paths[pathKey] = make(map[string]openAPIOperation)
		}
		op := openAPIOperation{
			OperationID: ep.ID,
			Summary:     strings.TrimSpace(ep.FunctionName + " " + ep.ControllerName + "." + ep.MethodsName),
			Description: fmt.Sprintf("kind=%s sources=%s", ep.Kind, strings.Join(ep.SourceRules, ",")),
			Tags:        []string{ep.Kind},
			Responses: map[string]openAPIResponse{
				"200": {Description: "static placeholder response"},
			},
		}
		if method == "unknown" || strings.EqualFold(ep.Method, "UNKNOWN") {
			if op.Extensions == nil {
				op.Extensions = map[string]interface{}{}
			}
			op.Extensions["x-unknown-method"] = true
		}
		if len(ep.ParamFields) > 0 {
			schemaProps := make(map[string]openAPISchema)
			for _, field := range ep.ParamFields {
				schemaProps[field] = openAPISchema{Type: "string"}
			}
			op.RequestBody = &openAPIRequestBody{
				Required: false,
				Content: map[string]openAPIMedia{
					"application/json": {
						Schema: openAPISchema{
							Type:       "object",
							Properties: schemaProps,
						},
					},
				},
			}
		}
		doc.Paths[pathKey][method] = op
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 OpenAPI 失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("写入 OpenAPI 失败: %w", err)
	}
	return nil
}

func generateOpenAPIFromEndpointMap(rootDir, filename, baseURL string) error {
	data, err := os.ReadFile(filepath.Join(rootDir, ".gwxapkg", "api_endpoint_map.json"))
	if err != nil {
		return fmt.Errorf("缺少 api_unified_map.json / api_endpoint_map.json: %w", err)
	}
	var endpointMap APIEndpointMapReport
	if err := json.Unmarshal(data, &endpointMap); err != nil {
		return err
	}
	unified := &UnifiedAPIMapReport{Endpoints: make([]UnifiedAPIEndpoint, 0, len(endpointMap.Endpoints))}
	for _, ep := range endpointMap.Endpoints {
		unified.Endpoints = append(unified.Endpoints, UnifiedAPIEndpoint{
			ID:          ep.ID,
			Kind:        "http",
			Method:      ep.Method,
			URL:         ep.RawURL,
			FilePath:    ep.FilePath,
			LineNumber:  ep.LineNumber,
			SourceRules: []string{ep.SourceRule},
		})
	}
	return GenerateOpenAPI(unified, filename, baseURL)
}

func openAPIPath(rawURL, controller, method string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL != "" {
		if parsed, err := url.Parse(rawURL); err == nil && parsed.Path != "" {
			return parsed.Path
		}
		if strings.HasPrefix(rawURL, "/") {
			if idx := strings.Index(rawURL, "?"); idx >= 0 {
				return rawURL[:idx]
			}
			return rawURL
		}
	}
	if controller != "" && method != "" {
		return "/rpc/" + controller + "/" + method
	}
	return ""
}

type openAPIDoc struct {
	OpenAPI string                                 `json:"openapi"`
	Info    openAPIInfo                            `json:"info"`
	Servers []openAPIServer                        `json:"servers,omitempty"`
	Paths   map[string]map[string]openAPIOperation `json:"paths"`
}

type openAPIInfo struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version"`
}

type openAPIServer struct {
	URL string `json:"url"`
}

type openAPIOperation struct {
	OperationID string                     `json:"operationId,omitempty"`
	Summary     string                     `json:"summary,omitempty"`
	Description string                     `json:"description,omitempty"`
	Tags        []string                   `json:"tags,omitempty"`
	RequestBody *openAPIRequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]openAPIResponse `json:"responses"`
	Extensions  map[string]interface{}     `json:"-"`
}

type openAPIRequestBody struct {
	Required bool                     `json:"required"`
	Content  map[string]openAPIMedia  `json:"content"`
}

type openAPIMedia struct {
	Schema openAPISchema `json:"schema"`
}

type openAPISchema struct {
	Type       string                    `json:"type,omitempty"`
	Properties map[string]openAPISchema  `json:"properties,omitempty"`
}

type openAPIResponse struct {
	Description string `json:"description"`
}
