package scanner

import (
	"net/url"
	"regexp"
	"strings"
)

type apiRegexExtractor struct {
	sourceRule string
	pattern    *regexp.Regexp
	handler    func(filePath, text string, match []int) (APIEndpoint, bool)
}

var (
	methodFieldPattern = regexp.MustCompile(`(?is)\b(?:method|type)\s*:\s*["'` + "`" + `]([a-z]+)["'` + "`" + `]`)
	urlFieldPattern    = regexp.MustCompile(`(?is)\burl\s*:\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	versionPathPattern = regexp.MustCompile(`^v\d+/`)
	axiosMethodPattern = regexp.MustCompile(`(?is)\b(?:axios|\$http|this\.\$http)\.(get|post|put|delete|patch|head|options)\b`)
	fetchCallPattern   = regexp.MustCompile(`(?is)\bfetch\s*\(`)
)

var apiExtractors = []apiRegexExtractor{
	{
		sourceRule: "axios-method",
		pattern:    regexp.MustCompile(`(?is)\b(?:axios|\$http|this\.\$http)\.(get|post|put|delete|patch|head|options)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`),
		handler: func(filePath, text string, match []int) (APIEndpoint, bool) {
			groups := extractGroups(text, match)
			if len(groups) < 3 {
				return APIEndpoint{}, false
			}
			rawURL := strings.TrimSpace(groups[2])
			if !isLikelyAPIURL(rawURL) {
				return APIEndpoint{}, false
			}
			method := strings.ToUpper(groups[1])
			return buildEndpoint(filePath, text, match[0], match[1], method, rawURL, "axios-method"), true
		},
	},
	{
		sourceRule: "fetch",
		pattern:    regexp.MustCompile(`(?is)\bfetch\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `](?:\s*,\s*\{.*?\})?`),
		handler: func(filePath, text string, match []int) (APIEndpoint, bool) {
			groups := extractGroups(text, match)
			if len(groups) < 2 {
				return APIEndpoint{}, false
			}
			rawURL := strings.TrimSpace(groups[1])
			if !isLikelyAPIURL(rawURL) {
				return APIEndpoint{}, false
			}
			method := inferMethodFromContext(groups[0])
			return buildEndpoint(filePath, text, match[0], match[1], method, rawURL, "fetch"), true
		},
	},
	{
		sourceRule: "object-request",
		pattern: regexp.MustCompile(
			`(?is)\b(?:axios|\$http|this\.\$http|wx\.request|uni\.request|tt\.request|my\.request|request|http|service|client)\s*\(\s*\{.*?\}\s*\)`,
		),
		handler: func(filePath, text string, match []int) (APIEndpoint, bool) {
			context := text[match[0]:match[1]]
			urlMatch := urlFieldPattern.FindStringSubmatch(context)
			if len(urlMatch) < 2 {
				return APIEndpoint{}, false
			}
			rawURL := strings.TrimSpace(urlMatch[1])
			if !isLikelyAPIURL(rawURL) {
				return APIEndpoint{}, false
			}
			method := inferMethodFromContext(context)
			return buildEndpoint(filePath, text, match[0], match[1], method, rawURL, "object-request"), true
		},
	},
	{
		sourceRule: "generic-method-call",
		pattern:    regexp.MustCompile(`(?is)\b(?:[A-Za-z_$][\w$]*\.)?(get|post|put|delete|patch|head|options)\s*\(\s*["'` + "`" + `]((?:https?://|/|(?:api|v\d+)/)[^"'` + "`" + `]*)["'` + "`" + `]`),
		handler: func(filePath, text string, match []int) (APIEndpoint, bool) {
			groups := extractGroups(text, match)
			if len(groups) < 3 {
				return APIEndpoint{}, false
			}
			rawURL := strings.TrimSpace(groups[2])
			if !isLikelyAPIURL(rawURL) {
				return APIEndpoint{}, false
			}
			method := strings.ToUpper(groups[1])
			return buildEndpoint(filePath, text, match[0], match[1], method, rawURL, "generic-method-call"), true
		},
	},
	{
		sourceRule: "url-field",
		pattern:    regexp.MustCompile(`(?is)\burl\s*:\s*["'` + "`" + `]((?:https?://|/|(?:api|v\d+)/)[^"'` + "`" + `]*)["'` + "`" + `]`),
		handler: func(filePath, text string, match []int) (APIEndpoint, bool) {
			groups := extractGroups(text, match)
			if len(groups) < 2 {
				return APIEndpoint{}, false
			}
			rawURL := strings.TrimSpace(groups[1])
			if !isLikelyAPIURL(rawURL) {
				return APIEndpoint{}, false
			}
			context := collectContextWindow(text, match[0], match[1])
			method := inferMethodFromContext(context)
			return buildEndpoint(filePath, text, match[0], match[1], method, rawURL, "url-field"), true
		},
	},
}

// ExtractAPIEndpoints 从文件内容提取 API Endpoint。
func ExtractAPIEndpoints(filePath string, content []byte) []APIEndpoint {
	return ExtractAPIEndpointsFromText(filePath, string(content))
}

// mergeAPIEndpoints 按 method:url 去重合并。
func mergeAPIEndpoints(parts ...[]APIEndpoint) []APIEndpoint {
	seen := make(map[string]struct{})
	out := make([]APIEndpoint, 0)
	for _, list := range parts {
		for _, ep := range list {
			key := ep.Method + ":" + ep.RawURL
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ep)
		}
	}
	return out
}

// ExtractAPIEndpointsFromText 从已转成 string 的内容提取 API Endpoint，避免重复分配。
func ExtractAPIEndpointsFromText(filePath, text string) []APIEndpoint {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	// 廉价预检：完全不像请求代码时跳过重正则
	if !looksLikeAPIContent(text) {
		return nil
	}

	results := make([]APIEndpoint, 0)
	seen := make(map[string]struct{})

	for _, extractor := range apiExtractors {
		matches := extractor.pattern.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			endpoint, ok := extractor.handler(filePath, text, match)
			if !ok {
				continue
			}
			key := endpoint.Method + ":" + endpoint.RawURL
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			results = append(results, endpoint)
		}
	}

	return results
}

func buildEndpoint(filePath, text string, start, end int, method, rawURL, sourceRule string) APIEndpoint {
	context := normalizeSnippet(collectContextWindow(text, start, end))
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "UNKNOWN"
	}

	return APIEndpoint{
		Name:       buildAPIName(method, rawURL),
		Method:     method,
		RawURL:     rawURL,
		FilePath:   filePath,
		LineNumber: lineNumberAtOffset(text, start),
		SourceRule: sourceRule,
		Context:    context,
	}
}

func buildAPIName(method, rawURL string) string {
	display := rawURL
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Path != "" {
		display = parsed.Path
		if parsed.RawQuery != "" {
			display += "?" + parsed.RawQuery
		}
	}

	if display == "" {
		display = rawURL
	}

	return method + " " + display
}

func inferMethodFromContext(context string) string {
	if match := axiosMethodPattern.FindStringSubmatch(context); len(match) > 1 {
		return strings.ToUpper(match[1])
	}

	if match := methodFieldPattern.FindStringSubmatch(context); len(match) > 1 {
		return strings.ToUpper(match[1])
	}

	if match := fetchCallPattern.FindString(context); match != "" {
		if method := methodFieldPattern.FindStringSubmatch(context); len(method) > 1 {
			return strings.ToUpper(method[1])
		}
		return "UNKNOWN"
	}

	return "UNKNOWN"
}

func isLikelyAPIURL(rawURL string) bool {
	value := strings.TrimSpace(rawURL)
	if value == "" {
		return false
	}

	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return true
	}

	if strings.HasPrefix(value, "/") {
		return true
	}

	return strings.HasPrefix(value, "api/") || versionPathPattern.MatchString(value)
}

func collectContextWindow(text string, start, end int) string {
	left := strings.LastIndex(text[:start], "\n")
	if left == -1 {
		left = 0
	} else {
		left++
	}

	rightRel := strings.Index(text[end:], "\n")
	if rightRel == -1 {
		rightRel = len(text) - end
	}
	right := end + rightRel

	if snippet := strings.TrimSpace(text[left:right]); snippet != "" {
		return snippet
	}
	return strings.TrimSpace(text[start:end])
}

func normalizeSnippet(snippet string) string {
	if snippet == "" {
		return ""
	}

	snippet = strings.Join(strings.Fields(snippet), " ")
	runes := []rune(snippet)
	if len(runes) > 220 {
		return string(runes[:220]) + "..."
	}
	return snippet
}

func lineNumberAtOffset(text string, offset int) int {
	if offset <= 0 {
		return 1
	}
	return strings.Count(text[:offset], "\n") + 1
}

func extractGroups(text string, match []int) []string {
	if len(match)%2 != 0 {
		return nil
	}

	result := make([]string, 0, len(match)/2)
	for i := 0; i < len(match); i += 2 {
		start, end := match[i], match[i+1]
		if start < 0 || end < 0 {
			result = append(result, "")
			continue
		}
		result = append(result, text[start:end])
	}
	return result
}
