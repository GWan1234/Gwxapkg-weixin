package scanner

import (
	"regexp"
	"strings"
)

// 黑名单
var (
	// 文件名黑名单
	fileNameBlacklist = map[string]bool{
		"index.weapp": true, "index.html": true, "index.wxss": true,
		"index.wxml": true, "main.html": true, "Date.now": true,
		"index.js": true, "app.js": true, "common.js": true,
		"document.dispatchEvent": true, "Math.random": true,
		"Object.keys": true, "Array.from": true,
		"document.getElementById": true, "document.querySelector": true,
		"window.location": true, "console.log": true,
		"Promise.resolve": true, "setTimeout": true,
		"index.weapp.wxss": true, "index.weapp.wxml": true,
		"area.wxss": true, "area.wxml": true, "result.wxss": true,
		"result.wxml": true, "page-list.wxss": true, "page-list.wxml": true,
		"page-question.wxss": true, "page-question.wxml": true,
		"page-banner.wxss": true, "page-banner.wxml": true,
		"page-empty.wxss": true, "page-empty.wxml": true,
		"project-list.wxss": true, "project-list.wxml": true,
		"fuse-component.wxss": true, "fuse-component.wxml": true,
		"banner.weapp": true, "confirm.wxss": true, "confirm.wxml": true,
		"auth.html": true, "doc.html": true, "bearPayPlugin.html": true,
		"canvas.html": true, "canvas2c.html": true, "json2canvas.html": true,
		"scope.userLocation": true,
	}

	// 文件扩展名模式
	fileExtPattern = regexp.MustCompile(`\.(weapp|html|js|wxss|wxml|css|json|xml|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$`)

	// 常见 TLD
	validTLDs = map[string]bool{
		"com": true, "cn": true, "net": true, "org": true, "io": true,
		"gov": true, "edu": true, "mil": true, "co": true, "uk": true,
		"us": true, "jp": true, "kr": true, "de": true, "fr": true,
		"ru": true, "au": true, "ca": true, "in": true, "br": true,
		"mx": true, "it": true, "es": true, "nl": true, "pl": true,
		"se": true, "no": true, "dk": true, "fi": true, "be": true,
		"at": true, "ch": true, "cz": true, "gr": true, "pt": true,
		// 中国常见域名后缀
		"myhuaweicloud": true, "aliyuncs": true, "myscrm": true,
		"myunke": true, "iwofang": true, "weixin": true, "qq": true,
		"dingtalk": true, "feishu": true,
	}

	credentialCategories = map[string]bool{
		"password":      true,
		"api_key":       true,
		"secret":        true,
		"token":         true,
		"private_key":   true,
		"cloud":         true,
		"payment":       true,
		"messaging":     true,
		"devops":        true,
		"observability": true,
		"security":      true,
		"saas":          true,
		"wechat":        true,
	}

	placeholderValues = map[string]bool{
		"api_key":                 true,
		"access_key":              true,
		"secret":                  true,
		"client_secret":           true,
		"token":                   true,
		"password":                true,
		"your_api_key":            true,
		"your_access_key":         true,
		"your_secret":             true,
		"your_client_secret":      true,
		"your_token":              true,
		"your_password":           true,
		"example_api_key":         true,
		"example_token":           true,
		"example_secret":          true,
		"sample_api_key":          true,
		"sample_token":            true,
		"replace_me":              true,
		"replace_with_real_value": true,
		"change_me":               true,
		"changeme":                true,
		"placeholder":             true,
		"dummy":                   true,
		"mock":                    true,
		"foobar":                  true,
		"null":                    true,
		"undefined":               true,
		"none":                    true,
		"nil":                     true,
	}

	placeholderContextPattern = regexp.MustCompile(`(?i)\b(example|sample|demo|dummy|mock|placeholder|replace(?:[_ -]?me|[_ -]?with)?|changeme|change[_ -]?me|todo)\b`)
	maskedValuePattern        = regexp.MustCompile(`(?i)^(?:x{4,}|\*{4,}|-{4,}|_{4,}|#.{3,}|<[^>]+>|\{[^}]+\}|\[[^\]]+\])$`)
)

// SensitiveFilter 误报过滤器
type SensitiveFilter struct {
	blacklist map[string]bool
}

// NewFilter 创建过滤器
func NewFilter() *SensitiveFilter {
	return &SensitiveFilter{
		blacklist: fileNameBlacklist,
	}
}

// ShouldSkip 判断是否应该跳过（误报）
func (f *SensitiveFilter) ShouldSkip(ruleID, content, context string) bool {
	// 去除空白字符
	content = strings.TrimSpace(content)
	if content == "" {
		return true
	}

	// 黑名单过滤
	if f.blacklist[content] {
		return true
	}

	category := GetCategoryKey(ruleID)
	trimmed := trimMatchWrappers(content)

	if f.isPlaceholderValue(trimmed, context) {
		return true
	}

	if credentialCategories[category] && f.isWeakCredential(trimmed, context, category) {
		return true
	}

	// 域名规则的特殊过滤
	if category == "domain" {
		return f.isDomainFalsePositive(trimmed, context)
	}

	// Path 规则的特殊过滤
	if category == "path" {
		return f.isPathFalsePositive(trimmed)
	}

	return false
}

// isDomainFalsePositive 判断域名规则的误报
func (f *SensitiveFilter) isDomainFalsePositive(content, context string) bool {
	// 1. 文件扩展名过滤
	if fileExtPattern.MatchString(content) {
		return true
	}

	// 2. 没有有效 TLD
	if !hasValidTLD(content) {
		return true
	}

	// 3. 在 JS API 调用中
	if isJavaScriptAPI(content, context) {
		return true
	}

	// 4. 单个词（不包含点）
	if !strings.Contains(content, ".") {
		return true
	}

	return false
}

// isPathFalsePositive 判断路径规则的误报
func (f *SensitiveFilter) isPathFalsePositive(content string) bool {
	// 过滤引号
	content = strings.Trim(content, "\"'")

	// 过滤太短的路径
	if len(content) < 5 {
		return true
	}

	return false
}

func (f *SensitiveFilter) isWeakCredential(content, context, category string) bool {
	normalized := normalizeCandidate(content)
	if normalized == "" {
		return true
	}

	if maskedValuePattern.MatchString(content) {
		return true
	}

	if len(normalized) >= 4 && isMostlyRepeatedMask(normalized) {
		return true
	}

	switch category {
	case "password":
		if len(normalized) < 4 {
			return true
		}
	default:
		if len(normalized) < 8 {
			return true
		}
	}

	if looksLikePlainWord(normalized) && len(normalized) < 20 {
		return true
	}

	if placeholderContextPattern.MatchString(context) && looksLikePlaceholderToken(normalized) {
		return true
	}

	return false
}

func (f *SensitiveFilter) isPlaceholderValue(content, context string) bool {
	normalized := normalizeCandidate(content)
	if normalized == "" {
		return true
	}

	if placeholderValues[normalized] {
		return true
	}

	if looksLikePlaceholderToken(normalized) {
		return true
	}

	if placeholderContextPattern.MatchString(context) && len(normalized) < 24 {
		return true
	}

	return false
}

// hasValidTLD 检查是否有有效的顶级域名
func hasValidTLD(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	tld := strings.ToLower(parts[len(parts)-1])
	return validTLDs[tld]
}

// isJavaScriptAPI 判断是否是 JS API
func isJavaScriptAPI(content, context string) bool {
	// 常见的 JS API 模式
	jsPatterns := []string{
		"Date\\.",
		"Math\\.",
		"Object\\.",
		"Array\\.",
		"document\\.",
		"window\\.",
		"console\\.",
		"JSON\\.",
		"Promise\\.",
		"Number\\.",
		"String\\.",
		"Boolean\\.",
	}

	for _, pattern := range jsPatterns {
		matched, _ := regexp.MatchString(pattern, context)
		if matched {
			return true
		}
	}

	return false
}

func trimMatchWrappers(content string) string {
	return strings.Trim(content, "\"'` ")
}

func normalizeCandidate(content string) string {
	normalized := strings.ToLower(strings.TrimSpace(content))
	normalized = strings.Trim(normalized, "\"'`")
	normalized = strings.TrimPrefix(normalized, "bearer ")
	normalized = strings.TrimPrefix(normalized, "basic ")
	return strings.Trim(nonAlnumPattern.ReplaceAllString(normalized, "_"), "_")
}

func looksLikePlaceholderToken(content string) bool {
	if content == "" {
		return false
	}

	return strings.Contains(content, "your_") ||
		strings.Contains(content, "example") ||
		strings.Contains(content, "sample") ||
		strings.Contains(content, "placeholder") ||
		strings.Contains(content, "replace_") ||
		strings.Contains(content, "changeme") ||
		strings.Contains(content, "change_me")
}

func isMostlyRepeatedMask(content string) bool {
	first := content[0]
	sameCount := 0
	maskCount := 0
	for i := 0; i < len(content); i++ {
		if content[i] == first {
			sameCount++
		}
		switch content[i] {
		case 'x', 'X', '*', '#', '_', '-':
			maskCount++
		}
	}

	return sameCount == len(content) || maskCount*100/len(content) >= 80
}

func looksLikePlainWord(content string) bool {
	if content == "" {
		return false
	}

	for i := 0; i < len(content); i++ {
		ch := content[i]
		if (ch >= 'a' && ch <= 'z') || ch == '_' {
			continue
		}
		return false
	}

	return true
}
