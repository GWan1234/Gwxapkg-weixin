package scanner

import (
	"path/filepath"
	"strings"
	"sync"
)

const (
	TierCritical = "critical"
	TierHigh     = "high"
	TierMedium   = "medium"
	TierLow      = "low"
	TierNoise    = "noise"
)

// DefaultMaxLineBytes 超过该长度的行会降级为 high+ 规则，并对超长内容分块扫描。
const DefaultMaxLineBytes = 256 * 1024

// ScanOptions 控制敏感扫描与 API 提取行为。
type ScanOptions struct {
	// Tiers 为允许执行的规则层级；nil/空表示全部层级。
	Tiers []string
	// MaxLineBytes 超长行阈值；<=0 时使用 DefaultMaxLineBytes。
	MaxLineBytes int
	// ExtractAPI 是否提取 API Endpoint；默认 true。
	ExtractAPI bool
	// DisableExtractAPI 为 true 时强制关闭 API 提取。
	DisableExtractAPI bool
}

// DefaultScanOptions 返回默认扫描选项（行为与历史版本一致：全量规则）。
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		Tiers:      nil,
		MaxLineBytes: DefaultMaxLineBytes,
		ExtractAPI: true,
	}
}

var (
	activeRulesMu sync.RWMutex
	// activeRules 是当前扫描实际使用的规则子集；nil 时回退到 CompiledRules。
	activeRules []*CompiledRule
	scanOptsMu  sync.RWMutex
	globalScanOptions = DefaultScanOptions()
)

// SetGlobalScanOptions 设置进程级默认扫描选项（CLI / pipeline 使用）。
func SetGlobalScanOptions(opts ScanOptions) {
	scanOptsMu.Lock()
	defer scanOptsMu.Unlock()
	if opts.MaxLineBytes <= 0 {
		opts.MaxLineBytes = DefaultMaxLineBytes
	}
	if !opts.DisableExtractAPI {
		opts.ExtractAPI = true
	}
	globalScanOptions = opts

	activeRulesMu.Lock()
	rebuildActiveRulesLocked(opts.Tiers)
	activeRulesMu.Unlock()
}

// GetGlobalScanOptions 返回当前全局扫描选项副本。
func GetGlobalScanOptions() ScanOptions {
	scanOptsMu.RLock()
	defer scanOptsMu.RUnlock()
	return globalScanOptions
}

// SetActiveTiers 按层级过滤 CompiledRules，供 InitRules 之后调用。
func SetActiveTiers(tiers []string) {
	scanOptsMu.Lock()
	globalScanOptions.Tiers = tiers
	scanOptsMu.Unlock()

	activeRulesMu.Lock()
	rebuildActiveRulesLocked(tiers)
	activeRulesMu.Unlock()
}

// RefreshActiveRules 在 InitRules 重新编译规则后刷新分层缓存。
func RefreshActiveRules() {
	scanOptsMu.RLock()
	tiers := globalScanOptions.Tiers
	scanOptsMu.RUnlock()

	activeRulesMu.Lock()
	rebuildActiveRulesLocked(tiers)
	activeRulesMu.Unlock()
}

func rebuildActiveRulesLocked(tiers []string) {
	if len(tiers) == 0 {
		activeRules = nil
		return
	}
	allowed := make(map[string]struct{}, len(tiers))
	for _, tier := range tiers {
		allowed[strings.ToLower(strings.TrimSpace(tier))] = struct{}{}
	}
	filtered := make([]*CompiledRule, 0, len(CompiledRules))
	for _, rule := range CompiledRules {
		if rule == nil {
			continue
		}
		tier := strings.ToLower(strings.TrimSpace(rule.Tier))
		if tier == "" {
			tier = GetTier(rule.ID)
		}
		if _, ok := allowed[tier]; ok {
			filtered = append(filtered, rule)
		}
	}
	activeRules = filtered
}

// ActiveRules 返回当前生效规则；未分层时返回全部 CompiledRules。
func ActiveRules() []*CompiledRule {
	activeRulesMu.RLock()
	defer activeRulesMu.RUnlock()
	if activeRules != nil {
		return activeRules
	}
	return CompiledRules
}

func activeRulesForOptions(opts ScanOptions) []*CompiledRule {
	if len(opts.Tiers) == 0 {
		return CompiledRules
	}
	allowed := make(map[string]struct{}, len(opts.Tiers))
	for _, tier := range opts.Tiers {
		allowed[strings.ToLower(strings.TrimSpace(tier))] = struct{}{}
	}
	filtered := make([]*CompiledRule, 0, len(CompiledRules))
	for _, rule := range CompiledRules {
		if rule == nil {
			continue
		}
		tier := strings.ToLower(strings.TrimSpace(rule.Tier))
		if tier == "" {
			tier = GetTier(rule.ID)
		}
		if _, ok := allowed[tier]; ok {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// highPriorityTiers 用于超长行降级扫描。
var highPriorityTiers = map[string]struct{}{
	TierCritical: {},
	TierHigh:     {},
}

func highPriorityRules(rules []*CompiledRule) []*CompiledRule {
	filtered := make([]*CompiledRule, 0, len(rules)/4)
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		tier := strings.ToLower(strings.TrimSpace(rule.Tier))
		if tier == "" {
			tier = GetTier(rule.ID)
		}
		if _, ok := highPriorityTiers[tier]; ok {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// ParseRuleTierSpec 解析 CLI 的 -rule-tier 参数。
//
// 支持：
//   - "" / "all" / "*" → 全部层级（返回 nil）
//   - "high" → critical + high（阈值语义）
//   - "medium" → critical + high + medium
//   - "low" → critical + high + medium + low
//   - "high,medium" / "critical,noise" → 精确列表
func ParseRuleTierSpec(spec string) []string {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" || spec == "all" || spec == "*" {
		return nil
	}

	// 精确列表
	if strings.Contains(spec, ",") {
		parts := strings.Split(spec, ",")
		out := make([]string, 0, len(parts))
		seen := make(map[string]struct{})
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if !isValidTier(part) {
				continue
			}
			if _, ok := seen[part]; ok {
				continue
			}
			seen[part] = struct{}{}
			out = append(out, part)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}

	// 阈值语义：指定级别及以上
	switch spec {
	case TierCritical:
		return []string{TierCritical}
	case TierHigh:
		return []string{TierCritical, TierHigh}
	case TierMedium:
		return []string{TierCritical, TierHigh, TierMedium}
	case TierLow:
		return []string{TierCritical, TierHigh, TierMedium, TierLow}
	case TierNoise:
		return []string{TierCritical, TierHigh, TierMedium, TierLow, TierNoise}
	default:
		if isValidTier(spec) {
			return []string{spec}
		}
		return nil
	}
}

func isValidTier(tier string) bool {
	switch tier {
	case TierCritical, TierHigh, TierMedium, TierLow, TierNoise:
		return true
	default:
		return false
	}
}

// IsScannableTextExt 判断扩展名是否值得跑敏感扫描。
func IsScannableTextExt(ext string) bool {
	ext = strings.ToLower(ext)
	switch ext {
	case ".js", ".ts", ".jsx", ".tsx", ".json",
		".wxml", ".wxss", ".wxs", ".html", ".css", ".xml",
		".txt", ".md", ".yaml", ".yml", ".env", ".config", ".conf",
		".map", ".sh", ".bat", ".ps1", ".go", ".py", ".rb", ".php",
		"":
		return true
	default:
		return false
	}
}

// ShouldScanPath 按路径/扩展名快速跳过静态资源。
func ShouldScanPath(filePath string) bool {
	base := filepath.Base(filePath)
	if base == "" {
		return false
	}
	// 隐藏审计产物目录
	if strings.Contains(filepath.ToSlash(filePath), "/.gwxapkg/") || strings.HasPrefix(filepath.ToSlash(filePath), ".gwxapkg/") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(base))
	// 明确排除二进制/媒体
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
		".mp3", ".mp4", ".wav", ".ogg", ".woff", ".woff2", ".ttf", ".eot",
		".zip", ".gz", ".br", ".wasm", ".bin", ".exe", ".dll", ".so",
		".pdf", ".xlsx", ".xls", ".doc", ".docx":
		return false
	}
	return IsScannableTextExt(ext)
}

// looksLikeAPIContent 廉价判断文件是否可能含 HTTP 请求调用。
func looksLikeAPIContent(text string) bool {
	if text == "" {
		return false
	}
	// 小写搜索会复制，对大文件用原串子串探测更便宜
	needles := []string{
		"request", "fetch", "axios", "http", "url",
		"wx.request", "uni.request", "tt.request", "my.request",
		"/api/", "https://", "http://",
	}
	lowered := false
	var lower string
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
		// 部分大小写变体
		if !lowered {
			lower = strings.ToLower(text)
			lowered = true
		}
		if strings.Contains(lower, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
