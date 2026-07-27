package validate

import "time"

// Status 验证结论（与 business 包语义对齐）。
const (
	StatusConfirmed         = "confirmed"               // 活体证实存在风险
	StatusConfirmedStatic   = "confirmed_static"        // 前端源码已可认定（活体不应降级）
	StatusUnauthDenied      = "unauth_denied"           // 匿名访问被拒（≠ 无洞）
	StatusAuthIDORUntested  = "auth_idor_untested"      // 登录后对象级越权尚未测试
	StatusFalsePositive     = "false_positive"          // 在已执行探测范围内充分否定
	StatusInconclusive      = "inconclusive"            // 发了请求但无法定论
	StatusSkipped           = "skipped"                 // 安全策略跳过
	StatusError             = "error"                   // 网络/配置错误
	StatusNeedsServer       = "needs_server_validation" // 仍依赖服务端
)

// Options 活体验证选项（默认不联网；必须显式授权）。
type Options struct {
	Dir string

	// 必须：目标 API 根，如 https://app-api.example.com
	BaseURL string

	// 授权声明：必须为 true，否则拒绝执行
	IAuthorizeLive bool

	// DryRun 只生成探测计划，不发请求
	DryRun bool

	// 鉴权
	Token       string            // 原始 token
	TokenHeader string            // 默认 Authorization；可 Bearer 前缀由 TokenPrefix 控制
	TokenPrefix string            // 如 "Bearer "；空则按常见方式自动
	ExtraHeaders map[string]string

	// 第二身份（IDOR 对比，可选）
	TokenB string

	// 探测用对象 ID（逗号分隔或多次传入聚合）
	ProbeIDs []string

	// 主机允许列表；空则仅允许 BaseURL 的 host
	AllowHosts []string

	// 限制
	MaxRequests int           // 默认 80
	Timeout     time.Duration // 默认 12s
	QPS         float64       // 默认 2
	InsecureTLS bool

	// IncludeUnsafe 允许对标记为副作用风险的接口发 1 次最小探测（仍禁止短信轰炸类）
	IncludeUnsafe bool

	// Surfaces 只验证这些业务面；空=全部
	Surfaces []string
}

// Report 活体验证总报告。
type Report struct {
	GeneratedAt    string            `json:"generated_at"`
	SourceDir      string            `json:"source_dir"`
	BaseURL        string            `json:"base_url"`
	DryRun         bool              `json:"dry_run"`
	Authorized     bool              `json:"authorized"`
	RequestCount   int               `json:"request_count"`
	PlanCount      int               `json:"plan_count"`
	Summary        map[string]int    `json:"summary"`
	Probes         []ProbeResult     `json:"probes"`
	HypothesisVerdicts []HypothesisVerdict `json:"hypothesis_verdicts"`
	FindingUpdates []FindingUpdate   `json:"finding_updates,omitempty"`
	Notes          []string          `json:"notes,omitempty"`
	JSONPath       string            `json:"json_path,omitempty"`
	MarkdownPath   string            `json:"markdown_path,omitempty"`
	LogPath        string            `json:"log_path,omitempty"`
}

// ProbePlan 单次探测计划。
type ProbePlan struct {
	ID          string   `json:"id"`
	HypothesisID string  `json:"hypothesis_id,omitempty"`
	Surface     string   `json:"surface"`
	Kind        string   `json:"kind"` // unauth_access | auth_access | idor_compare | method_probe
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	Path        string   `json:"path"`
	UseToken    string   `json:"use_token,omitempty"` // a|b|none
	Body        string   `json:"body,omitempty"`
	Reason      string   `json:"reason"`
	Tags        []string `json:"tags,omitempty"`
	Safe        bool     `json:"safe"`
	SkipReason  string   `json:"skip_reason,omitempty"`
}

// ProbeResult 单次探测结果。
type ProbeResult struct {
	Plan           ProbePlan `json:"plan"`
	Skipped        bool      `json:"skipped"`
	SkipReason     string    `json:"skip_reason,omitempty"`
	StatusCode     int       `json:"status_code,omitempty"`
	LatencyMS      int64     `json:"latency_ms,omitempty"`
	BodySnippet    string    `json:"body_snippet,omitempty"`
	BodyBytes      int       `json:"body_bytes,omitempty"`
	AuthRequired   bool      `json:"auth_required,omitempty"`
	LooksSensitive bool      `json:"looks_sensitive,omitempty"`
	Error          string    `json:"error,omitempty"`
	VerdictHint    string    `json:"verdict_hint,omitempty"`
}

// HypothesisVerdict 对业务假设的汇总结论。
type HypothesisVerdict struct {
	ID              string   `json:"id"`
	Surface         string   `json:"surface"`
	Title           string   `json:"title"`
	PreviousStatus  string   `json:"previous_status"`
	Status          string   `json:"status"`
	ValidationLayer string   `json:"validation_layer,omitempty"` // static | live | mixed
	Severity        string   `json:"severity"`
	Confidence      string   `json:"confidence"`
	Summary         string   `json:"summary"`
	Evidence        []string `json:"evidence,omitempty"`
	ProbeIDs        []string `json:"probe_ids,omitempty"`
}

// FindingUpdate 写回 ai_audit/findings.json 的变更。
type FindingUpdate struct {
	ID         string `json:"id"`
	OldStatus  string `json:"old_status"`
	NewStatus  string `json:"new_status"`
	Confidence string `json:"confidence,omitempty"`
	Note       string `json:"note,omitempty"`
}
