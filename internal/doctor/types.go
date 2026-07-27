package doctor

const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusPoor = "poor"
)

// HealthReport 描述解包目录的健康检查结果。
type HealthReport struct {
	GeneratedAt            string           `json:"generated_at"`
	SourceDir              string           `json:"source_dir"`
	Status                 string           `json:"status"`
	LooksLikeMiniProgram   bool             `json:"looks_like_miniprogram"`
	PackageStatus          string           `json:"package_status,omitempty"`
	MissingSubpackages     int              `json:"missing_subpackages"`
	PlaceholderPages       int              `json:"placeholder_pages"`
	SemanticEndpointCount  int              `json:"semantic_endpoint_count"`
	HTTPEndpointCount      int              `json:"http_endpoint_count"`
	UnifiedEndpointCount   int              `json:"unified_endpoint_count"`
	SensitiveMatchCount    int              `json:"sensitive_match_count"`
	ASTSkippedFiles        int              `json:"ast_skipped_files"`
	Artifacts              []ArtifactStatus `json:"artifacts"`
	Gaps                   []string         `json:"gaps,omitempty"`
	Suggestions            []string         `json:"suggestions,omitempty"`
	JSONPath               string           `json:"json_path,omitempty"`
	MarkdownPath           string           `json:"markdown_path,omitempty"`
}

// ArtifactStatus 单个产物检查结果。
type ArtifactStatus struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Required bool   `json:"required"`
	Size     int64  `json:"size,omitempty"`
}
