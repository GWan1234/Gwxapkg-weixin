package analyzer

// RouteManifest 页面与路由分析产物。
type RouteManifest struct {
	AppID                string               `json:"app_id"`
	ConfigSource         string               `json:"config_source"`
	GeneratedAt          string               `json:"generated_at"`
	EntryPage            string               `json:"entry_page,omitempty"`
	ExternalMiniPrograms []string             `json:"external_mini_programs,omitempty"`
	TabBar               []TabBarItem         `json:"tab_bar,omitempty"`
	SubPackages          []SubPackageInfo     `json:"subpackages,omitempty"`
	Pages                []PageNode           `json:"pages"`
	NavigationEdges      []NavigationEdge     `json:"navigation_edges,omitempty"`
	SharedRouterHelpers  []SharedRouterHelper `json:"shared_router_helpers,omitempty"`
	OrphanPages          []string             `json:"orphan_pages,omitempty"`
	Summary              RouteSummary         `json:"summary"`
}

// PageNode 页面节点。
type PageNode struct {
	Route           string         `json:"route"`
	Title           string         `json:"title,omitempty"`
	PackageType     string         `json:"package_type"`
	PackageRoot     string         `json:"package_root,omitempty"`
	IsEntry         bool           `json:"is_entry"`
	IsTabBar        bool           `json:"is_tab_bar"`
	Files           PageFiles      `json:"files"`
	UsingComponents []string       `json:"using_components,omitempty"`
	Dependencies    []string       `json:"dependencies,omitempty"`
	APIUsage        []PageAPIUsage `json:"api_usage,omitempty"`
}

// PageFiles 页面关联文件。
type PageFiles struct {
	JS   string `json:"js,omitempty"`
	WXML string `json:"wxml,omitempty"`
	WXSS string `json:"wxss,omitempty"`
	JSON string `json:"json,omitempty"`
}

// PageAPIUsage 页面命中的接口。
type PageAPIUsage struct {
	Name       string `json:"name"`
	Method     string `json:"method"`
	RawURL     string `json:"raw_url"`
	FilePath   string `json:"file_path"`
	LineNumber int    `json:"line_number"`
	SourceRule string `json:"source_rule"`
	SourceKind string `json:"source_kind,omitempty"`
	ViaModule  string `json:"via_module,omitempty"`
}

// TabBarItem TabBar 页面信息。
type TabBarItem struct {
	PagePath         string `json:"page_path"`
	Text             string `json:"text,omitempty"`
	IconPath         string `json:"icon_path,omitempty"`
	SelectedIconPath string `json:"selected_icon_path,omitempty"`
}

// SubPackageInfo 分包信息。
type SubPackageInfo struct {
	Root      string   `json:"root"`
	PageCount int      `json:"page_count"`
	Pages     []string `json:"pages"`
}

// NavigationEdge 页面跳转边。
type NavigationEdge struct {
	SourcePage   string          `json:"source_page"`
	TargetPage   string          `json:"target_page"`
	RawTarget    string          `json:"raw_target"`
	Method       string          `json:"method"`
	SourceType   string          `json:"source_type"`
	SourceFile   string          `json:"source_file"`
	LineNumber   int             `json:"line_number"`
	TargetExists bool            `json:"target_exists"`
	HandlerName  string          `json:"handler_name,omitempty"`
	TriggerEvent string          `json:"trigger_event,omitempty"`
	TriggerText  string          `json:"trigger_text,omitempty"`
	Dynamic      bool            `json:"dynamic,omitempty"`
	CallChain    []CallChainStep `json:"call_chain,omitempty"`
}

// CallChainStep 表示从页面事件到最终跳转之间的一步调用。
type CallChainStep struct {
	FilePath     string `json:"file_path"`
	FunctionName string `json:"function_name"`
	Kind         string `json:"kind"`
	LineNumber   int    `json:"line_number,omitempty"`
}

// SharedRouterHelper 表示被识别出的共享路由助手。
type SharedRouterHelper struct {
	FilePath     string   `json:"file_path"`
	FunctionName string   `json:"function_name"`
	UsedByPages  []string `json:"used_by_pages,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	TargetHints  []string `json:"target_hints,omitempty"`
	Dynamic      bool     `json:"dynamic,omitempty"`
}

// RouteSummary 摘要统计。
type RouteSummary struct {
	TotalPages                 int `json:"total_pages"`
	MainPages                  int `json:"main_pages"`
	SubPackagePages            int `json:"subpackage_pages"`
	TabBarPages                int `json:"tabbar_pages"`
	PagesWithAPI               int `json:"pages_with_api"`
	APIEndpointCount           int `json:"api_endpoint_count"`
	IndirectAPIEndpointCount   int `json:"indirect_api_endpoint_count"`
	ReferencedComponents       int `json:"referenced_components"`
	NavigationEdgeCount        int `json:"navigation_edge_count"`
	DynamicNavigationEdgeCount int `json:"dynamic_navigation_edge_count"`
	CallChainEdgeCount         int `json:"call_chain_edge_count"`
	SharedRouterHelperCount    int `json:"shared_router_helper_count"`
	ExternalMiniProgramCount   int `json:"external_mini_program_count"`
	OrphanPageCount            int `json:"orphan_page_count"`
}
