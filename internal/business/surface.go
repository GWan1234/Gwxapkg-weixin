package business

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/25smoking/Gwxapkg/internal/reporter"
)

const (
	reportDirName = ".gwxapkg"
	jsonFileName  = "business_surface.json"
	mdFileName    = "business_surface.md"

	// 业务面标签（给 LLM / audit 统一使用）
	TagAuth     = "auth"      // 登录/注册/验证码/重置密码
	TagIDOR     = "idor"      // 用户/订单/证件查询等对象级访问
	TagPayment  = "payment"   // 支付/优惠/积分
	TagUpload   = "upload"    // 文件上传
	TagShare    = "share"     // 分享
	TagWebView  = "webview"   // web-view / 外链打开
	TagPlugin   = "plugin"    // 插件
	TagSMS      = "sms"       // 短信验证码（auth 子类，便于筛选）
	TagProfile  = "profile"   // 用户资料
	TagOrder    = "order"     // 订单
	TagCert     = "cert"      // 证件/证照查询

	// Finding / 假设状态（静态层与活体层共用，避免 false_positive 误导）
	StatusNeedsServer      = "needs_server_validation" // 源码有攻击面，结论依赖后端
	StatusConfirmedStatic  = "confirmed_static"        // 仅前端源码即可认定的缺陷
	StatusUnauthDenied     = "unauth_denied"           // 活体：匿名访问被拒（≠ 无洞）
	StatusAuthIDORUntested = "auth_idor_untested"      // 活体：未带 token/双身份，登录后越权未测
	StatusConfirmed        = "confirmed"               // 活体已证实
	StatusFalsePositive    = "false_positive"          // 已充分否定该假设
	StatusInconclusive     = "inconclusive"
	StatusSkipped          = "skipped"
)

// SurfaceReport 业务漏洞面总览（确定性预筛，供 LLM 审计优先消费）。
type SurfaceReport struct {
	GeneratedAt   string            `json:"generated_at"`
	SourceDir     string            `json:"source_dir"`
	Summary       map[string]int    `json:"summary"`
	Endpoints     []TaggedEndpoint  `json:"endpoints"`
	Pages         []TaggedPage      `json:"pages,omitempty"`
	CodeSignals   []CodeSignal      `json:"code_signals,omitempty"`
	Hypotheses    []Hypothesis      `json:"hypotheses"`
	Checklist     []ChecklistItem   `json:"checklist"`
	Notes         []string          `json:"notes,omitempty"`
	JSONPath      string            `json:"json_path,omitempty"`
	MarkdownPath  string            `json:"markdown_path,omitempty"`
	NoRedaction   bool              `json:"no_redaction"`
}

// TaggedEndpoint 带业务标签的接口。
type TaggedEndpoint struct {
	ID             string   `json:"id"`
	Method         string   `json:"method,omitempty"`
	URL            string   `json:"url,omitempty"`
	ControllerName string   `json:"controller_name,omitempty"`
	MethodsName    string   `json:"methods_name,omitempty"`
	FunctionName   string   `json:"function_name,omitempty"`
	FilePath       string   `json:"file_path,omitempty"`
	LineNumber     int      `json:"line_number,omitempty"`
	ParamFields    []string `json:"param_fields,omitempty"`
	Tags           []string `json:"tags"`
	RiskHints      []string `json:"risk_hints,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	Context        string   `json:"context,omitempty"`
}

// TaggedPage 带业务标签的页面。
type TaggedPage struct {
	Route      string   `json:"route"`
	Title      string   `json:"title,omitempty"`
	Tags       []string `json:"tags"`
	Files      []string `json:"files,omitempty"`
	RiskHints  []string `json:"risk_hints,omitempty"`
}

// CodeSignal 源码中的业务能力信号（非接口）。
type CodeSignal struct {
	Kind       string `json:"kind"`
	FilePath   string `json:"file_path"`
	LineNumber int    `json:"line_number"`
	Evidence   string `json:"evidence"`
	Tags       []string `json:"tags"`
}

// Hypothesis 确定性业务风险假设（默认需后端验证）。
type Hypothesis struct {
	ID               string   `json:"id"`
	Surface          string   `json:"surface"` // auth/idor/payment/upload/share/webview/plugin
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Confidence       string   `json:"confidence"`
	Status           string   `json:"status"`
	ValidationLayer  string   `json:"validation_layer,omitempty"` // static | live | mixed
	Why              string   `json:"why"`
	Evidence         []string `json:"evidence,omitempty"`
	APIs             []string `json:"apis,omitempty"`
	Pages            []string `json:"pages,omitempty"`
	Files            []string `json:"files,omitempty"`
	LLMFocus         []string `json:"llm_focus,omitempty"`
}

// ChecklistItem LLM 必查清单项。
type ChecklistItem struct {
	Surface string   `json:"surface"`
	Items   []string `json:"items"`
}

type tagRule struct {
	tag     string
	pattern *regexp.Regexp
	hint    string
}

var endpointTagRules = []tagRule{
	// 登录注册验证码重置
	{TagAuth, regexp.MustCompile(`(?i)(login|signin|sign_in|oauth|sso|passport|auth/|authenticate|/token\b|session)`), "登录/鉴权相关接口"},
	{TagAuth, regexp.MustCompile(`(?i)(register|signup|sign_up|regist)`), "注册相关接口"},
	{TagSMS, regexp.MustCompile(`(?i)(sms|verifycode|verify_code|captcha|vcode|sendcode|send_code|手机验证|验证码|短信)`), "短信/验证码相关接口"},
	{TagAuth, regexp.MustCompile(`(?i)(reset.?password|forgot.?password|changepass|change_password|找回密码|重置密码|修改密码)`), "密码重置/修改相关接口"},
	// IDOR 高发
	{TagProfile, regexp.MustCompile(`(?i)(userinfo|user_info|profile|member/info|getuser|user/detail|个人信息|用户信息)`), "用户信息查询/更新"},
	{TagOrder, regexp.MustCompile(`(?i)(order|trade|订单)`), "订单相关接口"},
	{TagCert, regexp.MustCompile(`(?i)(certificate|license|idcard|id_card|证件|证照|查询结果|档案)`), "证件/证照/档案查询"},
	{TagIDOR, regexp.MustCompile(`(?i)(userId|userid|uid|memberId|orderId|order_id|certId|id=|/detail|/info\b)`), "可能按对象 ID 访问的接口（IDOR 面）"},
	// 支付优惠积分
	{TagPayment, regexp.MustCompile(`(?i)(pay|payment|wxpay|alipay|prepay|收银台|支付)`), "支付相关接口"},
	{TagPayment, regexp.MustCompile(`(?i)(coupon|voucher|promo|discount|优惠|券)`), "优惠/券相关接口"},
	{TagPayment, regexp.MustCompile(`(?i)(point|integral|score|积分|金币)`), "积分相关接口"},
	// 上传分享 webview 插件
	{TagUpload, regexp.MustCompile(`(?i)(upload|file/|image/upload|oss|cos|上传)`), "文件/图片上传"},
	{TagShare, regexp.MustCompile(`(?i)(share|timeline|朋友圈|分享)`), "分享相关"},
	{TagWebView, regexp.MustCompile(`(?i)(webview|web-view|h5url|h5_url|openurl|outer.?url)`), "webview/外链打开"},
	{TagPlugin, regexp.MustCompile(`(?i)(plugin|__plugin__|requirePlugin)`), "插件相关"},
}

var pageTagRules = []tagRule{
	{TagAuth, regexp.MustCompile(`(?i)(login|signin|register|signup|auth|passport|登录|注册)`), "登录/注册页"},
	{TagSMS, regexp.MustCompile(`(?i)(sms|verify|captcha|code|验证码)`), "验证码相关页"},
	{TagAuth, regexp.MustCompile(`(?i)(reset|forgot|password|密码)`), "密码相关页"},
	{TagProfile, regexp.MustCompile(`(?i)(user|profile|mine|member|我的|个人|中心)`), "用户中心/资料页"},
	{TagOrder, regexp.MustCompile(`(?i)(order|trade|订单)`), "订单页"},
	{TagCert, regexp.MustCompile(`(?i)(cert|license|查询|证照|证件|档案)`), "查询/证照页"},
	{TagPayment, regexp.MustCompile(`(?i)(pay|payment|coupon|point|积分|优惠|支付|收银台)`), "支付/营销页"},
	{TagUpload, regexp.MustCompile(`(?i)(upload|上传)`), "上传页"},
	{TagShare, regexp.MustCompile(`(?i)(share|分享)`), "分享页"},
	{TagWebView, regexp.MustCompile(`(?i)(webview|web-view|h5)`), "H5/webview 页"},
	{TagPlugin, regexp.MustCompile(`(?i)(plugin)`), "插件页"},
}

var codeSignalPatterns = []struct {
	kind string
	tags []string
	re   *regexp.Regexp
}{
	{"wx_login", []string{TagAuth}, regexp.MustCompile(`\bwx\.login\s*\(`)},
	{"getPhoneNumber", []string{TagAuth, TagSMS}, regexp.MustCompile(`(?i)getPhoneNumber|getphonenumber`)},
	{"getStorage_token", []string{TagAuth}, regexp.MustCompile(`(?i)getStorageSync\s*\(\s*['"][^'"]*(token|session|openid|Authorization)`)},
	{"setStorage_token", []string{TagAuth}, regexp.MustCompile(`(?i)setStorageSync\s*\(\s*['"][^'"]*(token|session|openid|Authorization)`)},
	{"chooseImage_upload", []string{TagUpload}, regexp.MustCompile(`\bwx\.chooseImage\s*\(|\buni\.chooseImage\s*\(`)},
	{"uploadFile", []string{TagUpload}, regexp.MustCompile(`\bwx\.uploadFile\s*\(|\buni\.uploadFile\s*\(`)},
	{"share_app_message", []string{TagShare}, regexp.MustCompile(`(?i)onShareAppMessage|onShareTimeline`)},
	{"web_view_component", []string{TagWebView}, regexp.MustCompile(`(?i)<web-view\b|web-view\s+src=`)},
	{"open_document_link", []string{TagWebView}, regexp.MustCompile(`(?i)wx\.navigateToMiniProgram|openEmbeddedMiniProgram`)},
	{"require_plugin", []string{TagPlugin}, regexp.MustCompile(`(?i)requirePlugin\s*\(|__plugin__`)},
	{"id_param", []string{TagIDOR}, regexp.MustCompile(`(?i)(userId|orderId|memberId|certId|idCard)\s*[:=]`)},
}

// AnalyzeAndWrite 分析并写出 business_surface 产物；同时回写 unified map 的 tags（若存在）。
func AnalyzeAndWrite(rootDir string) (*SurfaceReport, error) {
	report, err := Analyze(rootDir)
	if err != nil {
		return nil, err
	}
	if err := WriteReport(rootDir, report); err != nil {
		return report, err
	}
	// 尽力给 unified map 打上 tags，方便 LLM 单文件消费
	_ = annotateUnifiedMap(rootDir, report)
	return report, nil
}

// Analyze 基于 unified/api/route 与源码信号构建业务面。
func Analyze(rootDir string) (*SurfaceReport, error) {
	report := &SurfaceReport{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		SourceDir:   rootDir,
		Summary:     map[string]int{},
		Endpoints:   make([]TaggedEndpoint, 0),
		Pages:       make([]TaggedPage, 0),
		CodeSignals: make([]CodeSignal, 0),
		Hypotheses:  make([]Hypothesis, 0),
		Checklist:   defaultChecklist(),
		NoRedaction: true,
		Notes: []string{
			"本报告为确定性业务面预筛，供 LLM 审计优先阅读；不代表漏洞已确认。",
			"所有业务假设默认 status=needs_server_validation，除非另有后端响应证据。",
		},
	}

	// 1) 接口：优先 unified map
	if unified, err := reporter.LoadUnifiedAPIMap(rootDir); err == nil && unified != nil {
		for _, ep := range unified.Endpoints {
			te := tagEndpointFromUnified(ep)
			if len(te.Tags) == 0 {
				continue
			}
			report.Endpoints = append(report.Endpoints, te)
		}
	} else if data, err := os.ReadFile(filepath.Join(rootDir, reportDirName, "api_endpoint_map.json")); err == nil {
		var epMap struct {
			Endpoints []struct {
				ID         string `json:"id"`
				Method     string `json:"method"`
				RawURL     string `json:"raw_url"`
				FilePath   string `json:"file_path"`
				LineNumber int    `json:"line_number"`
				Context    string `json:"context"`
			} `json:"endpoints"`
		}
		if json.Unmarshal(data, &epMap) == nil {
			for _, ep := range epMap.Endpoints {
				te := tagEndpoint(ep.ID, ep.Method, ep.RawURL, "", "", "", ep.FilePath, ep.LineNumber, nil, ep.Context, "medium")
				if len(te.Tags) > 0 {
					report.Endpoints = append(report.Endpoints, te)
				}
			}
		}
	}

	// 2) 页面：route_manifest
	if data, err := os.ReadFile(filepath.Join(rootDir, "route_manifest.json")); err == nil {
		var routes struct {
			Pages []struct {
				Route string `json:"route"`
				Title string `json:"title"`
				Files struct {
					JS   string `json:"js"`
					WXML string `json:"wxml"`
					JSON string `json:"json"`
				} `json:"files"`
			} `json:"pages"`
		}
		if json.Unmarshal(data, &routes) == nil {
			for _, p := range routes.Pages {
				blob := strings.Join([]string{p.Route, p.Title, p.Files.JS, p.Files.WXML}, " ")
				tags, hints := matchTags(blob, pageTagRules)
				if len(tags) == 0 {
					continue
				}
				files := make([]string, 0, 3)
				for _, f := range []string{p.Files.JS, p.Files.WXML, p.Files.JSON} {
					if f != "" {
						files = append(files, f)
					}
				}
				report.Pages = append(report.Pages, TaggedPage{
					Route:     p.Route,
					Title:     p.Title,
					Tags:      tags,
					Files:     files,
					RiskHints: hints,
				})
			}
		}
	}

	// 3) 源码信号（抽样扫描 js/wxml，控制成本）
	report.CodeSignals = scanCodeSignals(rootDir, 400)

	// 4) 汇总 + 假设
	for _, ep := range report.Endpoints {
		for _, t := range ep.Tags {
			report.Summary[t]++
		}
	}
	for _, p := range report.Pages {
		for _, t := range p.Tags {
			report.Summary["page_"+t]++
		}
	}
	for _, s := range report.CodeSignals {
		for _, t := range s.Tags {
			report.Summary["signal_"+t]++
		}
	}
	report.Hypotheses = buildHypotheses(report)

	sort.SliceStable(report.Endpoints, func(i, j int) bool {
		return report.Endpoints[i].ID < report.Endpoints[j].ID
	})
	return report, nil
}

// WriteReport 写出 json/md。
func WriteReport(rootDir string, report *SurfaceReport) error {
	if report == nil {
		return fmt.Errorf("报告为空")
	}
	dir := filepath.Join(rootDir, reportDirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	report.JSONPath = filepath.Join(dir, jsonFileName)
	report.MarkdownPath = filepath.Join(dir, mdFileName)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(report.JSONPath, data, 0644); err != nil {
		return err
	}
	return os.WriteFile(report.MarkdownPath, []byte(BuildMarkdown(report)), 0644)
}

// Load 读取已有 business_surface.json。
func Load(rootDir string) (*SurfaceReport, error) {
	data, err := os.ReadFile(filepath.Join(rootDir, reportDirName, jsonFileName))
	if err != nil {
		return nil, err
	}
	var report SurfaceReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

// BuildMarkdown 生成 LLM 友好的业务面摘要。
func BuildMarkdown(report *SurfaceReport) string {
	var b strings.Builder
	b.WriteString("# 业务漏洞面（确定性预筛）\n\n")
	b.WriteString("> 供 LLM 审计优先阅读。默认需服务端验证，不得直接写成已确认可利用。\n\n")
	b.WriteString(fmt.Sprintf("- 时间: %s\n", report.GeneratedAt))
	b.WriteString(fmt.Sprintf("- 目录: %s\n", report.SourceDir))
	b.WriteString(fmt.Sprintf("- 打标接口: %d | 打标页面: %d | 源码信号: %d | 假设: %d\n\n",
		len(report.Endpoints), len(report.Pages), len(report.CodeSignals), len(report.Hypotheses)))

	b.WriteString("## 标签统计\n\n")
	keys := make([]string, 0, len(report.Summary))
	for k := range report.Summary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("- `%s`: %d\n", k, report.Summary[k]))
	}

	b.WriteString("\n## 高优先级假设\n\n")
	if len(report.Hypotheses) == 0 {
		b.WriteString("_未生成假设（可能缺少 API/路由产物）。_\n")
	} else {
		for _, h := range report.Hypotheses {
			b.WriteString(fmt.Sprintf("### %s [%s] %s\n\n", h.ID, h.Surface, h.Title))
			b.WriteString(fmt.Sprintf("- severity: %s | confidence: %s | status: %s\n", h.Severity, h.Confidence, h.Status))
			b.WriteString(fmt.Sprintf("- why: %s\n", h.Why))
			if len(h.APIs) > 0 {
				b.WriteString("- apis: " + strings.Join(h.APIs, "; ") + "\n")
			}
			if len(h.Pages) > 0 {
				b.WriteString("- pages: " + strings.Join(h.Pages, ", ") + "\n")
			}
			if len(h.LLMFocus) > 0 {
				b.WriteString("- llm_focus:\n")
				for _, f := range h.LLMFocus {
					b.WriteString("  - " + f + "\n")
				}
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## 打标接口（节选）\n\n")
	b.WriteString("| ID | Tags | Method | URL/Controller | File |\n|----|------|--------|----------------|------|\n")
	limit := len(report.Endpoints)
	if limit > 80 {
		limit = 80
	}
	for _, ep := range report.Endpoints[:limit] {
		target := ep.URL
		if target == "" {
			target = ep.ControllerName + "." + ep.MethodsName
		}
		target = strings.ReplaceAll(target, "|", "\\|")
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			ep.ID, strings.Join(ep.Tags, ","), ep.Method, target, ep.FilePath))
	}

	b.WriteString("\n## LLM 必查清单\n\n")
	for _, c := range report.Checklist {
		b.WriteString(fmt.Sprintf("### %s\n\n", c.Surface))
		for _, item := range c.Items {
			b.WriteString("- [ ] " + item + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func tagEndpointFromUnified(ep reporter.UnifiedAPIEndpoint) TaggedEndpoint {
	return tagEndpoint(
		ep.ID, ep.Method, ep.URL, ep.ControllerName, ep.MethodsName, ep.FunctionName,
		ep.FilePath, ep.LineNumber, ep.ParamFields, ep.Context, ep.Confidence,
	)
}

func tagEndpoint(id, method, url, controller, methods, function, file string, line int, params []string, context, confidence string) TaggedEndpoint {
	blob := strings.Join([]string{url, controller, methods, function, file, context, strings.Join(params, " ")}, " ")
	tags, hints := matchTags(blob, endpointTagRules)
	// IDOR：带对象 id 参数字段时强化
	for _, p := range params {
		pl := strings.ToLower(p)
		if strings.Contains(pl, "id") || strings.Contains(pl, "uid") || strings.Contains(pl, "user") || strings.Contains(pl, "order") {
			tags = appendUnique(tags, TagIDOR)
			hints = appendUnique(hints, "参数字段疑似对象标识，关注 IDOR")
		}
	}
	if confidence == "" {
		confidence = "medium"
	}
	return TaggedEndpoint{
		ID:             id,
		Method:         method,
		URL:            url,
		ControllerName: controller,
		MethodsName:    methods,
		FunctionName:   function,
		FilePath:       file,
		LineNumber:     line,
		ParamFields:    params,
		Tags:           tags,
		RiskHints:      hints,
		Confidence:     confidence,
		Context:        truncate(context, 200),
	}
}

func matchTags(text string, rules []tagRule) ([]string, []string) {
	tags := make([]string, 0)
	hints := make([]string, 0)
	for _, rule := range rules {
		if rule.pattern.MatchString(text) {
			tags = appendUnique(tags, rule.tag)
			if rule.hint != "" {
				hints = appendUnique(hints, rule.hint)
			}
		}
	}
	return tags, hints
}

func scanCodeSignals(rootDir string, maxFiles int) []CodeSignal {
	signals := make([]CodeSignal, 0)
	count := 0
	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || count >= maxFiles {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".gwxapkg" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".js" && ext != ".wxml" && ext != ".ts" {
			return nil
		}
		rel, _ := filepath.Rel(rootDir, path)
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// 超大文件只看前 200KB
		text := string(data)
		if len(text) > 200*1024 {
			text = text[:200*1024]
		}
		count++
		for _, pat := range codeSignalPatterns {
			locs := pat.re.FindAllStringIndex(text, 3)
			for _, loc := range locs {
				snippet := compact(text[loc[0]:min(len(text), loc[1]+40)])
				signals = append(signals, CodeSignal{
					Kind:       pat.kind,
					FilePath:   rel,
					LineNumber: lineAt(text, loc[0]),
					Evidence:   snippet,
					Tags:       pat.tags,
				})
			}
		}
		return nil
	})
	return signals
}

func buildHypotheses(report *SurfaceReport) []Hypothesis {
	out := make([]Hypothesis, 0)
	idx := 1

	has := func(tag string) bool {
		if report.Summary[tag] > 0 || report.Summary["page_"+tag] > 0 || report.Summary["signal_"+tag] > 0 {
			return true
		}
		return false
	}
	apisByTag := func(tag string, limit int) []string {
		items := make([]string, 0)
		for _, ep := range report.Endpoints {
			for _, t := range ep.Tags {
				if t == tag {
					label := strings.TrimSpace(ep.Method + " " + ep.URL)
					if ep.URL == "" {
						label = ep.ControllerName + "." + ep.MethodsName
					}
					items = append(items, label)
					break
				}
			}
			if len(items) >= limit {
				break
			}
		}
		return items
	}
	pagesByTag := func(tag string, limit int) []string {
		items := make([]string, 0)
		for _, p := range report.Pages {
			for _, t := range p.Tags {
				if t == tag {
					items = append(items, p.Route)
					break
				}
			}
			if len(items) >= limit {
				break
			}
		}
		return items
	}
	filesBySignal := func(kind string, limit int) []string {
		items := make([]string, 0)
		seen := map[string]struct{}{}
		for _, s := range report.CodeSignals {
			if s.Kind != kind {
				continue
			}
			if _, ok := seen[s.FilePath]; ok {
				continue
			}
			seen[s.FilePath] = struct{}{}
			items = append(items, fmt.Sprintf("%s:%d", s.FilePath, s.LineNumber))
			if len(items) >= limit {
				break
			}
		}
		return items
	}

	add := func(surface, title, severity, confidence, status, layer, why string, apis, pages, files, focus []string) {
		if status == "" {
			status = StatusNeedsServer
		}
		if layer == "" {
			layer = "static"
		}
		out = append(out, Hypothesis{
			ID:              fmt.Sprintf("BIZ-%03d", idx),
			Surface:         surface,
			Title:           title,
			Severity:        severity,
			Confidence:      confidence,
			Status:          status,
			ValidationLayer: layer,
			Why:             why,
			APIs:            apis,
			Pages:           pages,
			Files:           files,
			LLMFocus:        focus,
			Evidence:        append([]string{}, files...),
		})
		idx++
	}

	if has(TagAuth) || has(TagSMS) {
		add(TagAuth,
			"认证链路（登录/注册/验证码/重置）存在可审计攻击面",
			"high", "medium", StatusNeedsServer, "static",
			"源码侧已见登录/短信/token 落本地等实现；验证码频控与凭证强度依赖服务端，状态=needs_server_validation。",
			append(apisByTag(TagAuth, 8), apisByTag(TagSMS, 4)...),
			append(pagesByTag(TagAuth, 6), pagesByTag(TagSMS, 3)...),
			append(filesBySignal("wx_login", 3), filesBySignal("getStorage_token", 3)...),
			[]string{
				"验证码是否仅前端校验或可重放",
				"发送验证码接口是否缺频控/可刷",
				"登录成功 token 是否明文落 storage",
				"重置密码链路是否可用验证码/用户标识越权重置",
			},
		)
	}

	if has(TagIDOR) || has(TagProfile) || has(TagOrder) || has(TagCert) {
		add(TagIDOR,
			"对象级访问（用户/订单/证件查询）IDOR 高发面",
			"high", "medium", StatusNeedsServer, "static",
			"源码侧订单/用户/车辆等对象 ID 出现在路由与请求参数中，构成可测 IDOR 攻击面；是否可越权依赖服务端属主校验（登录后仍需验证，勿把「匿名被拒」当成无洞）。",
			append(append(apisByTag(TagIDOR, 6), apisByTag(TagOrder, 4)...), apisByTag(TagCert, 4)...),
			append(append(pagesByTag(TagProfile, 4), pagesByTag(TagOrder, 4)...), pagesByTag(TagCert, 4)...),
			filesBySignal("id_param", 5),
			[]string{
				"登录后替换他人 orderId/vid/userId 是否可读",
				"列表与详情权限是否一致",
				"证件/档案查询是否仅依赖前端隐藏参数",
				"未登录被拒 ≠ 登录后水平越权不存在",
			},
		)
	}

	if has(TagPayment) {
		add(TagPayment,
			"支付/优惠/积分接口需核对服务端金额与资格校验",
			"high", "medium", StatusNeedsServer, "static",
			"源码侧存在支付/券/积分相关接口与页面；金额与资格是否服务端重算需后端验证。匿名访问被拒只说明需登录，不否定登录后参数篡改风险。",
			apisByTag(TagPayment, 10),
			pagesByTag(TagPayment, 6),
			nil,
			[]string{
				"支付金额/数量是否前端传入且后端未复核",
				"优惠券是否可叠用、可刷、可越权领取",
				"积分增减是否仅前端触发",
				"支付回调/查询是否可伪造状态",
			},
		)
	}

	if has(TagUpload) {
		add(TagUpload,
			"文件上传能力需核对类型、鉴权与存储暴露",
			"medium", "medium", StatusNeedsServer, "static",
			"源码侧存在上传/COS 相关调用；鉴权与文件 ACL 依赖服务端。",
			apisByTag(TagUpload, 6),
			pagesByTag(TagUpload, 4),
			append(filesBySignal("uploadFile", 4), filesBySignal("chooseImage_upload", 3)...),
			[]string{
				"上传是否需登录",
				"是否限制类型/大小",
				"返回 URL 是否可未授权访问",
				"是否存在覆盖或路径穿越",
			},
		)
	}

	if has(TagShare) {
		add(TagShare,
			"分享链路参数是否导致越权或开放重定向",
			"medium", "medium", StatusNeedsServer, "static",
			"源码侧存在分享入口；scene/query 是否可信依赖落地页与后端，默认 needs_server_validation。",
			apisByTag(TagShare, 5),
			pagesByTag(TagShare, 4),
			filesBySignal("share_app_message", 4),
			[]string{
				"分享 scene/query 是否含敏感 id",
				"通过分享进入是否绕过鉴权",
				"分享落地页是否信任外部参数",
			},
		)
	}

	if has(TagWebView) {
		// 纯前端：decodeURIComponent(href)/web-view 无白名单 → 静态可确认设计缺陷
		wvFiles := filesBySignal("web_view_component", 8)
		if len(wvFiles) == 0 {
			wvFiles = pagesByTag(TagWebView, 6)
		}
		add(TagWebView,
			"开放 WebView：路由参数可控加载外链（静态已确认）",
			"high", "high", StatusConfirmedStatic, "static",
			"源码中 web-view 使用路由参数（如 href）经 decodeURIComponent 后直接作为 src，未见域名白名单校验。此为前端即可认定的高风险设计缺陷（钓鱼/外链加载面），不依赖后端响应。",
			apisByTag(TagWebView, 5),
			pagesByTag(TagWebView, 4),
			wvFiles,
			[]string{
				"确认入口是否可被分享/外链拉起并传入任意 href",
				"是否应增加业务域名白名单",
				"web-view 与小程序 postMessage 桥是否暴露敏感能力",
			},
		)
	}

	if has(TagPlugin) {
		add(TagPlugin,
			"插件/插件包边界需核对权限与数据外传",
			"medium", "low", StatusNeedsServer, "static",
			"源码侧存在插件引用；权限与数据出境需结合插件配置与业务验证。",
			apisByTag(TagPlugin, 4),
			pagesByTag(TagPlugin, 3),
			filesBySignal("require_plugin", 4),
			[]string{
				"插件是否可访问用户敏感数据",
				"插件版本与来源是否可信",
				"插件回调是否可被滥用",
			},
		)
	}

	return out
}

func defaultChecklist() []ChecklistItem {
	return []ChecklistItem{
		{Surface: TagAuth, Items: []string{
			"登录/注册/重置接口是否强制服务端校验",
			"短信验证码：发送频控、校验一次性、错误次数限制",
			"token/session 存储位置与失效策略",
			"微信手机号快速验证 getPhoneNumber 与自建短信是否混用可绕",
		}},
		{Surface: TagIDOR, Items: []string{
			"用户信息/订单/证件详情是否校验资源属主",
			"仅替换 id 参数是否可读他人数据",
			"批量查询/导出类接口权限",
		}},
		{Surface: TagPayment, Items: []string{
			"金额、优惠、积分是否服务端重算",
			"重复支付/重复领取",
			"支付状态查询是否可伪造",
		}},
		{Surface: TagUpload, Items: []string{
			"上传鉴权、类型限制、存储 ACL",
		}},
		{Surface: TagShare, Items: []string{
			"分享参数篡改与鉴权绕过",
		}},
		{Surface: TagWebView, Items: []string{
			"URL 白名单与桥接 API 暴露面",
		}},
		{Surface: TagPlugin, Items: []string{
			"插件权限最小化与数据出境",
		}},
	}
}

func annotateUnifiedMap(rootDir string, surface *SurfaceReport) error {
	path := filepath.Join(rootDir, reportDirName, "api_unified_map.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// 重新加载结构化并写回 tags
	unified, err := reporter.LoadUnifiedAPIMap(rootDir)
	if err != nil || unified == nil {
		return err
	}
	tagByID := map[string][]string{}
	for _, ep := range surface.Endpoints {
		tagByID[ep.ID] = ep.Tags
	}
	// 若 id 对不上，按 url/controller 再匹配
	type tagged struct {
		reporter.UnifiedAPIEndpoint
		BusinessTags []string `json:"business_tags,omitempty"`
		RiskHints    []string `json:"risk_hints,omitempty"`
	}
	out := make([]tagged, 0, len(unified.Endpoints))
	hintByID := map[string][]string{}
	for _, ep := range surface.Endpoints {
		hintByID[ep.ID] = ep.RiskHints
	}
	for _, ep := range unified.Endpoints {
		item := tagged{UnifiedAPIEndpoint: ep}
		if tags, ok := tagByID[ep.ID]; ok {
			item.BusinessTags = tags
			item.RiskHints = hintByID[ep.ID]
		} else {
			te := tagEndpointFromUnified(ep)
			item.BusinessTags = te.Tags
			item.RiskHints = te.RiskHints
		}
		out = append(out, item)
	}

	// 保留原 report 字段，替换 endpoints
	var full map[string]interface{}
	if err := json.Unmarshal(data, &full); err != nil {
		return err
	}
	full["endpoints"] = out
	full["business_surface"] = true
	encoded, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0644)
}

func appendUnique(values []string, items ...string) []string {
	seen := map[string]struct{}{}
	for _, v := range values {
		seen[v] = struct{}{}
	}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		values = append(values, item)
	}
	return values
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func compact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return truncate(s, 180)
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
