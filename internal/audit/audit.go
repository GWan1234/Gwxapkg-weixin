package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/25smoking/Gwxapkg/internal/business"
	"github.com/25smoking/Gwxapkg/internal/doctor"
	"github.com/25smoking/Gwxapkg/internal/reporter"
)

const auditDirName = "ai_audit"

// Options 控制确定性审计骨架生成。
type Options struct {
	Dir      string
	Fix      bool
	BurpFile string
	Version  string
}

// Result 审计输出路径。
type Result struct {
	AuditDir       string
	ReportPath     string
	FindingsPath   string
	CoveragePath   string
	EvidencePath   string
	ManifestPath   string
	DoctorStatus   string
	FindingCount   int
}

// Run 生成 .gwxapkg/ai_audit/ 下的确定性审计骨架（不调用 LLM）。
func Run(opts Options) (*Result, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("目录为空")
	}
	root := opts.Dir

	health, err := doctor.AnalyzeAndWrite(root)
	if err != nil {
		return nil, fmt.Errorf("doctor 失败: %w", err)
	}

	if opts.Fix {
		// 仅给出建议；实际补跑由 CLI 层调用 semantic/scan-only，避免循环依赖。
		// 这里只记录 fix 意图到 manifest。
	}

	auditDir := filepath.Join(root, ".gwxapkg", auditDirName)
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		return nil, err
	}

	// 业务漏洞面预筛（与解包流水线共用；缺失时现场生成）
	surface, err := business.AnalyzeAndWrite(root)
	if err != nil {
		// 不阻断 audit：无 API 图时仍可出密钥类 findings
		surface = nil
	}

	findings := buildStaticFindings(root)
	findings = append(findings, buildBusinessFindings(surface)...)
	if err := writeJSON(filepath.Join(auditDir, "findings.json"), findings); err != nil {
		return nil, err
	}

	// 业务假设单独落一份，方便 LLM 按面推进
	if surface != nil {
		_ = writeJSON(filepath.Join(auditDir, "business_hypotheses.json"), surface.Hypotheses)
		_ = os.WriteFile(filepath.Join(auditDir, "business_checklist.md"), []byte(buildBusinessChecklistMD(surface)), 0644)
	}

	coverage := buildCoverageGaps(health)
	if surface != nil {
		coverage += buildBusinessCoverageNote(surface)
	}
	if err := os.WriteFile(filepath.Join(auditDir, "coverage_gaps.md"), []byte(coverage), 0644); err != nil {
		return nil, err
	}

	evidence := buildEvidenceTable(root, findings)
	if err := os.WriteFile(filepath.Join(auditDir, "evidence_table.md"), []byte(evidence), 0644); err != nil {
		return nil, err
	}

	reportMD := buildSecurityReportSkeleton(root, health, findings, surface)
	reportPath := filepath.Join(auditDir, "security_report.md")
	if err := os.WriteFile(reportPath, []byte(reportMD), 0644); err != nil {
		return nil, err
	}

	artifacts := collectReadableArtifacts(root)
	if surface != nil {
		artifacts = append(artifacts, ".gwxapkg/business_surface.json", ".gwxapkg/business_surface.md")
	}
	manifest := map[string]interface{}{
		"generated_at":   time.Now().Format(time.RFC3339),
		"source_dir":     root,
		"tool":           "gwxapkg audit",
		"version":        opts.Version,
		"doctor_status":  health.Status,
		"fix_requested": opts.Fix,
		"burp_file":      opts.BurpFile,
		"artifacts_read": artifacts,
		"business_surfaces": surfaceSummary(surface),
		"priority_surfaces": []string{"auth", "idor", "payment", "upload", "share", "webview", "plugin"},
		"limitations": []string{
			"本报告由确定性规则生成骨架，不包含 LLM 业务推理。",
			"confirmed_static=仅前端源码即可认定；needs_server_validation=有攻击面但依赖后端。",
			"unauth_denied=匿名被拒，不等于无洞；auth_idor_untested=登录后越权未测。",
			"不联网、不重放请求（除非使用 validate -i-authorize-live）。",
		},
	}
	manifestPath := filepath.Join(auditDir, "llm_audit_manifest.json")
	if err := writeJSON(manifestPath, manifest); err != nil {
		return nil, err
	}

	return &Result{
		AuditDir:     auditDir,
		ReportPath:   reportPath,
		FindingsPath: filepath.Join(auditDir, "findings.json"),
		CoveragePath: filepath.Join(auditDir, "coverage_gaps.md"),
		EvidencePath: filepath.Join(auditDir, "evidence_table.md"),
		ManifestPath: manifestPath,
		DoctorStatus: health.Status,
		FindingCount: len(findings),
	}, nil
}

type finding struct {
	ID              string                   `json:"id"`
	Title           string                   `json:"title"`
	Severity        string                   `json:"severity"`
	Confidence      string                   `json:"confidence"`
	Status          string                   `json:"status"`
	ValidationLayer string                   `json:"validation_layer,omitempty"`
	Surface         string                   `json:"surface,omitempty"`
	Affected        map[string]interface{}   `json:"affected"`
	Evidence        []map[string]interface{} `json:"evidence"`
	Risk            string                   `json:"risk"`
	Remediation     []string                 `json:"remediation"`
	LLMFocus        []string                 `json:"llm_focus,omitempty"`
}

func buildBusinessFindings(surface *business.SurfaceReport) []finding {
	if surface == nil {
		return nil
	}
	out := make([]finding, 0, len(surface.Hypotheses))
	for _, h := range surface.Hypotheses {
		affected := map[string]interface{}{}
		if len(h.APIs) > 0 {
			affected["apis"] = h.APIs
		}
		if len(h.Pages) > 0 {
			affected["pages"] = h.Pages
		}
		if len(h.Files) > 0 {
			affected["files"] = h.Files
		}
		affected["business_flows"] = []string{h.Surface}

		evidence := make([]map[string]interface{}, 0)
		evidence = append(evidence, map[string]interface{}{
			"source":  "business_surface.json",
			"file":    ".gwxapkg/business_surface.json",
			"summary": h.Why,
		})
		for _, api := range h.APIs {
			if len(evidence) >= 6 {
				break
			}
			evidence = append(evidence, map[string]interface{}{
				"source":  "api_unified_map/business_surface",
				"file":    "",
				"summary": api,
			})
		}

		status := h.Status
		if status == "" {
			status = business.StatusNeedsServer
		}
		remediation := []string{
			"后端强制鉴权与对象级授权（属主）校验",
			"关键参数（金额、id、验证码）以服务端为准",
			"对 " + h.Surface + " 面做授权范围内的接口复测后再定级",
		}
		if status == business.StatusConfirmedStatic {
			remediation = []string{
				"为 web-view/外链增加业务域名白名单，禁止任意 href 加载",
				"分享/扫码入口对 URL 参数做校验与编码约束",
				"审计 postMessage 等桥接 API 的暴露面",
			}
		}
		for _, f := range h.Files {
			if f != "" {
				evidence = append(evidence, map[string]interface{}{
					"source":  "source_code",
					"file":    f,
					"summary": "static evidence path",
				})
			}
		}
		out = append(out, finding{
			ID:              h.ID,
			Title:           h.Title,
			Severity:        h.Severity,
			Confidence:      h.Confidence,
			Status:          status,
			ValidationLayer: h.ValidationLayer,
			Surface:         h.Surface,
			Affected:        affected,
			Evidence:        evidence,
			Risk:            h.Why,
			Remediation:     remediation,
			LLMFocus:        h.LLMFocus,
		})
	}
	return out
}

func surfaceSummary(surface *business.SurfaceReport) map[string]int {
	if surface == nil {
		return map[string]int{}
	}
	return surface.Summary
}

func buildBusinessChecklistMD(surface *business.SurfaceReport) string {
	var b strings.Builder
	b.WriteString("# 业务面 LLM 必查清单\n\n")
	b.WriteString("按面完成检查；每条 finding 必须挂接口/页面/文件证据。\n\n")
	for _, c := range surface.Checklist {
		b.WriteString("## " + c.Surface + "\n\n")
		for _, item := range c.Items {
			b.WriteString("- [ ] " + item + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func buildBusinessCoverageNote(surface *business.SurfaceReport) string {
	var b strings.Builder
	b.WriteString("\n## 业务面覆盖\n\n")
	b.WriteString(fmt.Sprintf("- 打标接口: %d\n- 打标页面: %d\n- 假设数: %d\n",
		len(surface.Endpoints), len(surface.Pages), len(surface.Hypotheses)))
	priority := []string{business.TagAuth, business.TagIDOR, business.TagPayment, business.TagUpload, business.TagShare, business.TagWebView, business.TagPlugin}
	for _, tag := range priority {
		n := surface.Summary[tag] + surface.Summary["page_"+tag] + surface.Summary["signal_"+tag]
		if n == 0 {
			b.WriteString(fmt.Sprintf("- `%s`: 未检出明显信号（可能未实现该业务，或命名过于隐晦）\n", tag))
		} else {
			b.WriteString(fmt.Sprintf("- `%s`: 已检出信号 %d\n", tag, n))
		}
	}
	return b.String()
}

func buildStaticFindings(root string) []finding {
	findings := make([]finding, 0)

	// 从 sensitive_report.json 抽取高置信密钥类
	data, err := os.ReadFile(filepath.Join(root, "sensitive_report.json"))
	if err == nil {
		var report struct {
			Items []struct {
				RuleID     string `json:"rule_id"`
				RuleName   string `json:"rule_name"`
				Category   string `json:"category"`
				Content    string `json:"content"`
				FilePath   string `json:"file_path"`
				LineNumber int    `json:"line_number"`
				Confidence string `json:"confidence"`
			} `json:"items"`
		}
		if json.Unmarshal(data, &report) == nil {
			idx := 1
			for _, item := range report.Items {
				if strings.ToLower(item.Confidence) != "high" {
					continue
				}
				cat := strings.ToLower(item.Category)
				if cat != "private_key" && cat != "cloud" && cat != "payment" && cat != "secret" && cat != "api_key" {
					continue
				}
				findings = append(findings, finding{
					ID:         fmt.Sprintf("SECRET-%03d", idx),
					Title:      "前端源码中发现高置信敏感凭证: " + item.RuleName,
					Severity:   "high",
					Confidence: "high",
					Status:     "audit_attention",
					Affected: map[string]interface{}{
						"files": []string{item.FilePath},
					},
					Evidence: []map[string]interface{}{
						{
							"source":  "sensitive_report.json",
							"file":    item.FilePath,
							"line":    item.LineNumber,
							"snippet": item.Content,
							"summary": item.RuleName,
						},
					},
					Risk: "凭证出现在小程序前端包中，可能被提取滥用；是否可直接造成业务损失取决于后端鉴权与密钥权限。",
					Remediation: []string{
						"轮换并作废已暴露密钥",
						"避免在前端硬编码云/支付/私钥类凭证",
						"后端校验并最小化密钥权限范围",
					},
				})
				idx++
				if idx > 50 {
					break
				}
			}
		}
	}

	// 外链绝对 URL 接口提示（不宣称可利用）
	if unified, err := reporter.LoadUnifiedAPIMap(root); err == nil {
		idx := 1
		for _, ep := range unified.Endpoints {
			if !strings.HasPrefix(strings.ToLower(ep.URL), "http://") && !strings.HasPrefix(strings.ToLower(ep.URL), "https://") {
				continue
			}
			findings = append(findings, finding{
				ID:         fmt.Sprintf("API-%03d", idx),
				Title:      "发现绝对地址接口线索: " + ep.Method + " " + ep.URL,
				Severity:   "info",
				Confidence: "medium",
				Status:     "needs_server_validation",
				Affected: map[string]interface{}{
					"apis":  []string{ep.Method + " " + ep.URL},
					"files": []string{ep.FilePath},
				},
				Evidence: []map[string]interface{}{
					{
						"source":  "api_unified_map.json",
						"file":    ep.FilePath,
						"line":    ep.LineNumber,
						"snippet": ep.Context,
						"summary": "static endpoint extraction",
					},
				},
				Risk: "前端暴露了完整接口地址，需结合鉴权与参数校验判断是否存在未授权/越权风险。",
				Remediation: []string{
					"后端强制鉴权与对象级授权校验",
					"避免依赖前端隐藏接口作为安全边界",
				},
			})
			idx++
			if idx > 30 {
				break
			}
		}
	}

	return findings
}

func buildCoverageGaps(health *doctor.HealthReport) string {
	var b strings.Builder
	b.WriteString("# 覆盖缺口\n\n")
	if health == nil {
		b.WriteString("无 doctor 报告。\n")
		return b.String()
	}
	b.WriteString(fmt.Sprintf("Doctor 状态: **%s**\n\n", health.Status))
	if len(health.Gaps) == 0 {
		b.WriteString("未发现明显覆盖缺口。\n")
	} else {
		for _, g := range health.Gaps {
			b.WriteString("- " + g + "\n")
		}
	}
	if len(health.Suggestions) > 0 {
		b.WriteString("\n## 建议\n\n")
		for _, s := range health.Suggestions {
			b.WriteString("- `" + s + "`\n")
		}
	}
	return b.String()
}

func buildEvidenceTable(root string, findings []finding) string {
	var b strings.Builder
	b.WriteString("# 证据索引表\n\n")
	b.WriteString("| ID | Title | Severity | File | Source |\n")
	b.WriteString("|----|-------|----------|------|--------|\n")
	for _, f := range findings {
		file := ""
		source := ""
		if len(f.Evidence) > 0 {
			if v, ok := f.Evidence[0]["file"].(string); ok {
				file = v
			}
			if v, ok := f.Evidence[0]["source"].(string); ok {
				source = v
			}
		}
		title := strings.ReplaceAll(f.Title, "|", "\\|")
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", f.ID, title, f.Severity, file, source))
	}
	if len(findings) == 0 {
		b.WriteString("\n_无确定性 findings；请结合 Agent 深度审计。_\n")
	}
	_ = root
	return b.String()
}

func buildSecurityReportSkeleton(root string, health *doctor.HealthReport, findings []finding, surface *business.SurfaceReport) string {
	var b strings.Builder
	b.WriteString("# 安全审计报告（骨架）\n\n")
	b.WriteString("> 本文件由 `gwxapkg audit` 确定性生成，用于 Agent/人工续写。默认不脱敏。\n\n")
	b.WriteString(fmt.Sprintf("- 目标目录: `%s`\n", root))
	if health != nil {
		b.WriteString(fmt.Sprintf("- Doctor 状态: **%s**\n", health.Status))
		b.WriteString(fmt.Sprintf("- API: semantic=%d http=%d unified=%d\n",
			health.SemanticEndpointCount, health.HTTPEndpointCount, health.UnifiedEndpointCount))
		b.WriteString(fmt.Sprintf("- 敏感命中(去重): %d\n", health.SensitiveMatchCount))
	}
	b.WriteString(fmt.Sprintf("- 静态 findings: %d\n", len(findings)))
	if surface != nil {
		b.WriteString(fmt.Sprintf("- 业务假设: %d | 打标接口: %d | 打标页面: %d\n",
			len(surface.Hypotheses), len(surface.Endpoints), len(surface.Pages)))
	}
	b.WriteString("\n")

	b.WriteString("## 执行摘要\n\n")
	b.WriteString("优先按业务面推进：`auth` → `idor` → `payment` → `upload/share/webview/plugin`。\n")
	b.WriteString("（待 LLM 结合 business_surface 与源码补充业务风险结论）\n\n")

	if surface != nil && len(surface.Hypotheses) > 0 {
		b.WriteString("## 业务面假设（确定性预筛）\n\n")
		for _, h := range surface.Hypotheses {
			b.WriteString(fmt.Sprintf("### %s [%s] %s\n\n", h.ID, h.Surface, h.Title))
			b.WriteString(fmt.Sprintf("- severity: %s | confidence: %s | status: %s\n", h.Severity, h.Confidence, h.Status))
			b.WriteString(fmt.Sprintf("- why: %s\n", h.Why))
			if len(h.LLMFocus) > 0 {
				b.WriteString("- llm_focus:\n")
				for _, f := range h.LLMFocus {
					b.WriteString("  - " + f + "\n")
				}
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## Findings\n\n")
	if len(findings) == 0 {
		b.WriteString("无确定性 findings。\n\n")
	} else {
		for _, f := range findings {
			b.WriteString(fmt.Sprintf("### %s %s\n\n", f.ID, f.Title))
			if f.Surface != "" {
				b.WriteString(fmt.Sprintf("- surface: %s\n", f.Surface))
			}
			b.WriteString(fmt.Sprintf("- severity: %s\n- confidence: %s\n- status: %s\n", f.Severity, f.Confidence, f.Status))
			b.WriteString(fmt.Sprintf("- risk: %s\n\n", f.Risk))
		}
	}

	b.WriteString("## 覆盖缺口\n\n详见 `coverage_gaps.md`。\n\n")
	b.WriteString("## 后续建议\n\n")
	b.WriteString("1. 读取 `.gwxapkg/business_surface.md` 与 `ai_audit/business_checklist.md`\n")
	b.WriteString("2. 使用 gwxapkg-ai-audit skill 按业务面补全证据与定级\n")
	b.WriteString("3. 对 needs_server_validation 项做授权范围内的后端验证\n")
	b.WriteString("4. 分包 partial 时补齐源码后再复测\n")
	return b.String()
}

func collectReadableArtifacts(root string) []string {
	candidates := []string{
		".gwxapkg/doctor_report.json",
		".gwxapkg/business_surface.json",
		".gwxapkg/api_unified_map.json",
		".gwxapkg/api_map.json",
		".gwxapkg/api_endpoint_map.json",
		".gwxapkg/api_call_chain.json",
		".gwxapkg/dataflow_hints.json",
		".gwxapkg/semantic_module_map.json",
		".gwxapkg/ast_rename_map.json",
		".gwxapkg/package_completeness.json",
		"sensitive_report.json",
		"route_manifest.json",
	}
	out := make([]string, 0)
	for _, rel := range candidates {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			out = append(out, rel)
		}
	}
	return out
}

func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
