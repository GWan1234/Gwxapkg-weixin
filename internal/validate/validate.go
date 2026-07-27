package validate

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/25smoking/Gwxapkg/internal/business"
	"github.com/25smoking/Gwxapkg/internal/reporter"
)

const (
	reportDirName = ".gwxapkg"
	jsonFileName  = "validation_report.json"
	mdFileName    = "validation_report.md"
	logFileName   = "validation_requests.jsonl"
)

var (
	// 明确禁止自动触发的副作用路径（短信、支付下单、删改等）
	destructivePath = regexp.MustCompile(`(?i)(sendVerificationCode|sendCode|sendSms|/sms/send|auth/mobile/send|verifyCode.*send|prepay|create/order|createPay|/pay$|balance/pay|payment/create|giftcard/send|delete|unbind|logoff|logout|upload|getUploadPolicy|pre-upload|register|signup|resetPassword|changePassword|refund/apply|card/consume)`)
	// 更像查询类、相对可安全探测（含用户/订单/配置读取）
	queryLikePath = regexp.MustCompile(`(?i)(query|list|detail|info|get|count|trace|search|banner|config|guide|rule|status|profile|userinfo|order|address|coupon|point|integral|finance|transaction|available|progress|auth/mobile/login|user/get|numberreduction)`)
	// 敏感响应特征
	sensitiveBody = regexp.MustCompile(`(?i)("token"\s*:|"mobile"\s*:|"phone"\s*:|"idCard"|"id_card"|"billCode"|"orderId"|"address"|"receiver"|"sender"|userId|openid|session)`)
	pagePathOnly  = regexp.MustCompile(`(?i)(^|/)pages/`)
	// 业务鉴权失败码（HTTP 200 但未授权）
	bizAuthFail = regexp.MustCompile(`(?i)(授权令牌不正确|未登录|token\s*invalid|unauthorized|login\s*required|"code"\s*:\s*(1229|401|403|10001|10002))`)
)

// Run 执行活体验证：生成探测计划 →（可选）发请求 → 汇总假设结论 → 写回 findings。
func Run(opts Options) (*Report, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("请指定 -dir 已解包目录")
	}
	if !opts.IAuthorizeLive {
		return nil, fmt.Errorf("拒绝执行：活体探测必须显式授权，请加 -i-authorize-live=true（仅限你已获得充分授权的目标）")
	}
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, fmt.Errorf("请指定 -base-url（例如 https://api.example.com）")
	}
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("无效 base-url: %s", opts.BaseURL)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("base-url 仅支持 http/https")
	}

	if opts.MaxRequests <= 0 {
		opts.MaxRequests = 80
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 12 * time.Second
	}
	if opts.QPS <= 0 {
		opts.QPS = 2
	}
	if opts.TokenHeader == "" {
		opts.TokenHeader = "Authorization"
	}
	if opts.TokenPrefix == "" && opts.Token != "" && !strings.HasPrefix(strings.ToLower(opts.Token), "bearer ") {
		// 默认不强制 Bearer，很多小程序直接传 token；用户可设 -token-prefix="Bearer "
		opts.TokenPrefix = ""
	}

	allowHosts := map[string]struct{}{strings.ToLower(base.Host): {}}
	for _, h := range opts.AllowHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			allowHosts[h] = struct{}{}
		}
	}

	surface, _ := business.Load(opts.Dir)
	if surface == nil {
		surface, err = business.AnalyzeAndWrite(opts.Dir)
		if err != nil {
			return nil, fmt.Errorf("加载/生成业务面失败: %w", err)
		}
	}

	unified, _ := reporter.LoadUnifiedAPIMap(opts.Dir)
	plans := buildPlans(opts, base, surface, unified)
	report := &Report{
		GeneratedAt: time.Now().Format(time.RFC3339),
		SourceDir:   opts.Dir,
		BaseURL:     base.String(),
		DryRun:      opts.DryRun,
		Authorized:  true,
		PlanCount:   len(plans),
		Summary:     map[string]int{},
		Probes:      make([]ProbeResult, 0, len(plans)),
		Notes: []string{
			"活体验证仅在你声明已获授权后执行；默认不会发送短信/下单/删除等破坏性请求。",
			"confirmed=活体证实风险；confirmed_static=前端源码已认定（不会被活体降级）。",
			"unauth_denied=匿名被拒（≠无洞）；auth_idor_untested=登录后越权未测（需 -token/-token-b）。",
			"false_positive 仅用于已充分否定的假设，勿与 unauth_denied 混淆。",
		},
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opts.InsecureTLS, //nolint:gosec // 用户显式选择
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var logFile *os.File
	if !opts.DryRun {
		logPath := filepath.Join(opts.Dir, reportDirName, logFileName)
		_ = os.MkdirAll(filepath.Dir(logPath), 0755)
		logFile, _ = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if logFile != nil {
			report.LogPath = logPath
			defer logFile.Close()
		}
	}

	interval := time.Duration(float64(time.Second) / opts.QPS)
	sent := 0
	for _, plan := range plans {
		if plan.SkipReason != "" {
			report.Probes = append(report.Probes, ProbeResult{
				Plan:       plan,
				Skipped:    true,
				SkipReason: plan.SkipReason,
				VerdictHint: StatusSkipped,
			})
			report.Summary[StatusSkipped]++
			continue
		}
		if opts.DryRun {
			report.Probes = append(report.Probes, ProbeResult{
				Plan:        plan,
				Skipped:     true,
				SkipReason:  "dry-run",
				VerdictHint: "would_probe",
			})
			report.Summary["dry_run"]++
			continue
		}
		if sent >= opts.MaxRequests {
			report.Probes = append(report.Probes, ProbeResult{
				Plan:       plan,
				Skipped:    true,
				SkipReason: "max-requests",
				VerdictHint: StatusSkipped,
			})
			report.Summary[StatusSkipped]++
			continue
		}

		// host allow
		u, err := url.Parse(plan.URL)
		if err != nil || u.Host == "" {
			report.Probes = append(report.Probes, ProbeResult{Plan: plan, Error: "bad url", VerdictHint: StatusError})
			report.Summary[StatusError]++
			continue
		}
		if _, ok := allowHosts[strings.ToLower(u.Host)]; !ok {
			report.Probes = append(report.Probes, ProbeResult{
				Plan: plan, Skipped: true, SkipReason: "host-not-allowed:" + u.Host, VerdictHint: StatusSkipped,
			})
			report.Summary[StatusSkipped]++
			continue
		}

		res := doProbe(client, opts, plan)
		report.Probes = append(report.Probes, res)
		sent++
		report.RequestCount++
		if res.Error != "" {
			report.Summary[StatusError]++
		} else if res.VerdictHint != "" {
			report.Summary[res.VerdictHint]++
		}
		if logFile != nil {
			line, _ := json.Marshal(res)
			_, _ = logFile.Write(append(line, '\n'))
		}
		time.Sleep(interval)
	}

	report.HypothesisVerdicts = judgeHypotheses(surface, report.Probes, opts)
	for _, v := range report.HypothesisVerdicts {
		report.Summary["hyp_"+v.Status]++
	}
	report.FindingUpdates = applyFindingUpdates(opts.Dir, report.HypothesisVerdicts)
	// 同步写回 business_surface 假设状态
	_ = updateBusinessHypotheses(opts.Dir, surface, report.HypothesisVerdicts)

	if err := WriteReport(opts.Dir, report); err != nil {
		return report, err
	}
	return report, nil
}

func buildPlans(opts Options, base *url.URL, surface *business.SurfaceReport, unified *reporter.UnifiedAPIMapReport) []ProbePlan {
	surfaceFilter := map[string]struct{}{}
	for _, s := range opts.Surfaces {
		surfaceFilter[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}
	allowSurface := func(s string) bool {
		if len(surfaceFilter) == 0 {
			return true
		}
		_, ok := surfaceFilter[strings.ToLower(s)]
		return ok
	}

	type ep struct {
		method string
		path   string
		tags   []string
		hyp    string
	}
	candidates := make([]ep, 0)

	// 从业务面 endpoints
	if surface != nil {
		for _, e := range surface.Endpoints {
			path := normalizeAPIPath(e.URL)
			if path == "" {
				continue
			}
			method := strings.ToUpper(strings.TrimSpace(e.Method))
			if method == "" || method == "UNKNOWN" {
				method = guessMethod(path)
			}
			// 关联假设
			hyp := ""
			for _, t := range e.Tags {
				if t == business.TagAuth || t == business.TagSMS {
					hyp = findHyp(surface, business.TagAuth)
				} else if t == business.TagIDOR || t == business.TagOrder || t == business.TagProfile || t == business.TagCert {
					hyp = findHyp(surface, business.TagIDOR)
				} else if t == business.TagPayment {
					hyp = findHyp(surface, business.TagPayment)
				} else if t == business.TagUpload {
					hyp = findHyp(surface, business.TagUpload)
				}
			}
			candidates = append(candidates, ep{method: method, path: path, tags: e.Tags, hyp: hyp})
		}
	}
	// 补充 unified 中 api/ 路径（含 business_tags 回写字段）
	if raw, err := os.ReadFile(filepath.Join(opts.Dir, reportDirName, "api_unified_map.json")); err == nil {
		var wrap struct {
			Endpoints []struct {
				Method       string   `json:"method"`
				URL          string   `json:"url"`
				BusinessTags []string `json:"business_tags"`
			} `json:"endpoints"`
		}
		if json.Unmarshal(raw, &wrap) == nil {
			for _, e := range wrap.Endpoints {
				path := normalizeAPIPath(e.URL)
				if path == "" {
					continue
				}
				method := strings.ToUpper(strings.TrimSpace(e.Method))
				if method == "" || method == "UNKNOWN" {
					method = guessMethod(path)
				}
				candidates = append(candidates, ep{method: method, path: path, tags: e.BusinessTags, hyp: ""})
			}
		}
	} else if unified != nil {
		for _, e := range unified.Endpoints {
			path := normalizeAPIPath(e.URL)
			if path == "" {
				continue
			}
			method := strings.ToUpper(strings.TrimSpace(e.Method))
			if method == "" || method == "UNKNOWN" {
				method = guessMethod(path)
			}
			candidates = append(candidates, ep{method: method, path: path, tags: nil, hyp: ""})
		}
	}

	// 去重 path+method
	seen := map[string]struct{}{}
	plans := make([]ProbePlan, 0)
	id := 0
	add := func(p ProbePlan) {
		key := p.Method + " " + p.Path + " " + p.Kind + " " + p.UseToken
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		id++
		p.ID = fmt.Sprintf("probe_%03d", id)
		plans = append(plans, p)
	}

	for _, c := range candidates {
		// 页面路径不是 HTTP API（pages/... 或 packageXxx/pages/...）
		if pagePathOnly.MatchString(c.path) || strings.Contains(c.path, "packageBike/") || strings.Contains(c.path, "packageMine/") || strings.Contains(c.path, "packageHelp/") {
			if !strings.Contains(c.path, "-api/") && !strings.HasPrefix(strings.TrimPrefix(c.path, "/"), "api") && !strings.Contains(c.path, "user-api") && !strings.Contains(c.path, "device-api") && !strings.Contains(c.path, "bike-") && !strings.Contains(c.path, "public/") {
				continue
			}
		}
		// 绝对外链非 base：跳过（避免打到任意第三方）
		if strings.HasPrefix(c.path, "http://") || strings.HasPrefix(c.path, "https://") {
			continue
		}

		primarySurface := primaryTag(c.tags)
		if primarySurface == "" {
			primarySurface = "api"
		}
		if !allowSurface(primarySurface) && !allowSurface(business.TagIDOR) && !allowSurface(business.TagAuth) {
			// 若用户过滤 surface，且该 ep 无匹配标签，仍允许通用 api 当未过滤
			if len(surfaceFilter) > 0 {
				continue
			}
		}
		if len(surfaceFilter) > 0 && primarySurface != "api" && !allowSurface(primarySurface) {
			// 标签表面不在过滤内则跳过
			matched := false
			for _, t := range c.tags {
				if allowSurface(t) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		full := joinURL(base, c.path)
		safe, skip := classifySafety(c.path, c.method, opts.IncludeUnsafe)

		// 1) 未授权访问探测
		p1 := ProbePlan{
			HypothesisID: c.hyp,
			Surface:      primarySurface,
			Kind:         "unauth_access",
			Method:       c.method,
			URL:          full,
			Path:         c.path,
			UseToken:     "none",
			Body:         defaultBody(c.method, c.path, opts.ProbeIDs),
			Reason:       "检测未登录是否可访问接口/返回敏感数据",
			Tags:         c.tags,
			Safe:         safe,
			SkipReason:   skip,
		}
		if !safe && skip != "" {
			p1.SkipReason = skip
		}
		add(p1)

		// 2) 授权访问基线
		if opts.Token != "" {
			p2 := p1
			p2.Kind = "auth_access"
			p2.UseToken = "a"
			p2.Reason = "登录态基线：是否 200 且返回业务数据"
			p2.SkipReason = skip
			add(p2)
		}

		// 3) IDOR：替换 id 参数 / body
		if hasAny(c.tags, business.TagIDOR, business.TagOrder, business.TagProfile, business.TagCert) || looksIDPath(c.path) {
			ids := opts.ProbeIDs
			if len(ids) == 0 {
				ids = []string{"1", "2", "99999999"}
			}
			for _, probeID := range ids {
				if len(ids) > 3 && probeID != ids[0] && probeID != ids[1] && probeID != ids[2] {
					continue
				}
				p := p1
				p.Kind = "idor_compare"
				p.UseToken = "a"
				if opts.Token == "" {
					p.UseToken = "none"
				}
				p.Path = injectID(c.path, probeID)
				p.URL = joinURL(base, p.Path)
				p.Body = injectIDBody(c.method, c.path, probeID)
				p.Reason = "使用探测 ID=" + probeID + " 访问对象级接口"
				p.HypothesisID = findHyp(surface, business.TagIDOR)
				if p.HypothesisID == "" {
					p.HypothesisID = c.hyp
				}
				p.SkipReason = skip
				if opts.Token == "" && opts.TokenB == "" {
					// 仍可做未授权 IDOR 面
				}
				add(p)
				if opts.TokenB != "" {
					pb := p
					pb.UseToken = "b"
					pb.Reason = "第二身份访问同一对象 ID=" + probeID
					add(pb)
				}
			}
		}
	}

	// 限制计划规模：优先 safe + idor/auth
	if len(plans) > opts.MaxRequests*3 {
		plans = prioritizePlans(plans, opts.MaxRequests*3)
	}
	return plans
}

func classifySafety(path, method string, includeUnsafe bool) (safe bool, skip string) {
	if destructivePath.MatchString(path) {
		if includeUnsafe {
			// 即使 unsafe 也不对短信发送类自动发
			if regexp.MustCompile(`(?i)(sms|sendCode|sendVerification|verifyCodeSms)`).MatchString(path) {
				return false, "safety:refuse-sms-send"
			}
			if regexp.MustCompile(`(?i)(prepay|createPay|pay/create|payment/create)`).MatchString(path) {
				return false, "safety:refuse-payment-create"
			}
			if regexp.MustCompile(`(?i)(delete|logoff|unbind)`).MatchString(path) {
				return false, "safety:refuse-destructive-write"
			}
			return true, ""
		}
		return false, "safety:destructive-or-side-effect-path"
	}
	// 非查询类 POST 默认跳过
	if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
		if queryLikePath.MatchString(path) {
			return true, ""
		}
		if includeUnsafe {
			return true, ""
		}
		return false, "safety:non-query-write-method"
	}
	return true, ""
}

func doProbe(client *http.Client, opts Options, plan ProbePlan) ProbeResult {
	res := ProbeResult{Plan: plan}
	var bodyReader io.Reader
	if plan.Body != "" && plan.Method != "GET" && plan.Method != "HEAD" {
		bodyReader = bytes.NewBufferString(plan.Body)
	}
	req, err := http.NewRequest(plan.Method, plan.URL, bodyReader)
	if err != nil {
		res.Error = err.Error()
		res.VerdictHint = StatusError
		return res
	}
	req.Header.Set("User-Agent", "Gwxapkg-Validate/2.8 (+authorized-audit)")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if plan.Body != "" && plan.Method != "GET" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range opts.ExtraHeaders {
		req.Header.Set(k, v)
	}
	switch plan.UseToken {
	case "a":
		if opts.Token != "" {
			req.Header.Set(opts.TokenHeader, opts.TokenPrefix+opts.Token)
		}
	case "b":
		if opts.TokenB != "" {
			req.Header.Set(opts.TokenHeader, opts.TokenPrefix+opts.TokenB)
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.VerdictHint = StatusError
		return res
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	res.StatusCode = resp.StatusCode
	res.BodyBytes = len(raw)
	res.BodySnippet = compactBody(string(raw), 400)
	bodyStr := string(raw)
	res.AuthRequired = resp.StatusCode == 401 || resp.StatusCode == 403 || bizAuthFail.MatchString(bodyStr)
	// 敏感且不是鉴权失败包
	res.LooksSensitive = sensitiveBody.Match(raw) && resp.StatusCode >= 200 && resp.StatusCode < 300 && !res.AuthRequired

	switch {
	case plan.Kind == "unauth_access" && res.StatusCode >= 200 && res.StatusCode < 300 && res.LooksSensitive && !res.AuthRequired:
		res.VerdictHint = StatusConfirmed
	case plan.Kind == "unauth_access" && res.AuthRequired:
		// 匿名被拒：只否定「未登录可访问」，不写成 false_positive
		res.VerdictHint = StatusUnauthDenied
	case plan.Kind == "idor_compare" && plan.UseToken != "none" && res.StatusCode >= 200 && res.StatusCode < 300 && res.LooksSensitive && !res.AuthRequired:
		res.VerdictHint = StatusConfirmed
	case plan.Kind == "idor_compare" && plan.UseToken == "none" && res.AuthRequired:
		res.VerdictHint = StatusUnauthDenied
	case plan.Kind == "idor_compare" && plan.UseToken != "none" && res.AuthRequired:
		res.VerdictHint = StatusUnauthDenied // 该 token/对象组合被拒
	case plan.Kind == "auth_access" && res.StatusCode >= 200 && res.StatusCode < 300 && !res.AuthRequired && res.LooksSensitive:
		res.VerdictHint = StatusInconclusive
	case res.StatusCode == 404:
		res.VerdictHint = StatusInconclusive
	case res.StatusCode >= 500:
		res.VerdictHint = StatusInconclusive
	default:
		res.VerdictHint = StatusInconclusive
	}
	return res
}

func judgeHypotheses(surface *business.SurfaceReport, probes []ProbeResult, opts Options) []HypothesisVerdict {
	if surface == nil {
		return nil
	}
	out := make([]HypothesisVerdict, 0, len(surface.Hypotheses))
	for _, h := range surface.Hypotheses {
		v := HypothesisVerdict{
			ID:              h.ID,
			Surface:         h.Surface,
			Title:           h.Title,
			PreviousStatus:  h.Status,
			Status:          StatusInconclusive,
			ValidationLayer: "live",
			Severity:        h.Severity,
			Confidence:      h.Confidence,
			Summary:         "已执行活体探测，但证据不足以最终定论",
		}
		// 静态已确认的前端缺陷：活体默认保留，不降级
		if h.Status == business.StatusConfirmedStatic || h.Status == StatusConfirmedStatic {
			v.Status = StatusConfirmedStatic
			v.ValidationLayer = "static"
			v.Confidence = "high"
			v.Summary = "静态源码已确认的前端缺陷；活体 API 探测通常无法覆盖，保持 confirmed_static"
			if h.Why != "" {
				v.Evidence = append(v.Evidence, h.Why)
			}
			out = append(out, v)
			continue
		}

		var related []ProbeResult
		for _, p := range probes {
			if p.Plan.HypothesisID == h.ID || hasAny(p.Plan.Tags, h.Surface) || surfaceMatch(p.Plan.Surface, h.Surface) {
				related = append(related, p)
				v.ProbeIDs = append(v.ProbeIDs, p.Plan.ID)
			}
		}

		// webview/share/plugin：非 API 面
		if h.Surface == business.TagWebView || h.Surface == business.TagPlugin || h.Surface == business.TagShare {
			if h.Surface == business.TagWebView {
				v.Status = StatusConfirmedStatic
				v.ValidationLayer = "static"
				v.Summary = "WebView 开放加载属前端缺陷，活体 HTTP 探测无法替代源码结论"
			} else {
				v.Status = StatusInconclusive
				v.Summary = "该面主要为前端能力，活体 API 探测覆盖有限"
			}
			out = append(out, v)
			continue
		}

		confirmed, unauthDenied, planned := 0, 0, 0
		authProbes := 0
		for _, p := range related {
			planned++
			if p.Skipped {
				continue
			}
			if p.Error != "" {
				continue
			}
			if p.Plan.UseToken == "a" || p.Plan.UseToken == "b" {
				authProbes++
			}
			switch p.VerdictHint {
			case StatusConfirmed:
				confirmed++
				v.Evidence = append(v.Evidence, fmt.Sprintf("%s %s -> %d sensitive=%v body=%s", p.Plan.Method, p.Plan.Path, p.StatusCode, p.LooksSensitive, truncate(p.BodySnippet, 80)))
			case StatusUnauthDenied, StatusFalsePositive:
				if p.Plan.UseToken == "none" || p.Plan.Kind == "unauth_access" {
					unauthDenied++
				}
			}
		}

		hasToken := opts.Token != ""
		hasTokenB := opts.TokenB != ""

		switch {
		case confirmed > 0:
			v.Status = StatusConfirmed
			v.ValidationLayer = "live"
			v.Confidence = "high"
			if v.Severity == "medium" || v.Severity == "low" || v.Severity == "" {
				v.Severity = "high"
			}
			v.Summary = fmt.Sprintf("活体证实 %d 处风险响应（如未授权可读或对象 ID 可取敏感数据）", confirmed)
		case planned > 0 && unauthDenied > 0 && confirmed == 0 && !allDryRun(related):
			// 匿名被拒：区分 IDOR/支付 与 其它
			if h.Surface == business.TagIDOR || h.Surface == business.TagPayment || h.Surface == business.TagAuth || h.Surface == business.TagUpload {
				if !hasToken {
					v.Status = StatusAuthIDORUntested
					v.ValidationLayer = "mixed"
					v.Confidence = "medium"
					v.Summary = fmt.Sprintf("匿名访问被拒（%d 次），说明需登录；登录后对象级/参数篡改风险仍未测（请提供 -token / -token-b）", unauthDenied)
				} else if hasToken && !hasTokenB && (h.Surface == business.TagIDOR) {
					v.Status = StatusAuthIDORUntested
					v.ValidationLayer = "mixed"
					v.Summary = fmt.Sprintf("匿名被拒；已有单 token 但缺少第二身份 -token-b，水平越权对比未完成（%d 次匿名拒绝）", unauthDenied)
				} else {
					v.Status = StatusUnauthDenied
					v.ValidationLayer = "live"
					v.Summary = fmt.Sprintf("匿名访问被拒（%d 次）；已带 token 的探测未证实敏感数据泄露，登录后越权仍建议人工复核", unauthDenied)
				}
			} else {
				v.Status = StatusUnauthDenied
				v.ValidationLayer = "live"
				v.Summary = fmt.Sprintf("探测显示需鉴权（%d 次拒绝向），不代表业务逻辑无风险", unauthDenied)
			}
		case planned == 0:
			v.Status = StatusSkipped
			v.Summary = "无安全可自动探测的 API（被安全策略跳过或缺少可拼路径）"
		case allDryRun(related):
			v.Status = StatusInconclusive
			v.Summary = fmt.Sprintf("dry-run 已覆盖 %d 条探测计划，尚未实际发请求", planned)
		default:
			v.Status = StatusInconclusive
			v.Summary = fmt.Sprintf("已关联 %d 条探测，响应无法明确支持或否定假设", planned)
		}
		_ = authProbes
		out = append(out, v)
	}
	return out
}

func applyFindingUpdates(root string, verdicts []HypothesisVerdict) []FindingUpdate {
	path := filepath.Join(root, reportDirName, "ai_audit", "findings.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var findings []map[string]interface{}
	if json.Unmarshal(data, &findings) != nil {
		return nil
	}
	byID := map[string]HypothesisVerdict{}
	for _, v := range verdicts {
		byID[v.ID] = v
	}
	updates := make([]FindingUpdate, 0)
	for i := range findings {
		id, _ := findings[i]["id"].(string)
		v, ok := byID[id]
		if !ok {
			continue
		}
		old, _ := findings[i]["status"].(string)
		// 永不把 confirmed_static 降级为 unauth_denied / false_positive
		newStatus := v.Status
		if old == StatusConfirmedStatic || old == business.StatusConfirmedStatic {
			if newStatus != StatusConfirmed {
				newStatus = StatusConfirmedStatic
			}
		}
		findings[i]["status"] = newStatus
		findings[i]["confidence"] = v.Confidence
		if v.ValidationLayer != "" {
			findings[i]["validation_layer"] = v.ValidationLayer
		}
		if v.Severity != "" {
			findings[i]["severity"] = v.Severity
		}
		// 附加活体证据
		ev, _ := findings[i]["evidence"].([]interface{})
		ev = append(ev, map[string]interface{}{
			"source":  "validation_report.json",
			"file":    ".gwxapkg/validation_report.json",
			"summary": v.Summary,
		})
		findings[i]["evidence"] = ev
		findings[i]["live_validation"] = map[string]interface{}{
			"status":           newStatus,
			"summary":          v.Summary,
			"evidence":         v.Evidence,
			"validation_layer": v.ValidationLayer,
		}
		updates = append(updates, FindingUpdate{
			ID: id, OldStatus: old, NewStatus: newStatus, Confidence: v.Confidence, Note: v.Summary,
		})
	}
	if len(updates) > 0 {
		out, _ := json.MarshalIndent(findings, "", "  ")
		_ = os.WriteFile(path, out, 0644)
	}
	return updates
}

func updateBusinessHypotheses(root string, surface *business.SurfaceReport, verdicts []HypothesisVerdict) error {
	if surface == nil {
		return nil
	}
	byID := map[string]HypothesisVerdict{}
	for _, v := range verdicts {
		byID[v.ID] = v
	}
	for i := range surface.Hypotheses {
		if v, ok := byID[surface.Hypotheses[i].ID]; ok {
			// 保留静态确认
			if surface.Hypotheses[i].Status == business.StatusConfirmedStatic && v.Status != StatusConfirmed {
				surface.Hypotheses[i].Status = business.StatusConfirmedStatic
			} else {
				surface.Hypotheses[i].Status = v.Status
			}
			surface.Hypotheses[i].Confidence = v.Confidence
			if v.ValidationLayer != "" {
				surface.Hypotheses[i].ValidationLayer = v.ValidationLayer
			}
			surface.Hypotheses[i].Why = surface.Hypotheses[i].Why + " | live: " + v.Summary
			if len(v.Evidence) > 0 {
				surface.Hypotheses[i].Evidence = append(surface.Hypotheses[i].Evidence, v.Evidence...)
			}
		}
	}
	return business.WriteReport(root, surface)
}

// WriteReport 写出验证报告。
func WriteReport(root string, report *Report) error {
	dir := filepath.Join(root, reportDirName)
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
	return os.WriteFile(report.MarkdownPath, []byte(buildMarkdown(report)), 0644)
}

func buildMarkdown(report *Report) string {
	var b strings.Builder
	b.WriteString("# 活体验证报告\n\n")
	b.WriteString(fmt.Sprintf("- 时间: %s\n- 目录: %s\n- base-url: %s\n- dry-run: %v\n- 请求数: %d / 计划: %d\n\n",
		report.GeneratedAt, report.SourceDir, report.BaseURL, report.DryRun, report.RequestCount, report.PlanCount))
	b.WriteString("## 假设结论\n\n")
	for _, v := range report.HypothesisVerdicts {
		b.WriteString(fmt.Sprintf("### %s [%s] → **%s**\n\n", v.ID, v.Surface, v.Status))
		b.WriteString(fmt.Sprintf("- %s\n- severity: %s | confidence: %s\n", v.Summary, v.Severity, v.Confidence))
		for _, e := range v.Evidence {
			b.WriteString("  - " + e + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("## 探测摘要\n\n")
	b.WriteString("| ID | Kind | Method | Path | Code | Hint |\n|----|------|--------|------|------|------|\n")
	limit := len(report.Probes)
	if limit > 100 {
		limit = 100
	}
	for _, p := range report.Probes[:limit] {
		code := "-"
		if !p.Skipped && p.Error == "" {
			code = fmt.Sprintf("%d", p.StatusCode)
		} else if p.Skipped {
			code = "skip"
		} else {
			code = "err"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			p.Plan.ID, p.Plan.Kind, p.Plan.Method, truncate(p.Plan.Path, 48), code, p.VerdictHint))
	}
	return b.String()
}

func normalizeAPIPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if pagePathOnly.MatchString(raw) {
		return raw
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if u, err := url.Parse(raw); err == nil {
			p := u.Path
			if u.RawQuery != "" {
				p += "?" + u.RawQuery
			}
			return p
		}
	}
	// 去掉 UNKNOWN 前缀痕迹
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "UNKNOWN "))
	if strings.HasPrefix(raw, "api/") || strings.HasPrefix(raw, "/api/") {
		return raw
	}
	// controller.method 无法直接探测
	if strings.Contains(raw, ".") && !strings.Contains(raw, "/") {
		return ""
	}
	return raw
}

func joinURL(base *url.URL, path string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(base.String(), "/") + path
}

func defaultBody(method, path string, probeIDs []string) string {
	// 36bike 等平台多数接口用 POST JSON，并带 brand/area
	id := "1"
	if len(probeIDs) > 0 {
		id = probeIDs[0]
	}
	// GET 也可带 query；body 仅非 GET
	if method == "GET" || method == "HEAD" {
		return ""
	}
	base := map[string]interface{}{
		"area_code":  "10000",
		"area_id":    "10000",
		"user_id":    "",
		"uid":        "",
		"brand_code": "laicaicx",
	}
	if looksIDPath(path) || regexp.MustCompile(`(?i)order|bill|user|detail|trace|vid`).MatchString(path) {
		base["id"] = id
		base["orderId"] = id
		base["order_id"] = id
		base["billCode"] = id
		base["userId"] = id
		base["vid"] = id
	}
	b, _ := json.Marshal(base)
	return string(b)
}

func guessMethod(path string) string {
	// 小程序业务 API 默认 POST JSON
	if strings.Contains(path, "-api/") || strings.Contains(path, "user-api") || strings.Contains(path, "device-api") || strings.Contains(path, "public/") {
		return "POST"
	}
	if queryLikePath.MatchString(path) {
		return "POST"
	}
	return "GET"
}

func injectID(path, id string) string {
	// query 参数
	if strings.Contains(path, "=") {
		re := regexp.MustCompile(`(?i)(orderId|userId|billCode|id|memberId|certId)=([^&]*)`)
		if re.MatchString(path) {
			return re.ReplaceAllString(path, "${1}="+id)
		}
		if strings.Contains(path, "?") {
			return path + "&id=" + id
		}
		return path + "?id=" + id
	}
	return path
}

func injectIDBody(method, path, id string) string {
	if method == "GET" || method == "HEAD" {
		return ""
	}
	return fmt.Sprintf(`{"id":"%s","orderId":"%s","billCode":"%s","userId":"%s"}`, id, id, id, id)
}

func looksIDPath(path string) bool {
	return regexp.MustCompile(`(?i)(orderId|userId|billCode|memberId|/detail|getDetail|trace)`).MatchString(path)
}

func findHyp(surface *business.SurfaceReport, surfaceTag string) string {
	if surface == nil {
		return ""
	}
	for _, h := range surface.Hypotheses {
		if h.Surface == surfaceTag {
			return h.ID
		}
	}
	return ""
}

func primaryTag(tags []string) string {
	priority := []string{business.TagAuth, business.TagSMS, business.TagIDOR, business.TagOrder, business.TagPayment, business.TagUpload, business.TagWebView, business.TagShare, business.TagPlugin}
	for _, p := range priority {
		for _, t := range tags {
			if t == p {
				if p == business.TagSMS {
					return business.TagAuth
				}
				if p == business.TagOrder || p == business.TagProfile || p == business.TagCert {
					return business.TagIDOR
				}
				return p
			}
		}
	}
	if len(tags) > 0 {
		return tags[0]
	}
	return ""
}

func hasAny(tags []string, want ...string) bool {
	set := map[string]struct{}{}
	for _, t := range tags {
		set[t] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; ok {
			return true
		}
	}
	return false
}

func surfaceMatch(a, b string) bool {
	if a == b {
		return true
	}
	if (a == business.TagAuth && b == business.TagSMS) || (a == business.TagSMS && b == business.TagAuth) {
		return true
	}
	return false
}

func allDryRun(related []ProbeResult) bool {
	if len(related) == 0 {
		return false
	}
	for _, p := range related {
		if !(p.Skipped && (p.SkipReason == "dry-run" || p.VerdictHint == "would_probe")) {
			return false
		}
	}
	return true
}

func prioritizePlans(plans []ProbePlan, limit int) []ProbePlan {
	score := func(p ProbePlan) int {
		s := 0
		if p.Safe {
			s += 5
		}
		if p.Kind == "unauth_access" {
			s += 4
		}
		if p.Kind == "idor_compare" {
			s += 5
		}
		if hasAny(p.Tags, business.TagIDOR, business.TagOrder, business.TagAuth, business.TagPayment) {
			s += 3
		}
		return s
	}
	// simple selection sort partial
	out := append([]ProbePlan(nil), plans...)
	for i := 0; i < len(out); i++ {
		best := i
		for j := i + 1; j < len(out); j++ {
			if score(out[j]) > score(out[best]) {
				best = j
			}
		}
		out[i], out[best] = out[best], out[i]
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func compactBody(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
