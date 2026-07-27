---
name: gwxapkg-ai-audit
description: Use when auditing a Gwxapkg unpacked WeChat Mini Program directory with LLM assistance; consumes .gwxapkg semantic artifacts, route maps, sensitive_report.json, and optional Burp raw requests to produce evidence-backed security findings.
version: 1.0.0
author: Gwxapkg
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, wechat, miniprogram, gwxapkg, audit, static-analysis, llm]
    related_skills: [codex, claude-code]
---

# Gwxapkg AI Audit

## 目标

对已经由 Gwxapkg 解包并执行过 `semantic` / `scan` 的微信小程序目录做本地静态安全审计。优先消费确定性产物，再让 LLM 做证据归纳、缺口检查、业务风险解释和报告组织。

**核心目标：在以下业务漏洞面上产出更多、更准确的 findings：**

1. **auth**：登录 / 注册 / 短信验证码 / 重置密码  
2. **idor**：用户信息、订单、证件/查询类（对象级越权高发）  
3. **payment**：支付 / 优惠 / 积分  
4. **upload / share / webview / plugin**：上传、分享、web-view、插件  

Gwxapkg 已用确定性规则生成 `.gwxapkg/business_surface.*` 与 `ai_audit` 中的业务假设；LLM 负责：回溯源码、补证据、去误报、写清风险边界与修复，而不是从零扫全站关键词。

该 skill 可由 Hermes + GPT-5.5、Codex、Claude Code 等 Agent 使用。

只在授权测试、内部审计、应急分析场景使用。默认不联网、不重放请求、不验证账号密码、不编写利用代码，不修改被审计源码。

**可选活体验证（需显式授权）：**

```bash
gwxapkg validate -dir=<dir> -base-url=https://api.example.com -i-authorize-live=true \
  -token=<登录token> -token-b=<第二账号token可选> -probe-ids=1,2,others
```

- 会把 `BIZ-*` 从 `needs_server_validation` 更新为 `confirmed` / `false_positive` / `inconclusive`
- 读取 `.gwxapkg/validation_report.json` 作为活体证据
- 默认不发送短信/下单/删除类请求

## 输入

- 必需：一个已解包目录，例如 `/path/to/output/wxappid`。
- 可选：Burp 原始请求文件或粘贴的 HTTP raw request。
- 可选：审计重点，例如未授权访问、算法还原、敏感信息、短信验证码、注册登录、证书查询。

## 快速流程

1. 校验目录：确认存在 JS/WXML/JSON 文件，优先确认 `.gwxapkg/` 目录。
2. **优先**运行 `gwxapkg audit -dir=<dir> -fix=true`（doctor + 业务面预筛 + findings 骨架）。
3. 若仍缺 API/扫描产物：`gwxapkg semantic -dir=<dir>` / `gwxapkg scan-only -dir=<dir> -format=both`。
4. **先读业务面**，再读 API/敏感信息；不要一上来全量读源码。
5. 按 `auth → idor → payment → upload/share/webview/plugin` 推进假设。
6. 对每条业务假设回溯源码，补证据行号与参数流；做覆盖缺口检查。
7. 去重、定级、写清 `needs_server_validation` 边界；续写 `ai_audit/`。

## 优先读取的产物

按顺序读取存在的文件：

- `.gwxapkg/business_surface.json` / `.md`（**业务面主入口**）
- `.gwxapkg/ai_audit/business_hypotheses.json` / `business_checklist.md`
- `.gwxapkg/ai_audit/findings.json`（含 `BIZ-*` 业务假设）
- `.gwxapkg/doctor_report.json`
- `.gwxapkg/api_unified_map.json`（含 `business_tags` 时优先）
- `.gwxapkg/api_map.json` / `api_endpoint_map.json`
- `.gwxapkg/api_call_chain.json` / `dataflow_hints.json`
- `.gwxapkg/semantic_module_map.json` / `ast_rename_map.json`
- `.gwxapkg/burp_api_link.json`
- `route_manifest.json`
- `sensitive_report.json`

`sensitive_report.html` 和 `sensitive_report.xlsx` 只作为人工复核材料，不作为 LLM 主数据源。

## 必做缺口检查

报告必须单独列出“覆盖缺口”，至少检查：

- 解析失败或跳过的 JS 文件。
- API 地图端点数量、敏感扫描接口数量、调用链数量是否明显不一致。
- 是否存在动态拼接 URL、动态 `controllerName`、动态 `methodsName`。
- 是否存在超大文件、压缩文件、source map、插件包或分包未覆盖。
- Burp 请求是否能关联到源码 API，未匹配时说明原因。
- `sensitive_report.json` 是否缺失，缺失时说明 HTML/Excel 不能作为稳定机器证据。
- 如果 `.gwxapkg/api_map.json` 为空但 `.gwxapkg/api_endpoint_map.json` 有数据，应明确写成“语义 API 地图覆盖不足，但通用 endpoint fallback 可用”，不要误判为没有接口证据。

## 业务面强制检查（必须覆盖）

对 `business_surface` 中 **已检出** 的面，报告里必须有对应章节或 findings；未检出的面在 coverage 中说明「无信号/可能未实现」。

| surface | 必查点 |
|---------|--------|
| auth | 登录注册、短信验证码频控/一次性、重置密码、token 落 storage |
| idor | userId/orderId/证件 id 是否仅登录态无属主校验 |
| payment | 金额/优惠/积分是否前端可控、资格与状态机 |
| upload | 上传鉴权、类型限制、URL 暴露 |
| share | 分享参数篡改、绕过鉴权进入 |
| webview | src 可控、域名白名单、桥接 API |
| plugin | 插件权限与数据外传 |

## 源码回溯命令

优先针对 `business_surface` 给出的 apis/pages/files；不足时再扩大：

```bash
rg -n "controllerName|methodsName|wx\\.request|uni\\.request|request\\(" <dir>
rg -n "login|register|sendCode|verifyCode|resetPassword|getPhoneNumber" <dir>
rg -n "userId|orderId|memberId|openid|token|session|Authorization|getStorageSync|setStorageSync" <dir>
rg -n "pay|prepay|coupon|integral|point|uploadFile|onShareAppMessage|web-view|requirePlugin" <dir>
rg -n "SM2|sm2|SM4|CryptoJS|encrypt|decrypt|sign|md5" <dir>
```

如果发现可疑 API，再用文件局部读取确认上下文，避免只凭关键词下结论。

## 分析分工

可以按需读取 `agents/` 下的角色提示词；工具支持并行时可并行分析，但最终必须统一去重和校验证据。

- `agents/context-reader.md`：整理产物和目录上下文。
- `agents/coverage-gap-checker.md`：检查遗漏和证据缺口。
- `agents/secret-triage.md`：复核敏感信息扫描结果。
- `agents/api-auth-analyzer.md`：分析 API 鉴权、越权、IDOR。
- `agents/crypto-dataflow-analyzer.md`：分析编码、加密、签名和前端可逆逻辑。
- `agents/business-risk-analyzer.md`：分析注册、登录、验证码、重置、证照查询等业务风险。
- `agents/burp-correlator.md`：把 Burp 请求映射到源码 API。
- `agents/reporter.md`：汇总报告和 JSON findings。

## Finding 要求

每个漏洞或风险项都必须包含：

- `id`、`title`、`severity`、`confidence`、`status`、可选 `validation_layer`
- 影响范围：接口、页面、文件、业务流程
- 证据：文件路径、行号、短片段、来源产物
- 风险边界与 `status` 语义（必须遵守）：

| status | 含义 |
|--------|------|
| `confirmed_static` | **仅前端源码即可认定**（如开放 WebView 无白名单） |
| `needs_server_validation` | 源码有攻击面，结论依赖后端 |
| `unauth_denied` | 活体：匿名被拒（**≠ 无洞**） |
| `auth_idor_untested` | 活体：匿名被拒或未给 token，**登录后越权未测** |
| `confirmed` | 活体响应证实风险 |
| `false_positive` | 在已执行探测范围内充分否定 |
| `inconclusive` / `skipped` | 证据不足或策略跳过 |

- 修复建议：前端、后端、网关、日志监控分别说明

**禁止**把 `unauth_denied` / `auth_idor_untested` 写成「已证实无漏洞」。  
不要把“前端能还原参数”直接等同于“后端必然越权”；但 **`confirmed_static` 的前端缺陷应直接写入报告**。

## 证据保真策略

默认输出本地授权审计报告，不做脱敏、不用 `[REDACTED]`、不截断关键凭据、Token、URL、参数和代码片段。证据表、findings、manifest、Markdown 报告都应保留原始值，方便复核和复现。

只有当用户明确要求“对外版”“客户版”“脱敏版”或“隐藏敏感值”时，才生成脱敏副本；脱敏副本必须另存为新文件名，不覆盖默认完整证据报告。

## 输出

默认写入 `<dir>/.gwxapkg/ai_audit/`：

- `security_report.md`：中文审计报告（含业务面章节）。
- `findings.json`：结构化漏洞清单（含 `SECRET-*` 与 `BIZ-*`），建议符合 `schemas/finding.schema.json`。
- `business_hypotheses.json`：业务假设原样（确定性）。
- `business_checklist.md`：按面必查清单。
- `coverage_gaps.md`：覆盖缺口和业务面检出情况。
- `evidence_table.md`：证据索引表。
- `llm_audit_manifest.json`：本次读取的产物、命令、模型、时间、限制说明。

可以使用 `templates/security_report.md` 作为报告骨架。

## 安全边界

- 不发送网络请求。
- 不重放 Burp 包。
- 不爆破验证码、账号、密码、token。
- 不生成可直接攻击第三方系统的脚本。
- 不修改小程序源码，除非用户明确要求做反混淆或修复 Gwxapkg 本身。
