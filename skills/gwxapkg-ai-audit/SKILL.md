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

该 skill 可由 Hermes + GPT-5.5、Codex、Claude Code 等 Agent 使用；模型越强，越应该把精力放在证据归纳、漏洞边界判断和遗漏检查，而不是替代 Gwxapkg 的确定性解析。

只在授权测试、内部审计、应急分析场景使用。默认不联网、不重放请求、不验证账号密码、不编写利用代码，不修改被审计源码。

## 输入

- 必需：一个已解包目录，例如 `/path/to/output/wxappid`。
- 可选：Burp 原始请求文件或粘贴的 HTTP raw request。
- 可选：审计重点，例如未授权访问、算法还原、敏感信息、短信验证码、注册登录、证书查询。

## 快速流程

1. 校验目录：确认存在 JS/WXML/JSON 文件，优先确认 `.gwxapkg/` 目录。
2. 补齐产物：如果缺少 `.gwxapkg/api_map.json`，且本机存在 `gwxapkg`，执行 `gwxapkg semantic -dir=<dir>`；如果缺少 `sensitive_report.json`，建议执行 `gwxapkg scan-only -dir=<dir> -format=both`。
3. 读取确定性产物，先不要直接全量读源码。
4. 做覆盖缺口检查，找出 AST 失败、API 未关联、动态 URL、超大文件、报告缺失、Burp 未匹配等风险。
5. 对高价值线索回溯源码，用 `rg` 精确定位文件和行号。
6. 产出 `<dir>/.gwxapkg/ai_audit/` 下的报告和 JSON 证据包。

## 优先读取的产物

按顺序读取存在的文件：

- `.gwxapkg/semantic_module_map.json`
- `.gwxapkg/api_map.json`
- `.gwxapkg/api_endpoint_map.json`
- `.gwxapkg/api_call_chain.json`
- `.gwxapkg/api_pseudo.md`
- `.gwxapkg/ast_rename_map.json`
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

## 源码回溯命令

只有当确定性产物不足、用户指定目标、或需要证据行号时，再使用源码检索：

```bash
rg -n "controllerName|methodsName|wx\\.request|uni\\.request|request\\(" <dir>
rg -n "userId|openid|token|session|Authorization|getStorageSync|setStorageSync" <dir>
rg -n "SM2|sm2|SM3|SM4|CryptoJS|Base64|btoa|atob|encrypt|decrypt|sign|md5" <dir>
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

- `id`、`title`、`severity`、`confidence`
- 影响范围：接口、页面、文件、业务流程
- 证据：文件路径、行号、短片段、来源产物
- 风险边界：已确认、需后端验证、证据不足、仅审计关注
- 修复建议：前端、后端、网关、日志监控分别说明

不要把“前端能还原参数”直接等同于“后端必然越权”。若没有后端响应证据，必须写成“可辅助构造请求，需服务端鉴权验证”。

## 证据保真策略

默认输出本地授权审计报告，不做脱敏、不用 `[REDACTED]`、不截断关键凭据、Token、URL、参数和代码片段。证据表、findings、manifest、Markdown 报告都应保留原始值，方便复核和复现。

只有当用户明确要求“对外版”“客户版”“脱敏版”或“隐藏敏感值”时，才生成脱敏副本；脱敏副本必须另存为新文件名，不覆盖默认完整证据报告。

## 输出

默认写入 `<dir>/.gwxapkg/ai_audit/`：

- `security_report.md`：中文审计报告。
- `findings.json`：结构化漏洞清单，建议符合 `schemas/finding.schema.json`。
- `coverage_gaps.md`：覆盖缺口和后续验证建议。
- `evidence_table.md`：证据索引表。
- `llm_audit_manifest.json`：本次读取的产物、命令、模型、时间、限制说明。

可以使用 `templates/security_report.md` 作为报告骨架。

## 安全边界

- 不发送网络请求。
- 不重放 Burp 包。
- 不爆破验证码、账号、密码、token。
- 不生成可直接攻击第三方系统的脚本。
- 不修改小程序源码，除非用户明确要求做反混淆或修复 Gwxapkg 本身。
