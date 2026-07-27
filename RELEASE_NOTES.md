# Release v2.8.0

## 版本概览

`v2.8.0` 将 Gwxapkg 从「解包 + 敏感扫描」推进为 **LLM 可消费的小程序安全审计工作台**：业务漏洞面预筛、统一 API 地图、doctor/audit 骨架、授权活体探测与分层 finding 状态。

**默认行为兼容**：AST 默认仍为 `deep`；敏感扫描默认全量规则；**默认不联网**。活体探测必须显式 `-i-authorize-live=true`。

---

## 重点更新

### 1. 业务漏洞面（LLM 主证据）

- 新增 `.gwxapkg/business_surface.json` / `.md`
- 业务标签：`auth` `sms` `idor` `profile` `order` `cert` `payment` `upload` `share` `webview` `plugin`
- 产出：打标接口/页面、源码信号、业务假设、LLM 必查清单
- `api_unified_map` 回写 `business_tags` / `risk_hints`
- `all` / `scan-only` 在路由分析后自动生成；`audit` 并入 `BIZ-*` findings

### 2. Finding 状态语义（静态 vs 活体）

| status | 含义 |
|--------|------|
| `confirmed_static` | 仅前端源码即可认定（如开放 WebView） |
| `needs_server_validation` | 源码有攻击面，结论依赖后端 |
| `unauth_denied` | 活体：匿名被拒（**≠ 无洞**） |
| `auth_idor_untested` | 匿名被拒或未提供 token，登录后越权未测 |
| `confirmed` | 活体响应证实风险 |
| `false_positive` | 在已执行探测范围内充分否定 |
| `inconclusive` / `skipped` | 证据不足或安全策略跳过 |

- 字段 `validation_layer`：`static` / `live` / `mixed`
- **禁止**将「匿名访问被拒」写成 false_positive 误导为「无漏洞」
- 活体探测**不会降级** `confirmed_static`

### 3. 授权活体验证

```bash
gwxapkg validate -dir=<已解包目录> -base-url=https://api.example.com \
  -i-authorize-live=true [-token=...] [-token-b=...] [-probe-ids=1,2] [-dry-run]
```

- 别名：`live`
- 探测：未授权访问 / 鉴权基线 / 对象 ID 替换
- 安全默认：跳过短信发送、支付创建、删除、上传等破坏性路径
- 产物：`.gwxapkg/validation_report.json/.md`、`validation_requests.jsonl`
- 回写：`ai_audit/findings.json`、`business_surface` 假设状态

### 4. doctor / audit

- `gwxapkg doctor|summary -dir=`：产物健康检查与覆盖缺口
- `gwxapkg audit -dir= [-fix=true]`：确定性审计骨架（不调用 LLM）
  - `findings.json` / `business_hypotheses.json` / `business_checklist.md`
  - `security_report.md` / `coverage_gaps.md` / `evidence_table.md`
- 全量流水线结束默认写 doctor 报告

### 5. 扫描与 API 地图

- 规则分层：`-rule-tier=all|high|medium|critical,noise`
- 扫描预过滤、API 廉价预检、超长行 high+ 分块、`scan-only` worker 并发
- `.gwxapkg/api_unified_map.json/.md`（semantic + HTTP endpoint 合并）
- AST request 提取（`source_rule=ast-request`，支持 base+path）
- Postman：`-base-url`；可选 `-sarif` / `-openapi`
- `.gwxapkg/dataflow_hints.json`：storage/token、crypto→request 共现线索

### 6. watch / CLI / 工程化

- `-watch` / `-watch=listen` / **`-watch=auto`**（捕获新包后自动解包）
- `gwxapkg version`；`cmd.ExecutePipeline` + `ExecuteOptions`
- 用户配置：`./.gwxapkg.yaml` / `~/.gwxapkg.yaml`
- CI/Release Go **1.23**
- 修复 WXML 还原 `nil` 空指针（真实样本解包稳定性）

### 7. AI Skill

- `skills/gwxapkg-ai-audit`：优先读 `business_surface`，按 auth→idor→payment→upload/share/webview 强制检查
- 状态语义表写入 skill，避免 LLM 误判 `unauth_denied`

---

## 推荐工作流

```bash
# 1) 解包（默认含业务面 + doctor）
./gwxapkg all -id=<AppID> -out=./output/<AppID>

# 2) 审计骨架
./gwxapkg audit -dir=./output/<AppID> -fix=true

# 3) 授权活体（可选）
./gwxapkg validate -dir=./output/<AppID> \
  -base-url=https://api.example.com \
  -i-authorize-live=true \
  -token='Bearer <token>' -token-b='Bearer <tokenB>'

# 4) 交给 Hermes/Codex/Claude 使用 gwxapkg-ai-audit skill 出终稿
```

---

## 兼容性说明

- 不改变默认 AST `deep` 策略
- 默认敏感扫描仍为全量规则（未指定 `-rule-tier`）
- 默认不发送网络请求；`validate` 需显式授权
- 既有 `scan` / `all` / `semantic` / `api-link` / `repack` 命令保留

---

## 验证

```bash
go test ./...
go build -ldflags="-s -w" -o gwxapkg .
./gwxapkg version   # 2.8.0
```

---

# Release v2.7.4

## 版本概览

`v2.7.4` 是一次面向 LLM 自动审计和真实解包覆盖率的版本：新增 `gwxapkg-ai-audit` skill，补齐机器可读的 `sensitive_report.json`，并新增分包完整性检测与缺失分包 watch 模式，让 Hermes / Codex / Claude Code 等 Agent 可以直接消费 Gwxapkg 的解包、语义还原、API 地图、调用链、Burp 关联、敏感扫描和覆盖缺口产物。

本版本不会改变 `v2.7.3` 的默认 AST 策略：`semantic` 仍默认使用 `-ast-rename=deep`，并继续保留 diff、patch、rollback 和公开标识保护。

---

## 重点更新

### 1. Gwxapkg AI 审计 Skill

新增仓库内 skill：

```text
skills/gwxapkg-ai-audit/
```

该 skill 面向 LLM Agent 使用，默认流程是：

- 优先读取 `.gwxapkg/` 下的确定性产物
- 检查 API、调用链、AST、Burp、敏感扫描的覆盖缺口
- 对未授权访问、IDOR、可逆编码、前端加密、短信验证码、注册登录等高价值线索做源码回溯
- 输出审计报告、结构化 findings、覆盖缺口和证据表

本地 Hermes 安装路径建议为：

```text
~/.hermes/skills/software-development/gwxapkg-ai-audit/
```

### 2. 机器可读敏感扫描报告

新增 `sensitive_report.json`：

- 默认解包流程 `-sensitive=true` 时生成
- `scan-only -format=both` 时生成
- `scan-only -format=json` 可只生成 JSON 报告

JSON 报告与现有 Excel / HTML 报告使用同一份扫描数据，适合自动审计、证据归档和 LLM 结构化消费。

### 3. 分包完整性检测与 watch 模式

新增 `.gwxapkg/package_completeness.json` 和 `.gwxapkg/package_completeness.md`：

- `scan` / `all` 在解包后自动解析 `app.json` 的主包、分包和页面清单
- 自动识别本机实际存在的分包包文件、真实页面、占位页面和缺失页面
- 当只下载了部分分包时，终端和 HTML 报告都会提示“当前结果不完整”
- `scan-only -dir=<已解包目录>` 也会基于目录内 `app.json` 和占位文件重新判断覆盖情况

新增 `-watch` 参数：

```bash
gwxapkg scan -watch
gwxapkg all -id=<AppID> -watch
```

当小程序缺失分包时，工具会进入纯监听模式；用户在微信中打开缺失功能页后，客户端下载的新 `.wxapkg` 会被自动捕获并提示。`-watch` 不执行解包、不自动重跑，用户退出监听后再运行普通 `scan` / `all` 合并源码。

### 4. 通用 API Endpoint fallback

新增 `.gwxapkg/api_endpoint_map.json` 和 `.gwxapkg/api_endpoint_map.md`：

- 直接基于敏感扫描器提取到的 `api_endpoints` 生成
- 不依赖 `controllerName/methodsName`
- 适合 Taro / webpack / 通用 URL request 风格小程序
- 每条 endpoint 保留原始 URL、上下文、文件路径、行号、source rule
- 增加 `source_artifact_exists`，当扫描阶段的原始打包路径在还原目录中不可直接回读时明确标记
- 明确 `no_redaction=true`，本地授权审计产物默认不脱敏

### 5. AI 审计报告默认不脱敏

更新 `gwxapkg-ai-audit` skill：

- 默认报告保留原始密钥、Token、URL、参数和代码片段
- 不主动输出 `[REDACTED]`
- 只有用户明确要求“对外版 / 脱敏版”时，才另存脱敏副本
- 当 `api_map.json` 为 0 但 `api_endpoint_map.json` 有数据时，写成“语义 API 地图覆盖不足，但通用 endpoint fallback 可用”

### 6. 生成产物跳过规则

路由分析和 `scan-only` 二次扫描会跳过：

- `.gwxapkg/` 下全部审计产物
- `sensitive_report.json`
- `sensitive_report.xlsx`
- `sensitive_report.html`
- `api_collection.postman_collection.json`
- `route_manifest.json`
- `route_map.md`
- `route_map.mmd`

这样可以避免生成报告被再次当成源码扫描，减少误报和重复命中。

---

## 命令示例

```bash
# 对已解包目录生成 JSON / Excel / HTML 报告
gwxapkg scan-only -dir=<已解包目录> -format=both

# 只生成机器可读 JSON 报告
gwxapkg scan-only -dir=<已解包目录> -format=json

# 重新执行 semantic，并保留默认 deep AST 语义还原
gwxapkg semantic -dir=<已解包目录>
```

---

## 验证

本地发布前建议执行：

```bash
go test ./...
go build ./...
```

Hermes skill 可通过确认以下文件存在完成基础验证：

```text
~/.hermes/skills/software-development/gwxapkg-ai-audit/SKILL.md
```

---

## 下载说明

| 文件 | 适用平台 |
|------|---------|
| `gwxapkg-windows-amd64.exe` | Windows 64 位 |
| `gwxapkg-linux-amd64` | Linux 64 位 |
| `gwxapkg-darwin-amd64` | macOS Intel |
| `gwxapkg-darwin-arm64` | macOS Apple Silicon |
