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
