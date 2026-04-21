# Release v2.7.1

## 版本概览

`v2.7.1` 是在 `v2.7.0` 基础上继续打磨的一次增强版本，重点补齐页面与路由分析的第三期能力。

本版本重点解决了以下几个方向的问题：

- 页面路由图只能恢复页面内直接跳转，难以识别跨文件 helper 链路
- 共享路由封装函数无法沉淀成独立资产清单，不利于批量分析

---

## 重点更新

### 1. 分析深度提升

#### Postman Collection 导出

- 新增 `-postman` 参数
- 支持命令：
  - `./gwxapkg all -id=<AppID> -postman`
  - `./gwxapkg scan -postman`
  - `./gwxapkg scan-only -dir=<目录> -postman`
  - 默认命令行模式同样支持 `-postman`
- 扫描结果中的 URL / API Endpoint 会自动提取为 `api_collection.postman_collection.json`
- 无法可靠判断 HTTP 方法时，Collection 中写入 `UNKNOWN`
- 相对接口路径保持原样，不自动拼接 `baseUrl`
- 即使未提取到接口，也会稳定生成空 `item` 数组的 Collection 文件

#### 默认 JavaScript 反混淆

- JavaScript 处理流程改为“先反混淆，再格式化”
- 默认支持以下常见混淆还原能力：
  - `\xNN` / `\uNNNN` 字面量还原
  - 十六进制数字字面量还原
  - 常见字符串数组、偏移索引、旋转数组壳识别
  - `javascript-obfuscator` / `de4js` 常见模式的受控解码
- 反混淆基于现有 `goja` 与 parser 完成，不新增外部 JS 引擎依赖
- 对无法完全恢复的样本，会保留部分结果并标记 `partial` / `flagged`
- 命中混淆阈值的输出文件会写入 `[OBFUSCATED]` 标签，便于后续人工分析

#### 混淆文件报告

- Excel / HTML 报告新增“混淆文件”统计与单独列表
- 每个命中样本会记录：
  - 文件路径
  - 分数
  - 命中技术
  - 状态：`restored` / `partial` / `flagged`
  - 输出标签

---

### 2. 扫描体验增强

#### `scan-only` 独立审查模式

- 新增 `scan-only`，可对已解包目录直接发起敏感信息审查
- 与解包流程解耦，适合对历史样本、第三方源码目录或手工整理后的工程单独复扫
- `scan-only` 与正常解包流程共用同一套扫描器、规则和 JS 反混淆逻辑

#### 候选路径诊断

- `scan` 与 `all` 新增 `--verbose`
- 开启后会打印微信缓存候选目录诊断信息，包括：
  - 扫描了哪些候选根路径
  - 路径是否存在
  - 是否无权限访问
  - glob 命中数量
  - 最终命中的 AppID / 版本数量
- 默认模式下仍保持简洁输出，不会显示这些诊断日志

#### 小程序名称显示增强

- 扫描列表中的名称优先从包内元数据提取
- 当当前缓存包或运行时补充信息无法明确给出名称时，将保留为空，避免错误错配
- 适配最新缓存目录结构后，扫描结果在 macOS / Windows 上更稳定

#### 批量处理能力增强

- `all` 支持：
  - `-id=wx123`
  - `-id=wx123,wx456`
  - `-id-file=ids.txt`
  - `--all`
- 适合批量解包、批量审计和自动化流水线使用

#### 默认输出目录行为统一

- 未指定 `-out` 时，默认输出到 `output/<AppID>`
- 无论是普通解包还是 `scan` 交互式选包，都遵循相同规则
- 便于统一定位解包结果和报告文件

---

### 3. 解包安全增强

#### 两阶段执行流

- 解包流程改为：
  1. 先完整分析包结构
  2. 全部通过后再并发写盘
- 这样可以保证无效包在分析失败时不写出任何文件

#### 路径安全校验

- 输出目录先做绝对路径解析
- 包内路径会先归一化为相对路径
- 最终目标路径必须位于输出目录内
- 会拒绝以下危险情况：
  - 空路径
  - `.` 路径
  - `../` 目录穿越
  - 文件 / 目录前缀冲突

#### 重名文件保护

- 归一化后若多个文件映射到同一路径，不再直接覆盖
- 自动重命名保留全部文件，例如：
  - `a.js`
  - `a-1.js`
  - `a-2.js`

#### 包结构硬上限

- 新增硬限制：
  - `fileCount <= 102400`
  - `0 < nameLen <= 1024`
  - `size <= 128 MiB`
- 同时前置校验：
  - 头标记 / 尾标记
  - 索引长度
  - 偏移越界
  - 文件长度越界

#### 阶段化错误信息

- 错误信息统一带阶段与源包路径
- 固定阶段名：
  - `头部校验`
  - `索引分析`
  - `路径规划`
  - `文件读取`
  - `文件格式化`
  - `文件写入`
  - `敏感扫描`
- CLI 中看到的错误格式更接近：

```text
wxapkg=/path/to/__APP__.wxapkg 阶段=路径规划 文件=../app.js: 包内路径存在目录穿越
```

---

### 4. 规则与默认行为调整

- 默认直接使用内置规则集
- 不再自动生成 `config/rule.yaml`
- 如果你手动放了 `config/rule.yaml`，则优先使用你的自定义规则覆盖内置规则
- 默认行为更稳定，同时保留高级用户自定义扫描口径的能力

---

### 5. 报告体系升级

- 保留并增强原有 Excel 报告
- 新增 HTML 交互式报告
- Postman Collection 与 Excel / HTML 共用同一份扫描结果，不再二次扫描
- 报告现支持输出：
  - 接口数量
  - 混淆文件数量
  - 风险分级统计
  - 文件路径与行号

---

### 6. CI / Release 自动化

仓库当前已经接入 GitHub Actions：

#### CI

- 工作流文件：`.github/workflows/ci.yml`
- 触发条件：
  - push 到 `main`
  - 针对 `main` 的 pull request
- 当前 CI 行为：
  - 执行 `go build -ldflags="-s -w" ./...`
  - 执行 `go test ./... -v -timeout 60s`

#### Release 自动编译发布

- 工作流文件：`.github/workflows/release.yml`
- 触发条件：
  - push 语义化 tag：`v*.*.*`
- 当前会自动构建并发布：
  - `gwxapkg-windows-amd64.exe`
  - `gwxapkg-linux-amd64`
  - `gwxapkg-darwin-amd64`
  - `gwxapkg-darwin-arm64`

---

## 推荐使用方式

```bash
# 扫描缓存列表
./gwxapkg scan

# 扫描并输出候选路径诊断
./gwxapkg scan --verbose

# 自动处理指定 AppID，并导出 Postman Collection
./gwxapkg all -id=wx1234567890abcdef -postman

# 批量处理多个 AppID
./gwxapkg all -id=wx123,wx456

# 从文件读取 AppID 列表批量处理
./gwxapkg all -id-file=ids.txt

# 对已解包目录独立扫描
./gwxapkg scan-only -dir=./output/wx1234567890abcdef -format=both -postman
```

---

## 升级说明

- 如果你之前依赖自动生成 `config/rule.yaml`，现在需要手动创建该文件
- 如果你没有放置 `config/rule.yaml`，程序会直接使用内置默认规则
- 若已有脚本依赖老的输出路径，请同步确认默认输出目录已统一为 `output/<AppID>`
- 若你需要 GitHub 自动编译产物，触发的是 `release.yml` 对应的 tag 发布流程，而不是普通 `ci.yml`

---

## 下载产物

### macOS

- `gwxapkg-darwin-arm64`
- `gwxapkg-darwin-amd64`

### Windows

- `gwxapkg-windows-amd64.exe`

### Linux

- `gwxapkg-linux-amd64`
