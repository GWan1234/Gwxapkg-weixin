# Release v2.7.2

## 版本概览

`v2.7.2` 是一次稳定性修复版本，重点修复部分真实小程序样本在 HTML 内嵌 JavaScript 反混淆阶段触发 `nil pointer dereference`，以及转义字符串、Excel 报告和 WXML 还原在边界样本中的失败问题。

本版本的目标是：**异常脚本不能中断整包解包流程，异常报告字段不能阻断报告生成，动态 WXML 尽量还原出有效结构**。当单个 JS 片段无法完成反混淆分析时，Gwxapkg 会保留原始内容继续写出文件，而不是让进程崩溃。

---

## 重点更新

### 1. 修复 JS / HTML 反混淆 panic

- 修复 HTML `<script>` 内嵌 JavaScript 进入反混淆分析时可能触发的 `nil pointer dereference`
- 反混淆入口增加 panic 兜底，异常样本会被标记为 `skipped` 并保留原始内容
- HTML 格式化流程中，即使内嵌脚本分析失败，也会继续输出 HTML 文件
- 修复 `\x22`、`\u0022` 等转义字符被解码后破坏字符串语法，导致后续 JavaScript 解析报错的问题

### 2. 强化 AST 与解码边界防护

- `VariableStatement`、`Binding`、`Identifier`、`ArrayLiteral` 等节点增加空值检查
- AST 遍历逻辑支持 typed nil 节点识别，避免反射遍历时再次触发 panic
- 构建 bootstrap 片段、去重 statement、截取节点源码等辅助路径均增加防御性判断

### 3. 修复 Excel 报告生成失败

- 修复分类名包含 `: \ / ? * [ ]` 等 Excel sheet 非法字符时，`.xlsx` 报告生成失败的问题
- 修复分类名过长、重复或为空时 sheet 名冲突的问题
- 修复空匹配结果下概览页百分比计算可能除零的问题

### 4. 改进 WXML 结构还原

- 支持跳过编译产物里的 `virtual` 虚拟节点，避免输出无效标签
- 为动态渲染函数补充安全 mock 参数，提升真实页面 WXML 结构还原率
- 对列表型渲染分支增加兜底尝试，减少空白 WXML 输出

### 5. 回归测试覆盖

- 新增 formatter 回归测试，覆盖：
  - JavaScript 分析阶段 panic
  - HTML 内嵌 `<script>` 分析阶段 panic
  - 字符串转义解码后仍保持合法 JavaScript
  - 不完整 AST 变量声明
  - typed nil AST 节点遍历
- 新增 reporter 回归测试，覆盖非法 Excel sheet 名清洗与报告生成
- 新增 unpack 回归测试，覆盖 WXML `virtual` 节点展开
- 已通过：

```bash
go test ./internal/formatter
go test ./internal/reporter
go test ./internal/unpack
go test ./...
GOOS=windows GOARCH=amd64 go build -o /tmp/gwxapkg-windows-amd64.exe .
```

---

## 影响范围

- 受影响命令：`all`、默认解包命令、涉及 HTML / JS 格式化与反混淆的流程
- 修复后行为：单个异常 JS 片段最多跳过反混淆，不会导致整次解包失败；Excel 报告遇到非法分类名会自动清洗 sheet 名；WXML 还原会跳过虚拟节点并尝试更完整的动态渲染分支
- 兼容性：不改变命令行参数，不改变输出目录结构

---

## 下载说明

| 文件 | 适用平台 |
|------|---------|
| `gwxapkg-windows-amd64.exe` | Windows 64 位 |
| `gwxapkg-linux-amd64` | Linux 64 位 |
| `gwxapkg-darwin-amd64` | macOS Intel |
| `gwxapkg-darwin-arm64` | macOS Apple Silicon |

## 使用方法

```bash
# Windows (PowerShell)
.\gwxapkg-windows-amd64.exe scan

# Linux / macOS
chmod +x gwxapkg-linux-amd64
./gwxapkg-linux-amd64 scan
```
