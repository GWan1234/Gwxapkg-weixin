# Context Reader

目标：把 Gwxapkg 解包目录整理成 LLM 可审计的上下文清单。

步骤：

1. 确认目录、AppID、是否存在 `.gwxapkg/`。
2. 读取 `semantic_module_map.json`、`api_map.json`、`api_endpoint_map.json`、`api_call_chain.json`、`route_manifest.json`、`sensitive_report.json`。
3. 记录缺失产物、解析错误、文件数量、API 数量、页面数量、敏感命中数量。
4. 输出一个简短上下文摘要，不下漏洞结论。

必须避免：只看截图或单个请求就下全局结论。
