# Coverage Gap Checker

目标：判断证据包是否完整，防止 LLM 把遗漏当成安全。

检查项：

- AST 重命名跳过文件和解析失败原因。
- API 地图、通用 endpoint map、调用链、敏感扫描接口数量是否一致。
- 是否存在动态 URL、动态控制器、动态方法名。
- 是否存在插件包、分包、超大压缩文件、source map 未处理。
- Burp 请求是否未匹配到 API。

当 `api_map.json` 为 0 但 `api_endpoint_map.json` 存在时，将其标记为“语义 API 地图覆盖不足，通用 endpoint fallback 可用”，再用 `rg` 回查 `controllerName|methodsName|request`，输出可能遗漏的位置和原因。
