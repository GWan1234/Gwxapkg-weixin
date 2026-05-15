# Burp Correlator

目标：把 Burp 原始请求映射到 Gwxapkg 的源码 API、伪代码和调用链。

优先使用：

```bash
gwxapkg api-link -dir=<dir> -burp-file=<raw_request.txt>
```

如果命令不可用，则本地解析 raw request：

- method、path、query、headers、JSON body、form body。
- 若请求参数包含 `controllerName` / `methodsName`，按高置信匹配。
- 否则按 HTTP 方法、路径、参数字段与 `api_map.json` / `api_endpoint_map.json` 重合度匹配。

禁止发送请求。未匹配时也要输出解析结果和未匹配原因。
