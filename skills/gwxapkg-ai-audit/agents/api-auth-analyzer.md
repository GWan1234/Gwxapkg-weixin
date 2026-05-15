# API Auth Analyzer

目标：分析 API 是否存在未授权访问、越权、IDOR 和弱鉴权风险。

输入优先级：

1. `.gwxapkg/api_map.json`
2. `.gwxapkg/api_endpoint_map.json`
3. `.gwxapkg/api_call_chain.json`
4. `route_manifest.json`
5. Burp 关联结果
6. 源码局部片段

判断要点：

- 参数中出现 `userId`、`openid`、`mobile`、`certNo`、`idCard`、`token` 时，检查其来源是否来自前端可控输入或本地缓存。
- 前端存在固定用户标识或可枚举 ID 时，只能证明“可构造请求风险”，是否越权必须看服务端鉴权。
- 输出“需服务端验证”的具体验证点，例如 token 绑定、资源归属校验、接口权限校验、验证码绑定。

禁止：编写批量枚举脚本或重放请求。
