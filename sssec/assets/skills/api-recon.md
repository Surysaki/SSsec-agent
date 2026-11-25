---
id: api-recon
name: API 与隐藏端点
when: 页面是 SPA/移动端接口，或存在 swagger/graphql/actuator 线索时
category: 信息搜集
stages: [recon, vuln_analysis]
version: 1.0.0
source: hack-skills/api-recon-and-docs (MIT)
license: MIT
---

## 快速路径
1. 常见文档：`/swagger.json`、`/openapi.json`、`/api-docs`、`/graphql`、`/actuator`。
2. 从 JS 抽路径、方法、参数、签名（配合 js-mining）。
3. 用 OPTIONS/405/401/403 的差异判断端点是否存在。

## 检查表
- [ ] 文档是否可匿名访问
- [ ] 版本前缀 `/v1` `/v2` 与兼容端点
- [ ] GraphQL introspection / playground
- [ ] 鉴权方式：Cookie / Bearer / API-Key
- [ ] 分页、批量、导出接口（越权高发）

## 反例
- 404 可能被 WAF 统一改写；401/403 反而说明端点存在。
- 文档可能过期，以实际响应为准。

## 验证与停止
- 文档 + JS + 常见路径都无新端点 → 转业务入口测试。
