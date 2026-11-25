---
id: graphql
name: GraphQL 测试
when: 存在 /graphql、/gql 或前端使用 Apollo/Relay 时
category: 漏洞扫描
stages: [vuln_analysis]
version: 1.0.0
source: hack-skills/graphql-and-hidden-parameters (MIT)
license: MIT
---

## 快速路径
1. 试 introspection；关闭时试常见字段与错误提示。
2. 查批量查询、深度嵌套、字段级鉴权。
3. 查 mutation 是否越权。

## 检查表
- [ ] introspection 是否开放
- [ ] 是否有 query 深度/复杂度限制
- [ ] 批量 alias 是否可绕过限流
- [ ] 字段级权限（用户 A 读 B 的字段）

## 反例
- introspection 关闭不代表不可测；错误信息会泄露 schema。
- 深度查询可能造成 DoS，禁止。

## 验证与停止
- 只读 query；不做批量 DoS。
- 无 introspection 且常见字段都 400 → 结束。
