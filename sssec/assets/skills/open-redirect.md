---
id: open-redirect
name: 开放重定向
when: 存在 redirect/next/return/url 等跳转参数时
category: 漏洞扫描
stages: [vuln_analysis]
version: 1.0.0
source: hack-skills/open-redirect (MIT)
license: MIT
---

## 快速路径
1. 试 `//evil.example`、`https://evil.example`、`@evil.example`。
2. 试编码/双写/白名单后缀：`target.com.evil.example`。
3. 看 302 Location 是否真的跳出。

## 检查表
- [ ] 是否只校验前缀/包含
- [ ] 是否允许 `//`、`\`、`%2f%2f`
- [ ] 是否可结合 OAuth 偷 code

## 反例
- 跳到站内路径不算开放重定向。
- 前端跳转不算，需服务端 302。

## 验证与停止
- 以 Location 头为证据；不用于钓鱼。
- 三种编码都被拒 → 结束。
