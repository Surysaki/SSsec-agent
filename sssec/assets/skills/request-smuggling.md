---
id: request-smuggling
name: 请求走私判定
when: 目标前置 CDN/反代，且存在多级代理或 HTTP/1.1 复用
category: 漏洞扫描
stages: [vuln_analysis]
version: 1.0.0
source: hack-skills/request-smuggling (MIT)
license: MIT
---

## 快速路径
1. 判断前后端对 `Content-Length`/`Transfer-Encoding` 的解析差异。
2. 用时间差或下一个请求的污染做低影响验证。
3. 只在授权且可回滚的环境做，不投毒共享缓存。

## 检查表
- [ ] CL.TE / TE.CL / TE.TE 变体
- [ ] 是否 HTTP/2 降级
- [ ] 代理是否规范化重复头
- [ ] 是否有缓存（影响面判断）

## 反例
- 单层代理可能直接拒绝，不能据此判断无走私。
- 误判可能导致请求错位，影响其他用户；必须低影响。

## 验证与停止
- 用自有回连/时间差验证，不攻击其他用户。
- 两种变体都无差异 → 结束。
