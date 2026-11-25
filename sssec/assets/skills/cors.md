---
id: cors
name: CORS 配置错误
when: 接口返回 Access-Control-Allow-Origin，或前端跨域调用第三方时
category: 漏洞扫描
stages: [vuln_analysis]
version: 1.0.0
source: hack-skills/cors-cross-origin-misconfiguration (MIT)
license: MIT
---

## 快速路径
1. 发 Origin: `https://evil.example`，看是否反射。
2. 看是否同时返回 `Access-Control-Allow-Credentials: true`。
3. 试 `null` Origin、子域后缀、协议降级。

## 检查表
- [ ] 是否反射任意 Origin
- [ ] 是否允许 credentials
- [ ] 是否校验前缀/后缀（`evil-target.com`）
- [ ] 预检是否放行敏感方法

## 反例
- 只反射 Origin 但不带凭证 = 低危，通常不可利用。
- `*` 与 credentials 不能同时存在。

## 验证与停止
- 用带 Cookie 的响应证明可读敏感数据；否则只记低危。
- 无反射/无凭证 → 结束。
