---
id: jwt-oauth
name: JWT 与 OAuth 配置
when: 存在 JWT、OAuth/OIDC 登录、SSO 回调时
category: 漏洞扫描
stages: [vuln_analysis]
version: 1.0.0
source: hack-skills/jwt-oauth-token-attacks (MIT)
license: MIT
---

## 快速路径
1. 解 JWT：alg、kid、claims、过期时间、签发者。
2. 试 `alg:none`、HS/RS 混淆、弱密钥、kid 注入。
3. OAuth：redirect_uri 校验、state、scope、code 复用。

## 检查表
- [ ] 签名是否真的校验
- [ ] `kid` 是否可路径穿越/注入
- [ ] 弱密钥（字典/常见 secret）
- [ ] redirect_uri 是否严格匹配
- [ ] refresh token 是否可重放

## 反例
- 库版本较新时 alg 混淆通常已被修复。
- 能改 claims 但签名校验通过才算漏洞。

## 验证与停止
- 只读验证；不伪造他人身份做破坏性操作。
- 三种算法/密钥尝试都失败 → 结束。
