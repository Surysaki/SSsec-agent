---
id: auth-bypass
name: 认证与密钥旁路
when: 存在登录、install.lock、secretkey、安装页或权限校验时
category: 漏洞扫描
stages: [vuln_analysis, exploit, final]
version: 1.0.0
source: jiker666/authbypass-test + 本次 DASCTF 复盘 (MIT)
license: MIT
---

## 快速路径
1. **列参数面**：用户名/口令之外，试 `name/file/fix/path/step/key/token` 等常见参数名。
2. **列凭证面**：Cookie、Basic Auth、`X-Forwarded-For`/`X-Real-IP`、Referer、Host。
3. **判密钥用途**：泄露的 secretkey 是否在参数/头/签名/加解密里真的有消费点。

## 检查表
- [ ] `install.lock` 是 `file_exists` 硬门还是可被参数/上下文绕过（直接访问 vs include 上下文）
- [ ] 参数名枚举用“响应长度/内容变化”做差分，不要只看 200
- [ ] 来源头伪造是否被信任（只影响展示还是影响鉴权）
- [ ] 密钥是否用于 Cookie 签名、JWT、上传白名单旁路、加解密
- [ ] 认证后接口是否存在 IDOR / 越权（用相邻 id 与边界外对照）

## 反例
- 泄露的密钥可能只是诱饵：40+ 参数、Cookie、Basic、来源头都无差异时，应判“无消费点”并停止。
- 安装页在 include 上下文与直接访问下 `__DIR__` 可能不同，但也可能完全一样；要用响应证据区分。
- 不要用字典爆破口令代替逻辑测试；爆破既慢又容易触发风控。

## 验证与停止
- 每个旁路都要有“带/不带凭证”的差分响应。
- 参数、头、凭证三面都无差异 → 判定无认证绕过面，转注入/上传/包含。
