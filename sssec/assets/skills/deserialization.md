---
id: deserialization
name: 反序列化识别
when: 出现 Java/PHP/Python/.NET 序列化数据、Cookie、RPC 或缓存键时
category: 漏洞扫描
stages: [vuln_analysis, exploit]
version: 1.0.0
source: hack-skills/deserialization-insecure (MIT)
license: MIT
---

## 快速路径
1. 识别格式：Java `rO0AB`/`aced`、PHP `O:`、Python pickle、.NET ViewState。
2. 找入口：Cookie、隐藏字段、上传、MQ、RPC。
3. 判断是否有可用 gadget（框架/依赖版本），不盲打。

## 检查表
- [ ] 序列化数据是否用户可控
- [ ] 是否签名/加密（能否绕过）
- [ ] 依赖版本与已知 gadget 链
- [ ] 反序列化点是否在鉴权前

## 反例
- 有序列化数据不等于可利用；没有 gadget 就只是“格式”。
- 盲目发 gadget 可能导致服务崩溃，违反低影响原则。

## 验证与停止
- 先用无害 gadget（如 DNS 回连）验证；不做破坏性利用。
- 无 gadget 证据/入口不可控 → 记录并停止。
