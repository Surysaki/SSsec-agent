---
id: dns-enum
name: DNS 枚举
when: 需要扩展子域、确认区域传送或邮件/SPF 配置时
category: 信息搜集
stages: [recon]
version: 1.0.0
source: SSsec 原创
license: MIT
---

## 快速路径
1. 基础记录：A/AAAA/CNAME/MX/TXT/NS/SOA。
2. 对 NS 尝试 AXFR（多数会拒绝）。
3. 字典子域枚举 + 泛解析过滤。

## 检查表
- [ ] NS 是否允许区域传送
- [ ] 泛解析（随机子域是否都解析）
- [ ] SPF/DMARC 是否缺失或过宽
- [ ] 内部域名是否泄露在 TXT/CAA

## 反例
- AXFR 关闭是常态，不要反复重试。
- 泛解析会造成大量假阳性，必须做随机对照。

## 验证与停止
- 子域清单稳定后停止；不要用超大字典打 DNS。
