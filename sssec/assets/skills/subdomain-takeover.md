---
id: subdomain-takeover
name: 子域接管判定
when: 发现子域 CNAME 指向 SaaS/对象存储，或页面出现服务商 404 指纹时
category: 信息搜集
stages: [recon, vuln_analysis]
version: 1.0.0
source: hack-skills/subdomain-takeover (MIT)
license: MIT
---

## 快速路径
1. 收集子域与 CNAME：`dns_lookup` CNAME/NS，或证书透明列表。
2. 识别悬空：CNAME 指向 github.io / s3 / heroku / azure / pages 等，但目标已释放。
3. 请求子域看指纹：NoSuchBucket、There isn't a GitHub Pages site here、Heroku no such app。

## 检查表
- [ ] CNAME 目标是否仍被占用
- [ ] 服务商 404 指纹
- [ ] 是否能创建同名资源（只验证到“可注册”为止）

## 反例
- CNAME 存在不等于可接管；服务商可能已保留名称。
- 子域 404 可能只是应用路由，不是悬空。

## 验证与停止
- 只做只读判定；不实际注册/占用第三方资源。
- 无悬空 CNAME 或指纹不匹配 → 结束该方向。
