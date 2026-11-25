---
id: recon-methodology
name: 资产测绘流程
when: 拿到一个新目标，需要系统地摸清资产、入口与技术栈时
category: 信息搜集
stages: [recon, final]
version: 1.0.0
source: SSsec 原创
license: MIT
---

## 快速路径
1. 根路径/常见路径指纹：状态、标题、Server、X-Powered-By、Set-Cookie。
2. 被动扩面：证书透明、DNS、ASN、搜索引擎、GitHub 泄露。
3. 主动扩面：子域、端口、目录、爬虫、JS 端点。
4. 汇总入口清单：路径、方法、参数、鉴权、上传/回调点。

## 检查表
- [ ] robots/sitemap/health/metrics
- [ ] 静态目录、备份、.git、.DS_Store
- [ ] 登录/注册/上传/搜索/回调
- [ ] 技术栈与版本（决定后续打法）
- [ ] 是否有 CDN/WAF/反代（Host、x-cache）

## 反例
- 目录 403 只代表索引被禁，具体文件仍可能 200。
- robots 里的 Disallow 可能是作者故意留的诱饵。
- 端口开放不等于有业务，先要 banner/协议确认。

## 验证与停止
- 入口清单稳定（连续两轮无新增）后交给 vuln_analysis。
- 不做无限字典；静态站不要反复扫同一批路径。
