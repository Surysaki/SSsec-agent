---
id: ssrf
name: SSRF 与云元数据
when: 存在 URL/图片/回调/代理/导入类参数时
category: 漏洞扫描
stages: [vuln_analysis, exploit]
version: 1.0.0
source: hack-skills/ssrf-server-side-request-forgery (MIT)
license: MIT
---

## 快速路径
1. 用可回连的外部地址确认服务端会发起请求（DNS/HTTP）。
2. 试内网：`127.0.0.1`、`localhost`、`169.254.169.254`、`[::1]`。
3. 试协议与重定向：http/https、302 跳转、DNS rebinding（只读）。

## 检查表
- [ ] 是否有回显（响应体/状态码/时间）
- [ ] 只允许 http 还是任意协议
- [ ] 是否跟随重定向
- [ ] 云元数据路径（AWS/GCP/Azure/阿里云）
- [ ] 是否可访问内网管理端口

## 反例
- 请求失败可能是出网限制，不是没有 SSRF。
- 内网扫描会越界；只验证单点，不扫段。

## 验证与停止
- 只读验证；不批量扫内网、不读取与目标无关的数据。
- 无回显/无回连/元数据 403 → 结束。
