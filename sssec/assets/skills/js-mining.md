---
id: js-mining
name: 前端 JS 挖接口
when: 页面加载多个 JS、接口参数带签名/加密、或存在隐藏 API 线索时
category: 信息搜集
stages: [recon, vuln_analysis, final]
version: 1.0.0
source: jiker666/js-reverse-guide (MIT)
license: MIT
---

## 快速路径
1. **收 JS**：从页面、`sourceMappingURL`、webpack chunk 里拿全量脚本。
2. **抽接口**：grep `/api/`、`fetch(`、`axios`、`$.get`、路径拼接与隐藏路由。
3. **抽参数**：签名算法、盐、公钥、演示账号、`admin`/`debug` 路由。

## 检查表
- [ ] 接口路径、HTTP 方法、必填参数、签名/token 生成逻辑
- [ ] 写死的演示号/测试租户（可能是钥匙）
- [ ] `sourceMappingURL` 是否指向可访问的 `.map`（能还原源码）
- [ ] `hidden`/`admin` 路由是否只在 JS 里出现
- [ ] 前端加密：是混淆、编码还是真加密；能否在本地复现

## 反例
- 混淆 JS 不等于接口泄露；先找 `path`/`sign` 这类关键字，再谈去混淆。
- 签名算法要靠 JS 复现，不要凭经验猜（猜错会得到 401，浪费轮次）。
- **不要把目标源码/密钥发到第三方代码执行服务**；本地 `run_command` 优先。

## 验证与停止
- 每个提取到的接口用一次真实请求确认（状态码/字段）。
- 没有隐藏路由、没有签名参数、map 也不可读 → 转其他入口，不要在 JS 里反复格式化。
