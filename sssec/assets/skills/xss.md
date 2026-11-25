---
id: xss
name: XSS 上下文与 CSP
when: 用户输入被回显到 HTML/属性/JS/URL，或存在富文本/预览时
category: 漏洞扫描
stages: [vuln_analysis, exploit]
version: 1.0.0
source: hack-skills/xss-cross-site-scripting (MIT)
license: MIT
---

## 快速路径
1. 定位回显上下文：HTML 正文、属性、`<script>`、URL、CSS。
2. 用最小 payload 验证执行（`alert(1)` 或等价），先不绕 WAF。
3. 检查 CSP/HttpOnly/SameSite，判断影响与利用面。

## 检查表
- [ ] 反射/存储/DOM 三类
- [ ] 编码：HTML 实体、JS 转义、URL 编码
- [ ] 属性闭合、事件处理器、`javascript:` URL
- [ ] CSP 是 enforce 还是 report-only
- [ ] 是否有 HttpOnly（决定能否拿 Cookie）

## 反例
- `alert` 被拦不代表没有 XSS；可能只是 CSP。
- 存储型需要二次访问才触发，别只看首次响应。

## 验证与停止
- 用最小 payload + 截图/响应作为证据；不投递蠕虫式 payload。
- 三类上下文都被正确编码 → 记录并转其他面。
