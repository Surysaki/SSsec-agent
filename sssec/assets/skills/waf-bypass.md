---
id: waf-bypass
name: WAF 识别与绕过
when: payload 被 403/406/拦截页挡住，需要判断是 WAF 还是应用逻辑时
category: 漏洞利用
stages: [any]
version: 1.0.0
source: hack-skills/waf-bypass-techniques (MIT)
license: MIT
---

## 快速路径
1. 先判断拦截来源：响应头/拦截页/状态码/大小。
2. 用无害 payload 做基线，再逐项改编码、大小写、注释、分块。
3. 只绕过到“证明可达”为止，不做大批量 fuzz。

## 检查表
- [ ] URL/双重 URL/Unicode 编码
- [ ] 大小写、内联注释、空白替换
- [ ] 参数污染（HPP）、分块传输
- [ ] Content-Type/方法变换
- [ ] 是否只拦 body 不拦 header

## 反例
- 403 可能是应用权限，不是 WAF。
- 绕过成功不等于漏洞成立，还要看业务响应。

## 验证与停止
- 低速率、单点验证；不跑大字典。
- 三种编码/变形仍被拦 → 记录 WAF 规则并转其他面。
