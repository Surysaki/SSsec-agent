---
id: xxe
name: XXE 外部实体
when: 存在 XML/SVG/DOCX/SOAP 等 XML 解析入口时
category: 漏洞扫描
stages: [vuln_analysis, exploit]
version: 1.0.0
source: hack-skills/xxe-xml-external-entity (MIT)
license: MIT
---

## 快速路径
1. 确认输入被 XML 解析（Content-Type、报错、回显）。
2. 试外部实体读文件：`file:///etc/hostname`。
3. 无回显时用 OOB：外部 DTD + DNS/HTTP 回连。

## 检查表
- [ ] 是否禁用 DTD/外部实体
- [ ] 是否支持 `php://filter`、`expect://`
- [ ] SVG/Office 上传是否触发解析
- [ ] 报错是否泄露文件内容

## 反例
- JSON 端点通常不解析 XML，先确认解析器。
- 实体被禁用时，OOB 也不会触发。

## 验证与停止
- 只读文件或 DNS 回连作为证据；不读取无关敏感文件。
- 实体禁用/无回显/无回连 → 结束。
