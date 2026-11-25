---
id: ssti-jinja2
name: 模板注入与黑名单绕过
when: 页面回显 {{7*7}}、模板报错、预览/渲染功能或 Jinja2/Twig/FreeMarker 特征时
category: 漏洞扫描
stages: [vuln_analysis, exploit, final]
version: 1.0.0
source: hack-skills/ssti-server-side-template-injection (MIT)
license: MIT
---

## 快速路径
1. **确认引擎**：`{{7*7}}`、`${7*7}`、`<%= 7*7 %>`、`#{7*7}` 各打一次，看谁算出 49。
2. **确认输出通道**：`{{ }}` 被过滤时试 `{% print(7*7) %}`；再试 `|attr`、`~` 拼接、`[]` 下标。
3. **再谈读取**：先读 `/proc/self/environ` 或 `config`，最后才找 flag 文件。

## 检查表
- [ ] 过滤器/黑名单是正则还是字符串替换；大小写、子串误伤（`os` 会命中 `hos`）
- [ ] `x|attr('a')['b']` 在 Jinja 里是语法错误；要写成 `(x|attr('a'))['b']` 或 `.get`
- [ ] 常见链：`lipsum.__globals__`、`cycler`、`joiner`、`config`、`request`
- [ ] 黑名单挡 `_`/`.`/`[]` 时用 `'~'` 拼接、`|attr` 和 `{% set %}`
- [ ] 报错页是否回显模板源码或行号（可用来确认引擎与位置）

## 反例
- 黑名单里没有 `[`，不代表 `[` 能用：过滤器后的下标是解析错误，不是被过滤。
- `{{` 被挡时 `{%` 仍可能可用；`print` 语句与输出表达式是两条通道。
- 一次 500 不等于链子错，可能只是目标文件不存在（例如 `/flag` 不在根目录）。

## 验证与停止
- 先 `49`，再读 `environ`，再 `listdir('/')`；每一步都要有响应证据。
- 三条对象链都 500 且错误回显关闭 → 换注入点，不要继续猜变量名。
