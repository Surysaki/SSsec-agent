---
id: include-path
name: 包含与路径穿越
when: 出现 ?inc= / ?file= / ?page=、存在性 oracle、目录 403 或静态 alias 时
category: 漏洞扫描
stages: [vuln_analysis, exploit, final]
version: 1.0.0
source: hack-skills/path-traversal-lfi + 本次 DASCTF 复盘 (MIT)
license: MIT
---

## 快速路径
1. **判定语义**：是 `include($x.'.php')`、`file_exists` 白名单，还是路由表？用三个不同内容的页面区分。
2. **判定边界**：`..`、绝对路径、`php://filter`、`data://`、编码点号（`%2e%2e`）挨个测，注意单层与双层不同。
3. **判定可利用性**：能否写入一个可被包含的 `.php`？写不了就只是“存在性 oracle”，不要当成 LFI。

## 检查表
- [ ] `?inc=index` 是否递归/报错（**`include_once` 会静默跳过**，不能据此判定白名单）
- [ ] `php://filter/convert.base64-encode/resource=...` 是否生效
- [ ] `/proc/self/environ`、日志、session 文件是否可包含
- [ ] 编码：`%2e%2e`、`%252e`、`..%2f`、`....//`（先想清楚过滤是剥离还是拒绝）
- [ ] 静态 alias：`/static/%2e%2e/robots.txt` 与 webroot 的 `robots.txt` 长度/内容是否不同

## 反例
- 过滤“剥离 `../`”时，`....//` 过一次 replace 恰好还原成 `../`；它 500 只说明目标不存在，不能证明“拒绝 `..`”。
- 目录 403 只代表索引被禁，具体文件仍可能 200；反之目录 404 也不代表文件不存在。
- 单层 `%2e%2e` 可用、双层被 400 拦，说明只能跨一层，不等于任意文件读。

## 验证与停止
- 用“不同内容页面”做正对照（About vs 首页），不要用长度 0/404 猜。
- LFI、写落盘、日志包含三条都验证失败 → 关闭该方向，转上传或认证面。
