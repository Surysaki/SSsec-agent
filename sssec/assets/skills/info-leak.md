---
id: info-leak
name: 信息泄露与目录线索
when: 需要从 robots、.DS_Store、source map、display_errors、备份文件中找入口或路径时
category: 信息搜集
stages: [recon, vuln_analysis, final]
version: 1.0.0
source: jiker666/info-leak-test + 本次 DASCTF 复盘 (MIT)
license: MIT
---

## 快速路径
1. **先看公开线索**：`robots.txt`、`sitemap.xml`、`/.well-known/`、`/health`、`/metrics`。
2. **再试构建残留**：`.DS_Store`、`.git/HEAD`、`.svn/`、`*.map`、`*.bak`、`~`、`.swp`。
3. **用报错定位**：传数组/错误类型触发 PHP warning，看是否回显绝对路径与行号。

## 检查表
- [ ] `.DS_Store` 是二进制：先用 `file_analyze`/本地解析，不要直接用 `http_request` 分段读文本
- [ ] robots 里的 `Disallow` 可能是作者故意留的诱饵；读到内容后要验证它有没有“消费点”
- [ ] `display_errors=On` 会泄露 docroot、文件行号；用 `?name[]=x` 之类参数触发
- [ ] source map / webpack chunk 里常有过期接口与内网地址
- [ ] 备份文件按框架命名：`index.php.bak`、`www.zip`、`app.tar.gz`、`.env`

## 反例
- robots 泄露的密钥可能在任何参数/头/凭证面上都没有消费点，此时应判“诱饵”并停止投入。
- `.DS_Store` 只列同目录文件名，不包含被删除文件，也不保证是当前版本（可能早于新入口）。
- 目录 403 不代表目录下文件 403；具体路径要单独请求。

## 验证与停止
- 每条泄露至少给出响应头/正文证据，并记入 finding（含“是否为诱饵”的判断）。
- 公开线索、构建残留、错误回显三类都无新入口 → 转入口验证，不要继续扫字典。
