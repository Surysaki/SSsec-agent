---
id: host-alias
name: Host 头与静态别名
when: 出现 Host 头差异、/static/ alias、x-cache、vhost 或反向代理行为时
category: 漏洞扫描
stages: [vuln_analysis, exploit, final]
version: 1.0.0
source: hack-skills/http-host-header-attacks + web-cache-deception (MIT)
license: MIT
---

## 快速路径
1. **换 Host**：`localhost`、`127.0.0.1`、目标域名，比较 body/长度/状态码。
2. **看 alias**：`/static/`、`/assets/` 是否指向另一个根目录；试单层 `%2e%2e` 与双层。
3. **看缓存**：`x-cache`、`Age`、`Cache-Control`；确认缓存键是否包含 Host/路径/编码差异。

## 检查表
- [ ] Host 头切换是否命中默认 server（nginx 自带页）或另一个 vhost
- [ ] `/static/%2e%2e/robots.txt` 与 webroot 的 `robots.txt` 内容/长度是否不同
- [ ] 单层 vs 双层 `..`：一层可能被放行，两层被 400
- [ ] `X-Forwarded-Host`、`X-Original-URL`、`X-Rewrite-URL` 是否改变路由
- [ ] 缓存投毒：同一 URL 不同 Host/头是否命中同一缓存条目

## 反例
- 默认 server 的 200 可能只是 nginx 自带的 `index.html`，不代表有独立应用。
- alias 根不一定是 webroot，也不一定是 `/tmp`；能跨一层不等于任意文件读。
- `%2e%2e` 单层有效不代表双层有效，也不代表能读出 `/etc/passwd`。

## 验证与停止
- 用“不同内容文件”做对照（25B vs 46B 这类长度差是强证据）。
- 两层穿越都被 400 且 alias 根无法枚举 → 放弃该方向。
