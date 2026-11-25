---
id: webshell-basics
name: Webshell 交互
when: 已有一个可用的 webshell/命令执行点，需要稳定交互与取证时
category: 后渗透
stages: [post_exploit]
version: 1.0.0
source: SSsec 原创
license: MIT
---

## 快速路径
1. 先确认执行上下文：用户、cwd、系统、可用命令。
2. 用最小命令取证（`id`、`pwd`、`ls`、`env`）。
3. 记录请求/响应原文，避免二次上传新 shell。

## 检查表
- [ ] 是否只读命令
- [ ] 编码/长度限制
- [ ] 是否有 WAF 拦截
- [ ] 证据是否完整（请求+响应）

## 反例
- 上传新 webshell 会扩大痕迹，优先复用现有点。
- 不要执行写文件/改配置/持久化命令。

## 边界与停止
- 只读取证；拿到所需证据立即停止，并说明清理建议。
- 连接不稳定时降低频率，不反复重连。
