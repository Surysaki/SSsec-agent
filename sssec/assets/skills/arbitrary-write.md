---
id: arbitrary-write
name: 任意写与落点
when: 存在上传/日志/配置/session/解压等可写原语，想升级为 RCE 时
category: 漏洞利用
stages: [exploit]
version: 1.0.0
source: hack-skills/arbitrary-write-to-rce (MIT)
license: MIT
---

## 快速路径
1. 确认写什么（内容）、写哪里（路径）、叫什么（文件名）。
2. 找消费点：include、cron、静态 alias、模板、session、日志解析。
3. 只有“可写 + 可执行/可包含”同时成立才是 RCE。

## 检查表
- [ ] 校验名与落盘名是否同源
- [ ] 路径穿越/绝对路径/符号链接
- [ ] 落点是否在 webroot、是否有定时搬运
- [ ] 权限（www-data/root）与扩展名解析

## 反例
- 能写 `/tmp` 不等于能执行；没有消费点就只是文件写入。
- 回显路径不等于真实落盘路径，要用存在性 oracle 复核。

## 验证与停止
- 写标记文件再读回作为证据；不覆盖目标既有文件。
- 三类写入原语都失败 → 停止并出“不可落盘”结论。
