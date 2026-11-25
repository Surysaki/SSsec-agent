---
id: cmdi
name: 命令注入
when: 输入可能进入 shell/系统命令/转换器/导入管道时
category: 漏洞利用
stages: [exploit]
version: 1.0.0
source: hack-skills/cmdi-command-injection (MIT)
license: MIT
---

## 快速路径
1. 试分隔符：`;`、`|`、`||`、`&&`、`$()`、反引号、`%0a`。
2. 无回显时用时间盲测（`sleep 5`）或 OOB DNS。
3. 先执行只读命令（`id`、`hostname`），证明后停止。

## 检查表
- [ ] 引号上下文（单/双/无引号）
- [ ] 空格过滤（`$IFS`、`{cat,path}`、`<`）
- [ ] Windows 变体（`&`、`|`、`%0a`）
- [ ] 是否有回显/仅时间/OOB

## 反例
- 输入被转义时不一定能注入；以实际回显为准。
- 一次时间变慢可能是网络抖动，重复 2 次。

## 验证与停止
- 只跑只读命令；不写文件、不反弹 shell、不持久化。
- 三类分隔符都无回显/无时间差 → 结束。
