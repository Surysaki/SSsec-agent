---
id: privesc-windows
name: Windows 提权枚举
when: 已获得 Windows 低权限 shell，需要评估提权面时
category: 权限提升
stages: [post_exploit]
version: 1.0.0
source: hack-skills/windows-privilege-escalation (MIT)
license: MIT
---

## 快速路径
1. `whoami /priv`、`whoami /groups`、系统版本与补丁。
2. 服务/计划任务/注册表权限、可写目录、未引用服务路径。
3. 凭据：配置、凭据管理器、浏览器（只读，不 dump 内存）。

## 检查表
- [ ] SeImpersonate/SeAssignPrimaryToken
- [ ] 服务二进制/目录可写
- [ ] 计划任务可写
- [ ] AlwaysInstallElevated
- [ ] UAC 等级与自动提权

## 反例
- 有特权令牌不等于可利用，需要 impersonation 条件。
- 不要使用 mimikatz/LSASS dump（越界且高风险）。

## 边界与停止
- 只读枚举；不修改服务、不写注册表、不持久化。
- 三类枚举无发现 → 记录并停止。
