---
id: privesc-linux
name: Linux 提权枚举
when: 已获得 Linux 低权限 shell，需要评估能否提权时
category: 权限提升
stages: [post_exploit]
version: 1.0.0
source: hack-skills/linux-privilege-escalation (MIT)
license: MIT
---

## 快速路径
1. 基础：`id`、`sudo -l`、SUID/SGID、capabilities、cron、可写服务。
2. 内核/发行版版本 → 已知漏洞（只做版本判断，不跑破坏性 exploit）。
3. 配置：可写 `/etc/passwd`、`/etc/cron*`、root 进程、环境变量。

## 检查表
- [ ] `sudo -l` 是否有 NOPASSWD
- [ ] SUID 二进制与 GTFOBins
- [ ] cron/定时任务是否可写
- [ ] 服务以 root 运行且配置可写
- [ ] Docker/lxc 组、挂载、cap

## 反例
- 内核 exploit 风险高，可能崩溃；优先配置类提权。
- 能读 root 文件不等于能执行命令。

## 边界与停止
- 只做只读枚举；不修改系统文件、不写持久化、不装后门。
- 三类枚举都无发现 → 记录“未发现提权面”并停止。
