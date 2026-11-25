---
id: persistence-check
name: 持久化面识别
when: 需要评估目标是否存在持久化风险或已有持久化痕迹时
category: 后渗透
stages: [post_exploit]
version: 1.0.0
source: SSsec 原创
license: MIT
---

## 快速路径
1. 识别常见持久化位置：cron、systemd、启动项、计划任务、SSH authorized_keys。
2. 判断是否可写、是否已有异常条目。
3. 只记录，不新增任何持久化。

## 检查表
- [ ] cron/systemd/rc.local
- [ ] Windows 服务/计划任务/启动目录
- [ ] SSH key、sudoers
- [ ] 容器 entrypoint/挂载脚本

## 反例
- **不要实际写入持久化**；这违反低影响与授权边界。
- 发现可写目录不等于已有持久化。

## 边界与停止
- 只读识别并写进报告；不新增、不修改。
- 列完清单即停止。
