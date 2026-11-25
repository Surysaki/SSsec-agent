---
id: lateral-movement
name: 横向移动评估
when: 已获得凭据/会话，需要评估授权范围内的横向可能性时
category: 后渗透
stages: [post_exploit]
version: 1.0.0
source: hack-skills/linux-lateral-movement + windows-lateral-movement (MIT)
license: MIT
---

## 快速路径
1. 列出可用凭据、会话、信任关系（SSH key、SMB、WinRM、数据库）。
2. 只验证“能否到达授权范围内的下一台主机”。
3. 每跳记录来源、目标、凭据、证据。

## 检查表
- [ ] 凭据复用范围
- [ ] 内网可达网段（只测授权范围）
- [ ] 隧道/代理需求
- [ ] 目标是否有日志/告警

## 反例
- 横向到范围外主机是越界，必须先确认 RoE。
- 一次登录成功不代表可持续访问。

## 边界与停止
- 只测授权目标；不装后门、不持久化、不批量扫描。
- 到达授权边界或拿到证明即停止。
