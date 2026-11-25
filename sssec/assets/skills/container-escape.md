---
id: container-escape
name: 容器逃逸判定
when: shell 在容器内，需要判断是否可逃逸到宿主机时
category: 权限提升
stages: [post_exploit]
version: 1.0.0
source: hack-skills/container-escape-techniques (MIT)
license: MIT
---

## 快速路径
1. 确认是否容器：`/.dockerenv`、cgroup、`/proc/1/cgroup`。
2. 查危险配置：privileged、`/var/run/docker.sock`、hostPath、cap、host PID/network。
3. 只做“能否逃逸”的判定，不实际逃出授权边界。

## 检查表
- [ ] docker.sock 是否挂载
- [ ] 是否 privileged / 有 SYS_ADMIN
- [ ] 宿主机目录是否挂载
- [ ] 是否 hostNetwork/hostPID
- [ ] 内核漏洞（只做版本判断）

## 反例
- 普通容器没有逃逸面，不要硬套 CVE。
- 逃逸到宿主机可能超出授权范围，必须先确认 RoE。

## 边界与停止
- 只读验证；不挂载宿主机、不写宿主文件、不逃逸出范围。
- 无危险配置 → 记录“容器隔离正常”并停止。
