---
id: anti-debug
name: 反调试识别
when: 动态调试被中断、检测到 ptrace/时间差/异常处理时
category: 逆向分析
stages: [reverse]
version: 1.0.0
source: hack-skills/anti-debugging-techniques (MIT)
license: MIT
---

## 快速路径
1. 识别反调试：ptrace、`/proc/self/status`、时间差、信号、硬件断点。
2. 静态定位检查函数，打补丁或绕过（仅本地样本）。
3. 记录检查点与绕过方式，不修改目标生产文件。

## 检查表
- [ ] 是否检测调试器/断点
- [ ] 是否检测时间/执行速度
- [ ] 是否自校验/完整性检查
- [ ] 是否反虚拟机/沙箱

## 反例
- 静态分析可以绕过大部分反调试，不必硬刚。
- 修改样本前先备份，只在授权环境操作。

## 验证与停止
- 定位到检查点即可；不追求“完全去反调试”。
- 三类检查都无 → 正常分析。
