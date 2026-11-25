---
id: binary-info
name: 二进制指纹与保护
when: 拿到 ELF/PE/固件样本，需要先看架构与保护时
category: 逆向分析
stages: [reverse]
version: 1.0.0
source: SSsec 原创
license: MIT
---

## 快速路径
1. `binary_info`：架构、位数、入口、PIE/NX/RELRO/Canary。
2. `strings`/`file_analyze`：可疑字符串、路径、密钥、错误提示。
3. 找 main/校验函数与输入点。

## 检查表
- [ ] 静态/动态链接
- [ ] 保护机制与可利用性
- [ ] 关键字符串与常量
- [ ] 输入/输出与校验逻辑

## 反例
- 字符串不等于逻辑，必须用反汇编/交叉引用确认。
- 加壳/混淆时先脱壳，别直接读字符串下结论。

## 验证与停止
- 保护与入口明确后进入具体分析。
- 样本损坏/无法解析 → 记录并停止。
