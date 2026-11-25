---
id: vm-bytecode
name: VM 与字节码逆向
when: 样本使用 VMProtect/自定义字节码/解释器执行时
category: 逆向分析
stages: [reverse]
version: 1.0.0
source: hack-skills/vm-and-bytecode-reverse (MIT)
license: MIT
---

## 快速路径
1. 找解释器循环：取指、解码、分派。
2. 提取 opcode 表与 handler，映射语义。
3. 用动态 trace 记录 opcode 序列，还原关键逻辑。

## 检查表
- [ ] 字节码入口与长度
- [ ] opcode 分派方式（switch/表）
- [ ] 寄存器/栈模型
- [ ] 是否有反 trace/自修改

## 反例
- 不是所有混淆都是 VM；先确认解释器存在。
- 不要逐条硬读，先 trace 高频路径。

## 验证与停止
- 还原关键 opcode（校验/分支）即可解题。
- 无法定位解释器 → 回到静态分析。
