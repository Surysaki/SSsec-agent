---
id: crypto-classic
name: 古典密码与编码
when: 题目给出一串编码/密文，需要先判断层次时
category: 逆向分析
stages: [reverse, final]
version: 1.0.0
source: hack-skills/classical-cipher-analysis (MIT)
license: MIT
---

## 快速路径
1. 看字符集与长度：base64/hex/URL/摩斯/凯撒/维吉尼亚。
2. 逐层解码，记录每层结果，不要跳步。
3. 频率分析/已知明文/密钥长度。

## 检查表
- [ ] 是否多重编码
- [ ] 是否有填充/换表
- [ ] 是否是 XOR/RC4 等对称
- [ ] 是否是 RSA 小指数/共模

## 反例
- 先确认编码层次，再谈破译；直接猜算法容易错。
- 一次解出乱码不代表方向错，可能还有一层。

## 验证与停止
- 解出可读文本/flag 即停止；记录每层变换。
- 三种假设都失败 → 回到题面找提示。
