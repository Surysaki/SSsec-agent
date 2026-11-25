---
id: idor
name: 越权与 IDOR
when: 存在对象 id、用户 id、订单号、文件 key 等直接引用时
category: 漏洞扫描
stages: [vuln_analysis, exploit]
version: 1.0.0
source: hack-skills/idor-broken-object-authorization (MIT)
license: MIT
---

## 快速路径
1. 用两个账号（A/B）各取一个对象，交换 id 访问。
2. 试相邻 id、边界外 id、编码变体。
3. 判断是读越权、写越权还是功能越权。

## 检查表
- [ ] 水平越权（同角色不同用户）
- [ ] 垂直越权（低权限访问高权限接口）
- [ ] 批量接口/导出接口
- [ ] 前端隐藏但后端未校验的字段（role/is_admin）

## 反例
- 404 可能是权限校验，不代表对象不存在。
- 只改前端参数不算越权，必须后端接受。

## 验证与停止
- 用两个账号的差分响应作为证据；不批量遍历用户数据。
- 3 组对象都 403/404 → 记录并停止。
