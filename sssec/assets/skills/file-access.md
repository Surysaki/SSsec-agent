---
id: file-access
name: 任意文件读取
when: 存在 download/file/path/模板名等参数，或响应回显文件内容时
category: 漏洞利用
stages: [exploit, post_exploit]
version: 1.0.0
source: hack-skills/file-access-vuln (MIT)
license: MIT
---

## 快速路径
1. 绝对路径正对照：`/etc/passwd`、`/etc/hostname`。
2. 相对穿越：`../`、`....//`、`..%2f`、`%2e%2e`。
3. 包装器/伪协议：`php://filter`、`file://`、`/proc/self/environ`。

## 检查表
- [ ] 过滤是“剥离”还是“拒绝”
- [ ] 绝对路径是否覆盖前缀（`os.path.join`）
- [ ] 是否只允许固定目录/扩展名
- [ ] 错误页是否区分“不存在/无权限”

## 反例
- `../` 返回 500 可能只是文件不存在，不是被过滤。
- `?file=nope` 也 500 时，说明 500 = 不存在，需要正对照。

## 验证与停止
- 只读；不读取与目标无关的敏感数据。
- 绝对路径/穿越/包装器都失败 → 结束。
