---
id: upload-bypass
name: 上传校验与落点
when: 存在上传端点、图片/文件校验、multipart 表单或“上传后处理”流程时
category: 漏洞扫描
stages: [vuln_analysis, exploit, final]
version: 1.0.0
source: hack-skills/upload-insecure-files + jiker666/file-upload-test (MIT)
license: MIT
---

## 快速路径
1. **先定落点**：上传成功后文件到底在哪（回显路径、报错路径、存在性 oracle、目录列表）。
2. **再定校验**：只校验扩展名？内容？文件名？大小？逐项做单变量对照。
3. **最后找消费点**：落点是否被 include、定时搬运、静态 alias、session/日志、模板引用。没有消费点就不是 RCE。

## 检查表
- [ ] 扩展名：大小写、结尾点、双扩展名、`%00`、`filename*`、双 `filename` 取哪个
- [ ] 内容：魔术字节、`getimagesize`、二次渲染、Content-Type
- [ ] 文件名：`basename` 之前是否先把 `\` 归一成 `/`；目录字段是否可改落点
- [ ] 竞态：同名 `.jpg`/`.php` 并发，校验名与落盘名是否可能不同源
- [ ] 消费点：`?inc=`、定时任务、`/tmp` 是否可 Web 读、日志/session 是否可写

## 反例（必须验证，不要直接下结论）
- `vendor` 不存在 **不等于** 不是 CodeIgniter；手工部署只有 `system/` + `app/`，用 oracle 查 `system/bootstrap.php`。
- 回显路径不等于真实落盘路径；先证明 `file_exists` 再谈写入。
- 落点固定 `/tmp` 且无消费点时，继续堆 20 种文件名变体是无效投入。

## 验证与停止
- 每个结论至少一条请求/命令证据；扩展名拦截要用“同样内容、不同名字”做差分。
- 连续 3 类写入原语（改名、改目录、竞态/解析差异）都失败 → 停止并出“不可落盘”结论，保留证据。
