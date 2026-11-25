---
id: cloud-storage
name: 对象存储暴露
when: 目标使用 OSS/S3/COS 等对象存储，或页面出现 bucket 域名时
category: 信息搜集
stages: [recon]
version: 1.0.0
source: SSsec 原创
license: MIT
---

## 快速路径
1. 从页面/JS/响应头提取 bucket 名与区域。
2. 尝试列表：`GET /?list-type=2`、`GET /?prefix=`。
3. 检查 ACL/策略：匿名读、目录列表、写入（只验证读）。

## 检查表
- [ ] 桶是否可匿名列目录
- [ ] 是否可匿名读已知对象
- [ ] 是否存在备份/源码/日志对象
- [ ] CORS 是否放开

## 反例
- 403 不代表桶不存在；可能只是禁止列表。
- 公开读不等于可写，不要尝试写入。

## 验证与停止
- 只读验证；不下载全量数据，只取证明所需的对象。
- 无匿名读/列目录 → 结束。
