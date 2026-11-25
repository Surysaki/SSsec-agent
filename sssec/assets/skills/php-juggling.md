---
id: php-juggling
name: PHP 弱类型
when: 目标是 PHP，出现比较、哈希、数组参数、intval 或登录校验时
category: 漏洞扫描
stages: [vuln_analysis, exploit, final]
version: 1.0.0
source: hack-skills/type-juggling (MIT)
license: MIT
---

## 快速路径
1. **找比较点**：登录、token、权限、金额、`in_array`、`strcmp`、`==`。
2. **判类型**：参数传数组（`?a[]=1`）是否触发 warning 或绕过；传 `0`、`0e...`、`true` 看差异。
3. **再谈利用**：弱比较/哈希魔法/数组绕过能过校验时，直接构造最小请求验证。

## 检查表
- [ ] `==` 与 `===`：`0 == "a"`、`"0e123" == "0e456"`、`"1" == "01"`
- [ ] 哈希：`md5(x) == md5(y)`、`sha1` 魔法值、数组传入 `md5()` 返回 null
- [ ] `strcmp($a,$b)` 传数组返回 null（旧 PHP）
- [ ] `intval`/`(int)` 截断、`%00`、超长数字
- [ ] `json_decode`/`unserialize` 的类型与对象注入边界

## 反例
- PHP 8 已修正部分 `0 == "a"` 行为；先确认版本（`X-Powered-By`、报错页），不要拿 PHP 5 的结论套 PHP 8。
- 数组绕过在 `declare(strict_types=1)` 或类型声明下可能直接 500，不是成功。
- 弱比较命中不等于能登录：还要看 session/JWT 是否在后续校验。

## 验证与停止
- 用同一接口做“数组 vs 字符串”的差分，响应不同才算命中。
- 三类比较点都无差异 → 记录“无弱类型面”，转注入/上传面。
