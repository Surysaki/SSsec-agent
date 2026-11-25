---
id: stego-pcap
name: 隐写与流量分析
when: 给出图片/音频/压缩包/pcap，怀疑藏有数据时
category: 逆向分析
stages: [reverse, final]
version: 1.0.0
source: hack-skills/steganography-techniques + traffic-analysis-pcap (MIT)
license: MIT
---

## 快速路径
1. 图片：EXIF、附加数据（binwalk/foremost）、LSB（PNG/BMP）。
2. 音频：频谱、波形、LSB。
3. 流量：HTTP 对象导出、DNS 隧道、TCP 流重组。

## 检查表
- [ ] 文件尾是否有附加数据
- [ ] EXIF/注释/缩略图
- [ ] PNG/BMP LSB（JPEG 有损，不可靠）
- [ ] pcap 中的上传/下载/DNS 查询

## 反例
- JPEG 的 LSB 通常不可靠，优先 EXIF/附加数据。
- 流量里可能有多条流，别只看第一条。

## 验证与停止
- 提取到可读文本/flag 即停止。
- 三类载体都无发现 → 记录并转其他方向。
