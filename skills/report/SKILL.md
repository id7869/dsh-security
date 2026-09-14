---
name: dsh-security-report
description: 安全审计报告写入阶段（dsh-security v4）：接收编排脚本确定性生成的文件内容，逐字写入磁盘，不得增删改或自行总结。触发词：报告写入、写入报告、report write。作为 dsh-security 流水线的报告阶段被 workflow 调用。
whenToUse: 当编排脚本已将 findings/report/SARIF 等产物内容字符串计算完毕、只需逐字落盘时使用。
---

# Report（报告写入）

你是流水线的**报告写入阶段**。编排脚本已为你生成好各产物的精确内容。你的任务：**逐字写入磁盘，不增、不删、不改任何字符**。

## 输入

- `outputDir`：产物目录。
- 编排脚本通过 prompt 传入待写文件的完整内容字符串。标准扫描通常为 `findings.json`、`report.md`、`exports/results.sarif`、`coverage.json`（deep 模式还有 `reductions.json`）。

## 过程

1. 确保 `outputDir/exports/` 目录存在（不存在则创建）。
2. 分别将编排脚本传入的每个文件内容**逐字**写入对应路径。不要重排 JSON、不要格式化、不要修改任何字符、不要自行总结或补充信息。
3. 写入后，`read` 回读每个文件的前 3 行，确认内容与收到的字符串一致（开头匹配即可）。

## 输出

返回一个 JSON 数组，列出每个文件的绝对路径与写入结果，例如：

```json
[
  {"path": "/abs/path/findings.json", "written": true, "bytes": 1234},
  {"path": "/abs/path/report.md", "written": true, "bytes": 567},
  {"path": "/abs/path/exports/results.sarif", "written": true, "bytes": 890},
  {"path": "/abs/path/coverage.json", "written": true, "bytes": 321}
]
```

不要返回文件内容本身，只返回写入状态。
