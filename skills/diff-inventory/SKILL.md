---
name: dsh-security-diff-inventory
description: diff 扫描首阶段：用 git diff 枚举变更文件并返回结构化 scope/coverage 数据，不直接写盘。触发词：diff scope、变更文件、PR 变更、工作区变更。作为 dsh-security diff 流水线的首阶段被 workflow 调用。
whenToUse: 当需要确定一次 PR/commit/工作区变更涉及哪些文件、把后续发现限定在变更范围内时使用。
---

# Diff-inventory（变更文件盘点）

你是 diff 流水线的**首阶段**。目标：确定本次变更的文件范围，并返回覆盖清单数据。你**不写任何文件**；编排脚本会据此确定性生成 `diff-scope.json` 与 `coverage.json`。

## 输入

- `repo`：待审计目录（Git 仓库）绝对路径。
- `baseRef` / `headRef`：可选；给了两者则枚举 `baseRef..headRef` 的变更；否则枚举工作区未提交变更。

## 过程

1. 在 `repo` 目录下用 shell 执行：
   - 有 `baseRef`/`headRef`：`git diff --name-only <baseRef>..<headRef>`
   - 否则：`git status --porcelain` 或 `git diff --name-only`
2. 只保留源代码文件（排除 lockfile、生成物、二进制、删除的文件）。
3. 对每个变更文件用 `pwsh Get-FileHash -Algorithm SHA256` 计算 SHA256，键为相对路径。
4. `totalFilesEstimate` 用变更文件数；`sinkCount` 可做轻量盘点后给出整数（拿不准给 0）。

## 输出

**只返回**单个 JSON 对象，不要写文件、不要返回其他文字：

```json
{
  "summary": "3 files changed",
  "files": ["src/index.js", "src/db.js"],
  "fileHashes": {"src/index.js": "SHA256_HEX", "src/db.js": "SHA256_HEX"},
  "totalFilesEstimate": 2,
  "sinkCount": 0
}
```

- `files` 必须是仓库内相对路径。
- `fileHashes` 键必须与 `files` 一致。
