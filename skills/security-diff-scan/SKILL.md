---
name: dsh-security-diff-scan
description: dsh-security diff 扫描入口：对 PR/commit/branch diff 或工作区变更做安全审计（只审变更文件）。触发词：diff scan、PR 扫描、commit 扫描、变更扫描、代码审查。当用户要求对一次代码变更做安全审查时使用。
whenToUse: 当用户要求对 PR/commit/分支差异/工作区变更做安全审计时使用；用原生 workflow 工具执行插件内 workflow/diff.js。
---

# dsh-security diff 扫描入口

你是 dsh-security 的 **diff 扫描入口 skill**。按用户意图，用 **DSH 原生 `workflow` 工具**执行 `workflow/diff.js`。

## 运行方式

先用 `read` 读取 `workflow/diff.js` 全文，再用原生 `workflow` 工具执行，`meta` 给一个 kebab-case 名字（如 `dsh-security-diff`），`args`：

```json
{
  "repo": "<待审计 Git 仓库绝对路径>",
  "skillDir": "<插件 skills 目录绝对路径>",
  "outputDir": "<产物目录绝对路径>",
  "stateDir": "<JSONL workbench 目录绝对路径>",
  "baseRef": "main",
  "headRef": "HEAD"
}
```

- `baseRef`/`headRef` 都给时审该区间；否则审工作区未提交变更。
- 只审变更文件，report-only，不改源码。
