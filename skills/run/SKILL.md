---
name: dsh-security-run
description: dsh-security 安全审计入口：运行 dsh-security 的扫描/修复/入库工作流。触发词：安全审计、扫描仓库、代码安全检查、漏洞扫描、security scan、run security audit、dsh-security。当用户要求对代码库做安全审计、扫描漏洞、修复漏洞或已有漏洞入库时使用。
whenToUse: 当用户要求安全审计/漏洞扫描/修复漏洞/finding 入库时使用；按意图用原生 workflow 工具执行插件内 workflow/scan.js、fix.js、triage.js。
---

# dsh-security 入口

你是 dsh-security 的**入口 skill**。按用户意图，用 **DSH 原生 `workflow` 工具**执行插件内的编排脚本（不是 `run_workflow` 具名 capsule，本机不依赖 @dsh-external/workflow）。

## 五个编排脚本（插件 `workflow/` 目录）

- `scan.js` — 扫描：inventory → threat-model → discover → validate(逐 finding 独立复核) → dedupe(指纹+历史两阶段) → report → severity(可选)
- `fix.js` — 修复：fix(最小修复) → verify-fix(独立复验) → fixes.jsonl
- `triage.js` — 入库：外部 finding 独立复核 → reportable 追加 findings.jsonl
- `diff.js` — diff 扫描：diff-inventory(变更文件) → discover → validate → report → seal，只审变更文件
- `track.js` — 跟踪：探针→去重→创建 GitHub/Linear/Jira issue 或导出 exports/track.json

## 运行方式

先用 `read` 读取插件 `workflow/<脚本>.js` 的完整内容，然后用原生 `workflow` 工具执行它，`meta` 给一个 kebab-case 名字（如 `dsh-security-scan`），`args` 按脚本要求传入。各脚本需要的 `args` 如下：

### scan（`workflow/scan.js`）

```json
{
  "repo": "<待审计目录绝对路径，工作区内>",
  "skillDir": "<插件 skills 目录绝对路径>",
  "outputDir": "<产物目录绝对路径>",
  "stateDir": "<JSONL workbench 目录绝对路径>",
  "mode": "standard",
  "maxDiscoveryRuns": 5,
  "stopAfterNoNew": 2,
  "classify": false
}
```

- `mode`: `standard`（单轮发现）或 `deep`（多 pass 深扫）。
- `classify: true` 时追加 rubric 严重度重分级。

### fix（`workflow/fix.js`）

```json
{
  "repo": "<待审计目录绝对路径>",
  "skillDir": "<插件 skills 目录绝对路径>",
  "outputDir": "<产物目录绝对路径>",
  "stateDir": "<JSONL workbench 目录绝对路径>",
  "verify": true,
  "findings": [{"title":"...","location":{"file":"..."},"category":"...","severity":"high","remediation":"..."}]
}
```

### diff（`workflow/diff.js`）

```json
{
  "repo": "<Git 仓库绝对路径>",
  "skillDir": "<插件 skills 目录绝对路径>",
  "outputDir": "<产物目录绝对路径>",
  "stateDir": "<JSONL workbench 目录绝对路径>",
  "baseRef": "main",
  "headRef": "HEAD"
}
```

- `baseRef`/`headRef` 都给时审该区间；否则审工作区未提交变更。

### triage（`workflow/triage.js`）

```json
{
  "repo": "<待审计目录绝对路径>",
  "skillDir": "<插件 skills 目录绝对路径>",
  "outputDir": "<产物目录绝对路径>",
  "stateDir": "<JSONL workbench 目录绝对路径>",
  "findings": [{"title":"Possible XSS","location":{"file":"src/index.js"},"category":"XSS"}]
}
```

## 注意

- `repo` 必须在当前会话工作区内（工作区外需更宽沙箱）。
- `skillDir` 指向插件安装目录下的 `skills/`（各阶段 SKILL.md 所在目录）；若插件 link 安装到工作区，即工作区里的 `dsh-security/skills`。
- 编排脚本自身无文件系统访问：所有读写由各阶段 subagent 用 read/write 完成，脚本只协调与传文本。
- 默认 report-only；只有 `fix.js` 会改源码。
- 产物与持久化只用本地 JSONL（stateDir 下 findings/scans/dedupe-groups/classification/fixes .jsonl），无 embedding/SQLite/Mnemon。
- 去重候选只来自身份指纹 + JSONL 历史，同模型两阶段（粗筛 SAME/DISTINCT → 深度确认），砍掉向量预筛。


