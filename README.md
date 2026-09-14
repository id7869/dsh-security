# dsh-security

在 DSH 内等价重建 OpenAI codex-security 的「发现 → 验证 → 报告」安全审计能力，只借鉴其方法论、不移植其代码。

- 目标：把 codex-security 的安全审计方法论移植到 DeepSeek Harness（DSH），以原生 skills + workflow 形态等价重建，不依赖 OpenAI 运行时或外部服务。
- 形态：独立 DSH 插件（skills + workflow），不是独立 CLI/CI。
- 主能力线：发现 → 验证 → 报告（report-only 默认；可选 patch/verify-fix 修复复验）。
- 去重：砍掉向量预筛，候选来自 finding 身份指纹 + 本地 JSONL 历史，同模型两阶段评审（粗筛 SAME/DISTINCT → 深度确认 canonical+merged）。
- 模型/依赖：严格只用 DSH 当前模型 + 原生能力（无 embedding / OpenAI key / Python / Docker）。
- 持久化：仅本地 JSONL 文件（`state/` 下），无 SQLite、无 Mnemon。

## 特性

- **确定性契约**：`workflow/scan.js` 与 `workflow/diff.js` 内联纯函数计算 FNV-1a 64 指纹、SHA-256、SARIF、manifest 与 coverage snapshot，跨扫描结果稳定。
- **独立验证**：discover 只提出候选，validate 由全新 subagent 重新读源码独立得出结论，切断推理泄漏。
- **两阶段去重**：指纹 + 本地历史召回 → 粗筛 → 深度确认 → 传递闭包分组。
- **完整产物**：`findings.json`、`report.md`、SARIF 2.1.0（含 CWE/`security-severity`）、`coverage.json`、`scan-manifest.json`，deep 模式另有 `reductions.json`。
- **封存校验**：`seal` 阶段按编排脚本生成的预期 SHA256/字节数校验产物，再逐字写 manifest 与 JSONL。
- **能力面**：标准/深扫扫描、diff 扫描、修复复验、已有告警入库、工单跟踪、漏洞报告与加固建议。

## v4 优化记录

- 指纹：djb2(32bit, 含 title+line) → FNV-1a 64（`category|file|context`），行号/标题扰动不影响 id。
- 契约：新增确定性生成（`workflow/scan.js` 内纯函数）+ `seal` 阶段校验/哈希/`scan-manifest.json` + `coverage.json`。
- 落库：`findings.jsonl` 改为「同 id 覆盖、唯一 id 重写」，新增 `findings-index.jsonl`，历史召回有界（`historyLimit`）。
- 新增 diff 扫描（`workflow/diff.js` + `diff-inventory`/`security-diff-scan`）。
- 新增 deep reducer（`reductions.json`）、track（`track.js`）、writeup、propose-hardening、`security-policy.md`。
- 新增纯 JS SHA-256、`coverage.snapshotDigest` 与 SARIF CWE/`security-severity`/relationships，seal 阶段改为「按预期哈希校验」。
- 打包：修复 `package.json` `files`（`workflow`、`cordis.patch.yml`）。
- 防护：path 白名单 + 不可信数据只读约定。

## 目录结构

```
dsh-security/
  package.json             # dsh.bundle.patch → cordis.patch.yml
  cordis.patch.yml         # insert 自身到 profile 合成树
  lib/index.js             # bundled skill provider（注册阶段 skill + 入口 skill）
  skills/                  # 各阶段 DSH skill（SKILL.md）
    inventory/             # 代码盘点
    threat-model/          # 威胁建模
    discover/              # 假设 → 候选 finding
    validate/              # 独立复核 → disposition
    dedupe/                # 去重：指纹+历史召回 → 两阶段评审 → 传递闭包
    severity/              # rubric 重分级（可选）
    report/                # 逐字写入 findings.json / report.md / SARIF / coverage.json
    seal/                  # 校验产物 + 哈希 + scan-manifest.json + JSONL 落库
    diff-inventory/        # diff 扫描：变更文件盘点
    security-diff-scan/    # diff 扫描入口
    track/                 # 跟踪 finding 到工单/导出
    writeup/               # 漏洞报告撰写
    propose-hardening/     # 安全加固建议
    fix/                   # 修复（patch，可写源码）
    verify-fix/            # 修复复验（独立读码，fixed/not_fixed/regressed）
    triage-finding/        # 已有 finding 独立复核入库
    run/                   # 入口 skill（驱动 workflow 脚本）
  workflow/scan.js         # 扫描编排（原生 workflow 工具执行）
  workflow/diff.js         # diff 扫描编排
  workflow/fix.js         # 修复编排（patch → verify-fix）
  workflow/triage.js       # 已有 finding 入库编排
  workflow/track.js        # 跟踪编排（issue 创建 / export-track）
  schema/finding.schema.json
  schema/coverage.schema.json
  rubric/severity-policy.md
  rubric/security-policy.md
  report/report.template.md
  examples/fixture/        # 合成测试靶（含故意埋入的漏洞，仅供自测）
  state/                   # 本地 JSONL workbench（运行时生成）
```

## 安装（本地 link，当前已装于 web profile）

```powershell
dsh plugin --profile web add "C:\dsh-workspace\branch1\dsh-security"
```

- 安装后需重启对应 profile（`dsh --profile web`）使 bundled skill provider 生效。
- 本插件 `lib/index.js` 零静态 peer 依赖（`BUNDLED_SKILL_RANK` 硬编码为 600，不 import `@deepseek-ai/dsh-skill`），link 安装无需在插件目录建 node_modules 软链。

## 使用方式

### 方式一：自然语言（推荐）

在会话中直接说「扫描这个仓库」「做一次安全审计」「修复这个漏洞」「把这个告警入库」，入口 skill `dsh-security-run` 会自动触发，并驱动 `workflow/scan.js` / `fix.js` / `triage.js` 执行。

### 方式二：手动执行 workflow 脚本

在 DSH 会话中，用原生 `workflow` 工具执行插件内脚本，并传入 `args`。

#### 扫描（`workflow/scan.js`）

```json
{
  "repo": "C:/dsh-workspace/branch1/dsh-security/examples/fixture",
  "skillDir": "C:/dsh-workspace/branch1/dsh-security/skills",
  "outputDir": "C:/dsh-workspace/branch1/dsh-security/examples/run-demo",
  "stateDir": "C:/dsh-workspace/branch1/dsh-security/state",
  "mode": "standard",
  "maxDiscoveryRuns": 5,
  "stopAfterNoNew": 2,
  "classify": false
}
```

`args` 字段：

| 字段 | 默认 | 说明 |
|---|---|---|
| `repo` | 必填 | 待审计目录绝对路径（工作区内） |
| `skillDir` | 必填 | 各阶段 SKILL.md 所在目录绝对路径 |
| `outputDir` | 必填 | 产物目录（独立目录） |
| `stateDir` | 必填 | 本地 JSONL workbench 目录 |
| `mode` | `standard` | `standard` 单轮发现；`deep` 多 pass 深扫 |
| `maxDiscoveryRuns` | 5 | 深扫最大发现轮数 |
| `stopAfterNoNew` | 2 | 连续 N 轮无新 reportable 根因即停止 |
| `classify` | false | 是否追加 rubric 严重度重分级 |

#### 修复（`workflow/fix.js`）

```json
{
  "repo": "C:/dsh-workspace/branch1/dsh-security/examples/fixture",
  "skillDir": "C:/dsh-workspace/branch1/dsh-security/skills",
  "outputDir": "C:/dsh-workspace/branch1/dsh-security/examples/run-fix",
  "stateDir": "C:/dsh-workspace/branch1/dsh-security/state",
  "verify": true,
  "findings": [{ "title": "SQL injection in POST /login handler", "location": {"file": "src/index.js", "line": 17}, "category": "SQL injection", "severity": "high", "remediation": "改用参数化查询" }]
}
```

流程：fix（最小修复，改源码）→ verify-fix（独立读码复验 `fixed/not_fixed/regressed`）→ 追加 `stateDir/fixes.jsonl`。

#### 已有 finding 入库（`workflow/triage.js`）

```json
{
  "repo": "C:/dsh-workspace/branch1/dsh-security/examples/fixture",
  "skillDir": "C:/dsh-workspace/branch1/dsh-security/skills",
  "outputDir": "C:/dsh-workspace/branch1/dsh-security/examples/run-triage",
  "stateDir": "C:/dsh-workspace/branch1/dsh-security/state",
  "findings": [{ "title": "Possible XSS in search", "location": {"file": "src/index.js"}, "category": "XSS" }]
}
```

流程：外部 finding 独立复核 → reportable 项追加进 `stateDir/findings.jsonl`。

## 产物

- `outputDir/inventory.json`、`threat-model.md`、`candidates.json`
- `outputDir/findings.json`、`outputDir/report.md`、`outputDir/exports/results.sarif`、`outputDir/coverage.json`
- `outputDir/scan-manifest.json`（seal 阶段写入）、`outputDir/reductions.json`（deep 模式）
- diff 扫描另有 `outputDir/diff-scope.json`
- `stateDir/findings.jsonl`（reportable finding，跨扫描去重历史）
- `stateDir/findings-index.jsonl`（finding 索引，历史召回用）
- `stateDir/scans.jsonl`（每次扫描汇总）
- `stateDir/dedupe-groups.jsonl`（确认的去重组）
- `stateDir/classification.jsonl`（`classify=true` 时）
- `stateDir/fixes.jsonl`（fix 流程时）

## 流水线

```
inventory → threat-model → [ discover → validate ]×(深扫多轮，按指纹去新)
  → dedupe(指纹+历史召回 → 粗筛 → 深度确认 → 传递闭包)
  → report-write(逐字写盘) → seal(哈希校验 + manifest + JSONL 入库)
  → severity(可选)
```

- **validate 独立性**：每个候选 finding 由一个全新 subagent 独立复核，只接收该 finding 的原始内容，不接收 discover 阶段的推理；重新读代码、独立得出 `disposition`（`reportable`/`suppressed`/`not_applicable`/`deferred`）。
- **指纹**：编排脚本用纯 JS 确定性哈希（FNV-1a 64）对 `category + file + context` 计算，跨扫描稳定；`context`/`evidence` 缺失时用 `wfp_` 弱指纹标记。
- **去重两阶段**：候选对来自「精确指纹匹配」或「类别相同 + 文件相同」；阶段 1 粗筛只判 SAME/DISTINCT 且不给理由；阶段 2 深度确认只收到两条原始 finding（不见粗筛理由，保证独立性），产出 canonicalFindingId + mergedFinding；确认 SAME 的边做传递闭包分组。
- **严重度**：按 `rubric/severity-policy.md` 定级 `critical/high/medium/low`。

## 环境注意事项（重要）

- **不要在本机 DSH 0.1.2-rc.1 上安装 `@dsh-external/workflow`（dsh_workflow）**：它与本机 Session API 不兼容（`agent.session.events is not iterable`），跑 workflow 会崩 host。本插件不依赖它，走原生 `workflow` 工具。
- 扫描目标 `repo` 必须在当前会话工作区内；工作区外需更宽沙箱/审批。
- 编排脚本自身无文件系统访问：所有读写由各阶段 subagent 用 read/write 完成，脚本只协调与传文本。
- 默认 report-only；只有 `fix.js` 会改源码。

## 后续

- 已完成：v0 骨架 + v1 只读核心闭环 + v2 深扫/去重/重分级 + v3 patch/verify-fix 与 triage 入库 + v4 确定性契约与 seal 校验。
- 能力线已对齐 codex-security 主能力线（发现 → 验证 → 报告，可选修复复验）；`scan.js`/`diff.js` 的产物与哈希均由脚本确定性生成，`seal` 只做校验。
- 具名 workflow（capsule）形态已实现并校验，但依赖 `@dsh-external/workflow`，需等 DSH 升级 ≥0.1.3-alpha.1 或该插件修复后才能启用。



