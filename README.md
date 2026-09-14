# dsh-security

在 DeepSeek Harness (DSH) 内等价重建 OpenAI codex-security 的「发现 → 验证 → 报告」安全审计能力，只借鉴其方法论、不移植其代码。

- 形态：独立 DSH 插件（skills + workflow），不是独立 CLI/CI。
- 主能力线：发现 → 验证 → 报告（report-only 默认；可选 patch/verify-fix 修复复验）。
- 去重：砍掉向量预筛，候选来自 finding 身份指纹 + 本地 JSONL 历史，同模型两阶段评审（粗筛 SAME/DISTINCT → 深度确认 canonical+merged）。
- 模型/依赖：严格只用 DSH 当前模型 + 原生能力（无 embedding / OpenAI key / Python / Docker）。
- 持久化：仅本地 JSONL 文件（`state/` 下），无 SQLite、无 Mnemon。

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

## 安装

### 前提

- **DSH ≥ 0.1.5-rc.1**（`npx --no-install @deepseek-ai/dsh --version` 确认）。
- Node.js ≥ 22（DSH 运行时自带，也可用系统 node）。
- 可选的 pnpm（DSH profile 通常用 pnpm 管理依赖；若用 `dsh plugin add` 安装则不需单独配置包管理器）。
- 本插件**零静态 peer 依赖**：`lib/index.js` 只 import node 内建模块，`BUNDLED_SKILL_RANK` 硬编码为 600，不 import `@deepseek-ai/dsh-skill`，因此安装**无需**在插件目录建 `node_modules`。

### 安装方式 A：从 GitHub clone + 本地 link（推荐）

```powershell
# 1) clone 到本地
git clone https://github.com/id7869/dsh-security.git C:\gh-workspace\dsh-security

# 2) link 到 DSH profile（以 web 为例）
dsh plugin --profile web add "C:\gh-workspace\dsh-security"

# 3) 重新启动该 profile 使 bundled skill provider 生效
dsh --profile web
```

DSH 的 link 安装会在 `%USERPROFILE%\.dsh\profiles\web\node_modules\dsh-security` 下创建 NTFS Junction 指向实际目录。

### 安装方式 B：手动添加 link（无需 dsh CLI）

如果 `dsh plugin add` 不可用，直接编辑 profile 的 `package.json`：

1. 在 `%USERPROFILE%\.dsh\profiles\web\package.json` 的 `dependencies` 中增加：
   ```json
   "dsh-security": "link:C:/path/to/dsh-security"
   ```
2. 在同一个文件的 `dsh.profile.bundles` 数组中添加 `"dsh-security"`（位置建议放在最后）。
3. 确保 `%USERPROFILE%\.dsh\profiles\web\cordis.yml` 内容为 `[]`（空列表，profile 默认）。
4. 确保 `%USERPROFILE%\.dsh\profiles\web\cordis.patch.yml` 文件存在（可创建空文件，或保留已有 patch）。
5. 确保 `%USERPROFILE%\.dsh\profiles\web\pnpm-workspace.yaml` 存在，内容包含 `packages:\n  - .`。
6. 在 profile 目录下运行 `npm install` 或 `pnpm install` 以解析 `link:` 协议并创建 `node_modules\dsh-security` → 实际目录的 junction。
7. 重新启动 DSH。

> **注意**：手动安装后必须重启对应的 DSH profile 才能使新的 bundled skill provider 生效。

### 验证安装

启动 DSH 并检查 `dsh-security` skill 是否在侧边栏可见。在会话中说「列出 dsh-security 的可用 skill」，入口 skill `dsh-security-run` 应出现在列表中。

### 卸载

```powershell
dsh plugin --profile web rm dsh-security
```

重启 DSH 生效。手动安装的需在 `package.json` 中移除 dependency 和 bundle 引用，再删除 `node_modules\dsh-security` 目录（可能为 Junction），删除后运行一次 `pnpm install` 清理锁文件。

## 使用方式

### 方式一：自然语言（推荐）

在会话中直接说「扫描这个仓库」「做一次安全审计」「修复这个漏洞」「把这个告警入库」，入口 skill `dsh-security-run` 会自动触发，并驱动 `workflow/scan.js` / `fix.js` / `triage.js` / `diff.js` 执行。

### 方式二：手动执行 workflow 脚本

在 DSH 会话中，用原生 `workflow` 工具执行插件内脚本，并传入 `args`。

#### 扫描（`workflow/scan.js`）

```json
{
  "repo": "C:/path/to/your/repo",
  "skillDir": "C:/path/to/dsh-security/skills",
  "outputDir": "C:/path/to/output",
  "stateDir": "C:/path/to/dsh-security/state",
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
| `historyLimit` | 500 | 历史召回上限（去重阶段） |
| `classify` | false | 是否追加 rubric 严重度重分级 |

#### diff 扫描（`workflow/diff.js`）

```json
{
  "repo": "C:/path/to/your/repo",
  "skillDir": "C:/path/to/dsh-security/skills",
  "outputDir": "C:/path/to/output",
  "stateDir": "C:/path/to/dsh-security/state",
  "baseRef": "main",
  "headRef": "HEAD"
}
```

- `baseRef`/`headRef` 都给时审该区间；否则审工作区未提交变更。
- 只审变更文件，report-only，不改源码。

#### 修复（`workflow/fix.js`）

```json
{
  "repo": "C:/path/to/your/repo",
  "skillDir": "C:/path/to/dsh-security/skills",
  "outputDir": "C:/path/to/output",
  "stateDir": "C:/path/to/dsh-security/state",
  "verify": true,
  "findings": [{ "title": "SQL injection in POST /login handler", "location": {"file": "src/index.js", "line": 17}, "category": "SQL injection", "severity": "high", "remediation": "改用参数化查询" }]
}
```

流程：fix（最小修复，改源码）→ verify-fix（独立读码复验 `fixed/not_fixed/regressed`）→ 追加 `stateDir/fixes.jsonl`。

#### 已有 finding 入库（`workflow/triage.js`）

```json
{
  "repo": "C:/path/to/your/repo",
  "skillDir": "C:/path/to/dsh-security/skills",
  "outputDir": "C:/path/to/output",
  "stateDir": "C:/path/to/dsh-security/state",
  "findings": [{ "title": "Possible XSS in search", "location": {"file": "src/index.js"}, "category": "XSS" }]
}
```

流程：外部 finding 独立复核 → reportable 项追加进 `stateDir/findings.jsonl`。

#### 跟踪（`workflow/track.js`）

```json
{
  "repo": "C:/path/to/your/repo",
  "skillDir": "C:/path/to/dsh-security/skills",
  "outputDir": "C:/path/to/output",
  "stateDir": "C:/path/to/dsh-security/state",
  "destination": "auto",
  "findings": [{ "id": "csf_1234567890abcdef", "title": "XSS" }]
}
```

- `destination`: `auto`（探针检测可用目标）、`github`、`linear`、`jira`、`export`。
- 无外部连接时降级为 `exports/track.json` 导出。

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
- `stateDir/tracked.jsonl`（track 流程时）

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

---

## codex-security vs dsh-security 等价对比

| 维度 | codex-security (OpenAI) | dsh-security (本仓库) | 等价性 |
|---|---|---|---|
| 运行宿主 | OpenAI Codex（Codex plugin + MCP server） | DeepSeek Harness（DSH plugin + skills + workflow） | 宿主不同，能力对齐 |
| 形态 | `.codex-plugin/plugin.json` + MCP (`mcp/server.mjs`) + Python workbench（脚本/持久化/SQLite） | `package.json` (`dsh.bundle.patch`) + `lib/index.js` + `workflow/*.js` 编排 + JSONL 持久化 | 等价重建（工程形态替换） |
| 编程语言 | TypeScript/JS 编排 + Python 脚本 | 纯 JS 脚本内联确定性纯函数（无 Python/Docker） | 等价（约束更少） |
| 模型/依赖 | OpenAI 模型 + 可选 embedding + SQLite/Mnemon 持久化 | DSH 当前模型 + 原生工具，本地 JSONL 持久化 | 语义等价，依赖最小化 |
| skill 数量 | 15 个：security-scan、finding-discovery、validation、attack-path-analysis、security-diff-scan、deep-security-scan、threat-model、triage-finding、track-findings、fix-finding、verify-fix、vulnerability-writeup、propose-security-hardening、assess-patch-risk、define-security-policy | 17 个：inventory、threat-model、discover、validate、dedupe、severity、report、seal、diff-inventory、security-diff-scan、track、writeup、propose-hardening、fix、verify-fix、triage-finding、run | 能力面超集（对 Codex 的 phase-skill 做了合并/拆分） |
| 主流程 | scan → discovery → validation → attack-path → report | inventory → threat-model → discover → validate → dedupe → report-write → seal | 语义等价 |
| 标准扫描 | `security-scan`（单遍全仓库审计） | `scan.js` `mode=standard` | 等价 |
| diff 扫描 | `security-diff-scan`（PR/commit/branch/working-tree） | `diff.js` + `diff-inventory`/`security-diff-scan` | 等价 |
| 深扫 | `deep-security-scan`（多 worker + reducer） | `scan.js` `mode=deep`（多 pass + 根因聚类） | 等价（reducer 简化为确定性聚类） |
| 威胁建模 | `threat-model` | `threat-model` | 等价 |
| 验证 | `validation`（动态 PoC 优先，静态兜底） | `validate`（独立重读源码，静态溯源） | 语义对齐（动态复现为可选项） |
| 攻击路径 | `attack-path-analysis`（source→sink + 严重度校准） | 并入 `validate`/`discover`（claim/evidence/context 溯源） | 语义对齐（未单列 phase skill） |
| 修复 | `fix-finding` + `verify-fix` | `fix` + `verify-fix` | 等价 |
| 已有告警入库 | `triage-finding`（ticket/GitHub REST intake） | `triage-finding`（外部 JSON 独立复核入库） | 等价（入参来源不同） |
| 跟踪 | `track-findings`（GitHub/Linear/Jira） | `track`（GitHub/Linear/Jira/export 探测降级） | 等价 |
| 报告撰写 | `vulnerability-writeup` | `writeup` | 等价 |
| 加固建议 | `propose-security-hardening` | `propose-hardening` | 等价 |
| 补丁风险评估 | `assess-patch-risk` | 未实现（由 fix/verify-fix 覆盖最小修复复验） | 能力缺口 |
| 安全策略定义 | `define-security-policy` | `rubric/security-policy.md`（静态策略文件，无交互生成） | 部分对齐 |
| 指纹 | `codex-security/v1:sha256:<64hex>`（target+rule+anchor+instance 派生） | FNV-1a 64 → `fp_<16hex>`/`wfp_<16hex>`（category+file+context 派生） | 语义等价（算法/长度不同、不可互认） |
| finding id | `csf_<24hex>` + `occ_<24hex>` | `csf_<16hex>`（无独立 occurrenceId） | 结构对齐，粒度略简 |
| 快照摘要 | `codex-security-snapshot/v1:sha256:<64hex>` | `dsh-security-snapshot/v1:sha256:<64hex>` | 等价（命名空间不同） |
| 覆盖清单 | `coverage.json`（include/exclude/surfaces/deferred） | `coverage.json`（scannedFiles/fileHashes/snapshotDigest） | 语义对齐（字段形态不同） |
| 封存 | `scan-manifest.json`（sealedAt + 每个 canonical artifact 的 sha256） | `scan-manifest.json`（status + 每个 artifact 的 bytes/sha256） | 等价 |
| SARIF | 生成下游投影（SARIF 2.1.0） | 脚本确定性生成 SARIF 2.1.0（含 CWE/security-severity/relationships） | 等价 |
| 结果文件 | `findings.json` + `report.md` + SARIF + CSV | `findings.json` + `report.md` + `exports/results.sarif` | 等价（无 CSV） |
| 深度归并 | workbench reducer + SQLite 检查点 | `reductions.json`（传递闭包 root-cause cluster） | 语义对齐（工程形态简化） |
| 历史去重 | 向量预筛 + 历史召回 | 指纹 + 本地 JSONL 历史 + 两阶段同模型评审 | 语义等价（无 embedding） |
| 运行时校验 | Python 脚本 + schema + MCP 工具 | `seal` 阶段按预期 sha256/bytes 校验 | 等价 |
| 测试 | 内置 schema/脚本 | `test/contract.test.mjs`（42 项）+ `test/workflow.smoke.test.mjs`（11 项） | 本仓库新增 |
| 授权 | Proprietary (OpenAI) | MIT | 开源 |
| 版本 | 0.1.24 | 0.1.0 | — |

### 等价结论

- **方法论等价**：发现 → 独立验证 → 攻击路径/严重度 → 报告 → 修复复验/入库/跟踪的审计语义一一对齐；finding 的 identity、fingerprint、snapshot、manifest、coverage、SARIF 核心概念均已重建。
- **工程等价重建**：把 MCP server + Python workbench + SQLite 持久化替换为 DSH 原生 `workflow` 编排 + 内联纯函数确定性契约 + JSONL 持久化，不依赖 OpenAI/向量/Python/Docker。
- **已对齐**：标准扫描、diff 扫描、深扫、威胁建模、验证、修复复验、入库、跟踪、writeup、加固建议、SARIF 与封存契约。
- **已知差异**：`assess-patch-risk` 未实现；`define-security-policy` 用静态 `security-policy.md` 替代；无 CSV 导出；fingerprint/findingId 算法与 Codex 不同（语义一致、不可互认）；动态 PoC 验证为可选项。
