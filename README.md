# dsh-security

在 DeepSeek Harness (DSH) 内等价重建 OpenAI codex-security 的「发现 → 验证 → 报告」安全审计能力。下表用于说明「等价」的边界：**方法论与审计语义等价，运行时与工程形态按 DSH 原生能力重建**。

## codex-security vs dsh-security 对比

| 维度 | codex-security (OpenAI) | dsh-security (本仓库) | 等价性 |
|---|---|---|---|
| 运行宿主 | OpenAI Codex（Codex plugin + MCP server） | DeepSeek Harness（DSH plugin + skills + workflow） | 宿主不同，能力对齐 |
| 形态 | `.codex-plugin/plugin.json` + MCP (`mcp/server.mjs`) + Python workbench | `package.json` (`dsh.bundle.patch`) + `lib/index.js` + `workflow/*.js` | 等价重建（工程形态替换） |
| 编程语言 | TypeScript/JS 编排 + Python 脚本（workbench/finalize） | 纯 JS 编排（脚本内联确定性纯函数，无 Python/Docker） | 等价（约束更少） |
| 模型/依赖 | OpenAI 模型 + 可选 embedding + SQLite/Mnemon 持久化 | 仅 DSH 当前模型 + 原生工具，本地 JSONL 持久化 | 语义等价，依赖最小化 |
| skill 数量 | 15 个（security-scan、finding-discovery、validation、attack-path-analysis、security-diff-scan、deep-security-scan、threat-model、triage-finding、track-findings、fix-finding、verify-fix、vulnerability-writeup、propose-security-hardening、assess-patch-risk、define-security-policy） | 17 个（inventory、threat-model、discover、validate、dedupe、severity、report、seal、diff-inventory、security-diff-scan、track、writeup、propose-hardening、fix、verify-fix、triage-finding、run） | 能力面超集（对 Codex 的 phase-skill 做了合并/拆分） |
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
| 指纹 | `codex-security/v1:sha256:<64hex>`（target+rule+anchor+instance 派生） | FNV-1a 64 → `fp_<16hex>`/`wfp_<16hex>`（category+file+context 派生） | 语义等价（算法/长度不同） |
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

## 等价结论

- **方法论等价**：发现 → 独立验证 → 攻击路径/严重度 → 报告 → 修复复验/入库/跟踪的审计语义一一对齐；finding 的 identity、fingerprint、snapshot、manifest、coverage、SARIF 核心概念均已重建。
- **工程等价重建**：把 MCP server + Python workbench + SQLite 持久化替换为 DSH 原生 `workflow` 编排 + 内联纯函数确定性契约 + JSONL 持久化，不依赖 OpenAI/向量/Python/Docker。
- **已对齐**：标准扫描、diff 扫描、深扫、威胁建模、验证、修复复验、入库、跟踪、writeup、加固建议、SARIF 与封存契约。
- **已知差异**：`assess-patch-risk` 未实现；`define-security-policy` 用静态 `security-policy.md` 替代；无 CSV 导出；fingerprint/findingId 算法与 Codex 不同（语义一致、不可互认）；动态 PoC 验证为可选项。
