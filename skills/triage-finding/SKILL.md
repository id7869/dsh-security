---
name: dsh-security-triage-finding
description: 已有 finding 本地入库（dsh-security v3）：对一条外部传入的 finding 独立复核，得出 disposition 与 severity，供入库到 findings.jsonl。触发词：triage、finding 入库、告警复核、已有漏洞入库、告警分级。作为 dsh-security 流水线的 triage 阶段被 workflow 调用。
whenToUse: 当有一条来自外部（其他扫描器、工单、人工报告）的 finding 需要复核并纳入本地 workbench 时使用。
---

# Triage-finding（已有 finding 复核入库）

你是流水线的**分诊阶段**。收到一条**外部传入**的 finding，独立复核后给出结论，供入库。

## 输入

- `repo`：待审计目录绝对路径。
- 一条 finding JSON（外部来源，字段可能只有 `title`/`location`/`category` 或不完整）。

## 过程

1. 用 `read` 精读 `location.file`（若给了位置），找不到定位就按 `title` 在 `repo` 内 `grep` 搜索对应代码。
2. 独立复核，得出 `disposition`（四选一）：`reportable` / `suppressed` / `not_applicable` / `deferred`。
3. 定级 `severity`（critical/high/medium/low，参考 rubric 思路：可达性 × 影响）。
4. 补全缺失字段：`category`、`cwe`、`claim`、`evidence`、`remediation`（证据不足则写"未找到对应代码"）。

## 输出

**只返回**单个 JSON 对象，字段含：

```json
{
  "title": "...",
  "location": {"file": "...", "line": 42, "symbol": "..."},
  "category": "...",
  "cwe": "CWE-...",
  "severity": "high",
  "disposition": "reportable",
  "confidence": "high",
  "claim": "...",
  "evidence": "...",
  "remediation": "..."
}
```

若完全找不到对应代码，`disposition` 写 `deferred`，`location.file` 保持原样，`evidence` 说明"未在仓库定位到该问题"。
