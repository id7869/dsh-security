---
name: dsh-security-severity
description: 严重度 rubric 重分级（dsh-security v2）：按策略文件独立重估 reportable finding 的严重度，落 classification.jsonl，不修改原 finding 的 severity。触发词：严重度分级、severity 重评、rubric 定级、classify severity、按策略重评。作为 dsh-security 流水线的可选重分级阶段被 workflow 调用。
whenToUse: 当需要按自定义策略对已有 reportable finding 重新定级、且保留原始 severity 不变时使用。
---

# Severity（rubric 重分级）

按策略文件对 `reportable` finding 做**独立重分级**，结果写 checkpoint，**不改动原 finding 的 `severity` 字段**。

## 输入

- `reportable`：待重分级的 finding JSON 数组（workflow 传入）。
- `rubric`：策略文件路径（如 `rubric/severity-policy.md`），用 `read` 读取。
- `stateDir`：追加 `classification.jsonl` 的目录。

## 过程

1. 读策略文件，理解四档定义与「可达性 × 影响」的定级规则。
2. 对每条 finding 独立重估，得出 `classifiedSeverity`（critical/high/medium/low）。
3. 记录 `rationale`：一句话说明重分级依据（可达性、前置条件、影响范围），若与原始 severity 相同也说明为何维持。

## 输出

追加 `stateDir/classification.jsonl`，每条 finding 一行：

```json
{"findingId":"csf_...","originalSeverity":"high","classifiedSeverity":"medium","rationale":"该密钥从未被引用且为合成示例，可达性不足","createdAt":"<ISO-8601>"}
```

返回一段摘要：重分级条数、发生升降级的条数。
