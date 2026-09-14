---
name: dsh-security-validate
description: 安全审计第四步「独立验证」：对单条候选 finding 重新读源码、独立得出 disposition（reportable/suppressed/not_applicable/deferred）与定级。触发词：验证 finding、disposition、误报确认、漏洞复核、独立复核。作为 dsh-security 流水线的第四阶段被 workflow 调用。
whenToUse: 当有一条候选 finding 需要被独立复核、判断是否真为可报告漏洞时使用。
---

# Validate（独立验证）

你是流水线**第四阶段**。你收到**单条**候选 finding，必须**独立**重新读源码做出结论，不得把候选里的 claim/severityGuess 当作既定事实。

## 输入

- `repo`：待审计目录绝对路径。
- 一条候选 finding 的 JSON（由 workflow 传入，字段含 `title`/`location`/`category`/`cwe`/`claim`/`evidence`/`context`/`severityGuess`）。

## 过程

1. 用 `read`（必要时 `grep`）**亲自**定位 `location.file` 对应代码及其调用链。
2. 独立判断：
   - 数据是否**确实**由不可信源流入 sink？
   - 中间是否存在校验/参数化/编码/授权把风险消除？
   - 是否可实际利用（可达性）、前置条件是什么？
3. 若存在 `rubric/security-policy.md`，先 `read` 读取；其中「风险接受 (accepted-risk)」列出的问题应判为 `suppressed`，「不审范围」内的候选应判为 `not_applicable`。
4. 得出 `disposition`（四选一）：
   - `reportable`：确认是真实、可报告的问题
   - `suppressed`：误报，或代码已明确抑制（如已参数化、已鉴权）
   - `not_applicable`：条件不成立，不可利用
   - `deferred`：证据不足，无法判定，需深查
4. 按 `severity-policy` 思路定级 `critical/high/medium/low`（只对 reportable 有意义；其余档位可仍给严重度但以 disposition 为准）。
5. 给 `confidence`（low/medium/high）与一段简洁的 `evidence`（你亲自确认的代码依据）与 `remediation`。

## 输出

返回**单个 JSON 对象**（不要多余文字），结构：

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
  "evidence": "亲自确认的代码片段",
  "context": "规范化代码片段（原样透传 candidate.context，若缺失则用你确认的关键代码片段规范化后填充）",
  "remediation": "改用参数化查询"
}
```

若该 candidate 缺失关键字段导致无法验证，`disposition` 写 `deferred` 并在 `evidence` 说明原因。\n\n注意：`context` 用于去重指纹，必须与 candidate 的 `context` 一致或等价（规范化后相同），不要改写语义。


