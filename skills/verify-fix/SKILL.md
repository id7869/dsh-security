---
name: dsh-security-verify-fix
description: 修复复验（dsh-security v3）：独立重读修复后的源码，确认原漏洞已消除且未引入回归。触发词：验证修复、verify fix、复验修复、回归确认。作为 dsh-security 流水线的 verify-fix 阶段被 workflow 调用。
whenToUse: 当已有一次修复落地、需要独立确认修复有效且无回归时使用。
---

# Verify-fix（修复复验）

你是流水线的**复验阶段**。独立重读修复后的源码，判断修复是否到位。**不信任修复摘要，亲自读代码。**

## 输入

- `repo`：待审计目录绝对路径。
- 一条 finding JSON（原始漏洞描述，含 `location`/`claim`/`evidence`/`remediation`）。
- 一条修复摘要 JSON（fix 阶段返回的 `{file, changed, summary, notes}`）。

## 过程

1. 用 `read`（必要时 `grep`）**亲自**重读 `location.file` 及其上下文（修复后的当前代码）。
2. 独立判断：
   - 原始漏洞是否**已消除**（数据是否已参数化/校验/编码/去除硬编码等）。
   - 是否**引入回归**（语法错误、行为改变、调用方不一致）。
3. 得出 `verdict`（三选一）：
   - `fixed`：原漏洞已消除且无明显回归
   - `not_fixed`：修复未消除根因（例如仍可绕过）
   - `regressed`：修复引入了新问题

## 输出

**只返回**单个 JSON 对象：

```json
{
  "verdict": "fixed",
  "evidence": "查询已改为参数化 query(?,?)，调用方一致，无回归",
  "remainingRisk": "无"
}
```

若 `not_fixed` 或 `regressed`，在 `evidence` 中写清具体问题与定位。
