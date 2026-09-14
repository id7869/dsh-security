---
name: dsh-security-discover
description: 安全审计第三步「漏洞发现」：基于盘点与威胁模型，产出候选 finding（假设→具体断言+证据）。触发词：漏洞发现、candidate finding、假设验证、审计假设。作为 dsh-security 流水线的第三阶段被 workflow 调用。
whenToUse: 当已有关盘点与威胁模型、需要生成结构化的候选安全发现供独立验证时使用。
---

# Discover（漏洞发现）

你是流水线**第三阶段**。把威胁假设转成**具体的、可独立验证的候选 finding**。

## 输入

- `repo`：待审计目录绝对路径。
- `outputDir`：产物目录，其中已有 `inventory.json` 与 `threat-model.md`。用 `read` 读取。

## 过程

对每条威胁假设，回到 `repo` 里精读相关源码，确认"假设是否真的对应一段可疑代码"。对每条成立的候选，记录：

- 精确定位（文件 + 行号 + 符号）
- 一句**断言 claim**：数据如何从 source 流到 sink、为何不安全
- **证据 evidence**：摘录关键代码片段（含变量名，证明输入确实未经处理流入 sink）
- 初步类别与严重度猜测（供 validate 参考，validate 会独立复核）

宁缺毋滥：只产出有代码依据的候选，不做泛泛而谈。若一条假设读了代码后不成立，就丢弃。

## 输出

1. 写入 `outputDir/candidates.json`，结构：

```json
{
  "candidates": [
    {
      "title": "Possible SQL injection in login handler",
      "location": {"file": "src/db.js", "line": 42, "symbol": "runQuery"},
      "category": "SQL injection",
      "cwe": "CWE-89",
      "claim": "未认证用户可控的 req.body.username 被字符串拼接进 SQL 查询",
      "evidence": "const q = `SELECT * FROM users WHERE name='${username}'`; db.query(q)",
      "context": "const q = `SELECT * FROM users WHERE name='${username}'`;",
      "severityGuess": "high"
    }
  ]
}
```

2. 返回 **`{"candidates":[...]}` 这一 JSON 对象本身**（不要返回其他文字，workflow 需要解析它来扇出验证）。

注意：`context` 是用于计算去重指纹的规范化代码片段（不含行号、去首尾空白）。
