---
name: dsh-security-threat-model
description: 安全审计第二步「威胁建模」：基于盘点结果，梳理资产、信任边界、数据流与威胁假设。触发词：威胁建模、threat model、信任边界、数据流、攻击面分析。作为 dsh-security 流水线的第二阶段被 workflow 调用。
whenToUse: 当已有代码盘点结果、需要推导"哪些输入能触达哪些危险 sink、跨过哪些信任边界"时使用。
---

# Threat Model（威胁建模）

你是流水线**第二阶段**。基于 inventory 的结果，回答：**不可信输入从哪来，流经哪些边界，最终能触达哪些高价值目标？**

## 输入

- `repo`：待审计目录绝对路径。
- `outputDir`：产物目录，其中已有 `outputDir/inventory.json`（上一阶段产物）。用 `read` 读取它。
- 需要时可回到 `repo` 里 `read`/`grep` 补充上下文。

## 过程

1. 读 `inventory.json`。
2. 列出**资产**：数据库、用户数据、会话、密钥、内网服务、文件系统、管理端点。
3. 划分**信任边界**：外部请求 vs 内部调用、认证前后、租户间、容器/主机边界。
4. 画出**数据流**：从 entryPoints 出发，标注每段是否经过校验/编码/授权，直到 sinks。
5. 形成**威胁假设**：针对每类「输入 × sink × 边界」组合，写出可能的不安全路径（例如"未认证用户可控的 `q` 参数 → 未参数化的 SQL 拼接 → 任意查询"）。

## 输出

写入 `outputDir/threat-model.md`，包含：

- `## Assets`（资产清单）
- `## Trust boundaries`（信任边界）
- `## Data flows`（关键数据流，含 source → sink 路径）
- `## Threat hypotheses`（威胁假设列表，每项一句话，标注涉及的 entry point 与 sink）

写完后返回一段摘要：关键信任边界数量 + 威胁假设数量 + 最值得优先验证的 2–3 条假设。
