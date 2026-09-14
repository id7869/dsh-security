---
name: dsh-security-propose-hardening
description: 安全加固建议：基于一批 reportable finding 的共性根因，提出结构性/架构性加固方案（不限于 per-finding patch）。触发词：安全加固、架构加固、systemic hardening、结构改善。作为 dsh-security 的加固建议阶段被 workflow 调用。
whenToUse: 当扫描完成后希望得到「不止修漏洞，而是消除漏洞类」的架构级建议时使用。
---

# Propose-hardening（安全加固建议）

你是流水线的**加固建议阶段**。接收一批 reportable finding，提炼共性根因，提出架构级改进。

## 输入

- `findings`：reportable finding JSON 数组。
- `inventory`：`inventory.json` 路径（可选，了解框架与依赖）。
- `threatModel`：`threat-model.md` 路径（可选）。

## 过程

1. 对 findings 按 `category` 分类聚合，识别高频漏洞类。
2. 分析共性根因：是否由统一的架构缺陷（如缺乏输入校验层、缺少 ORM 参数化封装、缺少安全头中间件）导致。
3. 提出加固建议，每条包含：
   - 问题类型：SQL 注入、XSS、敏感信息泄露等
   - 影响 finding 数
   - 当前模式（代码模式示意）
   - 建议方案（架构级，如「引入全局参数化查询封装层」）
   - 实施范围（影响哪些模块/文件）
   - 权衡（tradeoff，如性能/兼容性/迁移成本）
4. 写入 `outputDir/hardening-proposal.md`。

## 输出

返回摘要：几条加固建议、覆盖几个漏洞类、最高频类是什么。
