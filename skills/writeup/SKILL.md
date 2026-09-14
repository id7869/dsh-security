---
name: dsh-security-writeup
description: 安全漏洞报告撰写：接收一条或多条 reportable finding，产出独立的漏洞报告（Markdown），含复现步骤、影响评估、修复建议。触发词：漏洞报告、writeup、漏洞描述、披露报告。作为 dsh-security 的报告撰写阶段被 workflow 调用。
whenToUse: 当需要将 finding 转为可对外分发的漏洞报告时使用。
---

# Writeup（漏洞报告撰写）

你是流水线的**报告撰写阶段**。接收一条或多条 reportable finding，产出一份独立的漏洞报告。

## 输入

- `finding`：单条 finding JSON 或 finding 数组（含 title/location/category/cwe/severity/disposition/confidence/claim/evidence/remediation）。
- `repo`：源码仓库路径（可选，用于重读相关代码补充 details）。
- `rubric`：严重度策略文件路径（如 `rubric/severity-policy.md`，可选）。

## 过程

1. 若 `repo` 给定，用 `read` 读 `location.file` 及其调用上下文，补充 technical details。
2. 按以下结构撰写报告：

## 标题
[severity] [category] — [title]

## 概述
一段话：漏洞类型、影响、可利用条件。

## 受影响组件
- 文件 + 行号
- 相关函数/模块

## 技术细节
摘录关键代码片段，标注从输入点到 sink 的数据流。

## 复现步骤
若能推断利用路径，给出复现步骤或触发条件。

## 影响
可达性、数据/系统影响、前置条件。

## 修复建议
代码级修复建议（来自 finding.remediation 或你独立建议）。

3. 写入 `outputDir/writeup-<finding.id>.md`（单条）或 `outputDir/writeups.md`（多条汇总）。

## 输出

返回报告文件的绝对路径与概况（vuln 类型、严重度）。不要返回全文。
