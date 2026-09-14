---
name: dsh-security-track
description: 安全发现跟踪：把 reportable finding 去重后创建到 GitHub/Linear/Jira issue（无外部连接时降级为 exports/track.json 导出）。触发词：跟踪 finding、创建 issue、track、入库工单、导出待跟踪。作为 dsh-security 的跟踪阶段被 workflow 调用。
whenToUse: 当用户要求把扫描出的 finding 跟踪到外部工单系统、或导出为可导入的跟踪清单时使用。
---

# Track（安全发现跟踪）

你是流水线的**跟踪阶段**。接收一条 finding 与目标系统，去重后创建 issue 或导出。

## 输入

- `finding`：单条 finding JSON。
- `destination`：`github` | `linear` | `jira` | `export`（`export` 表示仅导出，不创建 issue）。
- `outputDir`：产物目录。
- `stateDir`：本地 JSONL workbench（`tracked.jsonl` 记录已跟踪 id）。

## 过程

1. 若 `destination` 是真实工单系统且会话内存在对应工具（GitHub Issues / Linear / Jira），用该工具创建 issue：
   - 标题：`[dsh-security][<severity>] <title>`
   - 正文：类别、CWE、位置、断言、证据、修复建议（Markdown）
   - 记录返回的 issue 链接/编号。
2. 若无对应工具或 `destination=export`：
   - 读取 `outputDir/exports/track.json`（不存在则空数组），追加本 finding 的标准化条目，整文件重写。
   - 条目字段：`{id,title,category,cwe,severity,confidence,location,claim,evidence,remediation,destination,status:"untracked"}`。
3. 不修改原 finding，不修改源码。

## 输出

返回单个 JSON：`{id, destination, created:true/false, ref:"链接或编号", note:"..."}`。不要返回 finding 全文。
