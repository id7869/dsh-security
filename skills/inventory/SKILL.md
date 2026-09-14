---
name: dsh-security-inventory
description: 安全审计第一步「代码盘点」：枚举仓库的语言、框架、依赖、入口点、认证与会话处理、危险 sink（SQL/命令执行/文件路径/eval/反序列化/跳转）。触发词：安全审计、代码盘点、inventory、盘点攻击面。作为 dsh-security 发现→验证→报告流水线的首阶段被 workflow 调用。
whenToUse: 当需要建立代码库的攻击面清单、为威胁建模与漏洞发现提供输入时使用。
---

# Inventory（代码盘点）

你是安全审计流水线的**首阶段**。目标不是找漏洞，而是建立一份**机器可读的攻击面清单**，供后续 threat-model 与 discover 使用。

## 输入

- `repo`：待审计目录的绝对路径。
- `outputDir`：产物目录（绝对路径），你写入 `outputDir/inventory.json` 与 `outputDir/coverage.json`。

## 过程

1. 用 `glob`、`grep`、`read` 摸清目录结构（跳过 `node_modules`、`.git`、`dist`、`build`、`target`、`__pycache__`、vendor 等依赖/产物目录）。
2. 识别语言与框架：读依赖清单（`package.json`、`requirements.txt`/`pyproject.toml`、`go.mod`、`pom.xml`/`build.gradle`、`Cargo.toml`、`*.csproj`、`composer.json` 等）。
3. 找出入口点：HTTP 路由/控制器、CLI 入口、事件处理器、cron/定时任务、消息队列消费者、serverless handler。
4. 定位认证与会话：登录/鉴权中间件、session 管理、JWT 签发与校验、API key 校验点。
5. 定位**危险 sink**（数据可能流入的危险点）：
   - SQL 执行、ORM 裸查询/拼接
   - 命令执行（exec/spawn/system/subprocess/os.command）
   - 文件读写/路径拼接（含 zip slip）
   - eval/动态执行、模板渲染
   - 反序列化
   - HTTP 重定向、外部请求（SSRF 候选）
   - 反序列化/日志注入
6. 每个 sink 记录：文件、行号、符号、一句话用途。

## 输出

写入 `outputDir/inventory.json`（结构如下）与 `outputDir/coverage.json`：

```json
{
  "repository": "<repo 目录名>",
  "languages": ["javascript", "python"],
  "frameworks": ["express"],
  "dependencies": [{"name": "express", "version": "4.18.2", "manifest": "package.json"}],
  "entryPoints": [{"file": "src/index.js", "line": 10, "kind": "http-route", "note": "GET /login"}],
  "auth": [{"file": "src/middleware/auth.js", "line": 3, "note": "JWT 校验中间件"}],
  "sinks": [{"file": "src/db.js", "line": 42, "kind": "sql", "symbol": "runQuery", "note": "拼接 SQL"}]
}
```

同时写入 `outputDir/coverage.json`，结构如下：

```json
{
  "repository": "<repo 目录名>",
  "inventoryStrategy": "directory",
  "scannedFiles": ["src/index.js", "src/db.js"],
  "totalFilesEstimate": 2,
  "skipped": {"node_modules": 1, ".git": 1},
  "sinkCount": 5
}
```

其中 `scannedFiles` 列出你实际盘点到的源码文件（相对路径）；`totalFilesEstimate` 为仓库源码文件总数估计；`skipped` 记录被跳过的依赖/产物目录；`sinkCount` 与 sinks 数量一致。

写完后，返回**一段简短摘要**（语言/框架/入口点数量/危险 sink 数量），不要返回整个 JSON。
