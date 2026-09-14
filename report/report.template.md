# 安全审计报告

> 扫描目标：`{{repository}}`
> 扫描 id：`{{scanId}}`
> 生成时间：`{{generatedAt}}`
> 模式：report-only（未修改任何源码）

## 执行摘要

- 候选 finding 数：{{candidateCount}}
- 报告（reportable）数：{{reportableCount}}
- 严重度分布：critical {{crit}} / high {{high}} / medium {{med}} / low {{low}}
- 覆盖：见 `coverage`（如存在）

## 关键发现

{{#findings}}
### {{severity}} — {{title}}

- 位置：`{{location.file}}{{#location.line}}:{{location.line}}{{/location.line}}`
- 类别：{{category}}{{#cwe}}（{{cwe}}）{{/cwe}}
- 置信度：{{confidence}}
- 断言：{{claim}}

证据：
```
{{evidence}}
```

修复建议：
{{remediation}}

{{/findings}}

## 验证说明

每条 finding 均由独立复核 agent 重新读源码得出 `disposition`，仅 `reportable` 项进入本报告。
原始候选与验证结果见 `candidates.json` / `validated.json`；机器可读汇总见 `findings.json`。
