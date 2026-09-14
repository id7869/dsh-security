---
name: dsh-security-dedupe
description: 跨扫描安全发现去重（dsh-security v2）：候选来自身份指纹+本地 JSONL 历史召回（无向量），同模型两阶段评审——粗筛 SAME/DISTINCT、深度确认 canonical+merged finding，传递闭包分组。触发词：去重、重复 finding、SAME/DISTINCT、duplicate、dedupe、合并漏洞。作为 dsh-security 流水线的去重阶段被 workflow 调用。
whenToUse: 当需要判断新扫描的 finding 是否与历史 finding 是同一根因、合并重复项时使用。
---

# Dedupe（跨扫描去重）

去重把「本次扫描」的 finding 与「历史扫描」的 finding 按根因合并。**不做向量召回**——候选只来自身份指纹匹配 + 类别/文件启发式匹配，再交给模型两阶段评审。

## 角色分工

本 skill 描述协议；workflow 编排脚本会按角色调用你。你可能被要求扮演以下之一：

### 1. 历史召回（history recall）——机械，不下判断

读取 `stateDir/findings.jsonl`，返回其中全部历史 finding 的 JSON 数组（文件不存在返回 `[]`）。**只做读取与返回，不要判断 SAME/DISTINCT。**

### 2. 粗筛（screen）——阶段 1

输入：两条原始 finding A、B。只判断二者是否**同一根因**。

- `SAME`：描述的是同一处问题（同一根因，可能措辞/行号/标题不同）。
- `DISTINCT`：是两处独立的不同问题。

输出：**只返回** `{"decision":"SAME"}` 或 `{"decision":"DISTINCT"}`，**不要给理由**（理由会被丢弃，且不得流入阶段 2，以保证独立性）。

### 3. 深度确认（confirm）——阶段 2

输入：两条**原始** finding A、B（不包含阶段 1 的任何推理）。独立复核后给出：

```json
{"decision":"SAME|DISTINCT", "canonicalFindingId":"<代表性 finding 的 id>", "mergedFinding":"<一句话合并描述>"}
```

- `canonicalFindingId`：确认 SAME 时，选出代表性 finding 的 id（通常取严重度更高者，同级取 id 更小者）。
- `mergedFinding`：合并后的一句话描述。
- 阶段 2 是**独立评审**：只依据原始 finding 重读代码，不接收阶段 1 的 rationale。

## 去重候选生成（由编排脚本做，机械规则）

对每条当前 finding 与每条历史 finding 比较：

- **精确匹配**：`fingerprint` 相等 → 候选。
- **启发式匹配**：`category` 相同 且 `location.file` 相同 → 候选（捕获行号漂移/标题改写）。

候选对交给两阶段评审；`DISTINCT` 的不进分组。

## 传递闭包分组

确认 SAME 的对按连通性合并成组；组内取 canonical（严重度高优先，同级 id 小优先）。分组结果追加到 `stateDir/dedupe-groups.jsonl`，每行：

```json
{"groupId":"csg_<hex>","findingIds":["csf_...","csf_..."],"canonicalFindingId":"csf_...","createdAt":"<ISO-8601>"}
```
