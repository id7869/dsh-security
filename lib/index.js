// Bundled skill provider for the dsh-security plugin.
// Registers the stage/entry skills into ctx.skills, mirroring the official @deepseek-ai/dsh-skill-badge pattern.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

// Hard-coded instead of `import { BUNDLED_SKILL_RANK } from "@deepseek-ai/dsh-skill"`
// so the plugin has no static peer import: a local `link:` install has no
// node_modules of its own, and Node would fail to resolve that package from
// the plugin's real path. The value (600) is the fixed `BUNDLED_SKILL_RANK`
// constant in @deepseek-ai/dsh-skill.
const BUNDLED_SKILL_RANK = 600;

const PROVIDER_NAME = "dsh-security";

// name is the frontmatter name (skill name); dir is the subdirectory under skills/ holding SKILL.md.
const SKILLS = [
  { name: "dsh-security-inventory", dir: "inventory", description: "安全审计第一步「代码盘点」：枚举仓库的语言、框架、依赖、入口点、认证与会话处理、危险 sink（SQL/命令执行/文件路径/eval/反序列化/跳转）。触发词：安全审计、代码盘点、inventory、盘点攻击面。作为 dsh-security 发现→验证→报告流水线的首阶段被 workflow 调用。" },
  { name: "dsh-security-threat-model", dir: "threat-model", description: "安全审计第二步「威胁建模」：基于盘点结果，梳理资产、信任边界、数据流与威胁假设。触发词：威胁建模、threat model、信任边界、数据流、攻击面分析。作为 dsh-security 流水线的第二阶段被 workflow 调用。" },
  { name: "dsh-security-discover", dir: "discover", description: "安全审计第三步「漏洞发现」：基于盘点与威胁模型，产出候选 finding（假设→具体断言+证据）。触发词：漏洞发现、candidate finding、假设验证、审计假设。作为 dsh-security 流水线的第三阶段被 workflow 调用。" },
  { name: "dsh-security-validate", dir: "validate", description: "安全审计第四步「独立验证」：对单条候选 finding 重新读源码、独立得出 disposition（reportable/suppressed/not_applicable/deferred）与定级。触发词：验证 finding、disposition、误报确认、漏洞复核、独立复核。作为 dsh-security 流水线的第四阶段被 workflow 调用。" },
  { name: "dsh-security-dedupe", dir: "dedupe", description: "跨扫描安全发现去重（dsh-security v2）：候选来自身份指纹+本地 JSONL 历史召回（无向量），同模型两阶段评审——粗筛 SAME/DISTINCT、深度确认 canonical+merged finding，传递闭包分组。触发词：去重、重复 finding、SAME/DISTINCT、duplicate、dedupe、合并漏洞。作为 dsh-security 流水线的去重阶段被 workflow 调用。" },
  { name: "dsh-security-severity", dir: "severity", description: "严重度 rubric 重分级（dsh-security v2）：按策略文件独立重估 reportable finding 的严重度，落 classification.jsonl，不修改原 finding 的 severity。触发词：严重度分级、severity 重评、rubric 定级、classify severity、按策略重评。作为 dsh-security 流水线的可选重分级阶段被 workflow 调用。" },
  { name: "dsh-security-report", dir: "report", description: "安全审计报告写入阶段（dsh-security v4）：接收编排脚本确定性生成的文件内容，逐字写入 findings.json、report.md、SARIF。触发词：报告写入、写入报告、report write。作为 dsh-security 流水线的报告阶段被 workflow 调用。" },
  { name: "dsh-security-seal", dir: "seal", description: "安全审计封存阶段（dsh-security v4）：校验产物 schema 与一致性、计算文件 SHA256、写入 scan-manifest.json、合并去重 findings.jsonl 与索引。触发词：封存、seal、校验产物、生成 manifest、JSONL 落库。作为 dsh-security 流水线的封存阶段被 workflow 调用。" },
  { name: "dsh-security-diff-inventory", dir: "diff-inventory", description: "diff 扫描首阶段：用 git diff 枚举变更文件并返回结构化 scope/coverage 数据，不直接写盘。触发词：diff scope、变更文件、PR 变更、工作区变更。作为 dsh-security diff 流水线的首阶段被 workflow 调用。" },
  { name: "dsh-security-diff-scan", dir: "security-diff-scan", description: "dsh-security diff 扫描入口：对 PR/commit/branch diff 或工作区变更做安全审计（只审变更文件）。触发词：diff scan、PR 扫描、commit 扫描、变更扫描、代码审查。当用户要求对一次代码变更做安全审查时使用。" },
  { name: "dsh-security-track", dir: "track", description: "安全发现跟踪：把 reportable finding 去重后创建到 GitHub/Linear/Jira issue（无外部连接时降级为 exports/track.json 导出）。触发词：跟踪 finding、创建 issue、track、入库工单、导出待跟踪。" },
  { name: "dsh-security-writeup", dir: "writeup", description: "安全漏洞报告撰写：接收 reportable finding，产出独立漏洞报告（Markdown，含复现步骤/影响/修复建议）。触发词：漏洞报告、writeup、漏洞描述、披露报告。" },
  { name: "dsh-security-propose-hardening", dir: "propose-hardening", description: "安全加固建议：基于一批 reportable finding 的共性根因，提出结构性/架构性加固方案。触发词：安全加固、架构加固、systemic hardening、结构改善。" },
  { name: "dsh-security-fix", dir: "fix", description: "安全审计修复（dsh-security v3）：对单条 reportable finding 做最小修复，修改源码，返回变更摘要。触发词：修复漏洞、patch、fix、修复建议落地、应用修复。作为 dsh-security 流水线的 patch 阶段被 workflow 调用。" },
  { name: "dsh-security-verify-fix", dir: "verify-fix", description: "修复复验（dsh-security v3）：独立重读修复后的源码，确认原漏洞已消除且未引入回归。触发词：验证修复、verify fix、复验修复、回归确认。作为 dsh-security 流水线的 verify-fix 阶段被 workflow 调用。" },
  { name: "dsh-security-triage-finding", dir: "triage-finding", description: "已有 finding 本地入库（dsh-security v3）：对一条外部传入的 finding 独立复核，得出 disposition 与 severity，供入库到 findings.jsonl。触发词：triage、finding 入库、告警复核、已有漏洞入库、告警分级。作为 dsh-security 流水线的 triage 阶段被 workflow 调用。" },
  { name: "dsh-security-run", dir: "run", description: "dsh-security 安全审计入口：安装并运行 dsh-security 的扫描/修复/入库工作流。触发词：安全审计、扫描仓库、代码安全检查、漏洞扫描、security scan、run security audit、dsh-security。当用户要求对代码库做安全审计、扫描漏洞、修复漏洞或已有漏洞入库时使用。" },
];

function bodyUrlOf(dir) {
  return new URL(`../skills/${dir}/SKILL.md`, import.meta.url);
}

function resourceBaseOf(dir) {
  return { kind: "directory", path: fileURLToPath(new URL(`../skills/${dir}/`, import.meta.url)) };
}

const provider = {
  name: PROVIDER_NAME,
  list: () => Promise.resolve(SKILLS.map((s) => ({
    name: s.name,
    description: s.description,
    invocation: { modelInvocable: true, userInvocable: true },
    provider: PROVIDER_NAME,
    source: "bundled",
    resourceBase: resourceBaseOf(s.dir),
    rank: BUNDLED_SKILL_RANK,
    locator: bodyUrlOf(s.dir),
  }))),
  async get(candidate) {
    const entry = SKILLS.find((s) => s.name === candidate.name);
    if (entry === undefined) return undefined;
    return {
      name: entry.name,
      description: entry.description,
      invocation: { modelInvocable: true, userInvocable: true },
      provider: PROVIDER_NAME,
      source: "bundled",
      resourceBase: resourceBaseOf(entry.dir),
      content: await readFile(bodyUrlOf(entry.dir), "utf8"),
    };
  },
};

/** Cordis plugin name. */
const name = "dsh-security";

/** Service required by the bundled provider. */
const inject = ["skills"];

/** Register the bundled dsh-security provider on ctx.skills. */
function apply(ctx) {
  ctx.skills.registerProvider(() => provider);
}

export { apply, inject, name };



