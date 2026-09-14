// dsh-security 修复编排（原生 DSH workflow 工具，v3 逻辑）
// 通过 DSH 原生 workflow 工具执行。脚本无文件系统访问：修复（写源码）与复验（读源码）在各阶段 subagent 内完成。

const repo = String(args.repo ?? "");
const skillDir = String(args.skillDir ?? "");
const outputDir = String(args.outputDir ?? "");
const stateDir = String(args.stateDir ?? "");
const verify = args.verify !== false; // 默认 true

const raw = args.findings ?? (args.finding ? [args.finding] : []);
const findings = (Array.isArray(raw) ? raw : [raw]).filter((f) => f && typeof f === "object");

function skillPrompt(stage, extra) {
  const lines = [
    `你是 dsh-security 安全审计流水线的「${stage}」阶段。`,
    `第一步用 read 工具读取并严格遵循该阶段说明：${skillDir}/${stage}/SKILL.md`,
    `repo = ${repo}`,
  ];
  if (outputDir) lines.push(`outputDir = ${outputDir}`);
  if (stateDir) lines.push(`stateDir = ${stateDir}`);
  for (const x of extra ?? []) lines.push(x);
  return lines.join("\n");
}
function extractJson(text) {
  if (text == null) return null;
  const s = String(text).replace(/```(?:json|javascript|js)?/g, "").replace(/```/g, "");
  const a = s.indexOf("{");
  const b = s.indexOf("[");
  const start = (a === -1 ? b : b === -1 ? a : Math.min(a, b));
  if (start === -1) return s;
  const open = s[start];
  const close = open === "{" ? "}" : "]";
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (inStr) { if (esc) { esc = false; continue; } if (c === "\\") { esc = true; continue; } if (c === "\"") inStr = false; continue; }
    if (c === "\"") { inStr = true; continue; }
    if (c === open) depth++;
    else if (c === close) { depth--; if (depth === 0) return s.slice(start, i + 1); }
  }
  return s.slice(start);
}
function parseObject(text) { try { const o = JSON.parse(extractJson(text)); return o && typeof o === "object" && !Array.isArray(o) ? o : null; } catch { return null; } }

const records = [];
for (let i = 0; i < findings.length; i++) {
  const f = findings[i];

  phase(`fix-${i}`);
  const fixText = await agent(
    skillPrompt("fix", [
      `待修复 finding：${JSON.stringify(f)}`,
      "亲自确认根因后做最小修复（用 edit 写源码），最终【只返回】单个 JSON 对象 {file, changed, summary, notes}。",
    ]),
    { label: `fix:${f.title ?? i}`, phase: "fix" },
  );
  const fixRes = parseObject(fixText) ?? { changed: false, summary: String(fixText ?? "") };

  let verifyRes = null;
  if (verify && fixRes.changed) {
    phase(`verify-fix-${i}`);
    const vText = await agent(
      skillPrompt("verify-fix", [
        `原始 finding：${JSON.stringify(f)}`,
        `修复摘要：${JSON.stringify(fixRes)}`,
        "独立重读修复后的源码，最终【只返回】单个 JSON 对象 {verdict, evidence, remainingRisk}。",
      ]),
      { label: `verify-fix:${f.title ?? i}`, phase: "verify-fix" },
    );
    verifyRes = parseObject(vText);
  }

  records.push({ finding: f, fix: fixRes, verify: verifyRes });
}

// 落盘 fixes.jsonl（一个 subagent 完成追加写入）
phase("fix-log");
const logRows = records.map((r) => ({
  id: r.finding?.id ?? null,
  title: r.finding?.title ?? null,
  location: r.finding?.location ?? null,
  ...r.fix,
  verify: r.verify,
  fixedAt: null,
}));
const logText = await agent(
  `将下面修复记录追加写入 ${stateDir}/fixes.jsonl（每行一个 JSON，fixedAt 用当前 ISO-8601 时间，目录不存在则创建）：${JSON.stringify(logRows)}\n用 write/pwsh 追加或重写该文件，最后返回追加了几行。`,
  { label: "fix-log", phase: "fix-log" },
);

return {
  repository: repo,
  fixed: records.filter((r) => r.fix?.changed).length,
  verified: records.filter((r) => r.verify?.verdict === "fixed").length,
  verdicts: records.map((r) => r.verify?.verdict ?? (r.fix?.changed ? "unverified" : "unchanged")),
  log: String(logText ?? ""),
};
