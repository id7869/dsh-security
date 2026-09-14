// dsh-security 已有 finding 入库编排（原生 DSH workflow 工具，v3 逻辑）
// 通过 DSH 原生 workflow 工具执行。每条外部 finding 独立复核后，reportable 项追加进 findings.jsonl。

const repo = String(args.repo ?? "");
const skillDir = String(args.skillDir ?? "");
const outputDir = String(args.outputDir ?? "");
const stateDir = String(args.stateDir ?? "");

const raw = args.findings ?? (args.finding ? [args.finding] : []);
const inputs = (Array.isArray(raw) ? raw : [raw]).filter((f) => f && typeof f === "object");

function norm(s) { return String(s ?? "").toLowerCase().replace(/\s+/g, " ").trim(); }
function fnv1a(s, basis) { let h = basis >>> 0; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return h >>> 0; }
function hash64(s) { const a = fnv1a(s, 0x811c9dc5); const b = fnv1a(s, 0x9dc5811c); return a.toString(16).padStart(8, "0") + b.toString(16).padStart(8, "0"); }
function fingerprintOf(f) { const ctx = norm(f?.context) || norm(f?.evidence) || norm(f?.title); const weak = !(f?.context || f?.evidence); const base = norm(f?.category) + "|" + norm(f?.location?.file) + "|" + ctx; return (weak ? "wfp_" : "fp_") + hash64(base); }
function idOf(f) { return "csf_" + fingerprintOf(f).replace(/^w?fp_/, ""); }
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

const triaged = [];
for (let i = 0; i < inputs.length; i++) {
  phase(`triage-${i}`);
  const tText = await agent(
    skillPrompt("triage-finding", [
      `待复核 finding（外部来源）：${JSON.stringify(inputs[i])}`,
      "独立复核补全字段，最终【只返回】单个 JSON 对象，字段含 title/location/category/cwe/severity/disposition/confidence/claim/evidence/remediation。",
    ]),
    { label: `triage:${inputs[i]?.title ?? i}`, phase: "triage" },
  );
  const t = parseObject(tText);
  if (!t || !t.title) continue;
  t.fingerprint = fingerprintOf(t);
  t.id = idOf(t);
  triaged.push(t);
}

const reportable = triaged.filter((t) => t.disposition === "reportable");

phase("triage-write");
let writeSummary = "";
if (reportable.length > 0) {
  writeSummary = await agent(
    `将下面 reportable finding 追加写入 ${stateDir}/findings.jsonl（每行一个 JSON，createdAt 用当前 ISO-8601 时间，目录不存在则创建）：${JSON.stringify(reportable)}\n用 write/pwsh 追加或重写，最后返回追加了几行。`,
    { label: "triage-write", phase: "triage-write" },
  );
}

return {
  repository: repo,
  input: inputs.length,
  triaged: triaged.length,
  reportable: reportable.length,
  dispositions: triaged.reduce((acc, t) => { const d = t?.disposition ?? "unknown"; acc[d] = (acc[d] ?? 0) + 1; return acc; }, {}),
  write: String(writeSummary ?? "（无 reportable，未写入）"),
};

