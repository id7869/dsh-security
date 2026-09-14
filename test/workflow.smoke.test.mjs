import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

function loadWorkflow(name) {
  const src = readFileSync(join(here, "..", "workflow", name), "utf8");
  return new Function("args", "agent", "parallel", "phase", "log", "return (async function __dsh_workflow__() { " + src + "\n})()");
}

function makeAgent(kind) {
  return async function agent(prompt, opts = {}) {
    const label = String(opts?.label ?? "");
    if (kind === "scan") {
      if (label === "inventory") return JSON.stringify({ summary: "fixture", coverage: { repository: "/repo", inventoryStrategy: "directory", scannedFiles: ["src/db.js", "src/index.js"], fileHashes: { "src/db.js": "h1", "src/index.js": "h2" }, totalFilesEstimate: 2, skipped: {}, sinkCount: 3 } });
      if (label === "threat-model") return "ok";
      if (label.startsWith("discover-")) return JSON.stringify({ candidates: [{ title: "SQL injection", location: { file: "src/db.js", line: 42 }, category: "SQL injection", cwe: "CWE-89", context: "const q = `SELECT * FROM users WHERE name='${username}'`;" }] });
      if (label.startsWith("validate:")) return JSON.stringify({ title: "SQL injection", location: { file: "src/db.js", line: 42 }, category: "SQL injection", cwe: "CWE-89", severity: "high", disposition: "reportable", confidence: "high", claim: "c", evidence: "e", remediation: "r", context: "const q = `SELECT * FROM users WHERE name='${username}'`;" });
      if (label === "dedupe-history") return "[]";
      if (label === "report-write") return "[]";
      if (label === "seal") return JSON.stringify({ ok: true, checks: [{ name: "hash-match", pass: true, detail: "ok" }] });
      if (label === "severity") return "ok";
      return "{}";
    }
    if (label === "diff-inventory") return JSON.stringify({ summary: "2 changed", files: ["src/db.js", "src/index.js"], fileHashes: { "src/db.js": "h1", "src/index.js": "h2" }, totalFilesEstimate: 2, sinkCount: 0 });
    if (label === "scope-write") return "[]";
    if (label === "discover") return JSON.stringify({ candidates: [{ title: "SQL injection", location: { file: "src/db.js", line: 42 }, category: "SQL injection", cwe: "CWE-89", context: "const q = `SELECT * FROM users WHERE name='${username}'`;" }] });
    if (label.startsWith("validate:")) return JSON.stringify({ title: "SQL injection", location: { file: "src/db.js", line: 42 }, category: "SQL injection", cwe: "CWE-89", severity: "high", disposition: "reportable", confidence: "high", claim: "c", evidence: "e", remediation: "r", context: "const q = `SELECT * FROM users WHERE name='${username}'`;" });
    if (label === "report-write") return "[]";
    if (label === "seal") return JSON.stringify({ ok: true, checks: [{ name: "hash-match", pass: true, detail: "ok" }] });
    return "{}";
  };
}

async function parallel(fns) {
  const out = [];
  for (const fn of fns) out.push(await fn());
  return out;
}
function phase() {}
function log() {}

let pass = 0, fail = 0;
function assert(name, cond, detail) {
  if (cond) { pass++; console.log("PASS " + name); }
  else { fail++; console.log("FAIL " + name + (detail ? " :: " + detail : "")); }
}

const scanRun = loadWorkflow("scan.js");
const scanRes = await scanRun(
  { repo: "/repo", skillDir: "/skills", outputDir: "/out", stateDir: "/state", mode: "standard", maxDiscoveryRuns: 5, stopAfterNoNew: 2, classify: false },
  makeAgent("scan"), parallel, phase, log,
);
assert("scan smoke sealed", scanRes.sealed === true, JSON.stringify(scanRes));
assert("scan smoke candidate count", scanRes.candidates === 1, JSON.stringify(scanRes));
assert("scan smoke reportable count", scanRes.reportable === 1, JSON.stringify(scanRes));
assert("scan smoke returns scanId", /^scan_/.test(scanRes.scanId), scanRes.scanId);

const diffRun = loadWorkflow("diff.js");
const diffRes = await diffRun(
  { repo: "/repo", skillDir: "/skills", outputDir: "/out", stateDir: "/state", baseRef: "main", headRef: "HEAD" },
  makeAgent("diff"), parallel, phase, log,
);
assert("diff smoke sealed", diffRes.sealed === true, JSON.stringify(diffRes));
assert("diff smoke reportable count", diffRes.reportable === 1, JSON.stringify(diffRes));
assert("diff smoke returns scanId", /^dscan_/.test(diffRes.scanId), diffRes.scanId);

const fixRun = loadWorkflow("fix.js");
const fixAgent = async function agent(prompt, opts = {}) {
  const label = String(opts?.label ?? "");
  if (label.startsWith("fix:")) return JSON.stringify({ file: "src/db.js", changed: true, summary: "patched", notes: "x" });
  if (label.startsWith("verify-fix:")) return JSON.stringify({ verdict: "fixed", evidence: "ok", remainingRisk: "none" });
  if (label === "fix-log") return "1";
  return "{}";
};
const fixRes = await fixRun({ repo: "/repo", skillDir: "/skills", outputDir: "/out", stateDir: "/state", verify: true, findings: [{ title: "SQL injection", location: { file: "src/db.js", line: 42 }, category: "SQL injection", severity: "high" }] }, fixAgent, parallel, phase, log);
assert("fix smoke fixed", fixRes.fixed === 1, JSON.stringify(fixRes));
assert("fix smoke verified", fixRes.verified === 1, JSON.stringify(fixRes));

const triageRun = loadWorkflow("triage.js");
const triageAgent = async function agent(prompt, opts = {}) {
  const label = String(opts?.label ?? "");
  if (label.startsWith("triage:")) return JSON.stringify({ title: "XSS", location: { file: "src/index.js", line: 7 }, category: "XSS", severity: "medium", disposition: "reportable", confidence: "high" });
  if (label === "triage-write") return "1";
  return "{}";
};
const triageRes = await triageRun({ repo: "/repo", skillDir: "/skills", outputDir: "/out", stateDir: "/state", findings: [{ title: "XSS" }] }, triageAgent, parallel, phase, log);
assert("triage smoke reportable", triageRes.reportable === 1, JSON.stringify(triageRes));

const trackRun = loadWorkflow("track.js");
const trackAgent = async function agent(prompt, opts = {}) {
  const label = String(opts?.label ?? "");
  if (label === "track-probe") return '["github"]';
  if (label === "track-dedupe") return "[]";
  if (label.startsWith("track:")) return JSON.stringify({ id: "csf_1234567890abcdef", destination: "github", created: true, ref: "issue-1" });
  if (label === "track-log") return "1";
  return "{}";
};
const trackRes = await trackRun({ repo: "/repo", skillDir: "/skills", outputDir: "/out", stateDir: "/state", destination: "auto", findings: [{ id: "csf_1234567890abcdef", title: "XSS" }] }, trackAgent, parallel, phase, log);
assert("track smoke newlyTracked", trackRes.newlyTracked === 1, JSON.stringify(trackRes));

console.log("\nRESULT pass=" + pass + " fail=" + fail);
if (fail > 0) process.exit(1);
