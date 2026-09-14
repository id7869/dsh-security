import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, "..", "workflow", "scan.js"), "utf8");
const start = src.indexOf("/* @contract-helpers-start */");
const end = src.indexOf("/* @contract-helpers-end */");
if (start === -1 || end === -1) throw new Error("contract helper markers not found");
const block = src.slice(start + "/* @contract-helpers-start */".length, end);

const prelude = `function norm(s) { return String(s ?? "").toLowerCase().replace(/\\s+/g, " ").trim(); }\n`;
const fn = new Function(prelude + block + "\nreturn {fnv1a, hash64, fingerprintOf, idOf, slugify, sevToLevel, sevScore, stableStringify, utf8Len, sha256Hex, buildFindings, buildSarif, buildManifest, buildReport, buildReductions, computeSnapshotDigest};");
const H = fn();

let pass = 0, fail = 0;
function assert(name, cond, detail) {
  if (cond) { pass++; console.log("PASS " + name); }
  else { fail++; console.log("FAIL " + name + (detail ? " :: " + detail : "")); }
}

// fingerprint stability
const a = { category: "SQL injection", location: { file: "src/db.js", line: 42 }, context: "const q = `SELECT * FROM users WHERE name='${username}'`;", evidence: "db.query(q)" };
const b = { category: "SQL injection", location: { file: "src/db.js", line: 99 }, context: "const q = `SELECT * FROM users WHERE name='${username}'`;", evidence: "db.query(q)" };
const c = { category: "SQL injection", location: { file: "src/db.js", line: 42 }, context: "const q = `SELECT * FROM users WHERE name='${username}'`;", evidence: "db.query(q)", title: "Renamed" };
assert("id stable under line shift", H.idOf(a) === H.idOf(b));
assert("id stable under title change", H.idOf(a) === H.idOf(c));
assert("id is 16-hex", /^csf_[0-9a-f]{16}$/.test(H.idOf(a)));
const d = { category: "SQL injection", location: { file: "src/db.js", line: 42 }, context: "const q = `SELECT * FROM orders WHERE id='${id}'`;", evidence: "db.query(q)" };
assert("distinct context differs", H.idOf(a) !== H.idOf(d));
const w = { category: "XSS", location: { file: "src/index.js", line: 1 }, title: "Possible XSS" };
assert("weak fingerprint marker", H.fingerprintOf(w).startsWith("wfp_"));

// slug / sev
assert("slugify", H.slugify("SQL injection") === "sql-injection");
assert("sevToLevel critical->error", H.sevToLevel("critical") === "error");
assert("sevToLevel medium->warning", H.sevToLevel("medium") === "warning");
assert("sevToLevel low->note", H.sevToLevel("low") === "note");
assert("sevScore critical 9.5", H.sevScore("critical") === 9.5);
assert("sevScore medium 5.0", H.sevScore("medium") === 5.0);

// sha256 correctness vs node:crypto
for (const s of ["", "abc", "安全审计 test 123", "x".repeat(1000)]) {
  const expect = createHash("sha256").update(s, "utf8").digest("hex");
  assert("sha256 matches crypto (" + s.length + ")", H.sha256Hex(s) === expect, H.sha256Hex(s));
}

// stableStringify
assert("stableStringify key order", H.stableStringify({ b: 2, a: 1 }) === '{"a":1,"b":2}');

// buildFindings / buildSarif (with CWE + security-severity)
const finding = { id: H.idOf(a), fingerprint: H.fingerprintOf(a), title: "SQLi", location: { file: "src/db.js", line: 42 }, category: "SQL injection", cwe: "CWE-89", severity: "high", disposition: "reportable", confidence: "high", claim: "x", evidence: "y", remediation: "z", context: a.context };
const findings = H.buildFindings("scan_1", "repo", "2026-01-01T00:00:00Z", "standard", [finding]);
assert("findings wrapper", findings.scanId === "scan_1" && findings.findings.length === 1);

const sarif = JSON.parse(H.stableStringify(H.buildSarif([finding], "repo", "scan_1")));
const rule = sarif.runs[0].tool.driver.rules[0];
const result = sarif.runs[0].results[0];
assert("sarif version 2.1.0", sarif.version === "2.1.0");
assert("sarif one result", sarif.runs[0].results.length === 1);
assert("sarif ruleId slug", result.ruleId === "sql-injection");
assert("sarif level error", result.level === "error");
assert("sarif cwe property", result.properties.cwe === "CWE-89", JSON.stringify(result.properties));
assert("sarif rule security-severity", rule.properties["security-severity"] === 8.0, JSON.stringify(rule.properties));
assert("sarif rule cwe relationship", rule.relationships[0].target.id === "CWE-89", JSON.stringify(rule.relationships));
assert("sarif fingerprint", result.properties.dshSecurity.fingerprint === finding.fingerprint);

// buildManifest + hashes
const manifest = H.buildManifest("scan_1", "repo", "standard", "t0", "t1", "completed", [{ path: "findings.json", bytes: 10, sha256: "ab" }]);
assert("manifest status", manifest.status === "completed" && manifest.artifacts.length === 1);

// buildReport
const report = H.buildReport("scan_1", "repo", "2026-01-01T00:00:00Z", 1, [finding]);
assert("report contains title", report.includes("SQLi"));
assert("report contains severity", report.includes("HIGH"));

// buildReductions (real root-cause clusters via transitive closure)
const rf1 = { id: "csf_aaaa", fingerprint: "fp_0001", category: "SQL injection", location: { file: "src/db.js" }, severity: "high" };
const rf2 = { id: "csf_bbbb", fingerprint: "fp_0002", category: "SQL injection", location: { file: "src/db.js" }, severity: "medium" };
const rf3 = { id: "csf_cccc", fingerprint: "fp_0003", category: "XSS", location: { file: "src/index.js" }, severity: "low" };
const rPass = new Map([["fp_0001", 1], ["fp_0002", 2], ["fp_0003", 1]]);
const red = H.buildReductions([rf1, rf2, rf3], rPass);
assert("reductions mode deep", red.mode === "deep");
assert("reductions one cluster (db.js SQLi merged)", red.clusterCount === 1, JSON.stringify(red.clusters));
assert("reductions canonical is higher severity", red.clusters[0].canonicalFindingId === "csf_aaaa", JSON.stringify(red.clusters[0]));
assert("reductions first/last pass", red.clusters[0].firstPass === 1 && red.clusters[0].lastPass === 2, JSON.stringify(red.clusters[0]));

// computeSnapshotDigest
const cov = { scannedFiles: ["src/db.js", "src/index.js"], fileHashes: { "src/db.js": "h1", "src/index.js": "h2" } };
const dig = H.computeSnapshotDigest(cov);
assert("snapshot digest prefix", dig.startsWith("dsh-security-snapshot/v1:sha256:"), dig);
assert("snapshot digest deterministic", dig === H.computeSnapshotDigest(cov));

// diff.js must share the same deterministic contract helpers
const diffSrc = readFileSync(join(here, "..", "workflow", "diff.js"), "utf8");
const diffStart = diffSrc.indexOf("/* @contract-helpers-start */");
const diffEnd = diffSrc.indexOf("/* @contract-helpers-end */");
if (diffStart === -1 || diffEnd === -1) throw new Error("diff contract helper markers not found");
const diffBlock = diffSrc.slice(diffStart + "/* @contract-helpers-start */".length, diffEnd);
const D = new Function(prelude + diffBlock + "\nreturn {fnv1a, hash64, fingerprintOf, idOf, slugify, sevToLevel, sevScore, stableStringify, utf8Len, sha256Hex, buildFindings, buildSarif, buildManifest, buildReport, buildReductions, computeSnapshotDigest};")();
assert("diff id parity with scan", D.idOf(a) === H.idOf(a));
assert("diff sha256 parity (CJK)", D.sha256Hex("安全审计 test") === H.sha256Hex("安全审计 test"));
const diffSarif = JSON.parse(D.stableStringify(D.buildSarif([finding], "repo", "dscan_1")));
assert("diff sarif cwe property", diffSarif.runs[0].results[0].properties.cwe === "CWE-89");
assert("diff sarif security-severity", diffSarif.runs[0].tool.driver.rules[0].properties["security-severity"] === 8.0);
const diffReport = D.buildReport("dscan_1", "repo", "2026-01-01T00:00:00Z", 1, [finding], { title: "安全审计报告（diff 扫描）", scope: "`main..HEAD`", coverage: "见 `diff-scope.json` 与 `coverage.json`", footer: "diff footer" });
assert("diff report custom title", diffReport.includes("安全审计报告（diff 扫描）"));
assert("diff report custom scope", diffReport.includes("main..HEAD"));
assert("diff report custom footer", diffReport.includes("diff footer"));
assert("diff snapshot digest parity", D.computeSnapshotDigest(cov) === dig);

console.log("\nRESULT pass=" + pass + " fail=" + fail);
if (fail > 0) process.exit(1);
