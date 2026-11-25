const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { render } = require("./render-reports.cjs");
const { CHECKLIST } = require("./validate-conformance.cjs");

const step = (kind, file, line) => ({ kind, file, line, scope: "handle", description: "Data reaches the operation." });
const proof = (file, line) => ({ file, line, description: "The check is absent here." });

function fixtures() {
  const findings = [
    {
      verdict: "confirmed", fingerprint: "a-missing-owner-check", title: "Missing ownership check", description: "A user changes another user's object.",
      standards: { cwe: ["CWE-639"], owasp_top10: ["A01:2025"], owasp_asvs: ["v5.0.0-8.2.2"], iso27001: ["A.8.3"] },
      root_cause: "handle omits the ownership check.", intended_behavior: "Only the owner can change an object.",
      trace: [step("entrypoint", "src/routes.js", 10), step("sink", "src/store.js", 30)], evidence: [proof("src/routes.js", 10)], conditions: [],
      execution: { attacker_perspective: "A user with an ordinary account.", payloads: ["id of another user's object"], instructions: ["Send the update with that id."], observed_result: "The other user's object changed." },
      remediation: { strategy: "Check ownership before the update.", code_changes: [{ file_name: "src/routes.js", fixed_code: "requireOwner(req)" }] },
      severity: { likelihood: { score: "high", reason: "Directly reachable." }, impact: { score: "high", reason: "Cross-user write." }, overall_severity: "high" },
      confidence: { score: "high", reason: "Reproduced locally." },
    },
    {
      verdict: "needs_validation", fingerprint: "b-proxy-header-trust", title: "Forwarded header trusted", description: "The app may trust a client-set header.",
      standards: { cwe: ["CWE-348"], iso27001: ["A.8.9"] }, claimed_root_cause: "No trusted proxy list.",
      trace: [step("entrypoint", "src/app.js", 5)], evidence: [proof("src/app.js", 5)], blockers: ["Whether a proxy strips the header is not in source."],
      validation_plan: { deployment: "Check the proxy configuration for the header." },
    },
    {
      verdict: "rejected", fingerprint: "c-refuted", title: "Refuted claim", description: "Claimed bypass.", claimed_root_cause: "Claimed missing check.",
      trace: [step("sink", "src/x.js", 1)], evidence: [proof("src/x.js", 1)], reason: "The check exists.",
    },
  ];
  const conformance = [...CHECKLIST.keys()].sort().map((id) => ({ control_id: id, status: "met", title: `Control ${id} present`, summary: "Present.", evidence: [proof("src/app.js", 12)] }));
  const set = (id, record) => { conformance[conformance.findIndex((entry) => entry.control_id === id)] = { control_id: id, ...record }; };
  set("AC-02", { status: "gap", title: "Object scope missing", summary: "Updates are not scoped to the owner.", evidence: [proof("src/routes.js", 10)], remediation: { strategy: "Scope the query to the caller." }, priority: { level: "high", reason: "Other users' data." }, related_fingerprints: ["a-missing-owner-check"] });
  set("AU-03", { status: "gap", title: "Login not throttled", summary: "No throttle on login.", evidence: [proof("src/login.js", 4)], remediation: { strategy: "Throttle the login route." }, priority: { level: "high", reason: "Reachable before authentication." } });
  set("LG-06", { status: "not_assessed", title: "Log storage", reason: "Log shipping is a deployment fact.", owner_check: "Check where production logs go." });
  set("AC-06", { status: "not_applicable", title: "No outbound requests", reason: "The server fetches no caller-influenced URL." });
  const ledger = [{ status: "covered", surface: "API", attack_class: "Access control", result_fingerprints: [], unresolved: [], hunter_hardening: ["AU-03: login has no throttle"] },
    { status: "deferred", surface: "CLI", attack_class: "Injection", result_fingerprints: [], unresolved: ["quick_profile_final_critic"] }];
  const meta = { run_id: "demo-run-1", repo: "demo", profile: "quick", scope_paths: ["."], budget: 10, source_ref: { commit: "abc123", dirty: false }, prior_runs: [], sandbox: { image: "demo:latest" }, verify_command: "npm test" };
  return { "findings.json": findings, "conformance.json": conformance, "coverage-ledger.json": ledger, "run-metadata.json": meta };
}

test("renders the five prose files from the run records", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "render-reports-"));
  try {
    for (const [name, value] of Object.entries(fixtures())) fs.writeFileSync(path.join(directory, name), JSON.stringify(value));
    const result = render(directory);
    assert.deepEqual(result.files, ["REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md", "STANDARDS-REPORT.md", "REMEDIATION.md"]);
    assert.equal(result.tasks, 2, "one task for the finding with its merged gap, one for the other gap");
    assert.equal(result.merged_gaps, 1);
    assert.equal(result.decisions, 2, "one lead and one control that was not assessed");
    const read = (name) => fs.readFileSync(path.join(directory, name), "utf8");

    const remediation = read("REMEDIATION.md");
    assert.match(remediation, /### T01: Missing ownership check/);
    assert.match(remediation, /also closes control `AC-02`/);
    assert.match(remediation, /### T02: Login not throttled/);
    assert.match(remediation, /A missing control, not a demonstrated vulnerability/);
    assert.match(remediation, /### D01: Forwarded header trusted/);
    assert.match(remediation, /### D02: LG-06 Log storage/);
    assert.match(remediation, /`npm test`/);
    assert.match(remediation, /partial pass/);
    assert.doesNotMatch(remediation, /c-refuted/);
    assert.equal(remediation.match(/a-missing-owner-check/g).length, 1, "each confirmed fingerprint appears once");

    const report = read("REPORT.md");
    assert.match(report, /\| high \| Missing ownership check \| `src\/routes\.js:10` \|/);
    assert.match(report, /## 5\. NEEDS VALIDATION/);
    assert.match(report, /They are not confirmed vulnerabilities and carry no severity/);
    assert.match(report, /deferred: CLI \/ Injection \(quick_profile_final_critic\)/);
    assert.match(report, /certifies conformity with none/);

    const standards = read("STANDARDS-REPORT.md");
    assert.match(standards, /\| A01 Broken Access Control \| A01, A10 \| 1 \| 0 \| 1 \|/);
    assert.match(standards, /Not reached by the checklist: .*V17 WebRTC/);
    assert.match(standards, /does not state conformity or nonconformity/);
    assert.doesNotMatch(standards + report + remediation, /\bcompliant\b/i);

    assert.match(read("FINDINGS-DETAIL.md"), /requireOwner\(req\)/);
    assert.match(read("NEEDS-VALIDATION.md"), /Owner-observed check/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
