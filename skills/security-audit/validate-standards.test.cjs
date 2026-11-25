const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const reportSchema = require("./report-schema.json");
const conformanceSchema = require("./conformance-schema.json");
const checklist = require("./conformance-checklist.json");
const index = require("./standards-index.json");
const { collectStandardsErrors, hasFrameworkReference, top10Title, asvsSectionTitle } = require("./standards.cjs");
const { validateDocument: validateFindings } = require("./validate-findings.cjs");
const { CHECKLIST, validateDocument: validateConformance } = require("./validate-conformance.cjs");

const findingsValidator = path.join(__dirname, "validate-findings.cjs");
const conformanceValidator = path.join(__dirname, "validate-conformance.cjs");
const CLI_TIMEOUT_MS = 5000;

function source(kind = "entrypoint", file = "src/handler.c", line = 10) {
  return { kind, file, line, scope: "handle", description: "Attacker data reaches the operation." };
}

function evidence(file = "src/handler.c", line = 10) {
  return { file, line, description: "The source performs the operation without the required check." };
}

function standards() {
  return {
    cwe: ["CWE-639"],
    owasp_top10: ["A01:2025", "A01:2021"],
    owasp_asvs: ["v5.0.0-8.2.2"],
    iso27001: ["A.8.3"],
  };
}

function confirmed() {
  return {
    verdict: "confirmed",
    fingerprint: "src-handler-missing-check",
    title: "Missing ownership check",
    description: "An attacker can reach an operation without the intended ownership check.",
    standards: standards(),
    root_cause: "handle omits the ownership check before changing the object.",
    intended_behavior: "Only the object's owner can change it.",
    trace: [source("entrypoint"), source("sink", "src/store.c", 30)],
    evidence: [evidence()],
    conditions: [],
    execution: {
      attacker_perspective: "An unprivileged remote user with their own account.",
      payloads: ["An object identifier owned by another user."],
      instructions: ["Submit the identifier through the public operation."],
      observed_result: "The other user's object changes.",
    },
    remediation: { strategy: "Check ownership before the state change." },
    severity: {
      likelihood: { score: "medium", reason: "The operation is directly reachable." },
      impact: { score: "medium", reason: "The attacker changes one protected object." },
      overall_severity: "medium",
    },
    confidence: { score: "high", reason: "The source path and result were reproduced." },
  };
}

function needsValidation() {
  return {
    verdict: "needs_validation",
    fingerprint: "src-parser-size-hypothesis",
    title: "Unchecked parsed size",
    description: "A parsed size may reach an allocation without a limit.",
    standards: { cwe: ["CWE-770"], iso27001: ["A.8.28"] },
    claimed_root_cause: "parse_size may pass an unbounded value to allocate.",
    trace: [source()],
    evidence: [evidence()],
    blockers: ["The generated parser source is absent from this checkout."],
    validation_plan: { local: "Generate the parser and submit the smallest input over the documented limit." },
  };
}

function rejected() {
  return {
    verdict: "rejected",
    fingerprint: "src-router-auth-bypass",
    title: "Authorization bypass in router",
    description: "The candidate claimed a route bypassed authorization.",
    claimed_root_cause: "dispatch was claimed to skip the authorization wrapper.",
    trace: [source("sink")],
    evidence: [evidence()],
    reason: "All routes pass through the authorization wrapper before dispatch.",
  };
}

function findingsErrors(findings, options) {
  return validateFindings(findings, reportSchema, options);
}

function fullConformance() {
  const records = [];
  for (const id of [...CHECKLIST.keys()].sort()) {
    records.push({
      control_id: id,
      status: "met",
      title: `Control ${id}`,
      summary: "The control is implemented at the cited location.",
      evidence: [evidence("src/app.js", 12)],
    });
  }
  return records;
}

function replaceRecord(records, id, replacement) {
  const position = records.findIndex((record) => record.control_id === id);
  assert.notEqual(position, -1, id);
  records[position] = { control_id: id, ...replacement };
  return records;
}

function gap(extra = {}) {
  return {
    status: "gap",
    title: "Login is not rate limited",
    summary: "The login route has no throttle and no lockout.",
    evidence: [evidence("routes/web.php", 20)],
    remediation: { strategy: "Add a per-account and per-address throttle to the login route." },
    priority: { level: "high", reason: "The endpoint is reachable before authentication." },
    ...extra,
  };
}

function conformanceErrors(records, options) {
  return validateConformance(records, conformanceSchema, options);
}

function runCli(validator, files, args = []) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-standards-"));
  try {
    const paths = Object.entries(files).map(([name, value]) => {
      const file = path.join(directory, name);
      fs.writeFileSync(file, JSON.stringify(value));
      return file;
    });
    const resolved = args.map((argument) => argument.startsWith("@") ? path.join(directory, argument.slice(1)) : argument);
    return spawnSync(process.execPath, [validator, ...resolved, paths[0]], { encoding: "utf8", timeout: CLI_TIMEOUT_MS });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("accepts existing identifiers of every standard", () => {
  assert.deepEqual(collectStandardsErrors(standards(), "$.standards"), []);
  assert.deepEqual(collectStandardsErrors({ owasp_asvs: ["v5.0.0-8.2"] }, "$.standards"), []);
  assert.equal(hasFrameworkReference(standards()), true);
  assert.equal(hasFrameworkReference({ cwe: ["CWE-79"] }), false);
});

test("rejects identifiers that no standard defines", () => {
  const cases = [
    [{ cwe: ["CWE-0"] }, /expected the form CWE-<number>/],
    [{ cwe: ["cwe-79"] }, /expected the form CWE-<number>/],
    [{ owasp_top10: ["A11:2025"] }, /expected the form A01:2025/],
    [{ owasp_top10: ["A01:2023"] }, /expected the form A01:2025/],
    [{ owasp_asvs: ["v5.0.0-8.9"] }, /section 8\.9, which ASVS 5\.0\.0 does not have/],
    [{ owasp_asvs: ["v5.0.0-8.2.9"] }, /beyond the 4 that ASVS 5\.0\.0 section 8\.2 has/],
    [{ owasp_asvs: ["v4.0.3-1.2.3"] }, /expected the form v5\.0\.0-/],
    [{ owasp_asvs: ["V8.2.2"] }, /expected the form v5\.0\.0-/],
    [{ iso27001: ["A.8.35"] }, /beyond the 34 that Annex A theme 8 has/],
    [{ iso27001: ["A.6.9"] }, /beyond the 8 that Annex A theme 6 has/],
    [{ iso27001: ["A.9.1"] }, /expected the form A\.<theme>\.<control>/],
    [{ iso27001: ["8.28"] }, /expected the form A\.<theme>\.<control>/],
    [{ nist: ["AC-3"] }, /unknown standard/],
    [{ cwe: [] }, /expected a non-empty array/],
    [{ cwe: ["CWE-79", "CWE-79"] }, /duplicate reference/],
    [{}, /must cite at least one reference/],
  ];
  for (const [value, expected] of cases) {
    const errors = collectStandardsErrors(value, "$.standards");
    assert.equal(errors.length, 1, `${JSON.stringify(value)} -> ${JSON.stringify(errors)}`);
    assert.match(errors[0], expected);
  }
});

test("rejects CWE views, categories and pillars as mapping targets", () => {
  for (const [id, kind] of [["CWE-1000", /view/], ["CWE-1003", /view/], ["CWE-16", /category/], ["CWE-264", /category/], ["CWE-284", /pillar/], ["CWE-693", /pillar/]]) {
    const errors = collectStandardsErrors({ cwe: [id] }, "$.standards");
    assert.equal(errors.length, 1, id);
    assert.match(errors[0], kind);
    assert.match(errors[0], /cannot classify a record/);
  }
});

test("does not echo hostile identifier text into diagnostics", () => {
  const errors = collectStandardsErrors({ cwe: ["CWE-79\u001b[31m‮"] }, "$.standards");
  assert.equal(errors.length, 1);
  assert.doesNotMatch(errors[0], /\u001b|‮/);
});

test("resolves titles for report writers", () => {
  assert.equal(top10Title("A01:2025"), "Broken Access Control");
  assert.equal(top10Title("A10:2021"), "Server-Side Request Forgery (SSRF)");
  assert.equal(top10Title("A11:2025"), null);
  assert.equal(asvsSectionTitle("v5.0.0-8.2.2"), "General Authorization Design");
  assert.equal(asvsSectionTitle("v5.0.0-99.1"), null);
});

test("index tables are internally consistent", () => {
  assert.equal(Object.keys(index.owasp_top10["2025"]).length, 10);
  assert.equal(Object.keys(index.owasp_top10["2021"]).length, 10);
  assert.equal(Object.keys(index.owasp_asvs.chapters).length, 17);
  const requirements = Object.values(index.owasp_asvs.requirements_per_section).reduce((sum, count) => sum + count, 0);
  assert.equal(requirements, 345);
  assert.deepEqual(Object.keys(index.owasp_asvs.section_titles), Object.keys(index.owasp_asvs.requirements_per_section));
  const controls = Object.values(index.iso27001.controls_per_theme).reduce((sum, count) => sum + count, 0);
  assert.equal(controls, 93);
});

test("findings keep standards optional by default and validate them when present", () => {
  const withoutStandards = confirmed();
  delete withoutStandards.standards;
  assert.deepEqual(findingsErrors([withoutStandards]), []);
  assert.deepEqual(findingsErrors([confirmed(), needsValidation(), rejected()].sort((a, b) => a.fingerprint < b.fingerprint ? -1 : 1)), []);

  const invented = confirmed();
  invented.standards.owasp_asvs = ["v5.0.0-8.2.9"];
  const errors = findingsErrors([invented]);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /\$\[0\]\.standards\.owasp_asvs\[0\]/);

  const view = confirmed();
  view.standards.cwe = ["CWE-1000"];
  assert.match(findingsErrors([view]).join("\n"), /Complete Weakness Hierarchy/);

  const unknownKey = confirmed();
  unknownKey.standards.pci = ["6.2.4"];
  assert.match(findingsErrors([unknownKey]).join("\n"), /unexpected field "pci"/);
});

test("--require-standards demands a CWE and a framework reference on reported records", () => {
  const options = { requireStandards: true };
  assert.deepEqual(findingsErrors([confirmed()], options), []);
  assert.deepEqual(findingsErrors([needsValidation()], options), []);
  assert.deepEqual(findingsErrors([rejected()], options), [], "rejected records need no mapping");

  const missing = confirmed();
  delete missing.standards;
  const missingErrors = findingsErrors([missing], options);
  assert.equal(missingErrors.length, 2);
  assert.match(missingErrors[0], /requires at least one CWE reference/);
  assert.match(missingErrors[1], /requires an OWASP Top 10, OWASP ASVS or ISO\/IEC 27001 reference/);

  const cweOnly = needsValidation();
  cweOnly.standards = { cwe: ["CWE-770"] };
  const cweOnlyErrors = findingsErrors([cweOnly], options);
  assert.equal(cweOnlyErrors.length, 1);
  assert.match(cweOnlyErrors[0], /needs_validation finding requires an OWASP Top 10/);

  const frameworkOnly = confirmed();
  frameworkOnly.standards = { owasp_top10: ["A01:2025"] };
  const frameworkOnlyErrors = findingsErrors([frameworkOnly], options);
  assert.equal(frameworkOnlyErrors.length, 1);
  assert.match(frameworkOnlyErrors[0], /requires at least one CWE reference/);
});

test("findings CLI accepts the flag in either position and rejects unknown flags", () => {
  const missing = confirmed();
  delete missing.standards;
  assert.equal(runCli(findingsValidator, { "findings.json": [missing] }).status, 0);
  const strict = runCli(findingsValidator, { "findings.json": [missing] }, ["--require-standards"]);
  assert.equal(strict.status, 1);
  assert.match(strict.stderr, /requires at least one CWE reference/);
  assert.equal(runCli(findingsValidator, { "findings.json": [confirmed()] }, ["--require-standards"]).status, 0);
  const unknown = runCli(findingsValidator, { "findings.json": [confirmed()] }, ["--strict"]);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /Usage:/);
});

test("every checklist control cites existing identifiers and a framework", () => {
  assert.equal(CHECKLIST.size, 67);
  for (const [id, control] of CHECKLIST) {
    assert.match(id, /^[A-Z]{2}-[0-9]{2}$/);
    assert.equal(id.slice(0, 2), control.family, id);
    assert.deepEqual(collectStandardsErrors(control.standards, id), [], id);
    assert.equal(hasFrameworkReference(control.standards), true, id);
    assert(control.statement.length > 40, id);
  }
  const ids = Object.values(checklist.families).flatMap((family) => family.controls.map((control) => control.control_id));
  assert.equal(new Set(ids).size, ids.length);
});

test("accepts a complete conformance document in every status", () => {
  const records = fullConformance();
  replaceRecord(records, "AU-03", gap({ related_fingerprints: ["src-handler-missing-check"] }));
  replaceRecord(records, "AC-06", { status: "not_applicable", title: "No outbound requests", reason: "The application makes no server-side request to a caller-influenced URL." });
  replaceRecord(records, "LG-06", { status: "not_assessed", title: "Log retention", reason: "Log shipping is a deployment fact absent from the repository.", owner_check: "Confirm where production logs are stored and who can read them." });
  records.push({
    control_id: "X-TENANT-EXPORT",
    status: "met",
    title: "Exports are scoped to the caller's tenant",
    summary: "The export query filters on the tenant of the session.",
    evidence: [evidence("src/export.js", 40)],
    standards: { owasp_asvs: ["v5.0.0-8.4.1"], iso27001: ["A.8.3"] },
  });
  assert.deepEqual(conformanceErrors(records), []);
  assert.deepEqual(conformanceErrors(records, { fingerprints: new Set(["src-handler-missing-check"]) }), []);
});

test("rejects a conformance document that skips, repeats or misorders controls", () => {
  const skipped = fullConformance().filter((record) => record.control_id !== "CF-01");
  assert.match(conformanceErrors(skipped).join("\n"), /checklist control "CF-01" is missing/);

  const repeated = fullConformance();
  repeated.splice(1, 0, { ...repeated[0] });
  assert.match(conformanceErrors(repeated).join("\n"), /duplicate control "AC-01"/);

  const misordered = fullConformance();
  [misordered[0], misordered[1]] = [misordered[1], misordered[0]];
  assert.match(conformanceErrors(misordered).join("\n"), /must be sorted by control_id/);

  const unknown = fullConformance();
  unknown.push({ ...unknown[0], control_id: "ZZ-99" });
  assert.match(conformanceErrors(unknown).join("\n"), /is not a checklist control/);
});

test("enforces the fields each conformance status needs", () => {
  const withoutEvidence = fullConformance();
  delete withoutEvidence[0].evidence;
  assert.match(conformanceErrors(withoutEvidence).join("\n"), /missing required field "evidence"/);

  const gapWithoutFix = replaceRecord(fullConformance(), "AU-03", gap());
  delete gapWithoutFix.find((record) => record.control_id === "AU-03").remediation;
  assert.match(conformanceErrors(gapWithoutFix).join("\n"), /missing required field "remediation"/);

  const gapWithSeverity = replaceRecord(fullConformance(), "AU-03", gap({ severity: "high" }));
  assert.match(conformanceErrors(gapWithSeverity).join("\n"), /unexpected field "severity"/);

  const notAssessed = replaceRecord(fullConformance(), "LG-06", { status: "not_assessed", title: "Log retention", reason: "Deployment fact." });
  assert.match(conformanceErrors(notAssessed).join("\n"), /missing required field "owner_check"/);

  const unsafePath = fullConformance();
  unsafePath[0].evidence = [evidence("../outside.js", 1)];
  assert.match(conformanceErrors(unsafePath).join("\n"), /safe repository-relative source path/);

  const custom = fullConformance();
  custom.push({ control_id: "X-CUSTOM", status: "met", title: "Custom", summary: "Present.", evidence: [evidence()] });
  assert.match(conformanceErrors(custom).join("\n"), /target-specific control must cite/);

  const invented = fullConformance();
  invented[0].standards = { iso27001: ["A.8.40"] };
  assert.match(conformanceErrors(invented).join("\n"), /beyond the 34 that Annex A theme 8 has/);
});

test("checks related fingerprints against findings.json when it is supplied", () => {
  const records = replaceRecord(fullConformance(), "AU-03", gap({ related_fingerprints: ["no-such-record"] }));
  assert.deepEqual(conformanceErrors(records), []);
  assert.match(conformanceErrors(records, { fingerprints: new Set(["other"]) }).join("\n"), /"no-such-record" is not a record in findings\.json/);
});

test("conformance CLI reports counts, failures and usage", () => {
  const records = replaceRecord(fullConformance(), "AU-03", gap({ related_fingerprints: ["src-handler-missing-check"] }));
  const pass = runCli(conformanceValidator, { "conformance.json": records });
  assert.equal(pass.status, 0, pass.stderr);
  assert.match(pass.stdout, /PASS: 67 controls valid \(66 met, 1 gap, 0 not applicable, 0 not assessed\)/);

  const linked = runCli(conformanceValidator, { "conformance.json": records, "findings.json": [confirmed()] }, ["--findings", "@findings.json"]);
  assert.equal(linked.status, 0, linked.stderr);

  const unlinked = runCli(conformanceValidator, { "conformance.json": records, "findings.json": [rejected()] }, ["--findings", "@findings.json"]);
  assert.equal(unlinked.status, 1);
  assert.match(unlinked.stderr, /is not a record in findings\.json/);

  const empty = runCli(conformanceValidator, { "conformance.json": [] });
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /checklist control "AC-01" is missing/);

  const usage = spawnSync(process.execPath, [conformanceValidator], { encoding: "utf8", timeout: CLI_TIMEOUT_MS });
  assert.equal(usage.status, 1);
  assert.match(usage.stderr, /Usage: node validate-conformance\.cjs/);
});

test("every identifier in the STANDARDS.md crosswalk and reference tables resolves", () => {
  const text = fs.readFileSync(path.join(__dirname, "STANDARDS.md"), "utf8");
  const start = text.indexOf("## Crosswalk by attack class");
  const end = text.indexOf("## Reference: OWASP Top 10");
  assert(start !== -1 && end > start);
  const rows = text.slice(start, end).split("\n")
    .filter((line) => line.startsWith("| ") && !line.startsWith("| Root cause") && !line.startsWith("|---"));
  assert(rows.length >= 45, `crosswalk rows: ${rows.length}`);

  for (const row of rows) {
    const cells = row.split("|").slice(1, -1).map((cell) => cell.trim());
    assert.equal(cells.length, 6, row);
    const [label, cwe, top2025, top2021, asvs, iso] = cells;
    const mapping = {};
    mapping.cwe = cwe.split(",").map((value) => value.trim());
    const categories = [];
    for (const [cell, edition] of [[top2025, "2025"], [top2021, "2021"]]) {
      if (cell === "none fits") continue;
      const matches = cell.match(/A(?:0[1-9]|10)/g);
      assert(matches, `${label}: ${cell}`);
      for (const category of matches) categories.push(`${category}:${edition}`);
    }
    if (categories.length > 0) mapping.owasp_top10 = categories;
    if (asvs !== "none fits") mapping.owasp_asvs = asvs.split(",").map((value) => `v5.0.0-${value.trim()}`);
    mapping.iso27001 = iso.split(",").map((value) => value.trim());
    assert.deepEqual(collectStandardsErrors(mapping, label), [], label);
  }

  const isoStart = text.indexOf("## Reference: ISO/IEC 27001:2022");
  const isoEnd = text.indexOf("## Validation rules");
  const isoControls = text.slice(isoStart, isoEnd).match(/A\.[5-8]\.[0-9]+/g);
  assert(isoControls.length >= 40);
  assert.deepEqual(collectStandardsErrors({ iso27001: [...new Set(isoControls)].slice(0, 12) }, "iso"), []);
  for (const control of new Set(isoControls)) {
    assert.deepEqual(collectStandardsErrors({ iso27001: [control] }, control), [], control);
  }

  for (const edition of ["2025", "2021"]) {
    for (const [category, title] of Object.entries(index.owasp_top10[edition])) {
      const shown = title.split(" (")[0];
      assert(text.includes(shown), `${category}:${edition} ${shown}`);
    }
  }
  for (const title of Object.values(index.owasp_asvs.chapters)) assert(text.includes(title), title);
});

test("the prose files point at every shipped standards artifact", () => {
  const skill = fs.readFileSync(path.join(__dirname, "SKILL.md"), "utf8");
  for (const name of ["STANDARDS.md", "STANDARDS-CONFORMANCE.md", "REMEDIATION-HANDOFF.md", "SANDBOX.md", "conformance.json", "STANDARDS-REPORT.md", "REMEDIATION.md", "validate-conformance.cjs", "--require-standards"]) {
    assert(skill.includes(name), `SKILL.md does not mention ${name}`);
  }
  const reporting = fs.readFileSync(path.join(__dirname, "VALIDATION-AND-REPORTING.md"), "utf8");
  assert.match(reporting, /validate-findings\.cjs --require-standards/);
  assert.match(reporting, /validate-conformance\.cjs --findings/);
  assert.match(reporting, /### Phase 7: Write the remediation handoff/);
  const conformance = fs.readFileSync(path.join(__dirname, "STANDARDS-CONFORMANCE.md"), "utf8");
  for (const [family, entry] of Object.entries(checklist.families)) {
    assert.match(conformance, new RegExp(`\\| ${family} \\| ${entry.controls.length} \\|`), `family ${family} count in STANDARDS-CONFORMANCE.md`);
  }
});
