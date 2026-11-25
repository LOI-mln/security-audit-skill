#!/usr/bin/env node

/**
 * Derives the Phase 6 and Phase 7 prose files from the validated run files.
 * Usage: node render-reports.cjs <output-dir>
 *
 * Reads run-metadata.json, findings.json, conformance.json and
 * coverage-ledger.json and writes REPORT.md, FINDINGS-DETAIL.md,
 * NEEDS-VALIDATION.md, STANDARDS-REPORT.md and REMEDIATION.md. Every verdict,
 * severity, priority, blocker and fix is copied from the records, so the prose
 * cannot disagree with the JSON. Run the validators first; the parent may then
 * edit wording, never a verdict or a level.
 */

const fs = require("node:fs");
const path = require("node:path");
const checklist = require("./conformance-checklist.json");
const index = require("./standards-index.json");
const { top10Title, asvsSectionTitle } = require("./standards.cjs");

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const PRIORITIES = ["high", "medium", "low"];
const STATUSES = ["met", "gap", "not_applicable", "not_assessed"];
// The 2021 category each 2025 category succeeded, as the 2025 edition describes it.
const PREDECESSOR_2021 = { A01: "A01, A10", A02: "A05", A03: "A06", A04: "A02", A05: "A03", A06: "A04", A07: "A07", A08: "A08", A09: "A09", A10: "new in 2025" };

const CONTROLS = new Map();
for (const [family, entry] of Object.entries(checklist.families)) {
  for (const control of entry.controls) CONTROLS.set(control.control_id, { family, familyTitle: entry.title, ...control });
}

const readJson = (file, fallback) => {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch (error) { if (fallback !== undefined) return fallback; throw error; }
};
const one = (text) => String(text ?? "").replace(/\s+/g, " ").trim();
const cell = (text) => one(text).replace(/\|/g, "\\|");
const brief = (text, max = 180) => { const value = one(text); return value.length > max ? value.slice(0, max - 1).trimEnd() + "…" : value; };
const where = (entry) => `\`${entry.file}:${entry.line}\``;
const code = (value) => `\`${value}\``;
const list = (items) => items.map((item) => `- ${one(item)}`).join("\n");
const table = (header, rows) => [`| ${header.join(" | ")} |`, `|${header.map(() => "---").join("|")}|`, ...rows.map((row) => `| ${row.map(cell).join(" | ")} |`)].join("\n");

function standardsOf(record) {
  if (record.standards) return record.standards;
  const control = CONTROLS.get(record.control_id);
  return control ? control.standards : {};
}

function standardsLine(standards) {
  const parts = [];
  for (const key of ["cwe", "owasp_top10", "owasp_asvs", "iso27001"]) {
    for (const reference of standards[key] || []) {
      if (key === "owasp_top10") parts.push(`${reference} ${top10Title(reference) || ""}`.trim());
      else if (key === "owasp_asvs") parts.push(`ASVS ${reference}`);
      else if (key === "iso27001") parts.push(`ISO/IEC 27001 ${reference}`);
      else parts.push(reference);
    }
  }
  return parts.join(" · ") || "none recorded";
}

function sourceRef(meta) {
  const ref = meta.source_ref;
  if (!ref) return "unknown";
  if (typeof ref === "string") return ref;
  return `${ref.commit || "unknown"}${ref.dirty ? " (worktree dirty)" : ""}`;
}

function partialNote(meta) {
  const notes = [];
  if (meta.profile === "quick") notes.push("quick profile");
  if (Array.isArray(meta.scope_paths) && !(meta.scope_paths.length === 1 && meta.scope_paths[0] === ".")) notes.push("scoped run");
  if (meta.run_status === "incomplete") notes.push(`incomplete: ${meta.incomplete_reason || "reason not recorded"}`);
  return notes.length ? `This is a partial pass (${notes.join(", ")}). Finishing every task does not mean the code is clean.` : "";
}

function render(outDir) {
  const meta = readJson(path.join(outDir, "run-metadata.json"));
  const findings = readJson(path.join(outDir, "findings.json"));
  const conformance = readJson(path.join(outDir, "conformance.json"), []);
  const ledger = readJson(path.join(outDir, "coverage-ledger.json"), []);

  const rank = (finding) => SEVERITIES.indexOf(finding.severity.overall_severity);
  const confirmed = findings.filter((finding) => finding.verdict === "confirmed").sort((a, b) => rank(a) - rank(b) || (a.fingerprint < b.fingerprint ? -1 : 1));
  const leads = findings.filter((finding) => finding.verdict === "needs_validation");
  const rejected = findings.filter((finding) => finding.verdict === "rejected");
  const byStatus = Object.fromEntries(STATUSES.map((status) => [status, conformance.filter((record) => record.status === status)]));
  const gaps = byStatus.gap.slice().sort((a, b) => PRIORITIES.indexOf(a.priority.level) - PRIORITIES.indexOf(b.priority.level) || (a.control_id < b.control_id ? -1 : 1));
  const fingerprints = new Set(confirmed.map((finding) => finding.fingerprint));
  const mergedGaps = new Map();
  for (const gap of gaps) {
    const target = (gap.related_fingerprints || []).find((fingerprint) => fingerprints.has(fingerprint));
    if (target) mergedGaps.set(gap.control_id, target);
  }
  const partial = partialNote(meta);
  const unitCounts = {};
  for (const unit of ledger) unitCounts[unit.status] = (unitCounts[unit.status] || 0) + 1;
  const unresolvedCandidates = ledger.filter((unit) => unit.status === "candidate")
    .flatMap((unit) => unit.result_fingerprints).filter((fingerprint) => !findings.some((finding) => finding.fingerprint === fingerprint));
  const title = (record) => one(record.title);
  const controlTitle = (record) => `${record.control_id} ${title(record)}`;

  // ------------------------------------------------------------ REPORT.md
  const top10Rows = Object.keys(index.owasp_top10["2025"]).map((category) => {
    const reference = `${category}:2025`;
    const has = (record) => (standardsOf(record).owasp_top10 || []).includes(reference);
    const counts = [confirmed.filter(has).length, leads.filter(has).length, byStatus.gap.filter(has).length, byStatus.met.filter(has).length, byStatus.not_assessed.filter(has).length];
    return { category, reference, counts, has, reviewed: counts.some((count) => count > 0) || byStatus.not_applicable.some(has) };
  });
  const report = [];
  report.push(`# Security audit report: ${meta.repo}`, "");
  report.push("## 1. Run", "");
  report.push(list([
    `Source ref: ${code(sourceRef(meta))}. Profile: ${meta.profile}. Scope: ${(meta.scope_paths || ["."]).join(", ")}.`,
    `Execution: source review and bounded local checks only, in a sandbox with no network (${meta.sandbox ? one(meta.sandbox.image || meta.sandbox.runtime) : "no sandbox was available, so nothing was executed"}). No deployed system was contacted.`,
    `Agents: budget ${meta.budget ?? "not set"}.${meta.budget_note ? " " + one(meta.budget_note) : ""}`,
    meta.agent_model_note ? one(meta.agent_model_note) : null,
    `Prior runs: ${(meta.prior_runs || []).length ? meta.prior_runs.join(", ") : "none; nothing was carried forward"}.`,
    meta.standards && meta.standards.resolution ? `Standards: ${one(meta.standards.resolution)}` : null,
    partial || null,
    unresolvedCandidates.length ? `Candidate validation is incomplete. These candidates were never verified and are not findings: ${unresolvedCandidates.map(code).join(", ")}.` : null,
  ].filter(Boolean)), "");
  report.push("## 2. Security posture", "", one(meta.posture_summary) || `${confirmed.length} confirmed findings, ${leads.length} leads that need validation, ${gaps.length} conformance gaps.`, "");
  report.push("## 3. Confirmed findings", "");
  report.push(confirmed.length ? table(["Severity", "Finding", "Location", "Observed result"], confirmed.map((finding) => [finding.severity.overall_severity, title(finding), where(finding.trace[0]), finding.execution.observed_result])) : "None.", "");
  report.push("## 4. Confirmed findings in detail", "");
  for (const finding of confirmed) {
    report.push(`### ${title(finding)}`, "");
    report.push(list([
      `Severity: **${finding.severity.overall_severity}** (likelihood ${finding.severity.likelihood.score}: ${one(finding.severity.likelihood.reason)}; impact ${finding.severity.impact.score}: ${one(finding.severity.impact.reason)}). Confidence ${finding.confidence.score}.`,
      `Record: ${code(finding.fingerprint)}. Standards: ${standardsLine(standardsOf(finding))}.`,
      `Location: ${finding.trace.map(where).join(" → ")}.`,
      `Lower-trust principal: ${one(finding.execution.attacker_perspective)}`,
      `Root cause: ${one(finding.root_cause)}`,
      `Bounded reproduction: ${finding.execution.instructions.map(one).join(" ")}`,
      finding.conditions.length ? `Conditions: ${finding.conditions.map((condition) => one(condition.description)).join("; ")}` : "Conditions: none beyond the principal above.",
      `Observed result: ${one(finding.execution.observed_result)}`,
      `Smallest fix: ${one(finding.remediation.strategy)}`,
    ]), "");
  }
  if (!confirmed.length) report.push("None.", "");
  report.push("## 5. NEEDS VALIDATION", "", "These are source-grounded leads whose deciding fact is outside the repository or the sandbox. They are not confirmed vulnerabilities and carry no severity.", "");
  report.push(leads.length ? table(["Lead", "Trace", "Blocker", "Local next step", "Owner-observed check"], leads.map((lead) => [title(lead), where(lead.trace[0]), lead.blockers.join("; "), lead.validation_plan.local || "none", lead.validation_plan.deployment || "none"])) : "None.", "");
  report.push("## 6. Hardening and positive patterns", "");
  report.push(`${gaps.length} expected controls are absent or partial. They are listed by control identifier in ${code("STANDARDS-REPORT.md")} and as tasks in ${code("REMEDIATION.md")}: ${gaps.map((gap) => gap.control_id).join(", ") || "none"}.`, "");
  report.push(`${byStatus.met.length} controls are in place: ${byStatus.met.map((record) => record.control_id).join(", ") || "none"}.`, "");
  const notes = ledger.flatMap((unit) => unit.hunter_hardening || []);
  if (notes.length) report.push("Hunter notes that are not findings:", "", list(notes.map((note) => brief(note, 320))), "");
  report.push("## 7. Coverage", "");
  report.push(list([
    `${ledger.length} coverage units: ${Object.entries(unitCounts).map(([status, count]) => `${count} ${status}`).join(", ")}.`,
    ...ledger.filter((unit) => ["deferred", "blocked", "out_of_scope"].includes(unit.status)).map((unit) => `${unit.status}: ${one(unit.surface)} / ${one(unit.attack_class)} (${unit.unresolved.map(one).join("; ")})`),
    meta.critic_result ? `Final critic: ${one(meta.critic_result)}` : "Final critic: not recorded.",
    rejected.length ? `${rejected.length} candidates were refuted during validation and are not findings: ${rejected.map((record) => code(record.fingerprint)).join(", ")}.` : null,
  ].filter(Boolean)), "");
  report.push("## 8. Standards", "");
  report.push("Records are classified against CWE, the OWASP Top 10 (2025, with 2021), OWASP ASVS 5.0.0 and ISO/IEC 27001:2022 Annex A. A source review gives evidence relevant to a standard. It certifies conformity with none.", "");
  report.push(table(["OWASP Top 10:2025", "Confirmed", "Needs validation", "Conformance gaps"], top10Rows.map((row) => [`${row.category} ${index.owasp_top10["2025"][row.category]}`, row.counts[0], row.counts[1], row.reviewed ? row.counts[2] : "not reviewed"])), "");
  report.push(`Conformance review: ${STATUSES.map((status) => `${byStatus[status].length} ${status.replace("_", " ")}`).join(", ")} of ${conformance.length} controls. Details: ${code("STANDARDS-REPORT.md")}. Work order: ${code("REMEDIATION.md")}.`, "");

  // --------------------------------------------------- FINDINGS-DETAIL.md
  const detail = [`# Findings detail: ${meta.repo}`, "", `Source ref ${code(sourceRef(meta))}. Confirmed records of medium severity and above, with their complete source path and bounded local reproduction.`, ""];
  const detailed = confirmed.filter((finding) => rank(finding) <= SEVERITIES.indexOf("medium"));
  for (const finding of detailed) {
    detail.push(`## ${title(finding)}`, "", `${code(finding.fingerprint)} · ${finding.severity.overall_severity} · ${standardsLine(standardsOf(finding))}`, "", one(finding.description), "");
    detail.push("**Trace**", "", list(finding.trace.map((step) => `${step.kind}: ${where(step)} in ${code(step.scope)}. ${one(step.description)}`)), "");
    detail.push("**Evidence**", "", list(finding.evidence.map((entry) => `${where(entry)}: ${one(entry.description)}`)), "");
    detail.push("**Reproduction**", "", `Principal: ${one(finding.execution.attacker_perspective)}`, "", "Input:", "", list(finding.execution.payloads.map((payload) => code(one(payload) || "(empty)"))), "", "Steps:", "", finding.execution.instructions.map((step, position) => `${position + 1}. ${one(step)}`).join("\n"), "", `Observed: ${one(finding.execution.observed_result)}`, "");
    detail.push("**Invariant**", "", one(finding.intended_behavior), "");
    if (finding.conditions.length) detail.push("**Conditions**", "", list(finding.conditions.map((condition) => `${condition.kind}: ${one(condition.description)}`)), "");
    detail.push("**Fix**", "", one(finding.remediation.strategy), "");
    for (const change of finding.remediation.code_changes || []) detail.push(`${code(change.file_name)}:`, "", "```", change.fixed_code, "```", "");
  }
  if (!detailed.length) detail.push("No confirmed record of medium severity or above.", "");

  // ------------------------------------------------- NEEDS-VALIDATION.md
  const validation = [`# Needs validation: ${meta.repo}`, "", "Leads with a real source path and one deciding fact that neither the repository nor the sandbox can settle. No severity is assigned. None of the checks below sends traffic to a deployed system: an owner looks at a configuration, a policy or a runtime fact.", ""];
  for (const lead of leads) {
    validation.push(`## ${title(lead)}`, "", `${code(lead.fingerprint)} · ${standardsLine(standardsOf(lead))}`, "", one(lead.description), "", `Claimed root cause: ${one(lead.claimed_root_cause)}`, "");
    validation.push("**Trace**", "", list(lead.trace.map((step) => `${step.kind}: ${where(step)} in ${code(step.scope)}. ${one(step.description)}`)), "");
    validation.push("**Evidence**", "", list(lead.evidence.map((entry) => `${where(entry)}: ${one(entry.description)}`)), "");
    validation.push("**Blockers**", "", list(lead.blockers), "");
    if (lead.validation_plan.local) validation.push(`**Bounded local check**: ${one(lead.validation_plan.local)}`, "");
    if (lead.validation_plan.deployment) validation.push(`**Owner-observed check**: ${one(lead.validation_plan.deployment)}`, "");
  }
  if (!leads.length) validation.push("None.", "");

  // -------------------------------------------------- STANDARDS-REPORT.md
  const standards = [`# Standards report: ${meta.repo}`, "", "## 1. Standards used", ""];
  standards.push(list([
    "MITRE CWE, OWASP Top 10 (2025 and 2021), OWASP ASVS 5.0.0, ISO/IEC 27001:2022 Annex A.",
    meta.standards && meta.standards.resolution ? one(meta.standards.resolution) : null,
  ].filter(Boolean)), "");
  standards.push("## 2. Limits of this review", "", list([
    "It covers what the repository shows. Process, people and physical controls, and anything decided at deployment, are not assessed.",
    "It is not an ISO/IEC 27001 audit and not an ASVS certification. It gives an owner or an auditor source evidence per control.",
    "A control marked met is present where the reviewer looked and no opt-out was found. It is not proof that the control has no defect.",
    "The checklist is a selection of source-verifiable controls, not the whole of ASVS.",
    partial || null,
  ].filter(Boolean)), "");
  const ids = (records, key) => records.map((record) => code(record[key])).join(", ") || "none";
  standards.push("## 3. OWASP Top 10:2025", "");
  standards.push(table(["Category", "2021", "Confirmed", "Needs validation", "Gaps", "Met", "Not assessed"], top10Rows.map((row) => {
    return [`${row.category} ${index.owasp_top10["2025"][row.category]}`, PREDECESSOR_2021[row.category], ...(row.reviewed ? row.counts : ["not reviewed", "", "", "", ""])];
  })), "");
  for (const row of top10Rows.filter((entry) => entry.reviewed)) {
    standards.push(`- **${row.reference}**: confirmed ${ids(confirmed.filter(row.has), "fingerprint")}; needs validation ${ids(leads.filter(row.has), "fingerprint")}; gaps ${ids(byStatus.gap.filter(row.has), "control_id")}; met ${ids(byStatus.met.filter(row.has), "control_id")}; not assessed ${ids(byStatus.not_assessed.filter(row.has), "control_id")}.`);
  }
  standards.push("", "## 4. OWASP ASVS 5.0.0", "");
  const chapterRows = [];
  const unreached = [];
  for (const [chapter, name] of Object.entries(index.owasp_asvs.chapters)) {
    const inChapter = (record) => (standardsOf(record).owasp_asvs || []).filter((reference) => reference.startsWith(`v5.0.0-${chapter}.`));
    const touched = conformance.filter((record) => inChapter(record).length);
    if (!touched.length) { unreached.push(`V${chapter} ${name}`); continue; }
    const count = (status) => touched.filter((record) => record.status === status).map((record) => record.control_id).join(", ") || "0";
    chapterRows.push([`V${chapter} ${name}`, count("met"), count("gap"), count("not_applicable"), count("not_assessed"), [...new Set(touched.filter((record) => record.status === "gap").flatMap(inChapter))].map((reference) => reference.slice(7)).join(", ") || "none"]);
  }
  standards.push(table(["Chapter", "Met", "Gap", "Not applicable", "Not assessed", "Requirements behind the gaps"], chapterRows), "");
  if (unreached.length) standards.push(`Not reached by the checklist: ${unreached.join(", ")}.`, "");
  standards.push("## 5. ISO/IEC 27001:2022 Annex A", "", "Each line lists source evidence relevant to a control. It does not state conformity or nonconformity.", "");
  const iso = new Map();
  const addIso = (record, label) => { for (const reference of standardsOf(record).iso27001 || []) { if (!iso.has(reference)) iso.set(reference, []); iso.get(reference).push(label); } };
  for (const finding of confirmed) addIso(finding, `confirmed ${code(finding.fingerprint)}`);
  for (const lead of leads) addIso(lead, `needs validation ${code(lead.fingerprint)}`);
  for (const record of conformance) if (record.status !== "not_applicable") addIso(record, `${record.status.replace("_", " ")} ${code(record.control_id)}`);
  const isoKey = (reference) => reference.split(".").slice(1).map((part) => part.padStart(3, "0")).join(".");
  standards.push(table(["Control", "Relevant evidence"], [...iso.entries()].sort(([a], [b]) => (isoKey(a) < isoKey(b) ? -1 : 1)).map(([reference, labels]) => [reference, labels.join(", ")])), "");
  standards.push("## 6. CWE", "");
  const cwe = new Map();
  for (const finding of [...confirmed, ...leads]) for (const reference of standardsOf(finding).cwe || []) { if (!cwe.has(reference)) cwe.set(reference, []); cwe.get(reference).push(`${finding.verdict === "confirmed" ? "confirmed" : "needs validation"} ${code(finding.fingerprint)}`); }
  standards.push(cwe.size ? table(["Weakness", "Records"], [...cwe.entries()].sort(([a], [b]) => Number(a.slice(4)) - Number(b.slice(4))).map(([reference, labels]) => [reference, labels.join(", ")])) : "No record cites a CWE.", "");
  standards.push("## 7. Conformance detail", "", "### Gaps", "");
  for (const gap of gaps) {
    const control = CONTROLS.get(gap.control_id);
    standards.push(`#### ${controlTitle(gap)}`, "", list([
      `Priority ${gap.priority.level}: ${one(gap.priority.reason)}`,
      control ? `Expected: ${one(control.statement)}` : null,
      `Found: ${one(gap.summary)}`,
      `Evidence: ${gap.evidence.map((entry) => `${where(entry)} (${one(entry.description)})`).join("; ")}`,
      `Fix: ${one(gap.remediation.strategy)}`,
      `Standards: ${standardsLine(standardsOf(gap))}`,
      mergedGaps.has(gap.control_id) ? `Same root cause as finding ${code(mergedGaps.get(gap.control_id))}.` : null,
    ].filter(Boolean)), "");
  }
  if (!gaps.length) standards.push("None.", "");
  standards.push("### Not assessed", "", byStatus.not_assessed.length ? list(byStatus.not_assessed.map((record) => `${controlTitle(record)}. Missing fact: ${one(record.reason)} Owner check: ${one(record.owner_check)}`)) : "None.", "");
  standards.push("### Not applicable", "", byStatus.not_applicable.length ? list(byStatus.not_applicable.map((record) => `${controlTitle(record)}. ${one(record.reason)}`)) : "None.", "");
  standards.push("### Met", "", byStatus.met.length ? list(byStatus.met.map((record) => `${controlTitle(record)}. ${where(record.evidence[0])}`)) : "None.", "");

  // ------------------------------------------------------- REMEDIATION.md
  const verify = one(meta.verify_command) || "run the project's test suite";
  const tasks = [];
  for (const finding of confirmed) tasks.push({ kind: "finding", level: finding.severity.overall_severity, record: finding, closes: gaps.filter((gap) => mergedGaps.get(gap.control_id) === finding.fingerprint) });
  const levelOrder = (task) => (task.kind === "finding" ? SEVERITIES.indexOf(task.level) * 2 : SEVERITIES.indexOf(task.level) * 2 + 1);
  const gapDecisions = meta.gap_decisions && typeof meta.gap_decisions === "object" ? meta.gap_decisions : {};
  const isDecision = (gap) => Object.prototype.hasOwnProperty.call(gapDecisions, gap.control_id) && !mergedGaps.has(gap.control_id);
  for (const gap of gaps) if (!mergedGaps.has(gap.control_id) && !isDecision(gap)) tasks.push({ kind: "gap", level: gap.priority.level, record: gap, closes: [] });
  tasks.sort((a, b) => levelOrder(a) - levelOrder(b));
  tasks.forEach((task, position) => { task.id = `T${String(position + 1).padStart(2, "0")}`; });
  const short = (standardsObject) => [...(standardsObject.cwe || []).slice(0, 1), ...(standardsObject.owasp_top10 || []).filter((reference) => reference.endsWith(":2025")).slice(0, 1), ...(standardsObject.owasp_asvs || []).slice(0, 1).map((reference) => `ASVS ${reference.slice(7)}`)].join(" · ");
  const remediation = [`# Security remediation plan: ${meta.repo}`, "", `Audited revision: ${code(sourceRef(meta))} · Audit run: ${code(meta.run_id)} · Profile: ${code(meta.profile)}${partial ? ", partial pass" : ""}`, ""];
  remediation.push("## How to use this file", "", `You are fixing the issues listed below in the repository \`${meta.repo}\`. Each task is independent unless it says otherwise.`, "");
  remediation.push([
    "1. Start from a clean working tree on a new branch. Do the tasks in order.",
    "2. For each task, read the cited code first. Line numbers refer to the audited revision; if the code moved, find it by the function or scope name.",
    "3. Write the regression test first and watch it fail. Then make the smallest change that enforces the stated invariant. Run the verify command.",
    "4. Keep one commit per task, with the task number in the message. Do not mix in refactoring, formatting, or fixes that are not in this file.",
    "5. Never weaken or delete an existing test to get a green run. If an existing test encodes the insecure behaviour, change it and say so in the commit.",
    "6. If a task turns out to be wrong for the current code, or needs a choice listed under \"Needs a decision\", stop that task, leave the code as it was, and report why. Do not improvise a different fix.",
    "7. Do not act on \"Needs a decision\" or \"Outside the repository\": they are for the owner.",
    "8. When every task is done or reported, fill in the status table and ask for a scoped re-audit of the changed paths.",
  ].join("\n"), "");
  if (partial) remediation.push(partial, "");
  remediation.push("## Status", "", table(["Task", "Title", "Level", "Standards", "Status"], tasks.map((task) => [task.id, title(task.record), `${task.kind === "finding" ? "confirmed" : "gap"} · ${task.level}`, short(standardsOf(task.record)), "to do"])), "", "## Tasks", "");
  for (const task of tasks) {
    const record = task.record;
    remediation.push(`### ${task.id}: ${title(record)}`, "");
    if (task.kind === "finding") {
      remediation.push(list([
        `**Record**: ${code(record.fingerprint)} in ${code("findings.json")} (confirmed, ${record.severity.overall_severity})${task.closes.length ? `; also closes ${task.closes.map((gap) => `control ${code(gap.control_id)}`).join(", ")}` : ""}`,
        `**Standards**: ${standardsLine(standardsOf(record))}`,
        `**Where**: ${record.trace.map((step) => `${where(step)} in ${code(step.scope)}`).join("; ")}`,
        `**Problem**: ${one(record.root_cause)}`,
        `**Invariant**: ${one(record.intended_behavior)}`,
        `**Change**: ${one(record.remediation.strategy)}${task.closes.length ? " " + task.closes.map((gap) => one(gap.remediation.strategy)).join(" ") : ""}`,
        `**Regression test**: turn the audit's reproduction into a test that asserts the opposite of what was observed. Principal: ${one(record.execution.attacker_perspective)} Steps: ${record.execution.instructions.map(one).join(" ")} Today this yields: ${one(record.execution.observed_result)} After the fix it must not.`,
        `**Verify**: ${code(verify)}`,
        "**Done when**: the new test fails before the change and passes after it, and the existing suite still passes.",
        `**Watch for**: other paths to the same effect in ${[...new Set(record.evidence.map((entry) => code(entry.file)))].join(", ")}; keep response shapes that existing callers rely on.`,
      ]), "");
      for (const change of record.remediation.code_changes || []) remediation.push(`Suggested code for ${code(change.file_name)}:`, "", "```", change.fixed_code, "```", "");
    } else {
      const control = CONTROLS.get(record.control_id);
      remediation.push(list([
        `**Record**: control ${code(record.control_id)} in ${code("conformance.json")} (gap, priority ${record.priority.level}). A missing control, not a demonstrated vulnerability.`,
        `**Standards**: ${standardsLine(standardsOf(record))}`,
        `**Where**: ${record.evidence.map((entry) => `${where(entry)} (${brief(entry.description)})`).join("; ")}`,
        `**Problem**: ${one(record.summary)}`,
        control ? `**Invariant**: ${one(control.statement)}` : null,
        `**Change**: ${one(record.remediation.strategy)}`,
        "**Regression test**: add a test that exercises the cited location and fails today because the control is absent, then passes once it is enforced. Where the change is configuration only, add the check the project's CI can run, or state in the commit why none applies.",
        `**Verify**: ${code(verify)}`,
        "**Done when**: the control is enforced at every location cited above and the existing suite still passes.",
        `**Why this priority**: ${one(record.priority.reason)}`,
      ].filter(Boolean)), "");
      for (const change of record.remediation.code_changes || []) remediation.push(`Suggested code for ${code(change.file_name)}:`, "", "```", change.fixed_code, "```", "");
    }
  }
  if (!tasks.length) remediation.push("No task: the run confirmed no finding and recorded no conformance gap.", "");
  remediation.push("## Needs a decision", "");
  let decision = 0;
  for (const lead of leads) {
    remediation.push(`### D${String(++decision).padStart(2, "0")}: ${title(lead)}`, "", list([
      `**Record**: ${code(lead.fingerprint)} (needs_validation)`,
      `**Question for the owner**: ${lead.blockers.map(one).join(" ")}`,
      `**How to settle it**: ${[lead.validation_plan.local, lead.validation_plan.deployment].filter(Boolean).map(one).join(" ")}`,
      "**If the answer confirms the lead**: open a task for it and ask for a scoped audit of that path. Do not change code on the strength of this entry alone.",
    ]), "");
  }
  for (const gap of gaps.filter(isDecision)) {
    remediation.push(`### D${String(++decision).padStart(2, "0")}: ${controlTitle(gap)}`, "", list([
      `**Record**: control ${code(gap.control_id)} (gap, priority ${gap.priority.level}). The control is missing, but closing it is a product or deployment choice.`,
      `**Question for the owner**: ${one(gapDecisions[gap.control_id])}`,
      `**What was found**: ${one(gap.summary)} (${gap.evidence.map(where).join(", ")})`,
      `**If the answer is yes**: ${one(gap.remediation.strategy)}`,
    ]), "");
  }
  for (const record of byStatus.not_assessed) {
    remediation.push(`### D${String(++decision).padStart(2, "0")}: ${controlTitle(record)}`, "", list([
      `**Record**: control ${code(record.control_id)} (not assessed)`,
      `**Question for the owner**: ${one(record.reason)}`,
      `**How to settle it**: ${one(record.owner_check)}`,
    ]), "");
  }
  if (!decision) remediation.push("None.", "");
  remediation.push("## Outside the repository", "", one(meta.outside_repository) || "Anything above that names a reverse proxy, a host firewall, TLS termination, production environment values or an organizational process is changed by the owner of the deployment, not in this repository.", "");
  remediation.push("## After the fixes", "", "Ask for a scoped audit of the changed paths against this run. Each fingerprint above is then re-verified on the new source: a fixed defect ends as a rejected claim with the reason it no longer holds, and a fix that only moved the problem shows up as a new candidate.", "");

  const files = { "REPORT.md": report, "FINDINGS-DETAIL.md": detail, "NEEDS-VALIDATION.md": validation, "STANDARDS-REPORT.md": standards, "REMEDIATION.md": remediation };
  for (const [name, lines] of Object.entries(files)) fs.writeFileSync(path.join(outDir, name), lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n");
  return { tasks: tasks.length, decisions: decision, confirmed: confirmed.length, leads: leads.length, gaps: gaps.length, merged_gaps: mergedGaps.size, files: Object.keys(files) };
}

module.exports = { render };

if (require.main === module) {
  const outDir = process.argv[2];
  if (!outDir) {
    console.error("Usage: node render-reports.cjs <output-dir>");
    process.exit(1);
  }
  try {
    console.log(JSON.stringify(render(outDir)));
  } catch (error) {
    console.error(`Failed to render reports: ${error.message}`);
    process.exit(1);
  }
}
