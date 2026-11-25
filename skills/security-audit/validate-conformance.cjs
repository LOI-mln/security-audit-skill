#!/usr/bin/env node

/**
 * Validates conformance.json against conformance-schema.json and
 * conformance-checklist.json.
 * Usage: node validate-conformance.cjs [--findings <path-to-findings.json>] <path-to-conformance.json>
 *
 * The checklist is the coverage claim of the standards conformance review:
 * every checklist control must appear exactly once, so a control cannot be
 * skipped silently. A control the run did not review is recorded as
 * not_assessed with its reason.
 */

const path = require("path");
const {
  JsonStructureError,
  LIMITS,
  SafeInputError,
  collectUnchecked,
  createErrorList,
  enforceJsonTextLimits,
  escapeUnsafeDiagnosticCharacters,
  isSafeRelativeSourcePath,
  loadSchema,
  readFileWithinLimit,
  safeQuote,
} = require("./validate-findings.cjs");
const { collectStandardsErrors, hasFrameworkReference } = require("./standards.cjs");
const checklist = require("./conformance-checklist.json");

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const CUSTOM_CONTROL = /^X-[A-Z0-9][A-Z0-9-]{0,23}$/;

function checklistControls() {
  const controls = new Map();
  for (const family of Object.keys(checklist.families)) {
    for (const control of checklist.families[family].controls) {
      controls.set(control.control_id, { family, statement: control.statement, standards: control.standards });
    }
  }
  return controls;
}

const CHECKLIST = checklistControls();

function collectConformanceSemanticErrors(records, options = {}) {
  const errors = createErrorList();
  if (!Array.isArray(records)) return errors;
  const knownFingerprints = options.fingerprints instanceof Set ? options.fingerprints : null;
  const seen = new Set();
  let previous = null;

  records.forEach((record, index) => {
    const base = `$[${index}]`;
    if (record === null || typeof record !== "object" || Array.isArray(record)) return;
    const id = record.control_id;

    if (typeof id === "string") {
      if (seen.has(id)) errors.push(`${base}.control_id: duplicate control ${safeQuote(id)}`);
      seen.add(id);
      if (previous !== null && previous > id) errors.push(`${base}.control_id: records must be sorted by control_id`);
      previous = id;
      if (!CHECKLIST.has(id) && !CUSTOM_CONTROL.test(id)) {
        errors.push(`${base}.control_id: ${safeQuote(id)} is not a checklist control; target-specific controls use an X- identifier`);
      }
      if (CUSTOM_CONTROL.test(id) && !hasFrameworkReference(record.standards)) {
        errors.push(`${base}.standards: a target-specific control must cite an OWASP Top 10, OWASP ASVS or ISO/IEC 27001 reference`);
      }
    }

    if (hasOwn(record, "standards")) {
      errors.push(...collectStandardsErrors(record.standards, `${base}.standards`));
    }

    if (Array.isArray(record.evidence)) {
      record.evidence.forEach((entry, entryIndex) => {
        if (entry && hasOwn(entry, "file") && !isSafeRelativeSourcePath(entry.file)) {
          errors.push(`${base}.evidence[${entryIndex}].file: must be a safe repository-relative source path`);
        }
      });
    }
    if (record.remediation && Array.isArray(record.remediation.code_changes)) {
      record.remediation.code_changes.forEach((change, changeIndex) => {
        if (change && hasOwn(change, "file_name") && !isSafeRelativeSourcePath(change.file_name)) {
          errors.push(`${base}.remediation.code_changes[${changeIndex}].file_name: must be a safe repository-relative source path`);
        }
      });
    }
    if (knownFingerprints && Array.isArray(record.related_fingerprints)) {
      record.related_fingerprints.forEach((fingerprint, fingerprintIndex) => {
        if (typeof fingerprint === "string" && !knownFingerprints.has(fingerprint)) {
          errors.push(`${base}.related_fingerprints[${fingerprintIndex}]: ${safeQuote(fingerprint)} is not a record in findings.json`);
        }
      });
    }
  });

  for (const id of CHECKLIST.keys()) {
    if (!seen.has(id)) errors.push(`$: checklist control ${safeQuote(id)} is missing; record it as not_assessed with its reason if this run did not review it`);
  }
  return errors;
}

function validateDocument(records, schema, options = {}) {
  const errors = collectUnchecked(records, schema, "$");
  if (errors.length < LIMITS.validationErrors) {
    errors.push(...collectConformanceSemanticErrors(records, options));
  }
  return errors;
}

function readJson(file, label) {
  let contents;
  try {
    contents = readFileWithinLimit(file);
  } catch (error) {
    const reason = error instanceof SafeInputError ? error.message : "input could not be opened or read safely";
    throw new Error(`Failed to read ${label}: ${reason}`);
  }
  try {
    enforceJsonTextLimits(contents);
  } catch (error) {
    const reason = error instanceof JsonStructureError ? error.message : "invalid JSON structure";
    throw new Error(`Failed to parse ${label}: ${reason}`);
  }
  try {
    return JSON.parse(contents);
  } catch {
    throw new Error(`Failed to parse ${label}: invalid JSON syntax`);
  }
}

function parseArguments(argv) {
  const files = [];
  let findings = null;
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    if (argument === "--findings") {
      findings = argv[++index];
      if (!findings) return null;
    } else if (typeof argument === "string" && argument.startsWith("--")) {
      return null;
    } else {
      files.push(argument);
    }
  }
  if (files.length !== 1 || !files[0]) return null;
  return { file: files[0], findings };
}

function run(argv) {
  const parsed = parseArguments(argv);
  if (!parsed) {
    console.error("Usage: node validate-conformance.cjs [--findings <path-to-findings.json>] <path-to-conformance.json>");
    return 1;
  }

  let schema;
  try {
    schema = loadSchema(path.join(__dirname, "conformance-schema.json"));
  } catch (error) {
    console.error("Failed to load conformance-schema.json:", error.message);
    return 1;
  }

  let records;
  const options = {};
  try {
    records = readJson(parsed.file, "conformance JSON");
    if (parsed.findings) {
      const findings = readJson(parsed.findings, "findings JSON");
      if (!Array.isArray(findings)) throw new Error("Failed to parse findings JSON: expected an array");
      options.fingerprints = new Set(findings
        .filter((finding) => finding && typeof finding.fingerprint === "string")
        .map((finding) => finding.fingerprint));
    }
  } catch (error) {
    console.error(escapeUnsafeDiagnosticCharacters(error.message));
    return 1;
  }

  let errors;
  try {
    errors = validateDocument(records, schema, options);
  } catch {
    console.error("Failed to validate conformance JSON: unexpected validation error");
    return 1;
  }
  for (const message of errors) console.error("ERROR:", escapeUnsafeDiagnosticCharacters(message));
  if (errors.length > 0) {
    const cap = errors.length === LIMITS.validationErrors ? `; output capped at ${LIMITS.validationErrors}` : "";
    console.error(`FAIL: ${errors.length} validation error(s)${cap}`);
    return 1;
  }

  const counts = { met: 0, gap: 0, not_applicable: 0, not_assessed: 0 };
  for (const record of records) counts[record.status] += 1;
  console.log(`PASS: ${records.length} controls valid (${counts.met} met, ${counts.gap} gap, ${counts.not_applicable} not applicable, ${counts.not_assessed} not assessed)`);
  return 0;
}

module.exports = {
  CHECKLIST,
  collectConformanceSemanticErrors,
  validateDocument,
};

if (require.main === module) process.exit(run(process.argv.slice(2)));
