/**
 * Checks standards references (CWE, OWASP Top 10, OWASP ASVS, ISO/IEC 27001
 * Annex A) against standards-index.json, so a record cannot cite an identifier
 * that does not exist or one that a standard forbids as a mapping target.
 *
 * A reference classifies a record. It is never evidence, and this module never
 * looks at verdict or severity.
 */

const index = require("./standards-index.json");

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

const STANDARD_KEYS = Object.freeze(["cwe", "owasp_top10", "owasp_asvs", "iso27001"]);
const FRAMEWORK_KEYS = Object.freeze(["owasp_top10", "owasp_asvs", "iso27001"]);
const CWE_PATTERN = /^CWE-([1-9][0-9]{0,4})$/;
const TOP10_PATTERN = /^(A(?:0[1-9]|10)):(2021|2025)$/;
const ASVS_PATTERN = /^v5\.0\.0-([1-9][0-9]?)\.([1-9][0-9]?)(?:\.([1-9][0-9]?))?$/;
const ISO_PATTERN = /^A\.([5-8])\.([1-9][0-9]?)$/;
const MAX_REFERENCES_PER_STANDARD = 12;

function describe(value) {
  return typeof value === "string" && value.length <= 40 && /^[\x21-\x7e]+$/.test(value) ? `"${value}"` : "<value>";
}

function checkCwe(value) {
  const match = CWE_PATTERN.exec(value);
  if (!match) return "expected the form CWE-<number>";
  const reason = index.cwe.not_mappable[match[1]];
  if (reason) return `is a ${reason} and cannot classify a record; use the specific weakness below it`;
  return null;
}

function checkTop10(value) {
  const match = TOP10_PATTERN.exec(value);
  if (!match) return "expected the form A01:2025 to A10:2025 (or the 2021 edition)";
  if (!hasOwn(index.owasp_top10[match[2]], match[1])) return "is not a category of that edition";
  return null;
}

function checkAsvs(value) {
  const match = ASVS_PATTERN.exec(value);
  if (!match) return "expected the form v5.0.0-<chapter>.<section> or v5.0.0-<chapter>.<section>.<requirement>";
  const section = `${match[1]}.${match[2]}`;
  const requirements = index.owasp_asvs.requirements_per_section;
  if (!hasOwn(requirements, section)) return `names section ${section}, which ASVS 5.0.0 does not have`;
  if (match[3] !== undefined && Number(match[3]) > requirements[section]) {
    return `names a requirement beyond the ${requirements[section]} that ASVS 5.0.0 section ${section} has`;
  }
  return null;
}

function checkIso(value) {
  const match = ISO_PATTERN.exec(value);
  if (!match) return "expected the form A.<theme>.<control>, for example A.8.28";
  const count = index.iso27001.controls_per_theme[match[1]];
  if (Number(match[2]) > count) return `names a control beyond the ${count} that Annex A theme ${match[1]} has`;
  return null;
}

const CHECKS = Object.freeze({
  cwe: checkCwe,
  owasp_top10: checkTop10,
  owasp_asvs: checkAsvs,
  iso27001: checkIso,
});

/**
 * Returns error strings for a `standards` object. `base` is the JSON path used
 * in messages.
 */
function collectStandardsErrors(standards, base) {
  const errors = [];
  if (standards === null || typeof standards !== "object" || Array.isArray(standards)) {
    errors.push(`${base}: expected an object`);
    return errors;
  }
  let total = 0;
  for (const key of Object.keys(standards)) {
    if (!hasOwn(CHECKS, key)) {
      errors.push(`${base}: unknown standard ${describe(key)} (expected ${STANDARD_KEYS.join(", ")})`);
      continue;
    }
    const list = standards[key];
    if (!Array.isArray(list) || list.length === 0) {
      errors.push(`${base}.${key}: expected a non-empty array`);
      continue;
    }
    if (list.length > MAX_REFERENCES_PER_STANDARD) {
      errors.push(`${base}.${key}: at most ${MAX_REFERENCES_PER_STANDARD} references; cite the closest ones`);
      continue;
    }
    const seen = new Set();
    list.forEach((value, itemIndex) => {
      const location = `${base}.${key}[${itemIndex}]`;
      if (typeof value !== "string") {
        errors.push(`${location}: expected a string`);
        return;
      }
      if (seen.has(value)) {
        errors.push(`${location}: duplicate reference ${describe(value)}`);
        return;
      }
      seen.add(value);
      total += 1;
      const problem = CHECKS[key](value);
      if (problem) errors.push(`${location}: ${describe(value)} ${problem}`);
    });
  }
  if (errors.length === 0 && total === 0) errors.push(`${base}: must cite at least one reference`);
  return errors;
}

function hasReference(standards, key) {
  return standards !== null && typeof standards === "object" && !Array.isArray(standards) &&
    Array.isArray(standards[key]) && standards[key].length > 0;
}

function hasFrameworkReference(standards) {
  return FRAMEWORK_KEYS.some((key) => hasReference(standards, key));
}

/** Title lookups for report writers; return null for an identifier that does not resolve. */
function top10Title(reference) {
  const match = TOP10_PATTERN.exec(reference);
  return match && hasOwn(index.owasp_top10[match[2]], match[1]) ? index.owasp_top10[match[2]][match[1]] : null;
}

function asvsSectionTitle(reference) {
  const match = ASVS_PATTERN.exec(reference);
  if (!match) return null;
  const section = `${match[1]}.${match[2]}`;
  return hasOwn(index.owasp_asvs.section_titles, section) ? index.owasp_asvs.section_titles[section] : null;
}

module.exports = {
  FRAMEWORK_KEYS,
  STANDARD_KEYS,
  asvsSectionTitle,
  collectStandardsErrors,
  hasFrameworkReference,
  hasReference,
  top10Title,
};
