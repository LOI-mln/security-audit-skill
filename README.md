# security-audit

A coding-agent skill that turns your agent into a security auditor. It orchestrates isolated agents through reconnaissance, coverage-led hunting, a standards conformance review, candidate validation, structured output, independent record verification, target-neutral reporting, and a remediation plan that a developer or another coding agent can execute.

This repository is a fork of [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill), the skill that seeded Cloudflare's vulnerability discovery harness, described in [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness). The hunting, validation and coverage-ledger workflow is theirs. The fork adds what a standards-based audit and a fix handoff need; see [What this fork adds](#what-this-fork-adds).

## What it does

The skill runs a structured audit in these phases:

1. **Reconnaissance** -- map architecture, trust boundaries, input surfaces, prior evidence, and deterministic coverage in `architecture.md` and `coverage-ledger.json`.
2. **Coverage-led hunting** -- assign isolated hunters from ledger units, record their checks, and use coverage critics to find gaps.
   - **2b. Standards conformance review** -- in parallel, read-only reviewers check 67 source-verifiable controls and record each as met, gap, not applicable or not assessed in `conformance.json`.
3. **Candidate validation** -- give every unique candidate to a fresh verifier that tries to disprove it.
4. **Structured output** -- write `confirmed`, `needs_validation`, and `rejected` records to `findings.json`, each classified against CWE, the OWASP Top 10, OWASP ASVS and ISO/IEC 27001 Annex A, and validate them.
5. **Independent record verification** -- fresh agents verify final source claims. Material replacements receive another independent verifier.
6. **Target-neutral reporting** -- derive `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, and `STANDARDS-REPORT.md` from the verified records, the conformance records and the coverage ledger.
7. **Remediation handoff** -- write `REMEDIATION.md`: ordered, self-contained tasks with the invariant to enforce, the change, the regression test and the command that verifies it.

The parent runs `validate-coverage-ledger.cjs` after creating the ledger and after each later ledger update. It runs `validate-findings.cjs --require-standards` and `validate-conformance.cjs` in Phase 4 and again after every Phase 5 replacement.

The verdicts are distinct: `confirmed` has a complete source trace and bounded observed result, `needs_validation` has an exact unresolved fact and no severity, and `rejected` records a disproved candidate. A missing control is none of these. It is a conformance `gap` with a priority, and it becomes a finding only if hunting demonstrates a boundary failure.

Multiple runs against the same repo are additive. The skill uses prior ledgers and findings to target gaps, revalidate changed source, and carry forward current-source evidence without treating stale or unresolved work as covered.

## What this fork adds

| Addition | Why |
|---|---|
| Standards mapping on every reported record: CWE, OWASP Top 10 (2025 and 2021), OWASP ASVS 5.0.0, ISO/IEC 27001:2022 Annex A | Upstream cites no standard, so a reader cannot place a finding in the framework their team or auditor uses |
| `standards-index.json` and `standards.cjs` | A model asked for an identifier will produce a plausible one. The validators reject any reference the standards do not define, and CWE views, categories and pillars that MITRE forbids as mapping targets |
| Standards conformance review with a 67-control checklist | Upstream reports boundary failures and deliberately leaves out missing best practices. A standards audit also has to say which expected controls are present, absent, or not visible in source |
| `STANDARDS-REPORT.md` | Coverage per Top 10 category, ASVS chapter and Annex A control, with "not reviewed" kept apart from "clean" |
| `REMEDIATION.md` | Upstream describes fixes for owners. This file is a work order written for a fixer who has seen nothing else from the run |
| `sandbox-run.sh` and `promote-artifact.py` | Upstream requires an OS-enforced sandbox and a no-follow promotion procedure but ships neither, so on an ordinary developer machine nothing can be executed and every candidate stays `needs_validation`. These are reference implementations on top of a local container runtime |

None of this lowers the evidence bar. A mapping never changes a verdict or a severity, a gap is never reported as a vulnerability, and the report says in so many words that a source review gives evidence relevant to a standard and certifies conformity with none.

If you ask for a standard by an approximate name ("OWASP 1000", "ISO 7400"), the skill resolves it to the closest published one, says so in the report, and does not invent identifiers to match the wording.

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Setup, core principles, platform terminology, workflow overview, and audit anti-patterns |
| `RECONNAISSANCE.md` | Phase 1 reconnaissance prompts and synthesis instructions |
| `HUNTING.md` | Phase 2 orchestration, hunting methodology, and validation rules |
| `ATTACK-CLASSES.md` | Core, wildcard, and obvious-things attack prompts |
| `STANDARDS.md` | Standards carried, mapping discipline, crosswalk from root cause to CWE, Top 10, ASVS and Annex A |
| `STANDARDS-CONFORMANCE.md` | Phase 2b conformance review: reviewer prompt, statuses, gap verification, consolidation |
| `REMEDIATION-HANDOFF.md` | Phase 7 rules and template for `REMEDIATION.md` |
| `SANDBOX.md` | How the parent approves a sandbox and promotes evidence with the shipped helpers |
| `MEMORY-SAFETY-AND-BINARY.md` | Memory-safety, binary, and kernel hunting classes for native targets |
| `AI-AND-LLM.md` | Prompt-injection, agent/tool, and output-handling hunting classes for LLM-backed targets |
| `WEB-PROTOCOL-AND-AUTH.md` | HTTP request-framing, cache, and authentication-protocol hunting classes for HTTP-protocol and auth targets |
| `CLIENT-SIDE.md` | DOM-injection, messaging-trust, UI-redress, and prototype-pollution hunting classes for client-side/browser targets |
| `SUPPLY-CHAIN-AND-RELEASE.md` | Dependency, CI, release, signing, update, plugin, and extension hunting classes |
| `CLOUD-AND-DEPLOYMENT.md` | IAM, infrastructure-as-code, container, serverless, ingress, and runtime-configuration hunting classes |
| `PROTOCOLS-RPC-AND-MESSAGING.md` | RPC, serialization, queue, broker, webhook, and streaming-protocol hunting classes |
| `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` | Shared resource, quota, queue, worker, and operator-spend hunting classes |
| `DATA-ISOLATION-AND-LIFECYCLE.md` | Tenant isolation, cache, search, export, backup, migration, deletion, and restore hunting classes |
| `DESKTOP-MOBILE-AND-LOCAL-IPC.md` | Native app, deep-link, webview, exported-component, helper, daemon, and local-IPC hunting classes |
| `VALIDATION-AND-REPORTING.md` | Phases 3–7 candidate validation, structured output, record verification, reporting, and the handoff |
| `report-schema.json` | JSON schema for all three `findings.json` verdicts |
| `conformance-schema.json` | JSON schema for the four `conformance.json` statuses |
| `conformance-checklist.json` | The 67 controls in 13 families, with the requirements and controls each relates to |
| `standards-index.json` | Identifier tables: Top 10 categories, ASVS sections and requirement counts, Annex A control counts, CWE identifiers that cannot be cited |
| `standards.cjs` | Zero-dependency check of standards references against the index |
| `validate-findings.cjs` | Zero-dependency validator for `findings.json` in Phases 4 and 5 |
| `validate-conformance.cjs` | Zero-dependency validator for `conformance.json`, including checklist completeness |
| `validate-coverage-ledger.cjs` | Zero-dependency validator for `coverage-ledger.json` in Phases 1–5 |
| `sandbox-run.sh` | Runs one command in a container with no network, an allowlisted environment, a read-only target and low limits |
| `promote-artifact.py` | Copies declared evidence files out of an agent's scratch directory without following links |
| `*.test.cjs` | Tests for the validators and helpers, run with `node --test` |

## Installation

Install the skill with the [Skills CLI](https://skills.sh):

```bash
npx skills add https://github.com/LOI-mln/security-audit-skill \
  --skill security-audit
```

Use `--global` for a user-level installation:

```bash
npx skills add https://github.com/LOI-mln/security-audit-skill \
  --skill security-audit \
  --global
```

Or clone the repository and link `skills/security-audit` into your agent's skills directory. Run `npx skills --help` for agent-selection and non-interactive options.

## Usage

Start your coding agent in (or pointed at) the codebase you want to audit, then ask it to do a security audit:

```
security audit this codebase
```

```
audit this repo against OWASP and ISO 27001 and write a remediation plan
```

```
find security vulnerabilities in ./src
```

```
do a security review, output to ~/audits/my-project
```

The skill activates automatically when the request matches its trigger (security audit, find vulnerabilities, pen-test the code, OWASP or ISO 27001 review, etc.). A direct codebase audit or pen-test request uses full audit mode. Security questions and focused vulnerability work use guidance mode unless you request report artifacts. In full audit mode, an unspecified output directory defaults to `~/security-audit-skill/<repo-name>/run-<N>`. The workflow writes inside the target repository only when you explicitly select a directory that version control ignores.

To have the issues fixed, start a coding agent in the target repository and give it the plan:

```
follow ~/security-audit-skill/<repo-name>/run-1/REMEDIATION.md
```

Then ask for a scoped audit of the changed paths. Each fingerprint is re-verified on the new source.

## Requirements

- A coding agent with a model that supports tool use and parallel sub-agents
- Node.js for the zero-dependency validators
- An OS-enforced sandbox for target-controlled builds, tests, processes, browsers, emulators, fuzzers, and fixtures. It must disable external networking, use a sanitized allowlisted environment, enforce resource limits, and allow writes only to assigned scratch paths. `sandbox-run.sh` provides one when Docker or Podman is running and a local image already holds the target's toolchain; `promote-artifact.py` needs Python 3 on a POSIX system. Without these controls, the workflow keeps the lead as `needs_validation` instead of executing target code.

## Design principles

- **Only confirm established boundary failures.** Keep a source-grounded blocked lead as `needs_validation` with its exact unresolved fact.
- **Adversarial validation.** The agent that checks a finding is never the agent that found it.
- **Severity requires impact.** Likelihood x impact, not deviation from a checklist.
- **Defense-in-depth gaps are not vulnerabilities.** If Layer A prevents the attack, the absence of Layer B is a hardening note, recorded as a conformance gap with a priority.
- **Standards classify, evidence decides.** A CWE or OWASP reference is added after the verdict and cannot change it. Identifiers are checked against the published lists.
- **Multiple runs improve coverage.** In Cloudflare's test runs, a single run found roughly half of the vulnerabilities that repeated runs found in total.

## Tests

```bash
cd skills/security-audit && node --test
```

## Credits and license

MIT -- see [LICENSE](LICENSE). The original skill is by Cloudflare; questions about the upstream workflow go to them at security-ai-research@cloudflare.com.

OWASP Top 10 and OWASP ASVS are works of the OWASP Foundation, CWE is maintained by MITRE, and ISO/IEC 27001 is published by ISO and IEC. This repository carries their identifiers and short titles for reference; the standards themselves remain authoritative.
