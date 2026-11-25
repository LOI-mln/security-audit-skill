# Standards Conformance Review

### Phase 2b: Review the controls the standards expect

Hunting looks for boundary failures and deliberately leaves out missing best practices. A standards-based audit needs the other half as well: which controls OWASP ASVS and ISO/IEC 27001 Annex A expect are visible in the source, which are absent, and which cannot be judged from source. This phase produces that answer in `conformance.json`.

The two tracks stay separate so that neither weakens the other. A missing control is a `gap` with a priority, never a vulnerability with a severity. A gap becomes a finding only if a hunter then demonstrates a boundary failure through the normal candidate path. And a gap is not dropped because nobody showed an exploit: it is hardening work the owner asked to see.

Run this phase alongside the hunting waves. It needs `architecture.md` and nothing from the hunters, so it can start as soon as Phase 1 ends.

## The checklist is the coverage claim

`conformance-checklist.json` holds 67 controls in 13 families, each with the ASVS 5.0.0 requirements, Top 10:2025 categories, Annex A controls and CWE weaknesses it relates to:

| Family | Controls | Scope |
|---|---|---|
| AC | 6 | Authorization and access control |
| AU | 7 | Authentication and credentials |
| SM | 5 | Session management |
| IV | 7 | Input validation, encoding and injection |
| FH | 4 | File handling |
| WF | 6 | Web frontend and browser mechanisms |
| CR | 4 | Cryptography and transport |
| CF | 6 | Configuration and secrets |
| DP | 4 | Data protection and privacy |
| LG | 6 | Logging, monitoring and error handling |
| SC | 5 | Supply chain and build |
| SD | 4 | Secure development and environment separation |
| AV | 3 | Availability and abuse limits |

Every checklist control appears exactly once in `conformance.json`; the validator fails otherwise. This plays the role the coverage ledger plays for hunting: a control cannot be skipped silently. A family the target has no surface for is recorded control by control as `not_applicable` with the source fact that excludes it. A family the run did not review is recorded as `not_assessed` with that reason.

Add a target-specific control when the product has a security expectation the checklist does not state, for example a domain rule that one group may never see another group's records. Give it an `X-` identifier (`X-TENANT-EXPORT`) and its own `standards` object.

## Statuses

| Status | Meaning | Must carry |
|---|---|---|
| `met` | The control is enforced and source shows where | `summary`, `evidence` with the enforcing location |
| `gap` | The control is absent or incomplete and source shows it | `summary`, `evidence`, `remediation`, `priority` |
| `not_applicable` | The target has no surface the control governs | `reason` |
| `not_assessed` | The deciding fact is outside source (deployment, proxy, organization), or the family was not reviewed | `reason`, `owner_check` |

`priority.level` orders hardening work. It is not a severity: nothing was demonstrated. Use `high` when the missing control guards a surface reachable before authentication, credentials, or privileged actions; `medium` when it guards authenticated functionality or data of other users; `low` for defense in depth behind a control that is `met`.

A framework default counts as `met` only when the project leaves it on. Cite the place that shows it: the middleware group that still contains the CSRF check, the template engine left in auto-escape mode, the ORM call that binds parameters. Many projects disable a default in one route file or one component, so search for the opt-outs (`withoutMiddleware`, `except`, `v-html`, `|raw`, `{!! !!}`, `verify=False`, `DEBUG=true`) before writing `met`.

## Assign reviewers

Use `research` agents: they read source and write nothing. Group families so one reviewer holds about 25 controls. The default grouping is three reviewers:

1. AC, AU, SM, DP (22 controls): who may do what, and what they can see.
2. IV, FH, WF, CR, AV (24 controls): how input and output are handled.
3. CF, LG, SC, SD (21 controls): how the system is configured, built and observed.

In a `quick` run keep the three reviewers; the review is what makes the standards part of the report meaningful. In a scoped run, review only the families the scope touches and record the others as `not_assessed` with reason `outside the scope of this run`. Reviewers and gap verifiers are agent invocations and count against a budget; reserve them before assigning hunters.

Every reviewer prompt contains, in this order: the role block below, `architecture.md` verbatim, the assigned controls copied from `conformance-checklist.json` with their statements and standards, the `Core discipline` block from [STANDARDS.md](STANDARDS.md), any hunter `hardening` notes already returned for those families, and the four status branches of `conformance-schema.json` copied verbatim.

#### Conformance-reviewer prompt

```text
You review whether security controls are visible in the source at <target>.
This is a conformance review, not vulnerability hunting. Read source only: do not
run target code, do not install anything, do not contact any network service.

For EACH assigned control return exactly one record. Decide in this order:
1. Does the target have a surface this control governs? If not: not_applicable,
   with the source fact that shows the absence.
2. Is the control enforced? Find the enforcing code or configuration. A framework
   default counts only if you cite where the project leaves it enabled, and only
   after you searched for places that opt out of it. If enforced everywhere it
   applies: met, with the enforcing file and line.
3. Is it absent or partial? State what you searched for and where it should be.
   Cite the file and line that show the absence: the route, handler, component or
   configuration key the control should cover. Give the smallest change that would
   enforce it and a priority. That is a gap.
4. Does the answer depend on a fact outside the repository (reverse proxy, TLS
   termination, production environment values, log storage, organizational
   process)? Then: not_assessed, with the exact missing fact and what the owner can
   look at to settle it. Never guess a deployment fact in either direction.

Rules:
- Partial enforcement is a gap. Name the paths that are covered and the ones that
  are not.
- One record per control. If two locations fail the same control, put both in
  evidence.
- Do not assign severity. Do not write "vulnerability". Use priority only.
- Do not copy the control statement into summary; write what you found here.
- If you see a concrete way a lower-trust principal can cross a boundary, do not
  escalate the gap yourself. Add it to "leads" so a hunter can test it.
- All paths are repository-relative. Line numbers are positive integers that you
  read, not estimates.

Return exactly one JSON object and no surrounding prose:
{"records": [ ... one per assigned control, sorted by control_id ... ],
 "leads": [{"control_id": "...", "surface": "...", "boundary": "...",
            "starting_paths": ["..."], "reason": "..."}]}
Each record matches the branch of the schema for its status, included below.
```

## Verify the gaps

A `gap` is a negative claim, and negative claims are where reviewers go wrong: the control often exists in a place the reviewer did not look. Give each reviewer's `gap` records to one fresh `research` agent that did not write them. It receives the gap records, the control statements, and `architecture.md`, and for each gap it searches for the control independently: global middleware, base classes, framework configuration, a wrapper around the cited call, an upstream component. It returns `{"control_id": "...", "decision": "gap" | "met" | "not_assessed", "record": {...}}` for every gap, with a replacement record when the decision changes.

Apply a change to `met` or `not_assessed` directly. A gap that the verifier confirms keeps the reviewer's record, with any corrected line numbers.

## Consolidate

The parent is the only writer of `conformance.json`.

1. Merge the reviewer results. Reject a result that omits an assigned control, repeats one, or wraps the JSON in prose; re-run that reviewer when the budget permits, otherwise record its controls as `not_assessed` with reason `reviewer result unusable`.
2. Turn each accepted `lead` into an `uncovered` entry for the hunting waves: derive its ledger unit as [HUNTING.md](HUNTING.md) describes and assign it in the next wave, or mark it `deferred` when the profile or budget ends hunting.
3. Reconcile with hunting. When a gap and a `findings.json` record share a root cause, set `related_fingerprints` on the gap so the fix is planned once. When a hunter `hardening` note names a missing control that a reviewer recorded as `met`, send both to the gap verifier and keep its decision.
4. Fill `standards` on checklist controls from `conformance-checklist.json` when a reviewer left it out. Do not let a reviewer change a checklist control's mapping; a different mapping belongs on an `X-` control.
5. Sort by `control_id`, write the file, and run:

```sh
node <skill-dir>/validate-conformance.cjs --findings <output-dir>/findings.json <output-dir>/conformance.json
```

Run it without `--findings` before Phase 4 has written `findings.json`, and again with it afterwards. Fix every error before reporting.

## What this review cannot say

State these limits in the report instead of leaving the reader to assume otherwise:

- It covers what a repository shows. Process, people and physical controls of Annex A, and anything decided at deployment, are `not_assessed`.
- It is not an ISO/IEC 27001 audit and not an ASVS certification. It gives an auditor or an owner source evidence per control.
- `met` means the control is present where the reviewer looked and no opt-out was found. It does not mean the control is free of defects; hunting tests that.
- The checklist is a selection of source-verifiable controls, not the whole of ASVS. `STANDARDS-REPORT.md` names the ASVS chapters the checklist does not reach.
