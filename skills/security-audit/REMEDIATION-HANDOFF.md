# Remediation Handoff

### Phase 7: Write the work order for whoever fixes the code

The audit describes fixes and does not modify the target. Somebody else does that afterwards: a developer, or a coding agent started in the repository with one file as its brief. `REMEDIATION.md` is that file. It has to work for a reader who has seen nothing else from the run and who will follow it literally.

Write it only after Phase 6, from the same final records. It adds no claim, no severity and no fix that the verified records do not contain.

## What becomes a task

| Source | Becomes |
|---|---|
| `confirmed` record | A task. Its severity orders it |
| `gap` control in `conformance.json` | A task. Its priority orders it, after confirmed records of the same level |
| `gap` with `related_fingerprints` | Part of the task for that finding: one root cause, one task |
| `gap` whose fix is a product or deployment choice (a new feature such as multi-factor authentication, a retention policy, a call to an outside service) | An entry under **Needs a decision**, with the question and the fix that follows a yes |
| `needs_validation` record | An entry under **Needs a decision**. Never a task: the defect is not established, and a blind fix can hide the question |
| `not_assessed` control | An entry under **Needs a decision**, with its `owner_check` |
| `rejected` record, `met` or `not_applicable` control | Nothing |
| A fix that is a deployment or organizational change | An entry under **Outside the repository** |

Order tasks by level: critical, high, medium, low, informational for confirmed records; high, medium, low for gaps, each placed after the confirmed records of the same word. Inside a level, put first the task that others build on: a central middleware before the routes that will use it, a shared helper before its callers. When two tasks edit the same function, say so in both, so they are not done in parallel.

Number tasks `T01`, `T02`, … in that order. The number is how the fixer and the owner refer to a task; the fingerprint or control identifier is how the next audit run finds it.

## What each task must contain

A fixer who reads only the task must be able to do it and to know when to stop.

- **Where**: repository-relative file, line and function or scope name. Line numbers come from the audited source ref and drift; the scope name is what the fixer searches for.
- **Problem**: the root cause in two or three sentences, in terms of the code. Not the attack narrative.
- **Invariant**: the one sentence the code must make true. This is what a reviewer checks the fix against.
- **Change**: the smallest source change that enforces the invariant at the last trusted decision point, with the code from `remediation.code_changes` when the record has it. Name what must not change: public behaviour, response shapes, existing callers.
- **Regression test**: where to add it, what it sets up, what it asserts. For a confirmed record, derive it from `execution`: the bounded reproduction becomes the test, with the assertion inverted. For a gap, describe the test that would fail today.
- **Verify**: the exact local command that runs that test and the neighbouring suite, taken from Phase 1's offline build and test facts.
- **Done when**: observable conditions, including "the new test fails before the change and passes after".
- **Watch for**: sibling paths with the same pattern that the record names, and anything the fix is likely to break.

Do not write a task whose change is "review", "consider" or "ensure". If the records do not support a specific change, the item is a decision, not a task.

## Template

Write `<output-dir>/REMEDIATION.md` in this shape. Keep the first section word for word apart from the bracketed values: it is the fixer's instructions.

````markdown
# Security remediation plan: <repo>

Audited revision: `<source ref>` · Audit run: `<run id>` · Profile: `<profile>`<, partial pass if so>

## How to use this file

You are fixing the issues listed below in the repository `<repo>`. Each task is
independent unless it says otherwise.

1. Start from a clean working tree on a new branch. Do the tasks in order.
2. For each task, read the cited code first. Line numbers refer to the audited
   revision; if the code moved, find it by the function or scope name.
3. Write the regression test first and watch it fail. Then make the smallest
   change that enforces the stated invariant. Run the verify command.
4. Keep one commit per task, with the task number in the message. Do not mix in
   refactoring, formatting, or fixes that are not in this file.
5. Never weaken or delete an existing test to get a green run. If an existing
   test encodes the insecure behaviour, change it and say so in the commit.
6. If a task turns out to be wrong for the current code, or needs a choice
   listed under "Needs a decision", stop that task, leave the code as it was,
   and report why. Do not improvise a different fix.
7. Do not act on "Needs a decision" or "Outside the repository": they are for
   the owner.
8. When every task is done or reported, fill in the status table and ask for a
   scoped re-audit of the changed paths.

## Status

| Task | Title | Level | Standards | Status |
|---|---|---|---|---|
| T01 | <title> | confirmed · high | CWE-639 · A01:2025 | to do |
| T02 | <title> | gap · high | A07:2025 · ASVS 6.3.1 | to do |

## Tasks

### T01: <title>

- **Record**: `<fingerprint>` in `findings.json` (confirmed, <severity>)<; also closes control `AC-02`>
- **Standards**: <CWE> · <Top 10> · <ASVS> · <ISO Annex A>
- **Where**: `<file>:<line>` in `<scope>`<; further locations>
- **Problem**: <root cause>
- **Invariant**: <what must be true after the fix>
- **Change**: <specific change>

  ```<language>
  <fixed code, when the record provides it>
  ```
- **Regression test**: <file to add or extend, setup, assertion>
- **Verify**: `<command>`
- **Done when**: <conditions>
- **Watch for**: <sibling paths, likely breakage>

## Needs a decision

### D01: <title>

- **Record**: `<fingerprint>` (needs_validation) or control `<id>` (not assessed)
- **Question for the owner**: <the exact unresolved fact>
- **How to settle it**: <local check or owner-observed check from the record>
- **If the answer is <x>**: <what follows: a task to open, or nothing>

## Outside the repository

- <deployment or organizational change, the control it relates to, who can make it>

## After the fixes

Ask for a scoped audit of the changed paths against this run. Each fingerprint
above is then re-verified on the new source: a fixed defect ends as a rejected
claim with the reason it no longer holds, and a fix that only moved the problem
shows up as a new candidate.
````

## Rules for the parent

1. Derive every line from `findings.json`, `conformance.json`, `architecture.md` and the Phase 1 build and test facts. If a task needs a fact none of them holds, the task is not ready; move it to **Needs a decision**.
2. Keep reproduction details bounded exactly as the record has them. The regression test uses the dummy principals and fixtures of the reproduction, never a live system or a real credential.
3. Do not restate severity or priority differently from the records, and do not rank a gap above a confirmed record of the same word.
4. Do not include secrets found during the audit. Name the file and line where one sits and say it must be rotated; never copy its value.
5. Check the file against the records before finishing: every `confirmed` fingerprint and every `gap` control identifier appears exactly once among the tasks, every `needs_validation` fingerprint and `not_assessed` control appears exactly once among the decisions, and no `rejected` fingerprint appears at all.
6. State in the header when the run was `quick`, scoped, budget-limited or incomplete. A fixer who finishes every task must not conclude the code is clean.
