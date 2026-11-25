# Sandbox and Artifact Promotion

#### When to use this file

Use it when a hunter or verifier needs to execute target-controlled code and the agent platform does not already provide a sandbox that meets every rule under `Universal execution safety` in [SKILL.md](SKILL.md). It describes two helpers shipped with the skill and how the parent uses them:

- `sandbox-run.sh` runs one command in a container with no network, an environment built only from an allowlist, the target mounted read-only, writes confined to one scratch directory, and low CPU, memory, process, file-size and wall-clock limits.
- `promote-artifact.py` is the trusted parent-side code of the promotion procedure: it copies declared files from an agent's `scratch/` to its `artifacts/` without following a link anywhere on the way.

They are one way to satisfy the rules, not an exception to them. If a helper cannot run, the blocker it reports is the `needs_validation` blocker.

## Why the helpers exist

A `confirmed` record needs a bounded observed result, and an observed result needs something to run. Without a sandbox every candidate in a run stays `needs_validation`, with no severity and no fix, however clear the source is. Most developer machines already have what a sandbox needs: a container runtime and the project's own development image. The launcher turns that into the controls the skill demands, with the same flags every time, so that no agent composes its own `docker run` line and forgets one.

## Approve a sandbox before anyone executes

The parent does this once, after reconnaissance, and records the outcome in `run-metadata.json`.

1. **Runtime.** Docker or Podman must respond locally. The launcher uses `docker`, then `podman`, or the binary named by `SANDBOX_RUNTIME`.
2. **Image.** Choose an image that is already present locally and already holds the target's toolchain: the project's development image, or a language base image the machine has. Do not pull one and do not build one during the audit. Pulling contacts a registry, and building runs the target's build instructions outside the sandbox. The launcher passes `--pull=never` and refuses an image it cannot find locally.
3. **Self-test.** Run the canaries and require `SELF-TEST PASS`:

   ```sh
   <skill-dir>/sandbox-run.sh --self-test --image <image> --scratch <output-dir>/agents/parent/scratch
   ```

   The self-test checks from inside the container that an outbound connection fails, that the target mount cannot be written, that scratch can, and that the environment holds nothing beyond the allowlist.
4. **Record.** Write `sandbox` in `run-metadata.json` with the launcher, runtime, image and self-test result. When no runtime or no suitable image exists, or the self-test fails, write `sandbox: null` with the reason. Every lead whose decisive check needs execution then stays `needs_validation` with that exact blocker.
5. **Hand over the invocation.** Give each hunter and verifier the launcher path, the approved image, the target path and its own scratch path, in the prompt. An agent may lower a limit or raise the timeout within what the parent states. It may not add a mount, a network, a capability, or a variable holding a real secret, and it never runs target code any other way.

## Running a check

```sh
<skill-dir>/sandbox-run.sh \
  --image <approved-image> \
  --target <target> \
  --scratch <output-dir>/agents/<agent-id>/scratch \
  --env APP_ENV=testing \
  --timeout 120 \
  -- <command> [args...]
```

- The target is mounted read-only at `/target` and scratch read-write at `/scratch`, which is also the working directory. `HOME`, `TMPDIR` and the cache directory point inside scratch.
- When a build or test must write beside the source, the agent first makes a disposable copy of what it needs inside its scratch directory, outside the sandbox, leaving out environment files, version-control metadata and anything holding secrets. It then runs from `/scratch/<copy>`.
- The container inherits nothing from the host environment. Pass each variable the check needs with `--env NAME=VALUE`, using dummy values. Never pass the project's real environment file or a real credential.
- There is no network. A check that needs a database uses an in-memory or file database in scratch; a check that needs an external service uses a mock or stays `needs_validation`.
- Exit status: the command's own status; 124 when the wall-clock limit killed it; 2 for a rejected argument; 3 when no runtime or image is available.
- The launcher prints one `sandbox-run:` line with the effective policy. Copy that line, the command, the test input and the variable names into the check record. Do not record variable values beyond the safe dummy ones.

Prefer the narrowest check that settles the claim: one existing test, or one new test file written in scratch that drives the real code with dummy principals. Stop at the minimum result.

### Prove the recipe once, then hand agents one command

Before delegating, the parent runs one of the target's existing tests through the launcher. A recipe that has not run once will fail in every agent at the same time. Two things commonly need fixing:

- **`operation not permitted` when the interpreter starts.** Some images give a binary a file capability (`setcap`, often so an interpreter can bind port 80). With every capability dropped and `no-new-privileges` set, the kernel refuses to execute such a binary. Do not add the capability back. Copy the binary into scratch inside the sandbox and run the copy: a plain copy carries no capability.

  ```sh
  ... -- sh -c 'mkdir -p /scratch/bin && cp /usr/bin/php8.3 /scratch/bin/php && exec /scratch/bin/php vendor/bin/phpunit "$@"' sh tests/Feature/ExampleTest.php
  ```
- **The target keeps local secrets beside its source.** A read-only mount of the working tree would expose an untracked environment file to target code. Mount a copy instead: the tracked files at the audited ref plus the already-installed dependency directory, without the environment file. On a copy-on-write filesystem (`cp -c` on APFS, `cp --reflink=auto` on Btrfs or XFS) this copy and the per-agent copies of it are instant and take no extra space.

Once the recipe works, wrap it in a small script in the output directory that takes the agent identifier and the test arguments, prepares that agent's disposable copy on first use, and calls the launcher. Agents then run one command, and none of them rebuilds the invocation.

## Promoting evidence

Scratch stays target-controlled after the process exits. Before execution the agent declares the scratch-relative files it expects to produce and the parent records them with byte limits. After the sandbox and all its processes have terminated, the parent promotes exactly those files:

```sh
python3 <skill-dir>/promote-artifact.py \
  --scratch-root   <output-dir>/agents/<agent-id>/scratch \
  --artifacts-root <output-dir>/agents/<agent-id>/artifacts \
  --max-file-bytes 262144 --max-total-bytes 1048576 \
  results/probe-output.txt
```

It prints `PROMOTED <path> <bytes> sha256=<hex>` for each file it copied and `REJECT <path>: <reason>` for each it refused, and exits non-zero if any was refused. A rejected file is not evidence. A symlink, a hard-linked file, a FIFO, a device, a directory, an oversized or changing file, and an existing destination are all refused; nothing is globbed, recursed or overwritten.

Only a promoted file may appear as the `artifact` of a `local` check in the coverage ledger.

## What the helpers do not do

- They do not make a container escape impossible. The isolation is the runtime's. On macOS and Windows the runtime adds a virtual machine between the container and the host; on Linux consider rootless Podman or a user-namespaced daemon for untrusted targets.
- They do not supply a toolchain. No local image with the target's tools means no execution.
- They do not police the agent. The agent prompt must still say that target code runs through the launcher and nowhere else, and the parent must still review the commands an agent reports.
- `promote-artifact.py` needs a POSIX system with directory-relative, no-follow file operations. Where those are missing it exits 3 and promotes nothing.
