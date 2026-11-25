const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const scriptPath = path.join(__dirname, "sandbox-run.sh");
const CLI_TIMEOUT_MS = 10000;
const SELF_TEST_TIMEOUT_MS = 180000;
const MISSING_RUNTIME = "/nonexistent/sandbox-run-test/container-runtime";
const PLACEHOLDER_IMAGE = "sandbox-run-test/placeholder:latest";
const TEST_IMAGE = process.env.SANDBOX_TEST_IMAGE || "";
const SKIP = skipReason();

function skipReason() {
  if (process.platform === "win32") return "the launcher needs a POSIX host";
  const probe = spawnSync("bash", ["--version"], { encoding: "utf8", timeout: CLI_TIMEOUT_MS });
  return probe.status === 0 ? false : "bash is not available";
}

function responds(command, args) {
  return spawnSync(command, args, { stdio: "ignore", timeout: 30000 }).status === 0;
}

// Mirrors the launcher's runtime choice: SANDBOX_RUNTIME, else docker, else podman.
function selfTestSkipReason() {
  if (SKIP) return SKIP;
  if (!TEST_IMAGE) return "set SANDBOX_TEST_IMAGE to a local image to run the real sandbox self-test";
  const runtime = process.env.SANDBOX_RUNTIME ||
    ["docker", "podman"].find((name) => !spawnSync(name, ["--version"], { stdio: "ignore", timeout: 30000 }).error);
  if (!runtime) return "neither docker nor podman is installed";
  if (!responds(runtime, ["info"])) return `${runtime} is not responding`;
  if (!responds(runtime, ["image", "inspect", TEST_IMAGE])) return `image ${TEST_IMAGE} is not present locally`;
  return false;
}

function withDirectories(run) {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-run-")));
  const directories = { base, target: path.join(base, "target"), scratch: path.join(base, "scratch") };
  try {
    fs.mkdirSync(directories.target);
    fs.mkdirSync(directories.scratch);
    return run(directories);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

// The runtime is pinned to a missing binary so these tests can never start a container.
function launch(args, env = {}) {
  return spawnSync("bash", [scriptPath, ...args], {
    encoding: "utf8",
    timeout: CLI_TIMEOUT_MS,
    env: { PATH: process.env.PATH, HOME: os.homedir(), SANDBOX_RUNTIME: MISSING_RUNTIME, ...env },
  });
}

function launchWith(directories, overrides = {}, extra = []) {
  const { target = directories.target, scratch = directories.scratch, env } = overrides;
  return launch(["--image", PLACEHOLDER_IMAGE, "--target", target, "--scratch", scratch, ...extra, "--", "true"], env);
}

function cliOutput(result) {
  return `${result.stdout}${result.stderr}`;
}

function assertRefused(result, reason) {
  const output = cliOutput(result);
  assert.notEqual(result.error && result.error.code, "ETIMEDOUT", output);
  assert.equal(result.status, 2, output);
  assert.equal(result.stdout, "", output);
  assert.match(result.stderr, reason);
}

test("refuses a relative target", { skip: SKIP }, () => {
  withDirectories((directories) => {
    assertRefused(launchWith(directories, { target: "relative/target" }), /--target must be an absolute path/);
    assertRefused(launchWith(directories, { scratch: "relative/scratch" }), /--scratch must be an absolute path/);
  });
});

test("refuses a symlinked scratch or target", { skip: SKIP }, () => {
  withDirectories((directories) => {
    const scratchLink = path.join(directories.base, "scratch-link");
    const targetLink = path.join(directories.base, "target-link");
    fs.symlinkSync(directories.scratch, scratchLink);
    fs.symlinkSync(directories.target, targetLink);

    assertRefused(launchWith(directories, { scratch: scratchLink }), /--scratch must not be a symlink/);
    assertRefused(launchWith(directories, { scratch: `${scratchLink}/` }), /--scratch must not be a symlink/);
    assertRefused(launchWith(directories, { target: targetLink }), /--target must not be a symlink/);
  });
});

test("refuses scratch inside target, target inside scratch, and a shared directory", { skip: SKIP }, () => {
  withDirectories((directories) => {
    const scratchInTarget = path.join(directories.target, "scratch");
    const targetInScratch = path.join(directories.scratch, "checkout");
    fs.mkdirSync(scratchInTarget);
    fs.mkdirSync(targetInScratch);

    assertRefused(launchWith(directories, { scratch: scratchInTarget }), /--scratch must not be the target or inside it/);
    assertRefused(launchWith(directories, { target: targetInScratch }), /--target must not be inside --scratch/);
    assertRefused(launchWith(directories, { scratch: directories.target }), /--scratch must not be the target or inside it/);
  });
});

test("refuses an invalid, valueless, or sandbox-fixed environment variable", { skip: SKIP }, () => {
  withDirectories((directories) => {
    assertRefused(launchWith(directories, {}, ["--env", "1BAD=value"]), /--env name must match/);
    assertRefused(launchWith(directories, {}, ["--env", "BAD-NAME=value"]), /--env name must match/);
    assertRefused(launchWith(directories, {}, ["--env", "INHERIT_ME"]), /--env takes NAME=VALUE/);
    assertRefused(launchWith(directories, {}, ["--env", "HOME=/root"]), /--env HOME is fixed by the sandbox/);
  });
});

test("refuses scratch that is the root, the home directory, or missing", { skip: SKIP }, () => {
  withDirectories((directories) => {
    assertRefused(launchWith(directories, { scratch: "/" }), /--scratch must not be \//);
    assertRefused(
      launchWith(directories, { scratch: directories.scratch, env: { HOME: directories.scratch } }),
      /--scratch must not be the home directory/,
    );
    assertRefused(
      launchWith(directories, { scratch: path.join(directories.base, "missing") }),
      /--scratch is not an existing directory/,
    );
  });
});

test("refuses unlimited limits, unknown options, and a missing command", { skip: SKIP }, () => {
  withDirectories((directories) => {
    for (const option of ["--cpus", "--memory", "--pids", "--fsize-mb", "--timeout", "--tmpfs-mb"]) {
      assertRefused(launchWith(directories, {}, [option, "0"]), new RegExp(`${option} must be a positive`));
    }
    assertRefused(launchWith(directories, {}, ["--privileged"]), /unknown argument '--privileged'/);

    const injected = launchWith(directories, {}, ["--bogus\u001b[31m"]);
    assertRefused(injected, /unknown argument/);
    assert.equal(injected.stderr.includes("\u001b"), false);

    const noCommand = launch(["--image", PLACEHOLDER_IMAGE, "--target", directories.target, "--scratch", directories.scratch]);
    assertRefused(noCommand, /a command is required after --/);
  });
});

test("exits 3 with a clear blocker when SANDBOX_RUNTIME does not exist", { skip: SKIP }, () => {
  withDirectories((directories) => {
    const result = launchWith(directories);
    const output = cliOutput(result);
    assert.equal(result.status, 3, output);
    assert.equal(result.stdout, "", output);
    assert.match(result.stderr, /sandbox unavailable: SANDBOX_RUNTIME '.*container-runtime' was not found or is not executable/);
    assert.match(result.stderr, /needs_validation blocker/);
    assert.deepEqual(fs.readdirSync(directories.scratch), []);
  });
});

test("self-test passes in a real sandbox", { skip: selfTestSkipReason() }, () => {
  withDirectories((directories) => {
    const result = spawnSync("bash", [scriptPath, "--self-test", "--image", TEST_IMAGE, "--scratch", directories.scratch], {
      encoding: "utf8",
      timeout: SELF_TEST_TIMEOUT_MS,
    });
    const output = cliOutput(result);
    assert.notEqual(result.error && result.error.code, "ETIMEDOUT", output);
    assert.equal(result.status, 0, output);
    assert.match(result.stdout, /^SELF-TEST PASS$/m);
  });
});
