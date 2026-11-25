const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const script = path.join(__dirname, "promote-artifact.py");
const hasPython = process.platform !== "win32" && spawnSync("python3", ["--version"]).status === 0;
const skip = hasPython ? false : "python3 on a POSIX system is required";

function withRoots(run) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "promote-artifact-"));
  const scratch = path.join(base, "scratch");
  const artifacts = path.join(base, "artifacts");
  fs.mkdirSync(scratch);
  fs.mkdirSync(artifacts);
  try {
    return run({ base, scratch, artifacts });
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

function promote({ scratch, artifacts }, files, limits = {}) {
  return spawnSync("python3", [script,
    "--scratch-root", scratch, "--artifacts-root", artifacts,
    "--max-file-bytes", String(limits.file ?? 1024), "--max-total-bytes", String(limits.total ?? 4096),
    ...files], { encoding: "utf8", timeout: 10000 });
}

test("promotes a declared file into nested directories and reports its hash", { skip }, () => {
  withRoots((roots) => {
    fs.mkdirSync(path.join(roots.scratch, "results"));
    fs.writeFileSync(path.join(roots.scratch, "results", "probe-1.txt"), "OK (3 tests)\n");
    const result = promote(roots, ["results/probe-1.txt"]);
    assert.equal(result.status, 0, result.stderr);
    const hash = crypto.createHash("sha256").update("OK (3 tests)\n").digest("hex");
    assert.match(result.stdout, new RegExp(`^PROMOTED results/probe-1\\.txt 13 sha256=${hash}`));
    assert.equal(fs.readFileSync(path.join(roots.artifacts, "results", "probe-1.txt"), "utf8"), "OK (3 tests)\n");
  });
});

test("rejects paths that leave the scratch root", { skip }, () => {
  withRoots((roots) => {
    fs.writeFileSync(path.join(roots.base, "outside.txt"), "secret");
    for (const name of ["../outside.txt", path.join(roots.base, "outside.txt"), "a/../../outside.txt", "./x"]) {
      const result = promote(roots, [name]);
      assert.equal(result.status, 1, name);
      assert.match(result.stderr, /REJECT/);
    }
    assert.deepEqual(fs.readdirSync(roots.artifacts), []);
  });
});

test("rejects links, hard links, directories and FIFOs without hanging", { skip }, () => {
  withRoots((roots) => {
    fs.writeFileSync(path.join(roots.base, "outside.txt"), "secret");
    fs.symlinkSync(path.join(roots.base, "outside.txt"), path.join(roots.scratch, "leaf-link.txt"));
    fs.symlinkSync(roots.base, path.join(roots.scratch, "dir-link"));
    fs.writeFileSync(path.join(roots.scratch, "original.txt"), "data");
    fs.linkSync(path.join(roots.scratch, "original.txt"), path.join(roots.scratch, "hard.txt"));
    fs.mkdirSync(path.join(roots.scratch, "folder"));
    assert.equal(spawnSync("mkfifo", [path.join(roots.scratch, "pipe")]).status, 0);
    for (const name of ["leaf-link.txt", "dir-link/outside.txt", "hard.txt", "folder", "pipe"]) {
      const result = promote(roots, [name]);
      assert.notEqual(result.error && result.error.code, "ETIMEDOUT", name);
      assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /REJECT/, name);
    }
    assert.deepEqual(fs.readdirSync(roots.artifacts), []);
  });
});

test("enforces the per-file and cumulative limits and keeps promoting other files", { skip }, () => {
  withRoots((roots) => {
    fs.writeFileSync(path.join(roots.scratch, "big.txt"), "x".repeat(200));
    fs.writeFileSync(path.join(roots.scratch, "a.txt"), "x".repeat(60));
    fs.writeFileSync(path.join(roots.scratch, "b.txt"), "x".repeat(60));
    fs.writeFileSync(path.join(roots.scratch, "c.txt"), "x".repeat(10));
    const result = promote(roots, ["big.txt", "a.txt", "b.txt", "c.txt"], { file: 100, total: 100 });
    assert.equal(result.status, 1);
    assert.deepEqual(fs.readdirSync(roots.artifacts).sort(), ["a.txt", "c.txt"]);
    assert.match(result.stderr, /REJECT big\.txt/);
    assert.match(result.stderr, /REJECT b\.txt/);
  });
});

test("never overwrites an existing destination or follows a destination link", { skip }, () => {
  withRoots((roots) => {
    fs.writeFileSync(path.join(roots.scratch, "probe.txt"), "new");
    fs.writeFileSync(path.join(roots.artifacts, "probe.txt"), "old");
    assert.equal(promote(roots, ["probe.txt"]).status, 1);
    assert.equal(fs.readFileSync(path.join(roots.artifacts, "probe.txt"), "utf8"), "old");

    fs.mkdirSync(path.join(roots.scratch, "results"));
    fs.writeFileSync(path.join(roots.scratch, "results", "x.txt"), "new");
    fs.mkdirSync(path.join(roots.base, "elsewhere"));
    fs.symlinkSync(path.join(roots.base, "elsewhere"), path.join(roots.artifacts, "results"));
    assert.equal(promote(roots, ["results/x.txt"]).status, 1);
    assert.deepEqual(fs.readdirSync(path.join(roots.base, "elsewhere")), []);
  });
});

test("reports usage errors with status 2", { skip }, () => {
  withRoots((roots) => {
    const result = spawnSync("python3", [script, "--scratch-root", roots.scratch], { encoding: "utf8", timeout: 10000 });
    assert.equal(result.status, 2);
  });
});
