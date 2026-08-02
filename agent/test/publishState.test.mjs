// Tests for scripts/publish-state.sh against real git repositories.
//
// The script is shell and its whole job is git side effects, so mocking git would test nothing
// that matters. Each case builds a throwaway origin + clone in a temp directory and asserts on
// the resulting object graph.
//
// The script is COPIED into each fixture rather than executed where it lives. It resolves its
// own repo with `cd "$(dirname "$0")/../.."`, so running the real file would operate on this
// checkout and push to the real origin. That is not a hypothetical: it is the one way this test
// file could do damage, so it is structural, not a convention.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, writeFile, readFile, copyFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const SCRIPT_SOURCE = fileURLToPath(new URL("../scripts/publish-state.sh", import.meta.url));

const STATE_PATH = "agent/data/sentinel-state.json";

/** git with an identity and no user config leaking in from the machine running the tests. */
async function git(cwd, args) {
  return execFileAsync("git", args, {
    cwd,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "test",
      GIT_AUTHOR_EMAIL: "test@example.invalid",
      GIT_COMMITTER_NAME: "test",
      GIT_COMMITTER_EMAIL: "test@example.invalid",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null",
    },
  });
}

/**
 * A bare origin holding one commit with a state file, plus a clone with the script installed.
 * Mirrors the real layout: the script lives at agent/scripts/ and resolves the repo two levels up.
 */
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "kokosh-publish-state-"));
  const origin = join(root, "origin.git");
  const work = join(root, "work");

  await git(root, ["init", "--quiet", "--bare", "--initial-branch=main", origin]);
  await git(root, ["clone", "--quiet", origin, work]);

  await mkdir(join(work, "agent", "data"), { recursive: true });
  await mkdir(join(work, "agent", "scripts"), { recursive: true });
  await copyFile(SCRIPT_SOURCE, join(work, "agent", "scripts", "publish-state.sh"));
  await writeFile(join(work, STATE_PATH), JSON.stringify({ lastRunAt: "2026-07-30T00:00:00.000Z" }) + "\n");
  await writeFile(join(work, "README.md"), "seed\n");

  await git(work, ["add", "."]);
  await git(work, ["commit", "--quiet", "-m", "seed"]);
  await git(work, ["push", "--quiet", "origin", "main"]);

  return { root, origin, work, cleanup: () => rm(root, { recursive: true, force: true }) };
}

/** Run the script inside a fixture clone. Returns stdout; the script never exits non-zero. */
async function run(work, args = []) {
  const { stdout } = await execFileAsync("bash", [join(work, "agent", "scripts", "publish-state.sh"), ...args], {
    cwd: work,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "sentinel",
      GIT_AUTHOR_EMAIL: "sentinel@example.invalid",
      GIT_COMMITTER_NAME: "sentinel",
      GIT_COMMITTER_EMAIL: "sentinel@example.invalid",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null",
    },
  });
  return stdout;
}

/** The file's content as it exists on origin's main, or null when absent. */
async function contentOnOrigin(origin, path) {
  try {
    const { stdout } = await git(origin, ["show", `main:${path}`]);
    return stdout;
  } catch {
    return null;
  }
}

test("publishes a changed state file to the remote branch", async (t) => {
  const fx = await fixture();
  t.after(fx.cleanup);

  await writeFile(join(fx.work, STATE_PATH), JSON.stringify({ lastRunAt: "2026-08-02T12:00:00.000Z" }) + "\n");
  const out = await run(fx.work);

  assert.match(out, /pushed [0-9a-f]{12} to origin\/main/);
  const published = await contentOnOrigin(fx.origin, STATE_PATH);
  assert.match(published, /2026-08-02T12:00:00\.000Z/);
});

test("is a no-op when the remote already has this exact content", async (t) => {
  const fx = await fixture();
  t.after(fx.cleanup);

  const { stdout: before } = await git(fx.origin, ["rev-parse", "main"]);
  const out = await run(fx.work);
  const { stdout: after } = await git(fx.origin, ["rev-parse", "main"]);

  assert.match(out, /already current/);
  assert.equal(before.trim(), after.trim(), "an unchanged run must not create a commit");
});

test("publishes only the named paths, never other local work in progress", async (t) => {
  const fx = await fixture();
  t.after(fx.cleanup);

  // The scenario the plumbing exists for: the cron fires while someone is mid-edit on main.
  await writeFile(join(fx.work, STATE_PATH), JSON.stringify({ lastRunAt: "2026-08-02T13:00:00.000Z" }) + "\n");
  await writeFile(join(fx.work, "README.md"), "HALF-FINISHED EDIT, MUST NOT BE PUBLISHED\n");
  await writeFile(join(fx.work, "agent", "secret-experiment.mjs"), "export const wip = true;\n");

  await run(fx.work);

  assert.equal(await contentOnOrigin(fx.origin, "README.md"), "seed\n");
  assert.equal(await contentOnOrigin(fx.origin, "agent/secret-experiment.mjs"), null);
  assert.match(await contentOnOrigin(fx.origin, STATE_PATH), /13:00:00/);
});

test("leaves the working tree, the index and HEAD untouched", async (t) => {
  const fx = await fixture();
  t.after(fx.cleanup);

  await writeFile(join(fx.work, STATE_PATH), JSON.stringify({ lastRunAt: "2026-08-02T14:00:00.000Z" }) + "\n");
  const { stdout: headBefore } = await git(fx.work, ["rev-parse", "HEAD"]);
  const { stdout: statusBefore } = await git(fx.work, ["status", "--porcelain"]);

  await run(fx.work);

  const { stdout: headAfter } = await git(fx.work, ["rev-parse", "HEAD"]);
  const { stdout: statusAfter } = await git(fx.work, ["status", "--porcelain"]);
  assert.equal(headAfter, headBefore, "HEAD must not move");
  assert.equal(statusAfter, statusBefore, "the state file must stay dirty locally, not be staged");
});

test("builds on the current remote tip, preserving a commit pushed since the last cycle", async (t) => {
  const fx = await fixture();
  t.after(fx.cleanup);

  // The local clone is behind: someone pushed from elsewhere and this machine never pulled.
  // Committing onto the stale local ref would revert their work, so the script fetches first.
  const other = join(fx.root, "other");
  await git(fx.root, ["clone", "--quiet", fx.origin, other]);
  await writeFile(join(other, "README.md"), "a human's commit\n");
  await git(other, ["add", "README.md"]);
  await git(other, ["commit", "--quiet", "-m", "human work"]);
  await git(other, ["push", "--quiet", "origin", "main"]);

  await writeFile(join(fx.work, STATE_PATH), JSON.stringify({ lastRunAt: "2026-08-02T15:00:00.000Z" }) + "\n");
  await run(fx.work);

  assert.equal(await contentOnOrigin(fx.origin, "README.md"), "a human's commit\n");
  assert.match(await contentOnOrigin(fx.origin, STATE_PATH), /15:00:00/);
  const { stdout: log } = await git(fx.origin, ["log", "--format=%s", "main"]);
  assert.ok(log.includes("human work"), "the human commit must remain reachable");
});

test("reports a rejected push and still exits clean, publishing nothing", async (t) => {
  const fx = await fixture();
  t.after(fx.cleanup);

  // The rejection this stands in for is a real non-fast-forward: the branch moving between this
  // cycle's fetch and its push. That race cannot be scheduled from a test, but every outcome
  // downstream of it is the same -- the push is refused -- so the refusal is what gets asserted.
  const hook = join(fx.origin, "hooks", "pre-receive");
  await writeFile(hook, "#!/bin/sh\nexit 1\n", { mode: 0o755 });

  const { stdout: before } = await git(fx.origin, ["rev-parse", "main"]);
  await writeFile(join(fx.work, STATE_PATH), JSON.stringify({ lastRunAt: "2026-08-02T16:00:00.000Z" }) + "\n");
  const out = await run(fx.work);
  const { stdout: after } = await git(fx.origin, ["rev-parse", "main"]);

  assert.match(out, /state publish FAILED -- push rejected/);
  assert.equal(before.trim(), after.trim(), "a rejected push must leave the branch where it was");
  // Exit code 0 is the contract: `run` would have thrown otherwise. A failed publish must not
  // turn a healthy scan into a failed cycle.
});

test("skips a named path that does not exist rather than failing the cycle", async (t) => {
  const fx = await fixture();
  t.after(fx.cleanup);

  const out = await run(fx.work, ["agent/data/does-not-exist.json"]);
  assert.match(out, /nothing to publish/);
});
