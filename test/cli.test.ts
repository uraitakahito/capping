/**
 * The command line, exercised as a command line.
 *
 * These spawn `dist/cli.js` rather than importing the module, because the thing
 * being checked is the part a user touches: argument parsing, what lands on
 * stdout versus stderr, and the exit code. A test that imported the functions
 * directly would pass while `capping verify` returned 0 on a bad archive.
 *
 * That means a build first. It costs a couple of seconds and buys certainty
 * that what shipped is what was tested — `bin` points at `dist/cli.js`, so a
 * source-only test would be measuring something nobody runs.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "dist", "cli.js");

interface Run {
  stdout: string;
  stderr: string;
  code: number;
}

/** Run the CLI, returning its exit code rather than throwing on a non-zero one. */
async function capping(...argv: string[]): Promise<Run> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [cli, ...argv], { cwd: root });
    return { stdout, stderr, code: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; code?: number };
    return { stdout: e.stdout ?? "", stderr: e.stderr ?? "", code: e.code ?? -1 };
  }
}

let dir: string;
let digest: string;
let caCert: string;

beforeAll(async () => {
  await execFileAsync("pnpm", ["run", "build"], { cwd: root });

  dir = await mkdtemp(join(tmpdir(), "capping-cli-"));
  caCert = join(dir, "id", "ca.crt");
  digest = join(dir, "datapackage-digest.json");

  await capping("init", "--dir", join(dir, "id"), "--domain", "sign.dev.local");
  const target = join(dir, "datapackage.json");
  await writeFile(target, '{"profile":"data-package"}', "utf8");
  await capping("sign", "--dir", join(dir, "id"), "--file", target, "--out", digest);
}, 240_000);

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("capping sign", () => {
  it("writes a datapackage-digest.json the verifier accepts", async () => {
    const parsed: unknown = JSON.parse(await readFile(digest, "utf8"));
    expect(parsed).toMatchObject({
      path: "datapackage.json",
      hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/) as unknown,
    });

    const run = await capping("verify", "--file", digest, "--root", caCert);
    expect(run.code).toBe(0);
    expect(run.stdout).toContain("valid");
    expect(run.stdout).not.toContain("FAILED");
  }, 120_000);

  it("hashes the file it was pointed at", async () => {
    // The same bytes openssl would digest from a shell — if these disagree, the
    // signature covers something other than the archive it claims to.
    const target = join(dir, "datapackage.json");
    const { stdout } = await execFileAsync("openssl", ["dgst", "-sha256", "-r", target]);
    const expected = `sha256:${stdout.trim().split(/\s+/)[0] ?? ""}`;

    const parsed = JSON.parse(await readFile(digest, "utf8")) as { hash: string };
    expect(parsed.hash).toBe(expected);
  }, 30_000);
});

describe("capping verify", () => {
  it("exits non-zero when a stage fails", async () => {
    // A wrong root is the failure a caller most needs the exit code to catch,
    // since the output still says the signature itself is fine.
    const other = join(dir, "other");
    await capping("init", "--dir", other, "--domain", "sign.dev.local");

    const run = await capping("verify", "--file", digest, "--root", join(other, "ca.crt"));
    expect(run.code).toBe(1);
    expect(run.stdout).toContain("not valid");
    expect(run.stdout).toMatch(/FAILED\s+chain/);
  }, 180_000);

  it("reports the chain as skipped, not failed, when no root is named", async () => {
    const run = await capping("verify", "--file", digest);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/skipped\s+chain/);
  }, 60_000);

  it("reads py-wacz's fixture, which needs --allow-expired to pass", async () => {
    const fixture = join(root, "test", "fixtures", "pywacz-signed.datapackage-digest.json");

    // Signed in 2021 against a real Let's Encrypt certificate, so by now both it
    // and the timestamp authority's certificate have expired. Strict is the
    // honest default; the flag is what a verifier reaches for once a timestamp
    // has shown the signature predates the expiry.
    const strict = await capping("verify", "--file", fixture);
    expect(strict.code).toBe(1);
    expect(strict.stdout).toMatch(/expired/i);

    const lenient = await capping("verify", "--file", fixture, "--allow-expired");
    expect(lenient.code).toBe(0);
    expect(lenient.stdout).toMatch(/ok\s+signature/);
  }, 120_000);

  it("prints every openssl command under --explain", async () => {
    const run = await capping("verify", "--file", digest, "--root", caCert, "--explain");

    // The claim this package makes is that nothing happens outside openssl.
    // These lines are what lets a reader check that claim by hand.
    expect(run.stderr).toContain("+ openssl dgst -sha256 -verify");
    expect(run.stderr).toContain("+ openssl verify -CAfile");
    expect(run.stderr).toContain("+ openssl x509 -in leaf.pem -noout -checkhost");
    expect(run.stderr).toContain("+ openssl ts -verify");
    // stdout stays the report, so `--explain` can be added without breaking a pipe.
    expect(run.stdout).not.toContain("+ openssl");
  }, 60_000);
});

describe("capping's argument handling", () => {
  it("prints usage and exits 0 with no command", async () => {
    const run = await capping();
    expect(run.code).toBe(0);
    expect(run.stdout).toContain("capping init");
  }, 30_000);

  it("exits 2 on an unknown command", async () => {
    const run = await capping("frobnicate");
    expect(run.code).toBe(2);
  }, 30_000);

  it("exits 2 when a required flag is missing", async () => {
    const run = await capping("verify");
    expect(run.code).toBe(2);
    expect(run.stderr).toContain("--file is required");
  }, 30_000);
});

describe("capping's paths", () => {
  it("accepts a relative --dir", async () => {
    // openssl runs with the identity directory as its cwd, so a relative --dir
    // used to be applied twice: `--dir ./id` looked for `./id/./id/ca.key`.
    // openssl reported it as "Can't open ... for writing", which reads like a
    // permissions problem, and every existing test passed absolute paths from
    // mkdtemp so nothing caught it.
    const run = await capping("init", "--dir", "./relative-id", "--domain", "sign.dev.local");
    expect(run.code).toBe(0);
    expect(existsSync(join(root, "relative-id", "ca.crt"))).toBe(true);

    await rm(join(root, "relative-id"), { recursive: true, force: true });
  }, 180_000);
});
