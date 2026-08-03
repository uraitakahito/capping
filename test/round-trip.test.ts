/**
 * Signing, then verifying what was signed.
 *
 * This only means something because the verifier was measured against py-wacz's
 * output first. Without that, a round trip proves the two halves agree with
 * each other and nothing more — they could share a misreading of the format and
 * still pass. The order the work was done in is what makes this test evidence.
 *
 * The failure cases are the reason capping issues its own certificates. None of
 * them can be arranged against a public CA or a public timestamp authority.
 */
import { mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { initIdentity, loadIdentity, type Identity } from "../src/ca.js";
import { hashFile, sign, toDatapackageDigest } from "../src/sign.js";
import { parseDatapackageDigest } from "../src/signed-data.js";
import { verifySignedData } from "../src/verify.js";

const HASH = "sha256:3dd086a0be145d1108bf32a5cac7c4b4c046eb78365792d4bb28e9f43e3c6571";

let dir: string;
let identity: Identity;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "capping-test-"));
  identity = await initIdentity({ dir: join(dir, "id"), domain: "sign.dev.local" });
}, 120_000);

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("a signature capping made", () => {
  it("passes every stage it can reach against its own roots", async () => {
    const signedData = await sign(identity, { hash: HASH });
    const report = await verifySignedData(signedData, {
      trustRoots: [identity.rootCert],
    });

    expect(report.stages.signature.status).toBe("ok");
    expect(report.stages.chain.status).toBe("ok");
    expect(report.stages.domain.status).toBe("ok");
    // Skipped rather than ok: capping no longer issues timestamps, so without
    // `--tsa-url` there is nothing here to check. See remote-tsa.test.ts for
    // the stage passing against an authority.
    expect(report.stages.timestamp.status).toBe("skipped");
    expect(report.valid).toBe(true);
  }, 60_000);

  it("fails the chain stage against an unrelated root", async () => {
    // The distinction py-wacz's "invalid" fixture exists to show: the signature
    // is fine, the vouching authority is not one we accept.
    const other = await initIdentity({ dir: join(dir, "other"), domain: "sign.dev.local" });
    const signedData = await sign(identity, { hash: HASH });
    const report = await verifySignedData(signedData, { trustRoots: [other.rootCert] });

    expect(report.stages.signature.status).toBe("ok");
    expect(report.stages.chain.status).toBe("failed");
    expect(report.valid).toBe(false);
  }, 120_000);

  it("fails when the hash it covers is changed", async () => {
    const signedData = await sign(identity, { hash: HASH });
    const tampered = { ...signedData, hash: HASH.replace(/.$/, "0") };
    const report = await verifySignedData(tampered, { trustRoots: [identity.rootCert] });

    expect(report.stages.signature.status).toBe("failed");
  }, 60_000);

  it("fails the domain stage when the claimed domain is not the certificate's", async () => {
    const signedData = await sign(identity, { hash: HASH });
    const report = await verifySignedData(
      { ...signedData, domain: "elsewhere.dev.local" },
      { trustRoots: [identity.rootCert] },
    );

    expect(report.stages.domain.status).toBe("failed");
  }, 60_000);
});

describe("input that cannot be examined at all", () => {
  it("reports rather than throws when domainCert holds no certificate", async () => {
    // The caller asked whether an archive checks out. "No, there is no
    // certificate in it" is an answer; a rejected promise is not, and would
    // look the same to a CLI as openssl being absent.
    const signedData = await sign(identity, { hash: HASH });
    const report = await verifySignedData(
      { ...signedData, domainCert: "not a certificate" },
      { trustRoots: [identity.rootCert] },
    );

    expect(report.valid).toBe(false);
    expect(report.stages.signature.status).toBe("failed");
    expect(report.stages.signature.detail).toMatch(/no PEM certificates/);
    // One problem, reported once — the other three were never asked.
    expect(report.stages.chain.status).toBe("skipped");
    expect(report.stages.domain.status).toBe("skipped");
    expect(report.stages.timestamp.status).toBe("skipped");
  }, 60_000);
});

describe("an expired signing certificate", () => {
  it("fails the chain stage, but only for being expired", async () => {
    // `--signer-days 0` is the point of running a local CA: an identity that is
    // already past its validity, which is the state every real signing
    // certificate reaches long before anyone verifies the archive.
    const expired = await initIdentity({
      dir: join(dir, "expired"),
      domain: "sign.dev.local",
      signerDays: 0,
    });
    const signedData = await sign(expired, { hash: HASH });

    const strict = await verifySignedData(signedData, { trustRoots: [expired.rootCert] });
    expect(strict.stages.signature.status).toBe("ok");
    expect(strict.stages.chain.status).toBe("failed");
    expect(strict.stages.chain.detail).toMatch(/expired/i);

    // With expiry set aside the chain is sound — which is what a timestamp
    // lets a verifier conclude, since it shows the signature predates it.
    const lenient = await verifySignedData(signedData, {
      trustRoots: [expired.rootCert],
      allowExpired: true,
    });
    expect(lenient.stages.chain.status).toBe("ok");
  }, 120_000);
});

describe("the file that carries the signature", () => {
  it("round-trips through datapackage-digest.json", async () => {
    const signedData = await sign(identity, { hash: HASH });
    const path = join(dir, "datapackage-digest.json");
    await writeFile(path, `${JSON.stringify(toDatapackageDigest(signedData), null, 2)}\n`, "utf8");

    const reloaded = parseDatapackageDigest(JSON.parse(await readFile(path, "utf8")));
    expect(reloaded.path).toBe("datapackage.json");
    expect(reloaded.hash).toBe(HASH);

    const report = await verifySignedData(reloaded.signedData!, {
      trustRoots: [identity.rootCert],
    });
    expect(report.valid).toBe(true);
  }, 60_000);
});

describe("hashFile", () => {
  it("produces the sha256: form datapackage-digest.json uses", async () => {
    const path = join(dir, "sample.json");
    await writeFile(path, '{"hello":"wacz"}', "utf8");

    expect(await hashFile(path)).toMatch(/^sha256:[0-9a-f]{64}$/);
  }, 30_000);
});

describe("an identity directory that was moved", () => {
  it("still signs, because nothing in it records where it lives", async () => {
    // The reason this matters: a development CA is most useful when it can be
    // committed and mounted somewhere else — a fixture directory in one repo,
    // /id inside a container. An identity that baked absolute paths at init
    // time works exactly once, on the machine that made it, and then fails
    // with openssl complaining about files that are not there.
    const made = join(dir, "portable-a");
    await initIdentity({ dir: made, domain: "sign.dev.local" });

    const moved = join(dir, "portable-b");
    await rename(made, moved);

    const identity = await loadIdentity(moved);
    const signedData = await sign(identity, { hash: HASH });
    const report = await verifySignedData(signedData, { trustRoots: [identity.rootCert] });

    // The signature stage is the one that would break: it reads the key and
    // the certificate out of the directory by path. This used to be the
    // timestamp stage's job to prove, back when signing wrote a config file
    // full of absolute paths — that file is gone, and with it the sharpest
    // way an identity could stop being portable.
    expect(report.stages.signature.status).toBe("ok");
    expect(report.stages.chain.status).toBe("ok");
    expect(report.valid).toBe(true);
  }, 120_000);
});
