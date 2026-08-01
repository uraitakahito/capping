/**
 * The verifier, measured against archives someone else signed.
 *
 * These two files come from py-wacz and are the only independent check
 * available: they were produced by the reference implementation, so a verifier
 * that reads them correctly has understood the format, and one that does not
 * has not — regardless of whether it agrees with a signature capping made
 * itself. Written before capping could sign anything, for that reason.
 *
 * The pair is chosen well by upstream. Both signatures are cryptographically
 * sound; they differ only in whether the certificate chain reaches a public
 * root, which is exactly the distinction a report has to preserve.
 */
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { Openssl, withTempDir } from "../src/openssl.js";
import { parseDatapackageDigest, splitPemChain } from "../src/signed-data.js";
import { verifySignedData } from "../src/verify.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

/** Every issuer name in a PEM chain, as text. */
const issuersOf = async (pem: string): Promise<string> =>
  withTempDir(async (dir) => {
    const openssl = new Openssl({ cwd: dir });
    const names: string[] = [];
    for (const [i, cert] of splitPemChain(pem).entries()) {
      const path = join(dir, `c${String(i)}.pem`);
      await writeFile(path, cert, "utf8");
      names.push(await openssl.text("x509", "-in", path, "-noout", "-issuer"));
    }
    return names.join("\n");
  });

const load = async (name: string) => {
  const raw = await readFile(join(FIXTURES, name), "utf8");
  const digest = parseDatapackageDigest(JSON.parse(raw));
  expect(digest.signedData).toBeDefined();
  return digest.signedData!;
};

describe("py-wacz's signed example", () => {
  it("reads as a Domain-Ownership signature", async () => {
    const signedData = await load("pywacz-signed.datapackage-digest.json");

    expect(signedData.domain).toBe("btrix-sign-test.webrecorder.net");
    expect(signedData.hash.startsWith("sha256:")).toBe(true);
    expect(signedData.timeSignature).toBeDefined();
    expect(signedData.timestampCert).toBeDefined();
  });

  it("verifies its signature and timestamp without any trust anchor", async () => {
    // Neither stage needs a root: one asks whether the signature matches the
    // key in the certificate, the other whether the token covers the signature.
    // Trust enters only at the chain stage.
    const signedData = await load("pywacz-signed.datapackage-digest.json");
    const report = await verifySignedData(signedData, { allowExpired: true });

    expect(report.stages.signature.status).toBe("ok");
    expect(report.stages.timestamp.status).toBe("ok");
    expect(report.stages.domain.status).toBe("ok");
  });

  it("reports the chain as skipped, not failed, when no roots are given", async () => {
    // The difference matters: "we did not check" must not read as "we checked
    // and it was bad".
    const signedData = await load("pywacz-signed.datapackage-digest.json");
    const report = await verifySignedData(signedData, { allowExpired: true });

    expect(report.stages.chain.status).toBe("skipped");
    expect(report.valid).toBe(true);
  });
});

describe("py-wacz's invalid signed example", () => {
  it("has a signature that is itself perfectly sound", async () => {
    // Upstream calls this file invalid, and it is — but not because anything
    // was forged. Asserting the signature passes keeps the reason visible.
    const signedData = await load("pywacz-signed-invalid.datapackage-digest.json");
    const report = await verifySignedData(signedData, { allowExpired: true });

    expect(report.stages.signature.status).toBe("ok");
    expect(report.stages.timestamp.status).toBe("ok");
  });

  it("was signed for the same domain as the valid one", async () => {
    const valid = await load("pywacz-signed.datapackage-digest.json");
    const invalid = await load("pywacz-signed-invalid.datapackage-digest.json");

    expect(invalid.domain).toBe(valid.domain);
  });

  it("differs from the valid one only in who issued its certificate", async () => {
    // The whole point of the fixture. Its chain terminates in Let's Encrypt's
    // staging hierarchy — deliberately absurd names, deliberately absent from
    // every trust store — so it can never be mistaken for production. The names
    // live inside the DER, so the chain has to be decoded to see them.
    const invalid = await load("pywacz-signed-invalid.datapackage-digest.json");
    const valid = await load("pywacz-signed.datapackage-digest.json");

    expect(await issuersOf(invalid.domainCert)).toMatch(/STAGING/i);
    expect(await issuersOf(valid.domainCert)).not.toMatch(/STAGING/i);
  });
});
