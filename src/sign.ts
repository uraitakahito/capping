/**
 * Producing a `signedData`.
 *
 * Two details decide whether the result verifies anywhere else, and neither is
 * stated in the spec — both were found by taking the reference implementation's
 * output apart:
 *
 *   - the signature covers the hash string *including* its `sha256:` prefix,
 *     with no trailing newline;
 *   - the timestamp covers the base64 *text* of that signature, not its bytes,
 *     and what gets stored is the whole TimeStampResp rather than the token.
 *
 * Get either wrong and the output looks entirely plausible while verifying
 * against nothing.
 */
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { SOFTWARE } from "./version.js";
import { buildTsaConfig, identityPaths, type Identity } from "./ca.js";
import { Openssl, withTempDir, writeExact } from "./openssl.js";
import type { SignedData } from "./signed-data.js";

export interface SignOptions {
  /** `sha256:<hex>` of `datapackage.json`, exactly as it appears there. */
  hash: string;
  /** Defaults to now. */
  created?: string;
  software?: string;
  onCommand?: (commandLine: string) => void;
}

export async function sign(identity: Identity, options: SignOptions): Promise<SignedData> {
  if (!options.hash.startsWith("sha256:")) {
    throw new Error(`hash must start with "sha256:", got "${options.hash}"`);
  }

  const p = identityPaths(identity.dir);

  return withTempDir(async (work) => {
    const openssl = new Openssl(
      options.onCommand === undefined ? { cwd: work } : { cwd: work, onCommand: options.onCommand },
    );

    // #region sign-steps
    // The signed bytes, written exactly — `writeExact` adds no newline.
    const hashPath = join(work, "hash.txt");
    await writeExact(hashPath, options.hash);

    await openssl.run("dgst", "-sha256", "-sign", p.signerKey, "-out", join(work, "sig.der"), hashPath);
    await openssl.run("base64", "-A", "-in", join(work, "sig.der"), "-out", join(work, "sig.b64"));
    const signature = (await readFile(join(work, "sig.b64"), "utf8")).trim();

    // Timestamp the base64 text of the signature.
    const b64Path = join(work, "sig-b64.txt");
    await writeExact(b64Path, signature);
    await openssl.run("ts", "-query", "-data", b64Path, "-sha256", "-cert", "-out", join(work, "ts.tsq"));
    // #endregion sign-steps
    // The TSA config and its serial live here, in the temp directory, not in
    // the identity. Both would otherwise pin the identity to one absolute path
    // and require it to be writable — and a development CA is most useful when
    // it can be committed, mounted read-only, and used from anywhere.
    //
    // The serial therefore restarts at 01 for every signature. A real TSA must
    // not repeat serials; this one is a stand-in whose tokens are checked by
    // `openssl ts -verify`, which does not care.
    const serialPath = join(work, "tsa.serial");
    const confPath = join(work, "tsa.cnf");
    await writeFile(serialPath, "01\n", "utf8");
    await writeFile(confPath, buildTsaConfig(p, serialPath), "utf8");

    await openssl.run(
      "ts", "-reply",
      "-config", confPath, "-section", "tsa_config",
      "-queryfile", join(work, "ts.tsq"),
      "-out", join(work, "ts.tsr"),
    );
    // Stored whole, status wrapper included — that is the shape py-wacz writes
    // and the shape `openssl ts -verify` expects back without `-token_in`.
    const timeSignature = (await readFile(join(work, "ts.tsr"))).toString("base64");

    const [signerCert, caCert, tsaCert, tsaCaCert] = await Promise.all([
      readFile(p.signerCert, "utf8"),
      readFile(p.caCert, "utf8"),
      readFile(p.tsaCert, "utf8"),
      readFile(p.tsaCaCert, "utf8"),
    ]);

    return {
      hash: options.hash,
      created: options.created ?? new Date().toISOString(),
      software: options.software ?? SOFTWARE,
      // The wacz-auth spec version, which is not capping's — it moves when the
      // spec does, not when this package does.
      version: "0.1.0",
      signature,
      domain: identity.domain,
      // Leaf first, then its issuer — the order every consumer assumes.
      domainCert: signerCert + caCert,
      timeSignature,
      timestampCert: tsaCert + tsaCaCert,
    };
  });
}

/**
 * Wrap a `signedData` as the `datapackage-digest.json` that belongs at a WACZ root.
 *
 * `path` is fixed by the spec, and `hash` repeats the signed value so the file
 * stands on its own without the signature having to be opened.
 */
export function toDatapackageDigest(signedData: SignedData): {
  path: string;
  hash: string;
  signedData: SignedData;
} {
  return { path: "datapackage.json", hash: signedData.hash, signedData };
}

/** `sha256:<hex>` of a file, in the form `datapackage-digest.json` uses. */
export async function hashFile(
  path: string,
  onCommand?: (commandLine: string) => void,
): Promise<string> {
  return withTempDir(async (dir) => {
    const openssl = new Openssl(onCommand === undefined ? { cwd: dir } : { cwd: dir, onCommand });
    const out = await openssl.text("dgst", "-sha256", "-r", path);
    // `-r` prints "<hex> *<path>"; the digest is the first field.
    const hex = out.trim().split(/\s+/)[0];
    if (hex?.length !== 64) {
      throw new Error(`could not read a sha256 out of: ${out.trim()}`);
    }
    return `sha256:${hex}`;
  });
}

/** Write a `datapackage-digest.json` to `path`. */
export async function writeDatapackageDigest(path: string, signedData: SignedData): Promise<void> {
  await writeFile(path, `${JSON.stringify(toDatapackageDigest(signedData), null, 2)}\n`, "utf8");
}
