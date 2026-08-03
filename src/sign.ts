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
import { identityPaths, type Identity } from "./ca.js";
import { Openssl, withTempDir, writeExact } from "./openssl.js";
import { splitPemChain, type SignedData } from "./signed-data.js";

export interface SignOptions {
  /** `sha256:<hex>` of `datapackage.json`, exactly as it appears there. */
  hash: string;
  /** Defaults to now. */
  created?: string;
  software?: string;
  /**
   * An RFC 3161 authority to timestamp the signature with.
   *
   * Omitted, the result carries no `timeSignature` and no `timestampCert`.
   * wacz-auth makes both optional, and a signature without a timestamp is
   * weaker rather than broken — but there is no longer a built-in authority to
   * fall back on, because a stand-in that reused serial 01 for every signature
   * was a worse answer than saying nothing.
   */
  tsaUrl?: string;
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

    // The bytes a timestamp would cover: the base64 *text* of the signature.
    const b64Path = join(work, "sig-b64.txt");
    await writeExact(b64Path, signature);
    // #endregion sign-steps

    const timestamp =
      options.tsaUrl === undefined
        ? undefined
        : await requestTimestamp(openssl, work, b64Path, options.tsaUrl, options.onCommand);

    const [signerCert, caCert] = await Promise.all([
      readFile(p.signerCert, "utf8"),
      readFile(p.caCert, "utf8"),
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
      ...timestamp,
    };
  });
}

/**
 * Ask an RFC 3161 authority to timestamp `dataPath`, and take its chain apart.
 *
 * Building the request stays an openssl invocation: `ts -query` is a pure
 * transformation that needs no key and no configuration. What was dropped is
 * answering it, which capping had no business doing.
 */
async function requestTimestamp(
  openssl: Openssl,
  work: string,
  dataPath: string,
  tsaUrl: string,
  onCommand?: (commandLine: string) => void,
): Promise<{ timeSignature: string; timestampCert: string }> {
  // #region timestamp-request
  const tsq = join(work, "ts.tsq");
  await openssl.run("ts", "-query", "-data", dataPath, "-sha256", "-cert", "-out", tsq);

  // Every other step prints the command that produced it, so that a reader can
  // repeat the whole thing by hand rather than trusting this tool. The step
  // stopped being an openssl invocation; it should not stop being repeatable.
  onCommand?.(
    `curl -sS -H "Content-Type: application/timestamp-query" \\\n` +
      `     --data-binary @ts.tsq ${tsaUrl} -o ts.tsr`,
  );

  const res = await fetch(tsaUrl, {
    method: "POST",
    headers: { "content-type": "application/timestamp-query" },
    body: await readFile(tsq),
  });
  if (!res.ok) {
    throw new Error(`the timestamp authority at ${tsaUrl} answered ${String(res.status)}`);
  }

  // Stored whole, status wrapper included — that is the shape py-wacz writes
  // and the shape `openssl ts -verify` expects back without `-token_in`.
  const response = Buffer.from(await res.arrayBuffer());
  const tsr = join(work, "ts.tsr");
  await writeFile(tsr, response);
  // #endregion timestamp-request

  // The authority's own certificates travel inside the token, because
  // `ts -query -cert` asked for them. There is no file to read them from any
  // more, and asking the authority a second time over a different endpoint
  // would be a second thing that can disagree with the first.
  const der = join(work, "ts-token.der");
  await openssl.run("ts", "-reply", "-in", tsr, "-token_out", "-out", der);
  const printed = await openssl.text("pkcs7", "-inform", "DER", "-in", der, "-print_certs");
  const chain = splitPemChain(printed);

  // `-cert` is a request, not a guarantee, and whether the root travels with
  // the leaf is the authority's choice — sigstore's, for one, leaves it out
  // unless told otherwise. A one-entry chain is the failure that hides: every
  // consumer reading the archive on its own takes the last certificate as the
  // root, so a lone leaf ends up checked against itself.
  if (chain.length < 2) {
    throw new Error(
      `the timestamp authority at ${tsaUrl} returned ${String(chain.length)} certificate(s) ` +
        `in its token; a chain needs the leaf and the root that issued it`,
    );
  }

  return {
    timeSignature: response.toString("base64"),
    timestampCert: chain.join(""),
  };
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
