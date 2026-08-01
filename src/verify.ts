/**
 * Verification, in the four stages wacz-auth describes.
 *
 * They are reported separately rather than as one boolean because the answers
 * mean different things. A signature that verifies against a certificate whose
 * chain does not reach a trusted root is not "invalid" in the way a tampered
 * archive is — the cryptography is intact and only the vouching authority is
 * unknown. Collapsing that into `false` throws away the distinction a reader
 * needs to decide what to do next.
 *
 * Every stage delegates to openssl. Nothing here interprets a certificate or a
 * signature itself.
 */
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Openssl, OpensslError, withTempDir, writeExact } from "./openssl.js";
import { splitPemChain, type SignedData } from "./signed-data.js";

export type StageStatus = "ok" | "failed" | "skipped";

export interface StageResult {
  status: StageStatus;
  /** One line, taken from openssl where it said something useful. */
  detail: string;
}

// #region VerifyReport
export interface VerifyReport {
  /** True only when no stage failed. A skipped stage does not make it false. */
  valid: boolean;
  stages: {
    /** Does `signature` verify against `hash` using the leaf certificate's key? */
    signature: StageResult;
    /** Does the certificate chain reach one of the supplied trust anchors? */
    chain: StageResult;
    /** Does `domain` match the certificate it claims? */
    domain: StageResult;
    /** Does the RFC 3161 token cover this signature, and is it itself trusted? */
    timestamp: StageResult;
  };
}
// #endregion VerifyReport

export interface VerifyOptions {
  /** PEM roots to trust. Without them the chain stage cannot pass. */
  trustRoots?: string[];
  /**
   * Accept an expired certificate.
   *
   * Signing certificates are deliberately short-lived, so by the time anyone
   * verifies, expiry is the normal case; the timestamp is what shows the
   * signature predates it. Off by default so the report stays honest.
   */
  allowExpired?: boolean;
  onCommand?: (commandLine: string) => void;
}

const ok = (detail: string): StageResult => ({ status: "ok", detail });
const failed = (detail: string): StageResult => ({ status: "failed", detail });
const skipped = (detail: string): StageResult => ({ status: "skipped", detail });

/**
 * The line of openssl's output that names the problem.
 *
 * openssl prefixes some subcommands with banners ("Using configuration from …")
 * and warnings that are not the failure, so taking the first non-empty line
 * reports noise. Skip the known-uninteresting prefixes and prefer a line that
 * looks like a diagnosis.
 */
const NOISE = /^(Using configuration|Warning:|Usage|Loading|WARNING)/;

/** `error 10 at 0 depth lookup: certificate has expired` — the diagnosis. */
const DIAGNOSIS = /^error \d+ at \d+ depth lookup:/;

/** `error leaf.pem: verification failed` — the summary that follows it. */
const SUMMARY = "verification failed";

const firstLine = (err: unknown): string => {
  const text = err instanceof OpensslError ? err.stderr : String(err);
  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !NOISE.test(l));

  // `openssl verify` prints the reason, then a summary line that repeats none
  // of it. Taking the last line would report "verification failed" and drop
  // "certificate has expired", which is the only part worth reading.
  const diagnosis = lines.find((l) => DIAGNOSIS.test(l));
  if (diagnosis !== undefined) return diagnosis;

  const informative = lines.filter((l) => !l.endsWith(SUMMARY));
  return informative.at(-1) ?? lines.at(-1) ?? "failed";
};

/**
 * A report for input that could not be examined at all.
 *
 * One failed stage rather than four: the certificate is missing, which is a
 * single problem, and four failures would read as four.
 */
const unverifiable = (detail: string): VerifyReport => ({
  valid: false,
  stages: {
    signature: failed(detail),
    chain: skipped(detail),
    domain: skipped(detail),
    timestamp: skipped(detail),
  },
});

export async function verifySignedData(
  signedData: SignedData,
  options: VerifyOptions = {},
): Promise<VerifyReport> {
  return withTempDir(async (dir) => {
    const openssl = new Openssl(
      options.onCommand === undefined ? { cwd: dir } : { cwd: dir, onCommand: options.onCommand },
    );

    let chain: string[];
    try {
      chain = splitPemChain(signedData.domainCert);
    } catch (err) {
      // A `domainCert` with nothing in it is a verification result, not a
      // program error: the caller asked whether an archive checks out, and the
      // answer is no. Throwing here would make the CLI exit on a stack trace
      // instead of printing a report, and would be indistinguishable from
      // openssl being missing.
      return unverifiable(firstLine(err));
    }
    const leaf = chain[0] ?? "";
    await writeFile(join(dir, "leaf.pem"), leaf, "utf8");

    // The rest of the chain plus any roots the caller trusts. openssl wants the
    // intermediates as `-untrusted` and the anchors as `-CAfile`.
    const intermediates = chain.slice(1);
    await writeFile(join(dir, "untrusted.pem"), intermediates.join(""), "utf8");
    await writeFile(join(dir, "roots.pem"), (options.trustRoots ?? []).join("\n"), "utf8");

    // The signed bytes are the hash string exactly as it appears — prefix
    // included, no trailing newline.
    await writeExact(join(dir, "hash.txt"), signedData.hash);
    await writeFile(join(dir, "sig.der"), Buffer.from(signedData.signature, "base64"));

    const signature = await verifySignature(openssl);
    const chainResult = await verifyChain(openssl, intermediates.length > 0, options);
    const domain = await verifyDomain(openssl, signedData.domain);
    const timestamp = await verifyTimestamp(openssl, dir, signedData, options);

    const stages = { signature, chain: chainResult, domain, timestamp };
    return {
      valid: Object.values(stages).every((s) => s.status !== "failed"),
      stages,
    };
  });
}

async function verifySignature(openssl: Openssl): Promise<StageResult> {
  try {
    // #region signature-stage
    await openssl.run("x509", "-in", "leaf.pem", "-pubkey", "-noout", "-out", "pub.pem");
    const out = await openssl.text(
      "dgst",
      "-sha256",
      "-verify",
      "pub.pem",
      "-signature",
      "sig.der",
      "hash.txt",
    );
    // #endregion signature-stage
    return out.includes("Verified OK")
      ? ok("signature matches the hash under the certificate's key")
      : failed(out.trim());
  } catch (err) {
    return failed(firstLine(err));
  }
}

async function verifyChain(
  openssl: Openssl,
  hasIntermediates: boolean,
  options: VerifyOptions,
): Promise<StageResult> {
  if ((options.trustRoots ?? []).length === 0) {
    // Saying "skipped" rather than "failed" keeps the two apart: nobody named a
    // trust anchor, which is not the same as the chain not reaching one.
    return skipped("no trust roots supplied");
  }
  const argv = ["verify", "-CAfile", "roots.pem"];
  if (hasIntermediates) argv.push("-untrusted", "untrusted.pem");
  if (options.allowExpired === true) argv.push("-no_check_time");
  argv.push("leaf.pem");

  try {
    await openssl.run(...argv);
    return ok("chain reaches a supplied trust root");
  } catch (err) {
    return failed(firstLine(err));
  }
}

async function verifyDomain(openssl: Openssl, domain: string): Promise<StageResult> {
  try {
    // `-checkhost` applies the same name-matching rules a TLS client uses,
    // including wildcards and subjectAltName, rather than comparing the CN by
    // hand and getting those rules subtly wrong.
    const out = await openssl.text("x509", "-in", "leaf.pem", "-noout", "-checkhost", domain);
    return out.includes("does match")
      ? ok(`certificate is valid for ${domain}`)
      : failed(`certificate is not valid for ${domain}`);
  } catch (err) {
    return failed(firstLine(err));
  }
}

async function verifyTimestamp(
  openssl: Openssl,
  dir: string,
  signedData: SignedData,
  options: VerifyOptions,
): Promise<StageResult> {
  if (signedData.timeSignature === undefined) {
    return skipped("no timeSignature");
  }

  // The token covers the base64 *text* of the signature, not its bytes.
  await writeExact(join(dir, "sig.b64"), signedData.signature);
  await writeFile(join(dir, "ts.tst"), Buffer.from(signedData.timeSignature, "base64"));

  const tsChain =
    signedData.timestampCert === undefined ? [] : splitPemChain(signedData.timestampCert);
  const tsLeaf = tsChain.at(0);
  const tsRoot = tsChain.at(-1);
  if (tsLeaf === undefined || tsRoot === undefined) {
    return skipped("no timestampCert to check the token against");
  }
  await writeFile(join(dir, "ts-leaf.pem"), tsLeaf, "utf8");
  // The TSA's own chain is self-contained in the token, so its last certificate
  // acts as the anchor here — this stage asks whether the token is internally
  // consistent, not whether that TSA is one we would choose to trust.
  await writeFile(join(dir, "ts-root.pem"), tsRoot, "utf8");

  try {
    // #region timestamp-stage
    // No `-token_in`. What `timeSignature` carries is the whole TimeStampResp —
    // status wrapper included — not the bare token inside it. Reading it as a
    // token fails in ASN.1 with "wrong tag ... Type=PKCS7", which is not an
    // obvious way to be told you passed the wrong flag.
    const argv = ["ts", "-verify", "-data", "sig.b64", "-in", "ts.tst", "-CAfile", "ts-root.pem"];
    if (tsChain.length > 1) argv.push("-untrusted", "ts-leaf.pem");
    if (options.allowExpired === true) argv.push("-no_check_time");
    // #endregion timestamp-stage

    const out = await openssl.text(...argv);
    return out.includes("Verification: OK")
      ? ok("timestamp covers this signature")
      : failed(out.trim());
  } catch (err) {
    return failed(firstLine(err));
  }
}

/** The time a timestamp token asserts, or undefined if it cannot be read. */
export async function timestampTime(
  timeSignature: string,
  onCommand?: (commandLine: string) => void,
): Promise<Date | undefined> {
  return withTempDir(async (dir) => {
    const openssl = new Openssl(onCommand === undefined ? { cwd: dir } : { cwd: dir, onCommand });
    await writeFile(join(dir, "ts.tst"), Buffer.from(timeSignature, "base64"));
    try {
      const out = await openssl.text("ts", "-reply", "-in", "ts.tst", "-text");
      const match = /^Time stamp: (.+)$/m.exec(out);
      if (match?.[1] === undefined) return undefined;
      const parsed = new Date(match[1]);
      return Number.isNaN(parsed.getTime()) ? undefined : parsed;
    } catch {
      return undefined;
    }
  });
}
