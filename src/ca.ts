/**
 * The private CA, the signing identity, and the timestamp authority.
 *
 * Everything here is deliberately local. A public CA cannot issue a
 * certificate that expired yesterday, or one for a domain nobody owns, and a
 * public timestamp authority will not report a time of its caller's choosing —
 * which makes the failure cases impossible to exercise against them. Those
 * cases are the ones worth testing, so capping issues its own.
 *
 * Let's Encrypt's staging environment is not an alternative: its roots are
 * absent from every trust store on purpose, so signatures made under it fail
 * the chain stage while looking perfect everywhere else. That is a confusing
 * state to develop in, and it is exactly what py-wacz's "invalid" fixture is.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { Openssl, withTempDir } from "./openssl.js";

export interface InitOptions {
  /** Directory to hold the keys and certificates. Created if absent. */
  dir: string;
  /** Hostname the signing certificate is issued for. */
  domain: string;
  /**
   * Validity of the signing certificate, in days.
   *
   * Accepts 0 and negative values so an already-expired identity can be made
   * on purpose — the state every real signing certificate reaches, and the one
   * a verifier has to keep handling.
   */
  signerDays?: number;
  /** Validity of the CA and TSA certificates, in days. */
  caDays?: number;
  onCommand?: (commandLine: string) => void;
}

export interface Identity {
  dir: string;
  domain: string;
  /** PEM of the root that signed the signing certificate. */
  rootCert: string;
}

/**
 * Absolute paths for everything in an identity directory.
 *
 * `resolve` rather than `join`, because openssl runs with the identity
 * directory as its cwd. A relative `dir` would then be applied twice —
 * `capping init --dir ./id` looked for `./id/./id/ca.key` and failed with
 * openssl's own "Can't open ... for writing", which reads like a permissions
 * problem rather than a path one.
 */
/**
 * Every file says what it is in its own name.
 *
 * An identity capping issues is a throwaway: the CA reaches no trust store, the
 * keys sign nothing anyone trusts, and the whole directory is meant to be
 * committed, mounted read-only and shared. A file called `insecure-dev-signer.key` does not
 * say any of that — it looks exactly like the one file you must never let out,
 * so finding it in a repository or a log starts an incident that did not happen.
 *
 * `insecure-dev-` is verbose on purpose. It is the part a person reads first,
 * and it answers the only question worth answering quickly: no, this one does
 * not matter.
 */
const PREFIX = "insecure-dev-";

const paths = (dir: string) => ({
  caKey: resolve(dir, `${PREFIX}ca.key`),
  caCert: resolve(dir, `${PREFIX}ca.crt`),
  signerKey: resolve(dir, `${PREFIX}signer.key`),
  signerCsr: resolve(dir, `${PREFIX}signer.csr`),
  signerCert: resolve(dir, `${PREFIX}signer.crt`),
  signerExt: resolve(dir, `${PREFIX}signer.ext`),
});

export type CappingPaths = ReturnType<typeof paths>;
export const identityPaths = paths;

export async function initIdentity(options: InitOptions): Promise<Identity> {
  const { dir, domain } = options;
  const signerDays = options.signerDays ?? 90;
  const caDays = options.caDays ?? 3650;

  await mkdir(dir, { recursive: true });
  const p = paths(dir);
  const openssl = new Openssl(
    options.onCommand === undefined ? { cwd: dir } : { cwd: dir, onCommand: options.onCommand },
  );

  // Root CA for the signing identity.
  await openssl.run(
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", p.caKey, "-out", p.caCert,
    "-days", String(caDays), "-subj", "/CN=capping-dev-ca",
  );

  // Signing key: ECDSA P-256, matching what the reference implementation uses.
  await openssl.run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p.signerKey);
  await openssl.run("req", "-new", "-key", p.signerKey, "-out", p.signerCsr, "-subj", `/CN=${domain}`);
  // subjectAltName rather than relying on the CN: `-checkhost` follows the
  // rules a TLS client uses, and those have looked at SAN for years.
  await writeFile(
    p.signerExt,
    `subjectAltName=DNS:${domain}\nkeyUsage=critical,digitalSignature\n`,
    "utf8",
  );
  await openssl.run(
    "x509", "-req", "-in", p.signerCsr,
    "-CA", p.caCert, "-CAkey", p.caKey, "-CAcreateserial",
    "-out", p.signerCert, "-days", String(signerDays), "-extfile", p.signerExt,
  );

  return {
    dir,
    domain,
    rootCert: await readFile(p.caCert, "utf8"),
  };
}

/**
 * Read an identity `initIdentity` wrote earlier back off disk.
 *
 * The domain comes from the certificate rather than from the caller, so a
 * long-lived process cannot sign under a name the certificate will not support
 * — the mismatch would only surface at the verifier, as a domain stage failure
 * with nothing to point at.
 */
export async function loadIdentity(
  dir: string,
  onCommand?: (commandLine: string) => void,
): Promise<Identity> {
  const p = paths(dir);
  const subject = await withTempDir(async (cwd) => {
    const openssl = new Openssl(onCommand === undefined ? { cwd } : { cwd, onCommand });
    return openssl.text("x509", "-in", p.signerCert, "-noout", "-subject");
  });

  const cn = /CN\s*=\s*([^,\n/]+)/.exec(subject)?.[1]?.trim();
  if (cn === undefined || cn.length === 0) {
    throw new Error(`no CN in ${p.signerCert}: ${subject.trim()}`);
  }

  return {
    dir,
    domain: cn,
    rootCert: await readFile(p.caCert, "utf8"),
  };
}
