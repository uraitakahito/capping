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
import { join } from "node:path";

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
  /** PEM of the root that signed the timestamp certificate. */
  tsaRootCert: string;
}

const paths = (dir: string) => ({
  caKey: join(dir, "ca.key"),
  caCert: join(dir, "ca.crt"),
  signerKey: join(dir, "signer.key"),
  signerCsr: join(dir, "signer.csr"),
  signerCert: join(dir, "signer.crt"),
  signerExt: join(dir, "signer.ext"),
  tsaCaKey: join(dir, "tsa-ca.key"),
  tsaCaCert: join(dir, "tsa-ca.crt"),
  tsaKey: join(dir, "tsa.key"),
  tsaCsr: join(dir, "tsa.csr"),
  tsaCert: join(dir, "tsa.crt"),
  tsaExt: join(dir, "tsa.ext"),
  tsaConf: join(dir, "tsa.cnf"),
  tsaSerial: join(dir, "tsa.serial"),
});

export type CappingPaths = ReturnType<typeof paths>;
export const identityPaths = paths;

/**
 * The TSA section openssl needs to act as a timestamp authority.
 *
 * `digests` looks optional and is not: without it every `ts -reply` stops with
 * "cannot find config variable". `accuracy` and `ess_cert_id_chain` genuinely
 * are optional — they warn and carry on.
 */
const tsaConfig = (dir: string): string =>
  [
    "[ tsa_config ]",
    `serial = ${join(dir, "tsa.serial")}`,
    `signer_cert = ${join(dir, "tsa.crt")}`,
    `certs = ${join(dir, "tsa-ca.crt")}`,
    `signer_key = ${join(dir, "tsa.key")}`,
    "signer_digest = sha256",
    "default_policy = 1.3.6.1.4.1.99999.1",
    "granularity = 1",
    "ordering = yes",
    "tsa_name = yes",
    "ess_cert_id_alg = sha256",
    "digests = sha256, sha384, sha512",
    "",
  ].join("\n");

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

  // A separate root for the TSA. Real deployments get their timestamps from an
  // unrelated party, and keeping the two hierarchies apart here means a test
  // cannot accidentally pass because one root vouched for both.
  await openssl.run(
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", p.tsaCaKey, "-out", p.tsaCaCert,
    "-days", String(caDays), "-subj", "/CN=capping-dev-tsa-ca",
  );
  await openssl.run(
    "req", "-newkey", "rsa:2048", "-nodes",
    "-keyout", p.tsaKey, "-out", p.tsaCsr, "-subj", "/CN=capping-dev-tsa",
  );
  // Without this EKU `openssl ts -verify` refuses the token outright.
  await writeFile(p.tsaExt, "extendedKeyUsage=critical,timeStamping\n", "utf8");
  await openssl.run(
    "x509", "-req", "-in", p.tsaCsr,
    "-CA", p.tsaCaCert, "-CAkey", p.tsaCaKey, "-CAcreateserial",
    "-out", p.tsaCert, "-days", String(caDays), "-extfile", p.tsaExt,
  );

  await writeFile(p.tsaConf, tsaConfig(dir), "utf8");
  await writeFile(p.tsaSerial, "01\n", "utf8");

  return {
    dir,
    domain,
    rootCert: await readFile(p.caCert, "utf8"),
    tsaRootCert: await readFile(p.tsaCaCert, "utf8"),
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
    tsaRootCert: await readFile(p.tsaCaCert, "utf8"),
  };
}
