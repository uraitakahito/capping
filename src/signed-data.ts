/**
 * The `signedData` object of wacz-auth 0.1.0, and the file that carries it.
 *
 * Two signature formats exist in the spec. capping implements the second —
 * Domain-Ownership Identity + Signed Timestamp — because it is the one that
 * says who signed: the identity is a domain, and the certificate for it is
 * checkable against the same trust anchors a browser uses.
 *
 * Field names follow the spec exactly, including `domainCert` carrying a whole
 * PEM chain in one string rather than a list.
 */

/** wacz-auth 0.1.0 — Domain-Ownership Identity + Signed Timestamp. */
// #region SignedData
export interface SignedData {
  /** The `sha256:<hex>` string from `datapackage-digest.json`. Signed verbatim, prefix included. */
  hash: string;
  /** ISO 8601. The signer's own claim, which the timestamp exists to corroborate. */
  created: string;
  software?: string;
  version?: string;
  /** base64 DER ECDSA signature over `hash`. */
  signature: string;
  /** Hostname the signing certificate was issued for. */
  domain: string;
  /** PEM chain, leaf first. */
  domainCert: string;
  /** base64 RFC 3161 token over the *base64 text* of `signature`. */
  timeSignature?: string;
  /** PEM chain for the timestamp authority, leaf first. */
  timestampCert?: string;
  /** Alternative trust path, used when `domainCert` can no longer be trusted. */
  crossSignedCert?: string;
}
// #endregion SignedData

/** `datapackage-digest.json` — the file at the WACZ root that carries the signature. */
export interface DatapackageDigest {
  /** Always the string "datapackage.json". */
  path: string;
  /** `sha256:<hex>` of `datapackage.json`. Matches `signedData.hash` when signed. */
  hash: string;
  signedData?: SignedData;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const requireString = (o: Record<string, unknown>, key: string, where: string): string => {
  const v = o[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`${where}: missing or empty "${key}"`);
  }
  return v;
};

const optionalString = (o: Record<string, unknown>, key: string): string | undefined => {
  const v = o[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
};

/**
 * Parse a `signedData` object, rejecting anything that would fail later anyway.
 *
 * Checked here rather than at verification time so a malformed file reports
 * what is wrong with it, instead of surfacing as an openssl error about a file
 * that turned out to be empty.
 */
export function parseSignedData(value: unknown): SignedData {
  if (!isRecord(value)) throw new Error("signedData: not an object");

  const out: SignedData = {
    hash: requireString(value, "hash", "signedData"),
    created: requireString(value, "created", "signedData"),
    signature: requireString(value, "signature", "signedData"),
    domain: requireString(value, "domain", "signedData"),
    domainCert: requireString(value, "domainCert", "signedData"),
  };

  if (!out.hash.startsWith("sha256:")) {
    // The prefix is part of the signed bytes, so a hash without one cannot be
    // what was signed — better to say so than to fail an opaque verification.
    throw new Error(`signedData: hash must start with "sha256:", got "${out.hash}"`);
  }

  const software = optionalString(value, "software");
  if (software !== undefined) out.software = software;
  const version = optionalString(value, "version");
  if (version !== undefined) out.version = version;
  const timeSignature = optionalString(value, "timeSignature");
  if (timeSignature !== undefined) out.timeSignature = timeSignature;
  const timestampCert = optionalString(value, "timestampCert");
  if (timestampCert !== undefined) out.timestampCert = timestampCert;
  const crossSignedCert = optionalString(value, "crossSignedCert");
  if (crossSignedCert !== undefined) out.crossSignedCert = crossSignedCert;

  return out;
}

/** Parse a whole `datapackage-digest.json`. */
export function parseDatapackageDigest(value: unknown): DatapackageDigest {
  if (!isRecord(value)) throw new Error("datapackage-digest: not an object");

  const out: DatapackageDigest = {
    path: requireString(value, "path", "datapackage-digest"),
    hash: requireString(value, "hash", "datapackage-digest"),
  };
  if (value["signedData"] !== undefined) {
    out.signedData = parseSignedData(value["signedData"]);
  }
  return out;
}

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/**
 * Split a concatenated PEM chain into individual certificates, leaf first.
 *
 * `openssl verify` wants the leaf and its issuers in separate files, but the
 * spec stores them glued together in one string, so every consumer of
 * `domainCert` has to do this.
 */
export function splitPemChain(pem: string): string[] {
  const certs = pem.match(PEM_CERT);
  if (certs === null || certs.length === 0) {
    throw new Error("certificate chain contains no PEM certificates");
  }
  return certs.map((c) => `${c}\n`);
}
