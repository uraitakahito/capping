/**
 * capping — a local stand-in for a wacz-auth signing service.
 *
 * Issues its own CA, signing certificate and RFC 3161 timestamp authority, and
 * produces the `signedData` that goes in a WACZ's `datapackage-digest.json`.
 * Every cryptographic step is an openssl invocation; this package supplies the
 * JSON, the temp files and the process handling around them.
 *
 * The reason it is not backed by a public CA is that the interesting cases are
 * the ones a public CA cannot produce: an already-expired identity, a chain
 * that leads somewhere untrusted, a timestamp from a party of your choosing.
 */
export { Openssl, OpensslError, withTempDir, writeExact } from "./openssl.js";
export type { OpensslOptions, RunResult } from "./openssl.js";

export { initIdentity, identityPaths, loadIdentity } from "./ca.js";
export type { CappingPaths, Identity, InitOptions } from "./ca.js";

export { hashFile, sign, toDatapackageDigest, writeDatapackageDigest } from "./sign.js";
export type { SignOptions } from "./sign.js";

export { parseDatapackageDigest, parseSignedData, splitPemChain } from "./signed-data.js";
export type { DatapackageDigest, SignedData } from "./signed-data.js";

export { createServer, listen } from "./server.js";
export type { ServerOptions } from "./server.js";

export { timestampTime, verifySignedData } from "./verify.js";
export type { StageResult, StageStatus, VerifyOptions, VerifyReport } from "./verify.js";
