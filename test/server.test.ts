/**
 * The HTTP surface.
 *
 * Its reason to exist is keeping the signing key off the capture machine, so
 * the tests that matter are the ones about that boundary: does `/sign` refuse a
 * caller without the token, and does `/verify` answer honestly for an archive
 * it did not sign.
 */
import type { AddressInfo } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { initIdentity, type Identity } from "../src/ca.js";
import { listen } from "../src/server.js";
import type { VerifyReport } from "../src/verify.js";
import type { SignedData } from "../src/signed-data.js";

const HASH = "sha256:3dd086a0be145d1108bf32a5cac7c4b4c046eb78365792d4bb28e9f43e3c6571";
const TOKEN = "a-development-token";

let dir: string;
let identity: Identity;
let server: Server;
let base: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "capping-server-"));
  identity = await initIdentity({ dir: join(dir, "id"), domain: "sign.dev.local" });

  // Port 0 lets the OS pick, so a stray process on a fixed port cannot make
  // this suite fail for a reason that has nothing to do with the code.
  server = await listen({ identity, token: TOKEN, trustRoots: [identity.rootCert] }, 0);
  base = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
}, 180_000);

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => { resolve(); }));
  await rm(dir, { recursive: true, force: true });
});

const post = async (path: string, body: unknown, token?: string): Promise<Response> =>
  fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    },
    body: JSON.stringify(body),
  });

describe("POST /sign", () => {
  it("returns a signedData that /verify accepts", async () => {
    const signRes = await post("/sign", { hash: HASH }, TOKEN);
    expect(signRes.status).toBe(200);

    const signedData = (await signRes.json()) as SignedData;
    expect(signedData.hash).toBe(HASH);
    expect(signedData.domain).toBe("sign.dev.local");

    const verifyRes = await post("/verify", signedData);
    const report = (await verifyRes.json()) as VerifyReport;
    expect(report.valid).toBe(true);
    expect(report.stages.chain.status).toBe("ok");
  }, 60_000);

  it("refuses a caller without the token", async () => {
    // The whole point of running this over HTTP is that the key lives here and
    // nowhere else. An open /sign would give that away.
    expect((await post("/sign", { hash: HASH })).status).toBe(401);
    expect((await post("/sign", { hash: HASH }, "wrong")).status).toBe(401);
    // A token of the right length but wrong content takes the same path as any
    // other mismatch, which is what the constant-time compare is for.
    expect((await post("/sign", { hash: HASH }, "b".repeat(TOKEN.length))).status).toBe(401);
  }, 60_000);

  it("rejects a hash it cannot sign", async () => {
    expect((await post("/sign", { hash: "not-a-hash" }, TOKEN)).status).toBe(400);
    expect((await post("/sign", {}, TOKEN)).status).toBe(400);
  }, 60_000);
});

describe("POST /verify", () => {
  it("needs no token, because verifying reveals nothing", async () => {
    const signedData = (await post("/sign", { hash: HASH }, TOKEN).then((r) =>
      r.json(),
    )) as SignedData;
    expect((await post("/verify", signedData)).status).toBe(200);
  }, 60_000);

  it("answers 200 with valid:false rather than an error status", async () => {
    // An archive that does not verify is an answer, not a failure to answer.
    // A 4xx here would look the same to a client as the server being wrong.
    const signedData = (await post("/sign", { hash: HASH }, TOKEN).then((r) =>
      r.json(),
    )) as SignedData;
    const tampered = { ...signedData, hash: HASH.replace(/.$/, "0") };

    const res = await post("/verify", tampered);
    expect(res.status).toBe(200);

    const report = (await res.json()) as VerifyReport;
    expect(report.valid).toBe(false);
    expect(report.stages.signature.status).toBe("failed");
  }, 60_000);

  it("accepts a whole datapackage-digest.json as well as a bare signedData", async () => {
    const signedData = (await post("/sign", { hash: HASH }, TOKEN).then((r) =>
      r.json(),
    )) as SignedData;

    const res = await post("/verify", { path: "datapackage.json", hash: HASH, signedData });
    expect(((await res.json()) as VerifyReport).valid).toBe(true);
  }, 60_000);
});

describe("the server's edges", () => {
  it("rejects a body that is not JSON", async () => {
    const res = await fetch(`${base}/verify`, { method: "POST", body: "{" });
    expect(res.status).toBe(400);
  }, 30_000);

  it("has only the two endpoints, and only over POST", async () => {
    expect((await post("/nope", {})).status).toBe(404);
    expect((await fetch(`${base}/verify`)).status).toBe(405);
  }, 30_000);
});
