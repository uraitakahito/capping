/**
 * Timestamps come from somewhere else now.
 *
 * capping used to answer its own timestamp requests, which made a `signedData`
 * self-contained but put a stand-in where RFC 3161 wants an authority: the
 * serial restarted at 01 for every signature, and the spec says serials MUST be
 * unique per TSA. Delegating means the tokens are somebody's job.
 *
 * The TSA here is a real one — `openssl ts -reply`, the same invocation capping
 * used to make inline — behind an HTTP server the test controls. A stub that
 * returned canned bytes would let a `sign()` that never called out pass every
 * test in this file.
 */
import { createServer, type Server } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { initIdentity, type Identity } from "../src/ca.js";
import { sign, TimestampUnavailableError } from "../src/sign.js";
import { splitPemChain } from "../src/signed-data.js";
import { timestampTime, verifySignedData } from "../src/verify.js";
import { Openssl, withTempDir, writeExact } from "../src/openssl.js";

const HASH = "sha256:3dd086a0be145d1108bf32a5cac7c4b4c046eb78365792d4bb28e9f43e3c6571";

interface FakeTsa {
  url: string;
  /** Every request body the TSA was handed, in order. */
  queries: Buffer[];
  /** base64 of the last TimeStampResp it answered with. */
  lastResponse: string;
  rootCert: string;
  close: () => Promise<void>;
}

/**
 * An authority that answers with `openssl ts -reply`, over its own identity.
 *
 * It issues from a root of its own so the tests can tell a token that came from
 * here apart from one capping made for itself: the two would otherwise verify
 * against the same anchor and prove nothing about who produced them.
 */
const startFakeTsa = async (dir: string): Promise<FakeTsa> => {
  const openssl = new Openssl({ cwd: dir });
  await openssl.run(
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", join(dir, "ca.key"), "-out", join(dir, "ca.crt"),
    "-days", "3650", "-subj", "/CN=fake-remote-tsa-ca",
  );
  await openssl.run(
    "req", "-newkey", "rsa:2048", "-nodes",
    "-keyout", join(dir, "tsa.key"), "-out", join(dir, "tsa.csr"),
    "-subj", "/CN=fake-remote-tsa",
  );
  await writeFile(join(dir, "tsa.ext"), "extendedKeyUsage=critical,timeStamping\n", "utf8");
  await openssl.run(
    "x509", "-req", "-in", join(dir, "tsa.csr"),
    "-CA", join(dir, "ca.crt"), "-CAkey", join(dir, "ca.key"), "-CAcreateserial",
    "-out", join(dir, "tsa.crt"), "-days", "3650", "-extfile", join(dir, "tsa.ext"),
  );
  await writeFile(join(dir, "serial"), "01\n", "utf8");
  await writeFile(
    join(dir, "tsa.cnf"),
    [
      "[ tsa_config ]",
      `serial = ${join(dir, "serial")}`,
      `signer_cert = ${join(dir, "tsa.crt")}`,
      `certs = ${join(dir, "ca.crt")}`,
      `signer_key = ${join(dir, "tsa.key")}`,
      "signer_digest = sha256",
      "default_policy = 1.2.3.4.1",
      "digests = sha256",
      "accuracy = secs:1",
      "tsa_name = yes",
      "",
    ].join("\n"),
    "utf8",
  );

  const state: Pick<FakeTsa, "queries" | "lastResponse"> = { queries: [], lastResponse: "" };

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      void (async () => {
        const query = Buffer.concat(chunks);
        state.queries.push(query);
        try {
          const answer = await withTempDir(async (work) => {
            await writeFile(join(work, "req.tsq"), query);
            await openssl.run(
              "ts", "-reply",
              "-config", join(dir, "tsa.cnf"), "-section", "tsa_config",
              "-queryfile", join(work, "req.tsq"),
              "-out", join(work, "resp.tsr"),
            );
            return await openssl.text("base64", "-A", "-in", join(work, "resp.tsr"));
          });
          state.lastResponse = answer.trim();
          res.writeHead(200, { "content-type": "application/timestamp-reply" });
          res.end(Buffer.from(state.lastResponse, "base64"));
        } catch {
          res.writeHead(500).end();
        }
      })();
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;

  return {
    url: `http://127.0.0.1:${String(port)}/api/v1/timestamp`,
    get queries() {
      return state.queries;
    },
    get lastResponse() {
      return state.lastResponse;
    },
    rootCert: await openssl.text("x509", "-in", join(dir, "ca.crt")),
    close: () => new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    }),
  };
};

let dir: string;
let identity: Identity;
let tsa: FakeTsa;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "capping-tsa-test-"));
  identity = await initIdentity({ dir: join(dir, "id"), domain: "sign.dev.local" });
  tsa = await startFakeTsa(await mkdtemp(join(tmpdir(), "capping-fake-tsa-")));
}, 180_000);

afterAll(async () => {
  await tsa.close();
  await rm(dir, { recursive: true, force: true });
});

describe("signing against an external TSA", () => {
  it("carries the token the authority returned, not one it made itself", async () => {
    const before = tsa.queries.length;

    const signedData = await sign(identity, { hash: HASH, tsaUrl: tsa.url });

    expect(tsa.queries.length).toBe(before + 1);
    expect(signedData.timeSignature).toBe(tsa.lastResponse);
  });

  it("asks the authority to timestamp the base64 text of the signature", async () => {
    // The one detail that makes a token verify somewhere else. Rebuilding the
    // query here from the signature capping produced, and comparing the bytes
    // the TSA was actually handed, pins it to the signature rather than to
    // whatever `sign()` happened to hash.
    const signedData = await sign(identity, { hash: HASH, tsaUrl: tsa.url });
    const sent = tsa.queries.at(-1);

    const rebuilt = await withTempDir(async (work) => {
      await writeExact(join(work, "sig.txt"), signedData.signature);
      const openssl = new Openssl({ cwd: work });
      await openssl.run(
        "ts", "-query", "-data", join(work, "sig.txt"),
        "-sha256", "-cert", "-out", join(work, "q.tsq"),
      );
      return await openssl.text("ts", "-query", "-in", join(work, "q.tsq"), "-text");
    });

    const received = await withTempDir(async (work) => {
      await writeFile(join(work, "q.tsq"), sent ?? Buffer.alloc(0));
      return await new Openssl({ cwd: work }).text(
        "ts", "-query", "-in", join(work, "q.tsq"), "-text",
      );
    });

    // Nonces differ between two queries; the message imprint must not.
    const imprintOf = (text: string): string | undefined =>
      /Message data:\n([\s\S]*?)\n[A-Z]/.exec(text)?.[1];
    expect(imprintOf(received)).toBe(imprintOf(rebuilt));
  });

  it("carries a timestamp from around when it was signed", async () => {
    const before = Date.now();
    const signedData = await sign(identity, { hash: HASH, tsaUrl: tsa.url });
    const stamped = await timestampTime(signedData.timeSignature ?? "");

    expect(stamped).toBeDefined();
    // RFC 3161 timestamps are second-granular here, so allow a minute either
    // way rather than asserting an exact instant.
    expect(Math.abs((stamped?.getTime() ?? 0) - before)).toBeLessThan(60_000);
  });

  it("builds timestampCert from the token, leaf first", async () => {
    const signedData = await sign(identity, { hash: HASH, tsaUrl: tsa.url });
    const chain = splitPemChain(signedData.timestampCert ?? "");

    expect(chain).toHaveLength(2);
    const subjectOf = async (pem: string): Promise<string> =>
      await withTempDir(async (work) => {
        await writeFile(join(work, "c.pem"), pem, "utf8");
        return await new Openssl({ cwd: work }).text(
          "x509", "-in", join(work, "c.pem"), "-noout", "-subject",
        );
      });

    expect(await subjectOf(chain[0] ?? "")).toContain("fake-remote-tsa");
    expect(await subjectOf(chain[1] ?? "")).toContain("fake-remote-tsa-ca");
  });

  it("verifies end to end against the authority's own root", async () => {
    const signedData = await sign(identity, { hash: HASH, tsaUrl: tsa.url });

    const report = await verifySignedData(signedData, { trustRoots: [identity.rootCert] });

    expect(report.valid).toBe(true);
    expect(report.stages.timestamp.status).toBe("ok");
  });

  it("fails the signature rather than returning a half-built chain", async () => {
    // An authority that answers without its root leaves `timestampCert` with a
    // leaf and nothing to anchor it to. Every consumer that reads the archive
    // on its own — `verify` included — treats the last certificate as the root,
    // so a one-entry chain quietly checks the leaf against itself.
    const bare = createServer((_req, res) => {
      res.writeHead(500).end();
    });
    await new Promise<void>((resolve) => {
      bare.listen(0, "127.0.0.1", resolve);
    });
    const address = bare.address();
    const port = typeof address === "object" && address !== null ? address.port : 0;

    // The type matters as much as the throw: the server turns this one into a
    // 502, and a plain Error would come back as 400 — telling the caller to fix
    // a request that was never the problem.
    await expect(
      sign(identity, { hash: HASH, tsaUrl: `http://127.0.0.1:${String(port)}/` }),
    ).rejects.toThrow(TimestampUnavailableError);
    await expect(
      sign(identity, { hash: HASH, tsaUrl: `http://127.0.0.1:${String(port)}/` }),
    ).rejects.toThrow(/500/);

    await new Promise<void>((resolve) => {
      bare.close(() => {
        resolve();
      });
    });
  });
});

describe("signing without an external TSA", () => {
  it("returns a signedData with no timestamp at all", async () => {
    const signedData = await sign(identity, { hash: HASH });

    // Not an empty string and not a placeholder: wacz-auth makes both timestamp
    // members optional, and absence is the only honest way to say a signature
    // was never timestamped.
    expect(signedData.timeSignature).toBeUndefined();
    expect(signedData.timestampCert).toBeUndefined();
  });

  it("still verifies, with the timestamp stage reported as skipped", async () => {
    const signedData = await sign(identity, { hash: HASH });

    const report = await verifySignedData(signedData, { trustRoots: [identity.rootCert] });

    // `skipped` rather than `failed`: nothing was checked because nothing was
    // claimed. A signature with no timestamp is weaker, not broken.
    expect(report.valid).toBe(true);
    expect(report.stages.timestamp.status).toBe("skipped");
  });
});

describe("--explain", () => {
  it("prints a curl command for the call it makes over HTTP", async () => {
    const printed: string[] = [];

    await sign(identity, { hash: HASH, tsaUrl: tsa.url, onCommand: (c) => printed.push(c) });

    // The openssl lines exist so a reader can repeat each step by hand. The
    // timestamp step stopped being an openssl invocation; it should not stop
    // being repeatable.
    const curl = printed.find((line) => line.startsWith("curl "));
    expect(curl).toBeDefined();
    expect(curl).toContain("application/timestamp-query");
    expect(curl).toContain(tsa.url);
  });
});
