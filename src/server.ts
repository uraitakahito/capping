/**
 * `/sign` and `/verify` over HTTP, shaped like authsign's.
 *
 * The reason to run this rather than call the library is to keep the signing
 * key off the machine doing the capturing: the capture process sends a hash and
 * gets a signature back, and never holds anything that could sign a second
 * archive.
 *
 * Built on `node:http` rather than Fastify, which the sibling repositories use.
 * The point of this package is that its only dependency is openssl, and that
 * claim is worth more than the routing conveniences would be for two endpoints.
 * It has no runtime dependencies at all, and this file is why it can stay that
 * way.
 */
import { timingSafeEqual } from "node:crypto";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import type { Identity } from "./ca.js";
import { sign } from "./sign.js";
import { parseDatapackageDigest, parseSignedData, type SignedData } from "./signed-data.js";
import { verifySignedData } from "./verify.js";

export interface ServerOptions {
  /** The identity to sign with, as `loadIdentity` returns it. */
  identity: Identity;
  /**
   * Bearer token required by `/sign`.
   *
   * Only `/sign` is protected, matching authsign: verification reveals nothing
   * a holder of the archive does not already have, while signing is the thing
   * that must not be open to anyone who can reach the port.
   */
  token?: string;
  /** Roots `/verify` trusts. Without them it reports the chain stage skipped. */
  trustRoots?: string[];
  allowExpired?: boolean;
  onCommand?: (commandLine: string) => void;
}

/** Signatures with certificate chains run about 8 KB; this is room to spare. */
const MAX_BODY = 1024 * 1024;

class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY) throw new HttpError(413, "body too large");
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const text = await readBody(req);
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "body is not JSON");
  }
}

/**
 * Compare in constant time, without leaking the length by throwing.
 *
 * `timingSafeEqual` rejects buffers of different sizes, so comparing directly
 * would answer "wrong length" faster than "wrong token".
 */
function tokenMatches(supplied: string, expected: string): boolean {
  const a = Buffer.from(supplied, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) {
    timingSafeEqual(b, b);
    return false;
  }
  return timingSafeEqual(a, b);
}

function authorize(req: IncomingMessage, token: string | undefined): void {
  if (token === undefined) return;
  const header = req.headers.authorization ?? "";
  const supplied = /^bearer\s+(.+)$/i.exec(header)?.[1]?.trim() ?? "";
  if (!tokenMatches(supplied, token)) throw new HttpError(401, "unauthorized");
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const json = `${JSON.stringify(body, null, 2)}\n`;
  res.writeHead(status, { "content-type": "application/json" });
  res.end(json);
}

/** Accept a bare `signedData` or a whole `datapackage-digest.json`. */
function asSignedData(parsed: unknown): SignedData {
  if (parsed !== null && typeof parsed === "object" && "signedData" in parsed) {
    const digest = parseDatapackageDigest(parsed);
    if (digest.signedData === undefined) throw new HttpError(400, "no signedData");
    return digest.signedData;
  }
  return parseSignedData(parsed);
}

export function createServer(options: ServerOptions): Server {
  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;

    if (req.method !== "POST") throw new HttpError(405, "use POST");

    if (path === "/sign") {
      authorize(req, options.token);
      const body = await readJson(req);
      if (body === null || typeof body !== "object" || !("hash" in body)) {
        throw new HttpError(400, 'expected {"hash": "sha256:…"}');
      }
      const { hash, created, software } = body as Record<string, unknown>;
      if (typeof hash !== "string") throw new HttpError(400, "hash must be a string");

      const signedData = await sign(options.identity, {
        hash,
        ...(typeof created === "string" ? { created } : {}),
        ...(typeof software === "string" ? { software } : {}),
        ...(options.onCommand === undefined ? {} : { onCommand: options.onCommand }),
      });
      send(res, 200, signedData);
      return;
    }

    if (path === "/verify") {
      const report = await verifySignedData(asSignedData(await readJson(req)), {
        trustRoots: options.trustRoots ?? [],
        allowExpired: options.allowExpired ?? false,
        ...(options.onCommand === undefined ? {} : { onCommand: options.onCommand }),
      });
      // 200 even when invalid: the question was answered. A transport-level
      // error code here would be indistinguishable from the server being down,
      // which is a different thing from an archive that does not verify.
      send(res, 200, report);
      return;
    }

    throw new HttpError(404, "no such endpoint");
  };

  return createHttpServer((req, res) => {
    void handle(req, res).catch((err: unknown) => {
      if (err instanceof HttpError) {
        send(res, err.status, { error: err.message });
        return;
      }
      // `sign` throws on a malformed hash, and the parsers throw on a
      // malformed signedData — both are the caller's doing, not the server's.
      send(res, 400, { error: err instanceof Error ? err.message : String(err) });
    });
  });
}

/** Start a server and resolve once it is accepting connections. */
export async function listen(options: ServerOptions, port: number, host = "127.0.0.1"): Promise<Server> {
  const server = createServer(options);
  await new Promise<void>((resolve) => server.listen(port, host, resolve));
  return server;
}
