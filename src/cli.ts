#!/usr/bin/env node
/**
 * The command line.
 *
 * Deliberately a thin layer over the library, so that anything the library does
 * can be reproduced by hand: `--explain` prints every openssl invocation before
 * it runs. When a signature will not verify, being able to paste the exact
 * command into a shell is what separates a five-minute problem from an
 * afternoon of guessing which side is wrong.
 */
import { readFile, writeFile } from "node:fs/promises";
import { argv, exit, stderr, stdout } from "node:process";

import { initIdentity, identityPaths, loadIdentity } from "./ca.js";
import { listen } from "./server.js";
import { hashFile, sign, toDatapackageDigest } from "./sign.js";
import { parseDatapackageDigest, parseSignedData } from "./signed-data.js";
import { verifySignedData, type VerifyReport } from "./verify.js";

const USAGE = `capping — local wacz-auth signing, driven by openssl

  capping init   --dir <dir> --domain <host> [--signer-days N] [--ca-days N]
  capping sign   --dir <dir> (--hash sha256:… | --file <path>) [--out <path>]
  capping verify --file <path> [--root <pem>…] [--allow-expired]
  capping serve  --dir <dir> [--port N] [--host H] [--token T]

Options
  --explain            print every openssl command before running it
  --signer-days N      validity of the signing certificate; 0 or less makes an
                       already-expired one, which is the case worth testing
  --root <pem>         a PEM file to trust. Without one the chain stage is
                       reported as skipped rather than failed
  --allow-expired      accept an expired certificate. Signing certificates are
                       short-lived by design, so this is the normal state by
                       the time anyone verifies
  --token T            bearer token required by POST /sign. Verification stays
                       open, as it reveals nothing the archive does not

Every step shells out to openssl; nothing here implements cryptography.`;

interface Args {
  command: string | undefined;
  flags: Map<string, string[]>;
  bools: Set<string>;
}

const parseArgs = (raw: string[]): Args => {
  const flags = new Map<string, string[]>();
  const bools = new Set<string>();
  let command: string | undefined;

  for (let i = 0; i < raw.length; i++) {
    const token = raw[i] ?? "";
    if (!token.startsWith("--")) {
      command ??= token;
      continue;
    }
    const name = token.slice(2);
    const next = raw[i + 1];
    if (next === undefined || next.startsWith("--")) {
      bools.add(name);
    } else {
      flags.set(name, [...(flags.get(name) ?? []), next]);
      i++;
    }
  }
  return { command, flags, bools };
};

const one = (args: Args, name: string): string | undefined => args.flags.get(name)?.[0];

const require_ = (args: Args, name: string): string => {
  const value = one(args, name);
  if (value === undefined) {
    stderr.write(`capping: --${name} is required\n`);
    exit(2);
  }
  return value;
};

const explainer = (args: Args): ((cmd: string) => void) | undefined =>
  args.bools.has("explain") ? (cmd) => stderr.write(`+ ${cmd}\n`) : undefined;

async function cmdInit(args: Args): Promise<void> {
  const dir = require_(args, "dir");
  const domain = require_(args, "domain");
  const onCommand = explainer(args);

  const identity = await initIdentity({
    dir,
    domain,
    ...(one(args, "signer-days") === undefined
      ? {}
      : { signerDays: Number(one(args, "signer-days")) }),
    ...(one(args, "ca-days") === undefined ? {} : { caDays: Number(one(args, "ca-days")) }),
    ...(onCommand === undefined ? {} : { onCommand }),
  });

  const p = identityPaths(identity.dir);
  stdout.write(`identity for ${domain} in ${identity.dir}\n`);
  stdout.write(`  signing certificate  ${p.signerCert}\n`);
  stdout.write(`  trust root           ${p.caCert}\n`);
  stdout.write(`  timestamp authority  ${p.tsaCert}\n`);
}

async function cmdSign(args: Args): Promise<void> {
  const dir = require_(args, "dir");
  const onCommand = explainer(args);
  const file = one(args, "file");

  const hash =
    one(args, "hash") ??
    (file === undefined
      ? require_(args, "hash")
      : await hashFile(file, ...(onCommand === undefined ? [] : [onCommand])));

  const identity = await loadIdentity(dir, onCommand);
  const signedData = await sign(identity, {
    hash,
    ...(onCommand === undefined ? {} : { onCommand }),
  });

  const json = `${JSON.stringify(toDatapackageDigest(signedData), null, 2)}\n`;
  const out = one(args, "out");
  if (out === undefined) stdout.write(json);
  else await writeFile(out, json, "utf8");
}

async function cmdVerify(args: Args): Promise<void> {
  const file = require_(args, "file");
  const onCommand = explainer(args);

  const parsed: unknown = JSON.parse(await readFile(file, "utf8"));
  // Accept either a whole datapackage-digest.json or a bare signedData, since
  // both turn up while debugging.
  const signedData =
    parsed !== null && typeof parsed === "object" && "signedData" in parsed
      ? parseDatapackageDigest(parsed).signedData
      : parseSignedData(parsed);
  if (signedData === undefined) {
    stderr.write(`capping: ${file} has no signedData\n`);
    exit(1);
  }

  const roots = await Promise.all(
    (args.flags.get("root") ?? []).map((path) => readFile(path, "utf8")),
  );

  const report = await verifySignedData(signedData, {
    trustRoots: roots,
    allowExpired: args.bools.has("allow-expired"),
    ...(onCommand === undefined ? {} : { onCommand }),
  });

  printReport(report);
  exit(report.valid ? 0 : 1);
}

async function cmdServe(args: Args): Promise<void> {
  const dir = require_(args, "dir");
  const onCommand = explainer(args);
  const port = Number(one(args, "port") ?? 8080);
  const host = one(args, "host") ?? "127.0.0.1";

  const token = one(args, "token");
  const identity = await loadIdentity(dir, onCommand);
  await listen(
    {
      identity,
      trustRoots: [identity.rootCert],
      allowExpired: args.bools.has("allow-expired"),
      ...(token === undefined ? {} : { token }),
      ...(onCommand === undefined ? {} : { onCommand }),
    },
    port,
    host,
  );

  stdout.write(`capping serving ${identity.domain} on http://${host}:${String(port)}\n`);
  stdout.write(`  POST /sign    ${token === undefined ? "(open)" : "(bearer token required)"}\n`);
  stdout.write(`  POST /verify\n`);
  // The process stays up on the listening socket; nothing more to do here.
}

const MARK: Record<string, string> = { ok: "ok     ", failed: "FAILED ", skipped: "skipped" };

function printReport(report: VerifyReport): void {
  for (const [name, stage] of Object.entries(report.stages)) {
    stdout.write(`  ${MARK[stage.status] ?? stage.status}  ${name.padEnd(10)} ${stage.detail}\n`);
  }
  stdout.write(report.valid ? "\nvalid\n" : "\nnot valid\n");
}

async function main(): Promise<void> {
  const args = parseArgs(argv.slice(2));
  switch (args.command) {
    case "init":
      return cmdInit(args);
    case "sign":
      return cmdSign(args);
    case "verify":
      return cmdVerify(args);
    case "serve":
      return cmdServe(args);
    default:
      stdout.write(`${USAGE}\n`);
      exit(args.command === undefined ? 0 : 2);
  }
}

await main();
