#!/usr/bin/env node
/**
 * The command line.
 *
 * Deliberately a thin layer over the library, so that anything the library does
 * can be reproduced by hand: `--explain` prints every openssl invocation before
 * it runs. When a signature will not verify, being able to paste the exact
 * command into a shell is what separates a five-minute problem from an
 * afternoon of guessing which side is wrong.
 *
 * commander does the parsing. The parser this replaced was hand-rolled and let
 * four things through: `--flag=value` did not work, unknown flags were ignored
 * in silence, `--version` printed the usage text, and there was no per-command
 * help. The silent one was the dangerous one — `--singer-days 0` left
 * `--signer-days` at its 90-day default, so an identity meant to be already
 * expired came out valid, and verifying it passed.
 */
import { readFile, writeFile } from "node:fs/promises";
import { argv, exit, stderr, stdout } from "node:process";
import { Command, Option } from "commander";

import { initIdentity, identityPaths, loadIdentity } from "./ca.js";
import { listen } from "./server.js";
import { hashFile, sign, toDatapackageDigest } from "./sign.js";
import { parseDatapackageDigest, parseSignedData } from "./signed-data.js";
import { verifySignedData, type VerifyReport } from "./verify.js";

/**
 * Kept in step with package.json by hand.
 *
 * Reading package.json at runtime would mean resolving a path relative to
 * dist/, which differs between `node dist/cli.js`, a global install and the
 * container — three ways to fail at startup for a string nobody needs that
 * badly.
 */
const VERSION = "0.1.0";

interface GlobalOpts {
  explain?: boolean;
}

/** `--explain` is declared per command; this turns it into the library's hook. */
const explainer = (opts: GlobalOpts): ((cmd: string) => void) | undefined =>
  opts.explain === true ? (cmd) => stderr.write(`+ ${cmd}\n`) : undefined;

/**
 * Days accept 0 and negative values.
 *
 * An already-expired identity is the state every real signing certificate
 * reaches, and being able to produce one on purpose is why capping runs its own
 * CA at all. Rejecting anything below 1 here would remove the case the tool
 * exists for.
 */
const toDays = (value: string): number => {
  const n = Number(value);
  if (!Number.isInteger(n)) throw new Error(`expected a whole number of days, got "${value}"`);
  return n;
};

/** `--root` may be given more than once; each PEM is a trust anchor. */
const collect = (value: string, previous: string[]): string[] => [...previous, value];

const explainOption = new Option("--explain", "print every openssl command before running it");

async function cmdInit(opts: {
  dir: string;
  domain: string;
  signerDays: number;
  caDays: number;
  explain?: boolean;
}): Promise<void> {
  const onCommand = explainer(opts);
  const identity = await initIdentity({
    dir: opts.dir,
    domain: opts.domain,
    signerDays: opts.signerDays,
    caDays: opts.caDays,
    ...(onCommand === undefined ? {} : { onCommand }),
  });

  const p = identityPaths(identity.dir);
  stdout.write(`identity for ${opts.domain} in ${identity.dir}\n`);
  stdout.write(`  signing certificate  ${p.signerCert}\n`);
  stdout.write(`  trust root           ${p.caCert}\n`);
  stdout.write(`  timestamp authority  ${p.tsaCert}\n`);
}

async function cmdSign(opts: {
  dir: string;
  hash?: string;
  file?: string;
  out?: string;
  explain?: boolean;
}): Promise<void> {
  const onCommand = explainer(opts);

  // Not `requiredOption` on either: exactly one of the two is needed, which
  // commander has no way to express. Written as a branch rather than a `??`
  // chain so the narrowing is the compiler's rather than an assertion's.
  let hash: string;
  if (opts.hash !== undefined) {
    hash = opts.hash;
  } else if (opts.file !== undefined) {
    hash = await hashFile(opts.file, ...(onCommand === undefined ? [] : [onCommand]));
  } else {
    stderr.write("capping: one of --hash or --file is required\n");
    exit(2);
  }

  const identity = await loadIdentity(opts.dir, onCommand);
  const signedData = await sign(identity, {
    hash,
    ...(onCommand === undefined ? {} : { onCommand }),
  });

  const json = `${JSON.stringify(toDatapackageDigest(signedData), null, 2)}\n`;
  if (opts.out === undefined) stdout.write(json);
  else await writeFile(opts.out, json, "utf8");
}

async function cmdVerify(opts: {
  file: string;
  root: string[];
  allowExpired?: boolean;
  explain?: boolean;
}): Promise<void> {
  const onCommand = explainer(opts);

  const parsed: unknown = JSON.parse(await readFile(opts.file, "utf8"));
  // Accept either a whole datapackage-digest.json or a bare signedData, since
  // both turn up while debugging.
  const signedData =
    parsed !== null && typeof parsed === "object" && "signedData" in parsed
      ? parseDatapackageDigest(parsed).signedData
      : parseSignedData(parsed);
  if (signedData === undefined) {
    stderr.write(`capping: ${opts.file} has no signedData\n`);
    exit(1);
  }

  const roots = await Promise.all(opts.root.map((path) => readFile(path, "utf8")));

  const report = await verifySignedData(signedData, {
    trustRoots: roots,
    allowExpired: opts.allowExpired === true,
    ...(onCommand === undefined ? {} : { onCommand }),
  });

  printReport(report);
  exit(report.valid ? 0 : 1);
}

async function cmdServe(opts: {
  dir: string;
  port: number;
  host: string;
  token?: string;
  allowExpired?: boolean;
  explain?: boolean;
}): Promise<void> {
  const onCommand = explainer(opts);
  const identity = await loadIdentity(opts.dir, onCommand);

  await listen(
    {
      identity,
      trustRoots: [identity.rootCert],
      allowExpired: opts.allowExpired === true,
      ...(opts.token === undefined ? {} : { token: opts.token }),
      ...(onCommand === undefined ? {} : { onCommand }),
    },
    opts.port,
    opts.host,
  );

  stdout.write(`capping serving ${identity.domain} on http://${opts.host}:${String(opts.port)}\n`);
  stdout.write(`  POST /sign    ${opts.token === undefined ? "(open)" : "(bearer token required)"}\n`);
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

const program = new Command()
  .name("capping")
  .description(
    "Local wacz-auth signing, driven by openssl.\n" +
      "Every cryptographic step is an openssl invocation; --explain prints them.",
  )
  .version(VERSION);

program
  .command("init")
  .description("issue a CA, an ECDSA signing certificate and a timestamp authority")
  .requiredOption("--dir <dir>", "directory to hold the keys and certificates")
  .requiredOption("--domain <host>", "hostname the signing certificate is issued for")
  .option(
    "--signer-days <n>",
    "validity of the signing certificate. 0 or less makes an already-expired one, which is the case worth testing",
    toDays,
    90,
  )
  .option("--ca-days <n>", "validity of the CA and TSA certificates", toDays, 3650)
  .addOption(explainOption)
  .action(cmdInit);

program
  .command("sign")
  .description("produce a datapackage-digest.json for a hash")
  .requiredOption("--dir <dir>", "identity directory made by `capping init`")
  .option("--hash <sha256:hex>", "the hash to sign, exactly as it appears in datapackage.json")
  .option("--file <path>", "hash this file instead of passing --hash")
  .option("--out <path>", "write here instead of stdout")
  .addOption(explainOption)
  .action(cmdSign);

program
  .command("verify")
  .description("check a signature in four stages: signature, chain, domain, timestamp")
  .requiredOption("--file <path>", "a datapackage-digest.json, or a bare signedData")
  .option(
    "--root <pem>",
    "a PEM file to trust. Repeatable. Without one the chain stage is reported as skipped rather than failed",
    collect,
    [],
  )
  .option(
    "--allow-expired",
    "accept an expired certificate. Signing certificates are short-lived by design, so this is the normal state by the time anyone verifies",
  )
  .addOption(explainOption)
  .action(cmdVerify);

program
  .command("serve")
  .description("an authsign-shaped HTTP service: POST /sign and POST /verify")
  .requiredOption("--dir <dir>", "identity directory made by `capping init`")
  .option("--port <n>", "port to listen on", (v) => Number(v), 8080)
  .option("--host <host>", "address to bind. Use 0.0.0.0 inside a container", "127.0.0.1")
  .option(
    "--token <token>",
    "bearer token required by POST /sign. Verification stays open, as it reveals nothing the archive does not",
  )
  .option("--allow-expired", "accept expired certificates when verifying")
  .addOption(explainOption)
  .action(cmdServe);

/**
 * Exit codes are part of a CLI's contract, so they are mapped rather than
 * inherited.
 *
 * capping has always answered a usage error with 2 — the conventional code for
 * "you invoked me wrongly" — and a bare invocation with 0 and the usage text on
 * stdout. commander answers 1 to all of it and writes the help to stderr. A
 * script keying on either would break on a change that was supposed to be about
 * parsing.
 */
if (argv.length <= 2) {
  stdout.write(program.helpInformation());
  exit(0);
}

program.exitOverride();
for (const sub of program.commands) sub.exitOverride();

try {
  await program.parseAsync(argv);
} catch (err) {
  const e = err as { code?: string; exitCode?: number };
  // `--help` and `--version` reach here too, having already printed. They are
  // not errors.
  if (e.code === "commander.helpDisplayed" || e.code === "commander.version") exit(0);
  exit(2);
}
