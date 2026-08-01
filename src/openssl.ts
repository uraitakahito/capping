/**
 * Every openssl invocation in this package goes through here.
 *
 * capping does no cryptography of its own: it shells out for key generation,
 * certificates, digests, signatures and RFC 3161, and confines itself to JSON,
 * temp files and process handling. That choice is only worth anything if the
 * commands stay inspectable, so this module records the argv of every call and
 * can print it — a caller who distrusts a result can paste the line into a
 * shell and get the same answer.
 *
 * openssl works on files, not streams, so temp directories are part of the job
 * and are cleaned up here rather than by each caller.
 */
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/** Raised when openssl exits non-zero. */
export class OpensslError extends Error {
  readonly argv: readonly string[];
  readonly stderr: string;
  readonly code: number | null;

  constructor(argv: readonly string[], stderr: string, code: number | null) {
    // openssl's own diagnostics are more precise than anything we could write
    // in their place, so they are surfaced verbatim alongside the command.
    super(`openssl ${argv.join(" ")}\n  exit ${String(code)}\n  ${stderr.trim()}`);
    this.name = "OpensslError";
    this.argv = argv;
    this.stderr = stderr;
    this.code = code;
  }
}

export interface OpensslOptions {
  /** Working directory for the invocation. All relative paths resolve against it. */
  cwd: string;
  /** Called with the exact command line before each run. Wire to `--explain`. */
  onCommand?: (commandLine: string) => void;
  /** Path to the binary. Overridable so a specific build can be pinned. */
  bin?: string;
}

export interface RunResult {
  argv: readonly string[];
  stdout: Buffer;
  stderr: string;
}

export class Openssl {
  private readonly bin: string;
  private readonly options: OpensslOptions;

  constructor(options: OpensslOptions) {
    this.options = options;
    this.bin = options.bin ?? "openssl";
  }

  /**
   * Run openssl and return its output.
   *
   * `maxBuffer` is raised because certificate chains and timestamp tokens
   * comfortably exceed the 1 MB default once several are printed at once.
   */
  async run(...argv: string[]): Promise<RunResult> {
    this.options.onCommand?.(`openssl ${argv.join(" ")}`);
    try {
      const { stdout, stderr } = await execFileAsync(this.bin, argv, {
        cwd: this.options.cwd,
        encoding: "buffer",
        maxBuffer: 32 * 1024 * 1024,
      });
      return { argv, stdout, stderr: stderr.toString("utf8") };
    } catch (err) {
      const e = err as { stderr?: Buffer | string; code?: number | null };
      throw new OpensslError(argv, String(e.stderr ?? ""), e.code ?? null);
    }
  }

  /** Run and return stdout as text — the common case for `-noout` queries. */
  async text(...argv: string[]): Promise<string> {
    return (await this.run(...argv)).stdout.toString("utf8");
  }

  /** The openssl build in use. Worth logging: it is the only external dependency. */
  async version(): Promise<string> {
    return (await this.text("version")).trim();
  }
}

/**
 * Run `fn` against a fresh temp directory, removing it afterwards.
 *
 * Since openssl reads and writes files, almost every operation needs somewhere
 * to put them. Keeping that here means no caller has to remember to clean up.
 */
export async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "capping-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * Write `content` with no trailing newline.
 *
 * Signatures are computed over exactly these bytes. A stray `\n` — which
 * `echo` would add, and which most editors add on save — changes the digest
 * and produces a signature that verifies against nothing.
 */
export async function writeExact(path: string, content: string): Promise<void> {
  await writeFile(path, content, { encoding: "utf8" });
}
