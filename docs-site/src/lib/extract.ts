/**
 * The one place documentation pulls facts out of the source.
 *
 * capping needs a single extractor — `// #region` snippets, so a page can show
 * real code rather than a copy that quietly drifts. That matters more here than
 * in a normal package: the pages document which openssl arguments capping
 * passes, and a page that showed a stale argument list would be describing a
 * different program.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// The capping root. `docs-site` sits directly under it, and every script
// (astro dev/build, node) runs with `docs-site` as its cwd — so the parent is
// the repo. `import.meta.url` is not usable here: the astro build bundles this
// file and the URL becomes a path inside `dist`.
const ROOT = resolve(process.cwd(), "..");

/**
 * The current text between `// #region <name>` and `// #endregion`.
 *
 * Throws when the region is gone. Note that this alone does not stop a build:
 * Starlight's docs loader catches a render error, logs
 * `[ERROR] [starlight-docs-loader] Error rendering …`, and carries on to emit
 * the page. Measured, not assumed — a build with a renamed region exits 0 and
 * reports "Complete!".
 *
 * So the guard that actually holds the line is scripts/check-doc-refs.mjs,
 * which exits non-zero. `npm run site:check` runs both; CI runs `site:check`,
 * never `site:build` alone, for exactly this reason.
 *
 * The name must run to the end of its line. `\b` is not enough: a word
 * boundary sits between `e` and `-`, so a region named `timestamp-stage` would
 * also match a marker reading `#region timestamp-stage-v2` and quietly serve
 * the wrong snippet. That is the failure this whole mechanism exists to
 * prevent, so it is worth the stricter pattern.
 */
export function sourceRegion(file: string, region: string): string {
  const text = readFileSync(resolve(ROOT, file), "utf8");
  const re = new RegExp(String.raw`//\s*#region\s+${region}[ \t]*\r?$([\s\S]*?)//\s*#endregion`, "m");
  const m = re.exec(text);
  if (!m) throw new Error(`region '${region}' not found in ${file}`);
  return (m[1] ?? "").replace(/^\n/, "").replace(/\s+$/, "");
}
