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
 * Throws when the region is gone — but whether that stops the build depends on
 * the page's extension, which is not obvious and was measured rather than
 * assumed (Starlight 0.41.4 / Astro 7.1.x):
 *
 *   .mdx — the throw surfaces through @astrojs/mdx's vite plugin and the
 *          build fails, exit 1.
 *   .md  — Starlight's docs loader catches it, logs
 *          `[ERROR] [starlight-docs-loader] Error rendering …`, and the build
 *          finishes with exit 0 and "Complete!".
 *
 * Every page in capping is .md, so here the build is not a guard at all. The
 * one that holds the line is scripts/check-doc-refs.mjs, which exits non-zero
 * for both kinds. `npm run site:check` runs both; CI runs `site:check`, never
 * `site:build` alone, for exactly this reason.
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
