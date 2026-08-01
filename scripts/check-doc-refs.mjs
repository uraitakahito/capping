/**
 * Verify that the Starlight docs-site stays in sync with the TypeScript source.
 *
 * `astro build` already throws on a missing `// #region` (see
 * docs-site/src/lib/extract.ts), so the build is itself a drift guard for
 * injected snippets. This script catches the reference kinds the build does NOT
 * see — a doc can build green while silently pointing at code that was renamed
 * or removed:
 *
 *   1. ```ts file="src/…#region"   → the file exists AND the region marker is present
 *   2. `src/….ts` code-span paths   → the referenced file still exists on disk
 *
 * BrowserHive's version of this script also validates `/terminology/#g-<Term>`
 * links against `@glossary` tags. capping has no glossary page, so that check
 * would have nothing to validate — and a check with zero subjects is worse than
 * no check, because it is permanently green and reads as coverage.
 *
 * Run via `npm run site:check` (build + this script). Exits 1 with a list of
 * broken references so CI fails the PR. To see it work: rename a `#region` and
 * re-run — the offending doc reference goes red.
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DOCS = resolve(ROOT, "docs-site/src/content/docs");
const SRC = resolve(ROOT, "src");

const walk = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const p = join(dir, entry.name);
    return entry.isDirectory() ? walk(p) : [p];
  });

// ─── Source facts: what the docs are allowed to reference ──────────────────
const srcText = new Map(
  walk(SRC)
    .filter((f) => f.endsWith(".ts"))
    .map((f) => [relative(ROOT, f), readFileSync(f, "utf8")]),
);

// `// #region <name>` markers, indexed by ROOT-relative file path.
const regionsByFile = new Map();
for (const [rel, text] of srcText) {
  regionsByFile.set(
    rel,
    new Set([...text.matchAll(/\/\/\s*#region\s+(\S+)/g)].map((m) => m[1])),
  );
}

// ─── Scan every doc and collect broken references ──────────────────────────
const problems = [];

for (const file of walk(DOCS).filter((f) => /\.mdx?$/.test(f))) {
  const text = readFileSync(file, "utf8");
  const rel = relative(ROOT, file);

  // 1. Live code regions: ```ts file="src/…#region"
  for (const [, path, region] of text.matchAll(/file="([^"#]+)#([^"]+)"/g)) {
    if (!existsSync(resolve(ROOT, path))) {
      problems.push(`${rel}: file="${path}" does not exist`);
      continue;
    }
    if (!regionsByFile.get(path)?.has(region)) {
      problems.push(`${rel}: region "${region}" not found in ${path} (renamed or removed?)`);
    }
  }

  // 2. Concrete source-file paths in code spans: `src/….ts`
  for (const [, path] of text.matchAll(/`(src\/[A-Za-z0-9_\-/]+\.ts)`/g)) {
    if (!existsSync(resolve(ROOT, path))) {
      problems.push(`${rel}: \`${path}\` does not exist (renamed or moved?)`);
    }
  }
}

// ─── Report ────────────────────────────────────────────────────────────────
if (problems.length > 0) {
  console.error(`✗ doc-ref check failed (${problems.length} broken reference(s)):`);
  for (const p of problems) console.error(`  - ${p}`);
  console.error(
    "\nDocs reference code that no longer matches. Update the doc or restore the code.",
  );
  process.exit(1);
}

console.log("✓ doc-ref check passed: all live regions and src paths resolve");
