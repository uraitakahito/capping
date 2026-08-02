/**
 * capping's own version, in one place.
 *
 * Three copies of this string had drifted apart before it became one: the tags
 * were at v0.2.1 while package.json, `--version` and the `software` field
 * written into every signature all still said 0.1.0. The `software` one is the
 * reason this file exists rather than a constant in cli.ts — it is baked into
 * archives, so a stale value outlives the process that wrote it.
 *
 * Not read from package.json at run time: resolving a path relative to dist/
 * differs between `node dist/cli.js`, a global install and the container, which
 * is three ways to fail at startup for a string nobody needs that badly.
 * `test/cli.test.ts` compares this against package.json instead.
 */
export const VERSION = "0.3.0";

/** The `software` field of a wacz-auth signedData. */
export const SOFTWARE = `capping/${VERSION}`;
