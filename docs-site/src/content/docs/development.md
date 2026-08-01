---
title: Development
description: How the test suite is ordered, and why the ordering is the point.
---

```console
$ npm install
$ npm run check   # typecheck, lint, test
```

Node 24 and `openssl` on `PATH`. There are no runtime dependencies to install.

## The order of the test suite

The suite is ordered deliberately, and the ordering is the substance rather than a matter of taste.

| File | What it establishes |
| --- | --- |
| `test/verify-real-fixtures.test.ts` | The verifier reads signatures **capping did not produce**. |
| `test/round-trip.test.ts` | capping's own signatures pass that verifier. |
| `test/cli.test.ts` | The shipped `dist/cli.js` behaves — arguments, output streams, exit codes. |
| `test/server.test.ts` | `/sign` refuses callers without the token; `/verify` answers honestly. |

The first file measures the verifier against two signed archives from py-wacz — one sound, one signed under a staging CA — **before** anything in this repository produces a signature.

Reversed, a round trip would prove the two halves agree with each other and nothing more. They could share a misreading of the format and still pass, cheerfully, forever.

That ordering paid for itself immediately: it is what caught the `-token_in` mistake described in [Signing](/signing/). The implementation plan for this package asserted that `timeSignature` holds a bare token and that `-token_in` is required. Both were wrong. Because the verifier met real data before it met capping's own output, the mistake surfaced as an ASN.1 error against a known-good fixture rather than as a self-consistent round trip that agreed with itself about the wrong format.

## The failure cases

These are why capping runs a private CA rather than borrowing a public one. None can be arranged against Let's Encrypt or a public timestamp authority:

- an already-expired signing certificate (`--signer-days 0`), strict and with `--allow-expired`;
- a chain that leads to an unrelated root;
- a tampered hash;
- a claimed domain the certificate does not cover;
- a `domainCert` with no certificate in it.

## Testing what ships

`test/cli.test.ts` spawns `dist/cli.js` rather than importing the module, so it builds first. That costs a couple of seconds and buys certainty that what shipped is what was tested — `bin` points at `dist/cli.js`, and a source-only test would be measuring something nobody runs. It would pass happily while `capping verify` returned 0 on a bad archive.

CI builds before testing for the same reason.

## The openssl version

CI prints `openssl version -a` before anything else runs.

capping does no cryptography of its own, which makes openssl the one external variable that can change the answers without a commit. When a test starts failing for no visible reason, that line is the first thing to check.

## Documentation

The pages under `docs-site/` pull code out of `src/` at build time via `// #region` markers, so a snippet cannot drift from what it claims to show.

```console
$ npm run site:build    # build the site
$ npm run site:check    # build + verify every doc reference resolves
```

Use `site:check`, not `site:build`, when you want the guarantee. The build alone does not enforce it here. The extractor throws on a missing region, but whether that stops the build depends on the page's extension: on `.mdx` the throw surfaces through vite and the build fails, while on `.md` — which is every page in capping — Starlight's docs loader catches it, logs `[ERROR] [starlight-docs-loader] Error rendering …`, and still exits 0. `scripts/check-doc-refs.mjs` is the part that exits non-zero, and it is what CI runs.
