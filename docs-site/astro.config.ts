import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import { satteri } from "@astrojs/markdown-satteri";
import mdastCodeRegion from "./src/plugins/mdast-code-region";
import hastRebaseLinks from "./src/plugins/hast-rebase-links";

const BASE = "/capping";

/**
 * Rehype plugin: give absolute local links written in markdown (`/page/`) the
 * site base, and — on pages under `/ja/` — the locale prefix too.
 *
 * Starlight's own sidebar and nav resolve slugs and are already base- and
 * locale-aware, but a `[text](/page/)` written in MDX/MD body text passes
 * through untouched and 404s once the site is served from a subpath. Assets
 * (an href whose last segment has an extension) only get the base.
 *
 * Front matter (hero.actions.link and friends) does not go through this
 * pipeline — write `/capping/page/` there directly.
 */

export default defineConfig({
  site: "https://uraitakahito.github.io",
  base: BASE,
  integrations: [
    starlight({
      title: "capping Docs",
      // Keep code tokens inside reference tables on one line; the openssl
      // command column is long enough to wrap badly.
      customCss: ["./src/styles/tables.css"],
      // English is the root locale (no prefix); Japanese lives under /ja/.
      // Same layout as the sibling repositories — an untranslated ja page
      // falls back to English automatically.
      defaultLocale: "root",
      locales: {
        root: { label: "English", lang: "en" },
        ja: { label: "日本語", lang: "ja" },
      },
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/uraitakahito/capping" },
      ],
      sidebar: [
        { label: "Overview", slug: "index" },
        { label: "Quickstart", slug: "quickstart" },
        { label: "Verification", slug: "verification" },
        { label: "Signing", slug: "signing" },
        { label: "Development", slug: "development" },
        // The specification capping implements, and the reference server it is
        // shaped like. Both are read often enough to belong in the nav.
        { label: "wacz-auth 0.1.0 ↗", link: "https://specs.webrecorder.net/wacz-auth/0.1.0/" },
        { label: "BrowserHive Docs ↗", link: "https://uraitakahito.github.io/browserhive/" },
      ],
    }),
  ],
  // ```ts file="src/…#region" is replaced with the real source at build time.
  markdown: {
    // Astro 7.2 の既定プロセッサ。legacy の remarkPlugins/rehypePlugins は
    // @astrojs/markdown-remark(unified) を要求するので、そちらは使わない。
    processor: satteri({
      mdastPlugins: [mdastCodeRegion],
      hastPlugins: [hastRebaseLinks],
    }),
  },
});
