import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import { satteri } from "@astrojs/markdown-satteri";
import mdastCodeRegion from "./src/plugins/mdast-code-region";
import hastRebaseLinks from "./src/plugins/hast-rebase-links";

const BASE = "/capping";

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
        // The specification capping implements. Read often enough to belong in
        // the nav. BrowserHive's docs used to sit next to it, but they are no
        // longer published on the web — that repo builds them locally now.
        { label: "wacz-auth 0.1.0 ↗", link: "https://specs.webrecorder.net/wacz-auth/0.1.0/" },
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
