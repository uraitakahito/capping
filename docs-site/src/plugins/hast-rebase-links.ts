// 本文中の絶対ローカルリンク (/page/) に base を付け、/ja/ 配下のページからの
// リンクには locale も注入する Sätteri の HAST プラグイン。
//
// Starlight のサイドバーやナビは slug 経由で base/locale-aware だが、MD/MDX
// 本文に書かれた [text](/page/) は素通しになるため、ここで補正する。
// アセット(最終セグメントに拡張子を持つ href)は base のみ付与する。
// 既に base-aware なリンクは二重付与しない。
//
// フロントマター (hero.actions.link 等) はこの pipeline を通らない。木に来るのは
// 本文だけなので、そちらは /capping/page/ と直接書く。
import { fileURLToPath } from "node:url";
import { defineHastPlugin } from "satteri";

const BASE = "/capping";

export default defineHastPlugin({
  name: "rebase-links",
  element: {
    // 走査する要素を宣言する。以前は木を自前で再帰して tagName を見ていた。
    filter: ["a"],
    visit(node, ctx) {
      const href = node.properties?.href;
      if (typeof href !== "string") return;
      // Leave links that already carry the base alone.
      if (!href.startsWith("/") || href.startsWith("//") || href.startsWith(`${BASE}/`) || href === BASE) {
        return;
      }
      // 日本語ページかどうかはファイルパスで判定する。unified の `file.path` に
      // あたるのが ctx.fileURL。**公式ドキュメントには載っておらず型定義にしか
      // 出てこない**ので、undefined になっていないかは実物で確かめること。
      const path = ctx.fileURL ? fileURLToPath(ctx.fileURL) : "";
      const inJa = /[\\/]docs[\\/]ja[\\/]/.test(path);
      const lastSeg = href.split(/[?#]/)[0].split("/").pop() ?? "";
      const isAsset = lastSeg.includes(".");
      const locale = inJa && !isAsset && !href.startsWith("/ja/") && href !== "/ja" ? "/ja" : "";
      // 直接代入 (node.properties.href = …) は arena に届かない。setProperty のみ。
      ctx.setProperty(node, "href", BASE + locale + href);
    },
  },
});
