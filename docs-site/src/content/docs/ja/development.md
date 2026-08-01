---
title: Development
description: テストの順序と、その順序こそが要点である理由。
---

```console
$ pnpm install
$ pnpm run check   # typecheck・lint・test
```

必要なのは Node 24・pnpm・`PATH` 上の `openssl` です。実行時依存はありません —— `package.json` に並んでいるものはすべて devDependencies で、実行時に要るのは openssl 1 つだけです。

`docs-site/` は独自の lockfile を持つ別の npm プロジェクトなので、`npm ci --prefix docs-site` で入れます。下の `site:*` スクリプトが中に入って実行してくれます。

## テストの順序

このテスト群の順序は意図的なもので、好みの問題ではなく中身そのものです。

| ファイル | 何を担保するか |
| --- | --- |
| `test/verify-real-fixtures.test.ts` | 検証器が、**capping が作ったのではない**署名を読めること |
| `test/round-trip.test.ts` | capping 自身の署名が、その検証器を通ること |
| `test/cli.test.ts` | 出荷される `dist/cli.js` の挙動（引数・出力先・終了コード） |
| `test/server.test.ts` | `/sign` がトークン無しの呼び出しを拒むこと、`/verify` が正直に答えること |

最初のファイルは、py-wacz の署名済みアーカイブ 2 件 —— 正常なものと、ステージング CA で署名されたもの —— に対して検証器を測ります。このリポジトリが署名を 1 つも作る**前に**です。

逆順にすると、往復テストが示すのは「2 つの半分が互いに一致している」ことだけになります。両方が同じ誤読を共有していても、機嫌よく、永久に通り続けます。

この順序はすぐに元を取りました。[Signing](/signing/) に書いた `-token_in` の間違いを捕まえたのがこれです。本パッケージの実装計画は「`timeSignature` には裸のトークンが入っており `-token_in` が要る」と断言していました。どちらも誤りでした。検証器が capping 自身の出力より先に実物と出会っていたため、この誤りは「既知の正解に対する ASN.1 エラー」として表面化しました。もし逆順なら、間違った形式について自分同士で意見が一致した往復テストが、静かに通っていたはずです。

## 失敗系

これらが「公的 CA を借りずに自前 CA を動かす」理由です。Let's Encrypt でも公開タイムスタンプ局でも用意できません。

- 既に期限切れの署名用証明書（`--signer-days 0`）を、厳格モードと `--allow-expired` の両方で
- 無関係なルートに繋がる鎖
- 改竄されたハッシュ
- 証明書が覆っていないドメインを名乗った場合
- 証明書が 1 つも入っていない `domainCert`

## 出荷されるものをテストする

`test/cli.test.ts` はモジュールを import するのではなく `dist/cli.js` を起動します。そのため先にビルドします。数秒のコストと引き換えに、「出荷したものがテストしたものである」という確証が得られます。`bin` が指しているのは `dist/cli.js` であり、ソースだけを見るテストは誰も動かさないものを測っていることになるからです。そういうテストは、`capping verify` が壊れたアーカイブに 0 を返している間もずっと通り続けます。

CI が test より先に build を走らせるのも同じ理由です。

## openssl の版

CI は何よりも先に `openssl version -a` を印字します。

capping は暗号処理を自前で持たないので、openssl は**コミット無しで答えを変えうる唯一の外部要因**です。理由の見えないテスト失敗が起きたとき、最初に疑うべき行がこれです。

## ドキュメント

`docs-site/` 配下のページは、`// #region` マーカー経由でビルド時に `src/` からコードを取り込みます。したがって断片が実物から乖離することはありません。

```console
$ pnpm run site:build    # サイトをビルド
$ pnpm run site:check    # ビルド + ドキュメント内の参照が全て解決することを検証
```

保証が欲しいときは `site:build` ではなく `site:check` を使ってください。ここではビルド単体は強制になりません。region が欠けていれば抽出器は例外を投げますが、それでビルドが止まるかはページの拡張子次第です。`.mdx` なら例外が vite 経由で表面化してビルドが落ちる一方、`.md` —— capping は全ページこちら —— では Starlight の docs loader が捕まえて `[ERROR] [starlight-docs-loader] Error rendering …` と記録し、そのまま終了コード 0 で完了します。非ゼロで落ちるのは `scripts/check-doc-refs.mjs` の方で、CI が走らせているのもこちらです。
