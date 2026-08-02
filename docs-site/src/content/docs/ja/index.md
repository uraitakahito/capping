---
title: capping
description: openssl だけで動く、ローカルの wacz-auth 署名スタンドイン。
---

capping は [wacz-auth](https://specs.webrecorder.net/wacz-auth/0.1.0/) 署名サービスのローカル代替です。自前の CA・署名用証明書・[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) タイムスタンプ局を発行し、WACZ の `datapackage-digest.json` に入る `signedData` を作ります。

**暗号処理はすべて `openssl` の呼び出しです。** capping が受け持つのは JSON・一時ファイル・プロセス起動だけです。暗号処理を npm から持ってくることはありません。実行時依存はコマンドラインを解析する [commander](https://www.npmjs.com/package/commander) 1 つだけです。

これは結果を人が確かめられるようにするための設計です。どのコマンドにも `--explain` を付ければ、実際に叩いた openssl の行がそのまま印字されます。信用できない結果は、手で打ち直して再現できます。

```console
$ capping verify --file datapackage-digest.json --root insecure-dev-ca.crt --explain
+ openssl x509 -in leaf.pem -pubkey -noout -out pub.pem
+ openssl dgst -sha256 -verify pub.pem -signature sig.der hash.txt
+ openssl verify -CAfile roots.pem -untrusted untrusted.pem leaf.pem
+ openssl x509 -in leaf.pem -noout -checkhost sign.dev.local
+ openssl ts -verify -data sig.b64 -in ts.tst -CAfile ts-root.pem -untrusted ts-leaf.pem
  ok       signature  signature matches the hash under the certificate's key
  ok       chain      chain reaches a supplied trust root
  ok       domain     certificate is valid for sign.dev.local
  ok       timestamp  timestamp covers this signature

valid
```

## なぜ自前の CA なのか

試す価値のあるケースが、公的 CA では作れないものばかりだからです。

- **昨日切れた証明書** — 実際の署名用証明書は短命なので、検証する頃にはたいてい期限切れになっています。
- **信頼されないところに繋がる鎖**。
- **こちらが選んだ相手**によるタイムスタンプ。

Let's Encrypt のステージング環境は代わりになりません。ステージングのルートは意図的にどの信頼ストアにも入っていないため、そこで署名したものは他が完璧に見えるままチェーン段階だけ落ちます。py-wacz の「invalid」フィクスチャがまさにこれで、開発対象としては混乱を招くだけです。

## やらないこと

| やらない | 理由 |
| --- | --- |
| `node:crypto` で署名・検証する | 暗号処理を 2 系統持つと、食い違ったときにどちらも証拠にならなくなる |
| ASN.1 / DER を自前で扱う | openssl に任せる。間違えても「それらしく動く」のが最も危険な領域 |
| ACME（Let's Encrypt）対応 | 開発用なので不要。ステージングは信頼済みルートに繋がらず、現実味より混乱が増える |
| 本番運用向けの鍵管理 | 開発用の踏み台。鍵はファイルで平置きでよい |
| Anonymous Signature 形式 | まず Domain-Ownership を通す。後から足すのは容易 |

## 次に読む

- [Quickstart](/quickstart/) — init・sign・verify の 3 コマンド。
- [Verification](/verification/) — 4 段階が何を問うているか、なぜ分けて報告するのか。
- [Signing](/signing/) — 仕様書に書かれていない 2 点。
- [Development](/development/) — テストの順序と、その順序こそが要点である理由。
