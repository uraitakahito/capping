---
title: Verification
description: 4 段階が何を問うているか、なぜ分けて報告するのか。
---

wacz-auth は検証を 4 つの確認として記述しています。capping はそれを 1 つの真偽値にまとめず、段階ごとに報告します。答えの意味が違うからです。

```ts file="src/verify.ts#VerifyReport"
```

信頼済みルートに届かない証明書の下で署名が検証できた場合、それは改竄されたアーカイブと同じ意味で「無効」なのでは**ありません**。暗号的には健全で、保証している当事者が分からないだけです。これを `false` に潰すと、読み手が次に何をすべきか決めるための区別が消えます。

## 4 つの段階

| 段階 | 問い | openssl |
| --- | --- | --- |
| `signature` | 署名は、証明書の鍵の下でハッシュと一致するか | `dgst -sha256 -verify` |
| `chain` | 鎖は、渡された信頼アンカーに届くか | `verify -CAfile` |
| `domain` | 証明書は、名乗っているドメインに対して有効か | `x509 -checkhost` |
| `timestamp` | RFC 3161 トークンは、この署名を覆っているか | `ts -verify` |

### signature

```ts file="src/verify.ts#signature-stage"
```

公開鍵はリーフ証明書から取り出します。署名対象のバイト列は、ファイルに書かれているとおりのハッシュ文字列です。`sha256:` 接頭辞を含み、末尾の改行はありません。

### chain

`openssl verify -CAfile roots.pem -untrusted untrusted.pem leaf.pem` です。仕様は鎖全体を `domainCert` という 1 本の文字列に連結して格納しますが、openssl はリーフと発行者を別ファイルで要求します。したがって、どの実装も `-----BEGIN CERTIFICATE-----` で切り分ける処理を持つことになります。

信頼ルートが渡されなかった場合、この段階は `skipped` になります。これは意図的で、失敗とは別のことです。

### domain

CN を手で比較するのではなく `openssl x509 -checkhost <domain>` を使います。`-checkhost` は TLS クライアントと同じ名前照合規則を適用します。ワイルドカードと `subjectAltName` を含む、自前で書き直すと微妙に間違えやすい規則です。

### timestamp

```ts file="src/verify.ts#timestamp-stage"
```

TSA 自身の鎖はトークンの中に入っているので、ここではその最後の証明書をアンカーとして扱います。この段階が問うているのは「トークンが内部的に整合しているか」であって、「そのタイムスタンプ局を信頼したいか」ではありません。

## 状態は 2 つではなく 3 つ

| 状態 | 意味 |
| --- | --- |
| `ok` | 確認を実行し、通った |
| `failed` | 確認を実行し、通らなかった |
| `skipped` | そもそも問われなかった（信頼ルート未指定、`timeSignature` 不在） |

`valid` は、どの段階も **failed** でないときに真になります。skipped があっても無効にはなりません。誰も問わなかった質問には、間違えようのある答えが存在しないからです。

## openssl が言ったこと

段階が落ちたとき、詳細行は openssl 自身の言葉であって、書き直したものではありません。

```
FAILED   chain      error 10 at 0 depth lookup: certificate has expired
```

この行を取り出すには少し注意が要ります。`openssl verify` は理由を印字したあと、その内容を一切含まない要約行を続けます。したがって最終行を採ると `verification failed` を報告し、唯一読む価値のある `certificate has expired` を捨てることになります。一方、サブコマンドによっては失敗ではない前置き（`Using configuration from …`）から始まるので、**最初の**行を採るとノイズを報告することになります。

## そもそも調べられない入力

証明書が 1 つも入っていない `domainCert` は、例外ではなく報告を返します。

```
  FAILED   signature  certificate chain contains no PEM certificates
  skipped  chain      certificate chain contains no PEM certificates
  skipped  domain     certificate chain contains no PEM certificates
  skipped  timestamp  certificate chain contains no PEM certificates
```

呼び出し側が訊いたのは「このアーカイブは通るか」であり、「いいえ、証明書が入っていません」はその答えです。4 つではなく 1 つを failed にするのは、問題が 1 つだからです。そして例外を投げれば CLI はスタックトレースで落ち、openssl が無いときと見分けがつかなくなります。
