---
title: Quickstart
description: 身元を発行し、datapackage.json に署名し、結果を検証する。
---

必要なのは `PATH` 上の `openssl` と Node 24 だけです。

```console
$ openssl version
OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)
```

## 1. 身元を発行する

```console
$ capping init --dir ./id --domain sign.dev.local
identity for sign.dev.local in ./id
  signing certificate  ./id/signer.crt
  trust root           ./id/ca.crt
  timestamp authority  ./id/tsa.crt
```

ここでは独立した 2 本の階層を作ります。署名用証明書を発行する CA と、タイムスタンプ局の証明書を発行する無関係な CA です。実運用ではタイムスタンプは別の当事者から得るものですし、分けておけば「1 つのルートが両方を保証してしまったせいでテストが通る」ことが起きません。

署名鍵は ECDSA P-256 で、リファレンス実装と同じです。証明書には `subjectAltName=DNS:<domain>` を入れます。domain 段階は CN を手で読むのではなく、TLS クライアントと同じ規則で名前を照合するからです。

## 2. 署名する

```console
$ capping sign --dir ./id --file datapackage.json --out datapackage-digest.json
```

`--file` を渡すとファイルのハッシュを計算します。既にダイジェストがあるなら `--hash sha256:…` を使います（キャプチャ側で計算済みの場合など）。

出力は WACZ のルートに置くファイルそのものです。

```json
{
  "path": "datapackage.json",
  "hash": "sha256:128e81a6…",
  "signedData": {
    "hash": "sha256:128e81a6…",
    "created": "2026-08-01T13:59:39.504Z",
    "software": "capping/0.3.0",
    "version": "0.1.0",
    "signature": "MEQCIGS0Ydsd…",
    "domain": "sign.dev.local",
    "domainCert": "-----BEGIN CERTIFICATE-----\n…",
    "timeSignature": "MIIJHTADAgEAMIIJFAYJ…",
    "timestampCert": "-----BEGIN CERTIFICATE-----\n…"
  }
}
```

## 3. 検証する

```console
$ capping verify --file datapackage-digest.json --root ./id/ca.crt
  ok       signature  signature matches the hash under the certificate's key
  ok       chain      chain reaches a supplied trust root
  ok       domain     certificate is valid for sign.dev.local
  ok       timestamp  timestamp covers this signature

valid
```

終了コードは、どの段階も落ちなければ 0、そうでなければ 1 です。出力を解析しなくてもスクリプトに組み込めます。

`--root` を省くと、チェーン段階は `failed` ではなく `skipped` になります。誰も信頼アンカーを指定しなかったということであって、鎖がアンカーに届かないことではありません。詳しくは [Verification](/verification/) を参照してください。

## 最初に試すべき失敗

```console
$ capping init --dir ./expired --domain sign.dev.local --signer-days 0
$ capping sign --dir ./expired --hash sha256:3dd086a0… --out expired.json
$ capping verify --file expired.json --root ./expired/ca.crt
  ok       signature  signature matches the hash under the certificate's key
  FAILED   chain      error 10 at 0 depth lookup: certificate has expired
  ok       domain     certificate is valid for sign.dev.local
  ok       timestamp  timestamp covers this signature

not valid
```

`--signer-days 0` は、発行時点で既に有効期限を過ぎた身元を作ります。これは特殊なケースではありません。署名用証明書は意図的に短命なので、誰かが検証する頃には期限切れなのが**通常の状態**です。

`--allow-expired` は、タイムスタンプによって「署名が期限切れより前だった」ことが示された後に検証者が使うものです。タイムスタンプが存在する理由そのものです。

```console
$ capping verify --file expired.json --root ./expired/ca.crt --allow-expired
  ok       chain      chain reaches a supplied trust root
```

## サービスとして動かす

```console
$ capping serve --dir ./id --port 8080 --token "$CAPPING_TOKEN"
capping serving sign.dev.local on http://127.0.0.1:8080
  POST /sign    (bearer token required)
  POST /verify
```

[authsign](https://github.com/webrecorder/authsign) と同じ形です。

```console
$ curl -s -X POST http://127.0.0.1:8080/sign \
    -H "authorization: Bearer $CAPPING_TOKEN" \
    -H 'content-type: application/json' \
    -d '{"hash":"sha256:128e81a6…"}' > signed.json

$ curl -s -X POST http://127.0.0.1:8080/verify \
    -H 'content-type: application/json' --data-binary @signed.json
{
  "valid": true,
  "stages": { "signature": { "status": "ok", … }, … }
}
```

トークンで守るのは `/sign` だけです。検証は、そのアーカイブを持っている人が既に知っていること以上を明かしません。一方、署名はポートに到達できる誰にでも開いていてはいけないものです。

ライブラリを直接呼ばずにこれを動かす理由は、**署名鍵をキャプチャする機械に置かない**ためです。キャプチャ側はハッシュを送って署名を受け取るだけで、2 本目のアーカイブに署名できるものは何も持ちません。
