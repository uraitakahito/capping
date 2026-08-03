---
title: Signing
description: Producing a signedData, and the two details the spec does not state.
---

`signedData` is the object wacz-auth defines, carried in `datapackage-digest.json` at the WACZ root:

```ts file="src/signed-data.ts#SignedData"
```

capping implements the second of the spec's two formats — **Domain-Ownership Identity + Signed Timestamp** — because it is the one that says *who* signed. The identity is a domain, and the certificate for it is checkable against the same trust anchors a browser uses.

## The steps

```ts file="src/sign.ts#sign-steps"
```

The timestamp is not capping's to make: it is asked for, from the RFC 3161 authority `--tsa-url` names. Building the request stays an openssl invocation — `ts -query` is a pure transformation that needs no key and no configuration — so what was dropped is only the part that answered it.

```ts file="src/sign.ts#timestamp-request"
```

## Two things the spec does not say

Both were found by taking the reference implementation's output apart rather than by reading the specification, and getting either one wrong produces something that looks entirely plausible while verifying against nothing.

### 1. The signature covers the hash string, prefix included

The signed bytes are `sha256:fcf066f7…` — not the hex alone, and with no trailing newline. Sign the hex only and openssl fails in `digest_verify_final`. Add a newline (which `echo` does, and which most editors add on save) and the digest changes, so the signature verifies against nothing.

This is why capping writes those bytes through a function that exists solely to promise it adds nothing:

> Signatures are computed over exactly these bytes. A stray `\n` — which `echo` would add, and which most editors add on save — changes the digest and produces a signature that verifies against nothing.

### 2. `timeSignature` holds a whole TimeStampResp

The timestamp covers the **base64 text** of the signature, not the signature's bytes. And what gets stored is the entire `TimeStampResp` — status wrapper included — not the bare token inside it.

That second point is worth dwelling on, because it is easy to get backwards. RFC 3161 has a request (`TSQ`) and a response (`TSR`), and the response *contains* a token (`TST`). It is natural to assume the field named `timeSignature` holds the token. It does not.

Reading it as a token means passing `-token_in`, and the failure looks like this:

```
asn1_check_tlen:wrong tag … Field=type, Type=PKCS7
```

which is not an obvious way to be told you passed the wrong flag. The way to settle it is to ask openssl to read the bytes as a response and see whether it can:

```console
$ openssl ts -reply -in ts.tst -text
Status info:
Status: Granted.
…
Time stamp: Aug  1 13:59:39 2026 GMT
```

It can. So no `-token_in`, on either side.

## Signing on one machine, capturing on another

```console
$ capping serve --dir ./id --port 8080 --token "$CAPPING_TOKEN"
```

`POST /sign` takes `{"hash": "sha256:…"}` and returns the `signedData`. `POST /verify` takes either a `signedData` or a whole `datapackage-digest.json` and returns the four-stage report.

Only `/sign` is protected, matching authsign. The capture process sends a hash and gets a signature back; it never holds anything that could sign a second archive. Verification stays open because it reveals nothing that a holder of the archive does not already have.

`/verify` answers **200 with `valid: false`** for an archive that does not check out, rather than a 4xx. The question was answered. A transport-level error code there would be indistinguishable from the server being down, which is a different thing entirely from an archive that fails to verify.
