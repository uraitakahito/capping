---
title: Quickstart
description: Issue an identity, sign a datapackage.json, and verify the result.
---

capping needs `openssl` on `PATH` and Node 24. Nothing else.

```console
$ openssl version
OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)
```

## 1. Issue an identity

```console
$ capping init --dir ./id --domain sign.dev.local
identity for sign.dev.local in ./id
  signing certificate  ./id/insecure-dev-signer.crt
  trust root           ./id/insecure-dev-ca.crt
  timestamps           pass --tsa-url to sign; capping issues none
```

The `insecure-dev-` in every filename is not decoration. These keys are **safe to leak**: the CA reaches no trust store, and the certificates sign nothing anyone trusts. Commit the identity directory, mount it read-only, hand it around. A file called `signer.key` says none of that, and someone who finds one in a repository or a log **starts responding to an incident that did not happen**.

capping issues no timestamps of its own. It used to, and the stand-in that did restarted its serial number at `01` for every signature — RFC 3161 says serials MUST be unique per authority, so what came out looked like a timestamp and was not one. Timestamping is now somebody else's job, named by `--tsa-url`.

The signing key is ECDSA P-256, matching what the reference implementation uses. The certificate carries `subjectAltName=DNS:<domain>`, because the domain stage checks names the way a TLS client does rather than reading the CN by hand.

## 2. Sign

```console
$ capping sign --dir ./id --file datapackage.json --out datapackage-digest.json \
    --tsa-url http://localhost:3004/api/v1/timestamp
```

`--file` hashes the file for you. `--hash sha256:…` takes a digest you already have — for example one a capture pipeline computed.

`--tsa-url` is optional. Without it the signature carries no `timeSignature` and no `timestampCert`, and verification reports the timestamp stage as `skipped` rather than failing — wacz-auth makes both members optional, and a signature with no timestamp is weaker rather than broken.

The result is the file that belongs at the WACZ root:

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

## 3. Verify

```console
$ capping verify --file datapackage-digest.json --root ./id/insecure-dev-ca.crt
  ok       signature  signature matches the hash under the certificate's key
  ok       chain      chain reaches a supplied trust root
  ok       domain     certificate is valid for sign.dev.local
  ok       timestamp  timestamp covers this signature

valid
```

The exit code is 0 when nothing failed and 1 otherwise, so this drops into a script without parsing the output.

Leave out `--root` and the chain stage reports `skipped` rather than `failed`. Nobody named a trust anchor, which is a different thing from the chain not reaching one — see [Verification](/verification/).

## The failure you should try first

```console
$ capping init --dir ./expired --domain sign.dev.local --signer-days 0
$ capping sign --dir ./expired --hash sha256:3dd086a0… --out expired.json
$ capping verify --file expired.json --root ./expired/insecure-dev-ca.crt
  ok       signature  signature matches the hash under the certificate's key
  FAILED   chain      error 10 at 0 depth lookup: certificate has expired
  ok       domain     certificate is valid for sign.dev.local
  ok       timestamp  timestamp covers this signature

not valid
```

`--signer-days 0` issues an identity that is already past its validity. This is not an exotic case: signing certificates are deliberately short-lived, so by the time anyone verifies an archive, expiry is the *normal* state. `--allow-expired` is what a verifier reaches for once the timestamp has shown the signature predates the expiry — which is the entire reason the timestamp is there.

```console
$ capping verify --file expired.json --root ./expired/insecure-dev-ca.crt --allow-expired
  ok       chain      chain reaches a supplied trust root
```

## As a service

```console
$ capping serve --dir ./id --port 8080 --token "$CAPPING_TOKEN"
capping serving sign.dev.local on http://127.0.0.1:8080
  POST /sign    (bearer token required)
  POST /verify
```

Shaped like [authsign](https://github.com/webrecorder/authsign):

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

Only `/sign` takes a bearer token. Verification reveals nothing a holder of the archive does not already have, while signing is the thing that must not be open to anyone who can reach the port.

The reason to run this rather than call the library is to keep the signing key off the machine doing the capturing: the capture process sends a hash and gets a signature back, and never holds anything that could sign a second archive.
