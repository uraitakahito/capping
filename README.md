# capping

A local stand-in for a [wacz-auth](https://specs.webrecorder.net/wacz-auth/0.1.0/) signing service. It issues its own CA, signing certificate and RFC 3161 timestamp authority, and produces the `signedData` that goes in a WACZ's `datapackage-digest.json`.

**Every cryptographic step is an `openssl` invocation.** This package contributes JSON, temp files and process handling. Run any command with `--explain` and it prints the exact openssl lines it used, so a result you distrust can be reproduced by hand:

```console
$ capping verify --file datapackage-digest.json --root ca.crt --explain
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

There are no runtime dependencies. openssl is the only thing capping needs, and its version is printed in CI because it is the one external variable that can change the answers.

## Why a private CA

Because the cases worth testing are the ones a public CA cannot produce:

- a certificate that **expired yesterday** — the state every real signing certificate reaches long before anyone verifies the archive;
- a chain that leads somewhere **untrusted**;
- a timestamp from a party of **your** choosing.

Let's Encrypt's staging environment is not an alternative. Its roots are absent from every trust store on purpose, so signatures made under it fail the chain stage while looking perfect everywhere else — which is exactly what py-wacz's "invalid" fixture turns out to be.

## Use

```console
$ capping init   --dir ./id --domain sign.dev.local
$ capping sign   --dir ./id --file datapackage.json --out datapackage-digest.json
$ capping verify --file datapackage-digest.json --root ./id/ca.crt
```

`capping init --signer-days 0` issues an already-expired identity on purpose. Verification is strict about expiry by default; `--allow-expired` is what a verifier reaches for once a timestamp has shown the signature predates it.

### As a service

```console
$ capping serve --dir ./id --port 8080 --token "$CAPPING_TOKEN"
```

Shaped like [authsign](https://github.com/webrecorder/authsign): `POST /sign` takes `{"hash": "sha256:…"}` and returns the `signedData`; `POST /verify` takes either a `signedData` or a whole `datapackage-digest.json` and returns the four-stage report. Only `/sign` takes a bearer token — verification reveals nothing a holder of the archive does not already have.

The reason to run this rather than call the library is to keep the signing key off the machine doing the capturing.

## What verification reports

Four stages, reported separately rather than as one boolean, because the answers mean different things:

| Stage | Question | openssl |
| --- | --- | --- |
| `signature` | Does the signature match the hash under the certificate's key? | `dgst -verify` |
| `chain` | Does the chain reach a supplied trust anchor? | `verify -CAfile` |
| `domain` | Is the certificate valid for the domain it claims? | `x509 -checkhost` |
| `timestamp` | Does the RFC 3161 token cover this signature? | `ts -verify` |

A signature that verifies against a certificate whose chain reaches no trusted root is not "invalid" the way a tampered archive is — the cryptography is intact and only the vouching authority is unknown. A stage is `skipped` when it was never asked (no `--root` given, no `timeSignature` present), and `skipped` does not make the result invalid.

## Two things the spec does not say

Both were found by taking the reference implementation's output apart, and getting either wrong produces something that looks entirely plausible while verifying against nothing:

1. **The signature covers the hash string including its `sha256:` prefix**, with no trailing newline. Signing the hex alone fails in `digest_verify_final`.
2. **The timestamp covers the base64 *text* of the signature**, not its bytes — and what `timeSignature` stores is the whole `TimeStampResp`, status wrapper included, not the bare token inside it. Reading it as a token fails in ASN.1 with `wrong tag … Type=PKCS7`, which is not an obvious way to be told you passed the wrong flag.

## Development

```console
$ npm install
$ npm run check   # typecheck, lint, test
```

The test suite is ordered deliberately. `test/verify-real-fixtures.test.ts` measures the verifier against two signed archives from py-wacz — one sound, one signed under a staging CA — **before** anything in this repository produces a signature. Only then does `test/round-trip.test.ts` sign and verify its own output. Reversed, a round trip would prove the two halves agree with each other and nothing more; they could share a misreading of the format and still pass.

That ordering paid for itself: it is what caught the `-token_in` mistake above.

See `NOTICE` for the fixtures' provenance and licence.
