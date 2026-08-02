---
title: capping
description: A local wacz-auth signing stand-in, driven entirely by openssl.
---

capping is a local stand-in for a [wacz-auth](https://specs.webrecorder.net/wacz-auth/0.1.0/) signing service. It issues its own CA, signing certificate and RFC 3161 timestamp authority, and produces the `signedData` that goes in a WACZ's `datapackage-digest.json`.

**Every cryptographic step is an `openssl` invocation.** capping contributes JSON, temp files and process handling — nothing more. Nothing cryptographic comes from npm; the one runtime dependency is [commander](https://www.npmjs.com/package/commander), which parses the command line.

That is not a minimalism exercise. It is what makes the results checkable: run any command with `--explain` and it prints the exact openssl lines it used, so a result you distrust can be reproduced by hand.

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

## Why a private CA

Because the cases worth testing are the ones a public CA cannot produce:

- a certificate that **expired yesterday** — the state every real signing certificate reaches long before anyone verifies the archive;
- a chain that leads somewhere **untrusted**;
- a timestamp from a party of **your** choosing.

Let's Encrypt's staging environment is not an alternative. Its roots are absent from every trust store on purpose, so signatures made under it fail the chain stage while looking perfect everywhere else — which is exactly what py-wacz's "invalid" fixture turns out to be, and a confusing state to develop against.

## What it does not do

| Not done | Why |
| --- | --- |
| Sign or verify with `node:crypto` | Two cryptographic implementations means that when they disagree, neither one is evidence. |
| Handle ASN.1 / DER directly | Left to openssl. This is the area where a mistake is most likely to "work" convincingly. |
| ACME / Let's Encrypt | Development only. Staging roots reach no trust store, which adds confusion rather than realism. |
| Production key management | The keys sit in files, in plain sight. This is a development stand-in. |
| The Anonymous Signature format | Domain-Ownership Identity + Signed Timestamp first; the other is easy to add later. |

## Where to go next

- [Quickstart](/quickstart/) — init, sign, verify, in three commands.
- [Verification](/verification/) — the four stages, what each one asks, and why they are reported separately.
- [Signing](/signing/) — the two details the spec does not state.
- [Development](/development/) — how the test suite is ordered, and why that ordering is the point.
