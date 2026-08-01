---
title: Verification
description: The four stages, what each one asks, and why they are reported separately.
---

wacz-auth describes verification as four checks. capping reports them separately rather than collapsing them into one boolean, because the answers mean different things.

```ts file="src/verify.ts#VerifyReport"
```

A signature that verifies against a certificate whose chain reaches no trusted root is **not** "invalid" the way a tampered archive is. The cryptography is intact; only the vouching authority is unknown. Collapsing that into `false` throws away the distinction a reader needs in order to decide what to do next.

## The four stages

| Stage | Question | openssl |
| --- | --- | --- |
| `signature` | Does the signature match the hash under the certificate's key? | `dgst -sha256 -verify` |
| `chain` | Does the chain reach a supplied trust anchor? | `verify -CAfile` |
| `domain` | Is the certificate valid for the domain it claims? | `x509 -checkhost` |
| `timestamp` | Does the RFC 3161 token cover this signature? | `ts -verify` |

### signature

```ts file="src/verify.ts#signature-stage"
```

The public key comes out of the leaf certificate; the signed bytes are the hash string exactly as it appears in the file, `sha256:` prefix included and no trailing newline.

### chain

`openssl verify -CAfile roots.pem -untrusted untrusted.pem leaf.pem`. The spec stores the whole chain glued into one `domainCert` string, but openssl wants the leaf and its issuers in separate files, so every consumer has to split on `-----BEGIN CERTIFICATE-----`.

With no trust roots supplied, this stage is `skipped`. That is deliberate and it is not the same as failing.

### domain

`openssl x509 -checkhost <domain>` rather than comparing the CN by hand. `-checkhost` applies the name-matching rules a TLS client uses, including wildcards and `subjectAltName` — rules that are easy to reimplement subtly wrong.

### timestamp

```ts file="src/verify.ts#timestamp-stage"
```

The TSA's own chain travels inside the token, so its last certificate acts as the anchor here. This stage asks whether the token is internally consistent, not whether that timestamp authority is one you would choose to trust.

## Three statuses, not two

| Status | Meaning |
| --- | --- |
| `ok` | The check ran and passed. |
| `failed` | The check ran and did not pass. |
| `skipped` | The check was never asked — no trust roots given, no `timeSignature` present. |

`valid` is true when no stage **failed**. A skipped stage does not make a report invalid, because a question nobody asked has no answer to be wrong about.

## What openssl said

When a stage fails, the detail line is openssl's own words, not a rewrite:

```
FAILED   chain      error 10 at 0 depth lookup: certificate has expired
```

Picking that line out takes a little care. `openssl verify` prints the reason and then a summary line that repeats none of it, so taking the last line would report `verification failed` and drop `certificate has expired` — the only part worth reading. Some subcommands also open with banners (`Using configuration from …`) that are not the failure, so taking the *first* line reports noise instead.

## Input that cannot be examined

A `domainCert` with no certificate in it produces a report, not an exception:

```
  FAILED   signature  certificate chain contains no PEM certificates
  skipped  chain      certificate chain contains no PEM certificates
  skipped  domain     certificate chain contains no PEM certificates
  skipped  timestamp  certificate chain contains no PEM certificates
```

The caller asked whether an archive checks out, and "no, there is no certificate in it" is an answer. One failed stage rather than four, because it is one problem — and throwing instead would make the CLI exit on a stack trace, indistinguishable from openssl being missing.
