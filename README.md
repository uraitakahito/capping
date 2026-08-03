# capping

A local stand-in for a [wacz-auth](https://specs.webrecorder.net/wacz-auth/0.1.0/)
signing service: it issues its own CA and signing certificate, asks an RFC 3161
authority of your choosing for the timestamp, and produces the `signedData` that
goes in a WACZ's `datapackage-digest.json` — as a CLI, a library, or an
[authsign](https://github.com/webrecorder/authsign)-shaped HTTP server.

Every cryptographic step is an `openssl` invocation, and `--explain` prints the
exact commands used, so any result can be reproduced by hand.

## Documentation

Everything — quickstart, the four verification stages, signing, and
development — lives on the docs site:

- **English** — <https://uraitakahito.github.io/capping/>
- **日本語** — <https://uraitakahito.github.io/capping/ja/>

`NOTICE` covers the provenance and licence of the two signed fixtures under
`test/fixtures/`, which come from
[py-wacz](https://github.com/webrecorder/py-wacz) and are what the verifier is
measured against.
