# did-btcr2-resolver-http FIXTURES — the two mainnet fixtures the W3C suite is pointed at

> See also: `CONFORMANCE.md` (the assertion ledger), `DEPLOY.md` (§9 validate a deployment),
> `w3c/localConfig.cjs` (the suite config that names these two identifiers), and
> `crates/did-btcr2-cli/RUNBOOK.md` (the CLI whose `create` minted them).

This file is the provenance record for two `did:btcr2` identifiers: where each came from, what
it resolves to, and what was destroyed so that nothing about it can change. It is written for a
reader years from now who finds one of these DIDs in a test config or an interop report and
wants to know whether it is safe to rely on. It is not a runbook for minting new fixtures (a new
fixture is a new identifier with a new record, §6), and nothing in it is funded or anchored.

**Neither fixture is funded and neither has an on-chain footprint; the interop report re-runs
weekly against them and nothing can change what they resolve to.**

## 1. At a glance

| name | DID | kind | HTTP | `type` | chain cost |
|------|-----|------|------|--------|------------|
| `valid` | `did:btcr2:k1qqphzydl2apenfzenkm8lcs4cnxz4nryeetpvhqwlgs6k0ul8p95u8q5tzlsv` | `k1` key-based | `200` | — | chain tip + 3 address lookups, all empty |
| `notFound` | `did:btcr2:x1qp98pkkg4mp3e4k2yj9a5z5uu4x8jxkr0cqcvkt0s58k7fe87uh3v63tlqq` | `x1` external | `404` | `https://www.w3.org/ns/did#NOT_FOUND` | chain tip only; no beacon scan |

Both are mainnet, version 1. The `valid` DID resolves to its deterministic initial document with
zero confirmations because no beacon address derived from its key has ever received a payment.
The `notFound` DID fails before any beacon scan because its Genesis Document was never published
anywhere and no longer exists.

## 2. Provenance

- Mint date: **2026-09-19** (UTC).
- Tool: `did-btcr2-cli` at `did-btcr2-rust` commit `054ef24108b44964c41512cc9c261e6c62d8851c`.
- Toolchain: `rustc 1.94.0 (4a4ef493e 2026-03-02)` — the workspace `rust-toolchain.toml` pin.
- Both were minted offline with `create --network mainnet`: no broadcast, no network call of
  any kind. The CLI's `--network` default is **testnet**, so the flag is load-bearing — without
  it the identifiers would carry the testnet nibble and the beacon addresses would be testnet
  addresses.

## 3. valid — `did:btcr2:k1qqphzydl2apenfzenkm8lcs4cnxz4nryeetpvhqwlgs6k0ul8p95u8q5tzlsv`

The exact command, from the workspace root:
```sh
# laptop
cargo run -q -p did-btcr2-cli -- create --generate --network mainnet
```

- Public key: `zQ3shnFUtkXgLVeA3n4SiGYgUobbyBT7Yi39uwiUD6deZbt5R` (Multikey, secp256k1
  compressed) — the `publicKeyMultibase` of the document's only verification method.
- Derivation: mainnet, version 1, `k1` = bech32m of the key-based components (`k` HRP, the
  version/network byte, the 33-byte compressed key). Version 1 and mainnet both encode as nibble
  `0`, so the identifier's layout byte is `0x00` under either nibble ordering; no
  identifier-layout change can touch this DID.
- The initial document is deterministic from the identifier (`InitialDocument::from_did`): one
  `Multikey` verification method `#initialKey`, and three `SingletonBeacon` services
  (`#initialP2PKH`, `#initialP2WPKH`, `#initialP2TR`) on addresses derived from the key that
  nobody has ever paid.

> **Nobody holds this secret.** The secret key was written to a scratch file, the public lines were split off, and the file was shredded in the same command; it was never displayed or copied. A Singleton beacon signal is a spend from a beacon address derived from this key, so with the secret gone the DID can never be updated or deactivated: "never anchored" is a permanent property, not a promise. Do not look for a key file; there is none. An update demo needs a different DID on a test network.

```sh
# laptop
H='Accept: application/did-resolution'
curl -sS -i -H "$H" "https://143-198-140-182.sslip.io/1.0/identifiers/did:btcr2:k1qqphzydl2apenfzenkm8lcs4cnxz4nryeetpvhqwlgs6k0ul8p95u8q5tzlsv"   # 200
```
Expected body fragments:
`"id":"did:btcr2:k1qqphzydl2apenfzenkm8lcs4cnxz4nryeetpvhqwlgs6k0ul8p95u8q5tzlsv"`,
`"versionId":"1"`, `"confirmations":0`, `"deactivated":false`, and
`"contentType":"application/did"`. That last value is the *document's* media type, carried in
the body's `didResolutionMetadata.contentType` (`src/accept.rs`); the response *header* is
`Content-Type: application/did-resolution`, which is the media type of the full result. The
request costs one chain-tip fetch and three address lookups (one per beacon), all empty.

Verification line: status `200`, `Content-Type: application/did-resolution`, and the five body
fragments above are present verbatim.

## 4. notFound — `did:btcr2:x1qp98pkkg4mp3e4k2yj9a5z5uu4x8jxkr0cqcvkt0s58k7fe87uh3v63tlqq`

Recipe. An intermediate ("genesis") document was authored in placeholder form — `did:btcr2:_`
in every `id` and `controller` position — with:

- one `Multikey` verification method `#key-0` holding the public key
  `zQ3shQFA1idsG35nHTrRrssL5Ugd1haZJbBNt7YfqAExoqsMG`, listed under `authentication`,
  `assertionMethod`, `capabilityInvocation` and `capabilityDelegation`;
- one `SingletonBeacon` service `#service-0` whose endpoint is a mainnet P2WPKH address that is
  **deliberately not recorded here**;
- the `@context` `["https://www.w3.org/ns/did/v1.1", "https://btcr2.dev/context/v1"]`.

It was minted, from the workspace root, with:
```sh
# laptop
cargo run -q -p did-btcr2-cli -- create --intermediate-document <file> --network mainnet
```

- Derivation: genesis bytes = SHA-256 of the JCS canonical form of that document; mainnet,
  version 1, `x1` = bech32m of the external components (`x` HRP, the `0x00` layout byte, the
  32-byte hash).
- Cost: one chain-tip fetch (the client reads the tip before the core resolver runs) and no
  beacon scan — resolution stops in Process Sidecar Data.

> **Nobody holds the genesis document.** The intermediate document, the key behind its verification method and the key behind its beacon address were shredded after minting; the beacon address is omitted from this record so the document cannot be rebuilt from this page. Resolution therefore fails in Process Sidecar Data (did-btcr2 resolve.md, before any beacon scan) with NOT_FOUND. This is deliberate: a published genesis document could be pinned to CAS or handed to a sidecar-accepting resolver, and once CAS retrieval ships the fixture could flip from 404 to 200 without anyone here acting. With the preimage gone it cannot.

```sh
# laptop
H='Accept: application/did-resolution'
curl -sS -i -H "$H" "https://143-198-140-182.sslip.io/1.0/identifiers/did:btcr2:x1qp98pkkg4mp3e4k2yj9a5z5uu4x8jxkr0cqcvkt0s58k7fe87uh3v63tlqq"   # 404
```
Expected body: `"didDocument":null`, `"didDocumentMetadata":{}`, and under
`didResolutionMetadata.error` the exact URI `"type":"https://www.w3.org/ns/did#NOT_FOUND"` —
the string `tests/10-bindings.js` compares — with a `title` and a `detail` saying no sidecar
`genesisDocument` was supplied and the resolver has no CAS fetcher.

Verification line: status `404`, `Content-Type: application/did-resolution`, `"didDocument":null`
and the `NOT_FOUND` type URI present verbatim.

## 5. How the suite sees them

`w3c/localConfig.cjs` lists `valid` as the README's array of `{did, resolutionOptions}` objects
and `notFound` as a **bare string**. At pin `2649fdf7`, `tests/10-bindings.js:38` reads
`supportedDids.notFound` as a scalar and line `231` builds `${endpoint}/${notFoundDid}`; the
README's array form would request `/1.0/identifiers/[object Object]` and fail the row for a
reason that is not the resolver's. Upstream PR #18 (open, unmerged) changes the read to the
array form; the entry flips when the pin moves, together with a `CONFORMANCE.md` re-curation.

`tests/fixtures.rs` parses both DIDs out of the config and asserts mainnet / version 1 / `k1`
and mainnet / version 1 / `x1`, that both appear verbatim in this file, that `notFound` is a
scalar, and that the endpoint has the resolver-path shape (`https://…/1.0/identifiers`, no
trailing slash). A typo in either file fails the build, not the weekly report.

## 6. What must never happen

- **Never fund either beacon address.** A payment to any beacon address of the `valid` DID
  would make `confirmations` non-zero and a spend would be a beacon signal; the secret is gone,
  so the signal could never be a valid update, but the resolver would still scan it.
- **Never re-mint a fixture with the same name.** A new DID is a new fixture with a new record;
  the old identifier stays documented here so an old report can be read.
- **Never commit a `localConfig.cjs` inside the `w3c-resolution-suite` submodule.** The
  vendored tree tracks upstream `main`; the config is copied in for a run and left uncommitted.
