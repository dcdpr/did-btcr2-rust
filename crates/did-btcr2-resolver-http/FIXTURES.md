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

§7 lists two **funded** mutinynet demo DIDs used by `DEPLOY.md` §10; they are not in the suite config.

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

`w3c/localConfig.cjs` lists `valid` and `notFound` alike, each as the README's array of
`{did, resolutionOptions}` objects. That is the shape the suite reads at pin `c3fb2a88`:
upstream PR #18 is merged there, and `tests/10-bindings.js:38` now defaults the entry to `[]`
and iterates it, destructuring `{did, resolutionOptions}` and routing each through
`addQueryParametersToUrl`. A bare DID string is truthy but has no `.forEach`, so leaving one
in place would throw and take out the whole binding column rather than one row — which is why
the pin bump and this entry's shape have to move together, with a `CONFORMANCE.md` re-curation.

`tests/fixtures.rs` parses both DIDs out of the config and asserts mainnet / version 1 / `k1`
and mainnet / version 1 / `x1`, that both appear verbatim in this file, that `notFound` is a
one-entry array carrying the `x1` under a `did` key, and that the endpoint has the
resolver-path shape (`https://…/1.0/identifiers`, no trailing slash). A typo in either file
fails the build, not the weekly report.

## 6. What must never happen

- **Never fund either beacon address.** A payment to any beacon address of the `valid` DID
  would make `confirmations` non-zero and a spend would be a beacon signal; the secret is gone,
  so the signal could never be a valid update, but the resolver would still scan it.
- **Never re-mint a fixture with the same name.** A new DID is a new fixture with a new record;
  the old identifier stays documented here so an old report can be read.
- **Never commit a `localConfig.cjs` inside the `w3c-resolution-suite` submodule.** The
  vendored tree tracks upstream `main`; the config is copied in for a run and left uncommitted.

## 7. mutinynet demo DIDs (funded; POST-with-sidecar demonstration)

Everything above this heading is unfunded and secret-free. The two identifiers below are the
opposite on purpose: each has a real on-chain update history on **mutinynet**, a public test network
that is periodically reset, so their records name transaction ids (64-hex) and one of them has a
secret that is deliberately kept. They are the inputs to `DEPLOY.md` §10 and appear in no suite
config. `tests/fixtures.rs` scans this section separately: a 64-hex token is allowed here only on a
line that labels it `txid`; the §7.1 DID must be the one `demo/updated-v2.sidecar.json` names, and
the §7.2 record must describe `fixtures/chain/minted/clean-rotating-beacons.json` as committed —
the same DID (also under "The minted DIDs" in the `chain-capture` RUNBOOK), network, capture tip,
signal txids and heights, and end state — so a re-mint without a new record fails the build.

Record shape (one subsection per DID): the DID; the exact mint command; public key and derivation;
funding txid; update / deactivate txids in version order; key disposition (kept where, or thrown
away); the `curl` rows of `DEPLOY.md` §10 that use it. After a mutinynet reset both DIDs resolve to
version 1 and must be re-minted with the same commands. What happens to the record differs: §7.1
keeps its DID (the secret is kept), so a dated new record goes below the old one; §7.2 gets a fresh
key at the same fixture path, so its record is updated in place and the guard fails the build until
it matches the committed fixture. A new dated record is for a new scenario or a new fixture file
only.

### 7.1 updated — `did:btcr2:k1q5pdy265auv0wht5ah5ljjk94xjyas34dm4cl9c8x4vq4qpczl46xxqly88yr`

- Mint date: **2026-09-21** (UTC).
- Tool: `did-btcr2-cli` at `did-btcr2-rust` commit `92c421663c874d19833206d5ed1daf966c280ab7`
  (`crates/did-btcr2-cli/RUNBOOK.md` steps 1–5).
- Toolchain: `rustc 1.94.0 (4a4ef493e 2026-03-02)`.

The exact commands, from the workspace root. Step 1 generated the key; the secret line of its
output went straight into a mode-0600 file outside the repository and the capture was shredded.
Step 2 (funding) was a faucet visit; step 4 spent the funded UTXO as the beacon signal:
```sh
# laptop
cargo run -q -p did-btcr2-cli -- create --generate --network mutinynet
printf '[{"op":"add","path":"/assertionMethod/-","value":"%s#initialKey"}]\n' "$DID" > patch.json
cargo run -q -p did-btcr2-cli -- update "$DID" --patch patch.json --key-file <secret> --network mutinynet --sidecar-out updated-v2.sidecar.json --yes
```

- Public key: `zQ3shbZChKmK2V4cDuYsSwh63egEyFBJkVvoYvgJXRocM5xTy` (Multikey, secp256k1
  compressed) — the `publicKeyMultibase` of `#initialKey`.
- Derivation: mutinynet, version 1, `k1` = bech32m of the key-based components (`k` HRP, the
  version/network byte, the 33-byte compressed key).
- Funding txid: `eb70debed238d1e5f01bfe8d34df7c72b24df6319df474a038fabc3782b8f551` — faucet
  payment to the `#initialP2WPKH` beacon `tb1qcc7406lzakzllkkxlatlr3p52szxx8ftkyunxd`, confirmed
  in block 3443715.
- Update txid (version 2): `dd6c7991dc8bf3c50515ea41ca13a0027ac386374be967a1bf4df21bb94f7fd8` —
  the beacon signal, confirmed in block 3443718. Patch: append `#initialKey` to
  `assertionMethod`.
- Sidecar: `demo/updated-v2.sidecar.json` (one signed update in wire form; the on-chain signal is
  its 32-byte commitment, so the update itself is only available from this file).

> **The secret is kept.** It lives outside the repository in a gitignored working file on the minting laptop so this DID can be updated again for a later demo; it is not in this record, not in the sidecar, and not on the host.

Resolves to (`DEPLOY.md` §10 rows 1–3): `versionId "2"` with two `assertionMethod` entries via
`POST` with the sidecar; `versionId "1"` via `POST` with the sidecar and `versionId: 1`;
`500 MISSING_UPDATE_DATA` via `GET`, which carries no sidecar. On the laptop the same three
answers come from `did-btcr2-cli resolve --network mutinynet` with and without
`--sidecar demo/updated-v2.sidecar.json`; without it the CLI fails with "Update payload could not
be located in the sidecar data or CAS" (the same did:btcr2 error, rendered as its message rather
than its code). The CLI's `--min-conf` defaults to 6, so a resolve inside the first few blocks
after the signal still reports `"1"`.

Verification line: `POST` with the sidecar answers `200`, `"versionId":"2"`, and
`assertionMethod` of length 2.

After a mutinynet reset this DID resolves to `versionId "1"` (the signal is gone; the sidecar is
never consulted). Re-mint with the same commands — the kept secret makes that the same DID, which
is why this record is appended to rather than replaced — and append a dated new record below this
one; do not edit this one.

### 7.2 deactivated — `did:btcr2:k1q5pew2jcfvr5v9x6vhkz67gfuyfs4ggtqxuq5hlm8wg7ydy26205evgxxrhdk`

- Mint date: **2026-09-21** (UTC).
- Tool: `chain-capture` at `did-btcr2-rust` commit `92c421663c874d19833206d5ed1daf966c280ab7`
  (`crates/chain-capture/RUNBOOK.md` Part 3, the `clean` scenario on its mutinynet rung).
- Toolchain: `rustc 1.94.0 (4a4ef493e 2026-03-02)`.

The exact command, from the workspace root; the key and state files live outside both working
trees, as the RUNBOOK requires:
```sh
# laptop
cargo run -q -p chain-capture -- mint --scenario clean --network mutinynet --key-file ~/.btcr2-mint/clean-mutinynet.hex --state-file ~/.btcr2-mint/clean-mutinynet-state.json --fee 1000 --yes
```
The tool printed the DID and the three announcing beacons to fund (6 000 sats each, one faucet
visit), then broadcast each update once the previous one confirmed and waited five settlement
blocks before writing the fixture.

- Public key: `zQ3shppC94ES3CSSdSTNBtNWZhqQkCApN9ikjHdvACU4qqFAG` (Multikey, secp256k1
  compressed) — the `publicKeyMultibase` of `#initialKey`.
- Derivation: mutinynet, version 1, `k1` = bech32m of the key-based components (`k` HRP, the
  version/network byte, the 33-byte compressed key).
- Funding txids, one per announcing beacon in signal order (faucet payments):
  - `#initialP2WPKH` `tb1qgsdeutk5gcyndy8mtjceedvfxtzmrgl2wn3zm4` — funding txid `3095a2ecbca72006db05f681f2eaabbc66f2a7ee1aa49c95d5a5458402706ec1`
  - the P2WPKH beacon the version 2 update added, `tb1qy35te8sk60dnrvxu7u6uerwhnsd37a5mdnjagg` — funding txid `296a61773a3164ecc4d86c0a91c4a47e2b80f5103030da87740ce1a53f11f9a4`
  - `#initialP2PKH` `mmj5L2Lscg8kiWigEfcSg4NtWXDW4EuhmP` — funding txid `02d1341750e8a21443752eb8fcecfc12af756d8557beeadfb66f3d109bae20e2`
- Update txid (version 2): `a365d3c765e545fd81ba04397659ec440a232de485bcdadd5b6481ebc3e1ff5d` — block 3443744, from `#initialP2WPKH`; adds a P2WPKH beacon service.
- Update txid (version 3): `52b7859599a05f52a2ee28ffb27841d0d8c4ff6662bc153611d01ef5cea02419` — block 3443745, from the beacon version 2 added; adds a non-beacon service.
- Deactivate txid (version 4): `54becf8b2e972a91655a0f003f9cbf37811cae992b1a0e4afaa6fa031bd4f4ad` — block 3443746, from `#initialP2PKH`.
- Captured at tip 3443751 (five blocks past the last announcement, so the replay runs under the
  default `minConf`).
- Sidecar: `fixtures/chain/minted/clean-rotating-beacons.json`, its `.sidecar` member (three
  updates). `DEPLOY.md` §10 extracts it with one `jq` line; it is not committed twice.

> **The key is a throwaway.** The DID is deactivated on chain; nothing further can be done with the key and nothing depends on it. The replay tests (`src/test_vectors.rs`, `src/resolver.rs`) read this DID, its heights and block times from the fixture.

Resolves to (`DEPLOY.md` §10 row 4): `410` with `deactivated: true` and `versionId "4"` via
`POST` with the sidecar. Without a sidecar (`GET`, or the CLI's `resolve` with no `--sidecar`) it
fails at the first signal exactly as §7.1 does.

Verification line: `POST` with the sidecar answers `410`, `"deactivated":true` and
`"versionId":"4"`.

This capture is rung 2 of the minting ladder for `clean` (`crates/chain-capture/RUNBOOK.md`,
"Climbing to a public chain") and replaced the regtest capture at the same path — the
`k1qgp74wu…` DID recorded under "The minted DIDs" in that RUNBOOK, announcements at blocks
760 / 762 / 764, tip 769, on a disposable Polar chain that no longer exists.
`late-publishing-fork` stays on regtest.

After a mutinynet reset this DID resolves to `versionId "1"` and `200`, not `410`. The state file
re-emits the fixture without broadcasting, but a reset chain has no signals to re-emit against:
re-mint with the same command under a fresh key and state file, commit the new capture, and update
this record in place — heading DID, mint date, tool commit, public key, funding and signal txids,
block heights, capture tip — to describe the new capture; `tests/fixtures.rs` fails the build until
the record matches the committed fixture. The superseded capture is gone from the file at that
path, so its record goes with it; git history keeps both. Append a dated new record only for a new
scenario or a new fixture file. The replay tests read the DID and heights from the file and need
no edit.
