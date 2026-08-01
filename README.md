# did-btcr2

A Rust implementation of the **did:btcr2** Bitcoin DID method — a sans-I/O core
for creating and resolving `did:btcr2` identifiers, with strong types over the
DID document, beacons, keys, and update proofs. The resolver is a sans-I/O state
machine: it never makes network calls itself; the caller drives the loop and
supplies blockchain data (see the `did-btcr2-client` crate and the
`did-btcr2-cli` for an I/O-bearing facade).

## Status

**Pre-1.0 — not yet published on crates.io.** This crate tracks the in-progress
[did:btcr2 method specification](https://github.com/dcdpr/did-btcr2), which is
itself not finalized; the on-wire format and API may change without a semver
bump while the spec stabilizes (see [CHANGELOG.md](./CHANGELOG.md) for the
held-version policy).

Conformance is currently limited to the **Singleton beacon** resolution path
(single-party, single beacon). The CAS and Sparse Merkle Tree beacon paths, and
multi-party aggregation, are not yet implemented. See
[CONFORMANCE.md](./CONFORMANCE.md) for the conformance matrix and the gap list
mapping spec requirements to implementation status.

## Links

- **Specification:** [did:btcr2 method spec](https://github.com/dcdpr/did-btcr2)
- **Conformance matrix + gap list:** [CONFORMANCE.md](./CONFORMANCE.md)
- **Test-suite map:** [TESTING.md](./TESTING.md)
- **Resolve usage:** the `did-btcr2-cli` `resolve` subcommand (below)

## Resolving a DID

The `did-btcr2-cli` crate ships a `resolve` subcommand that drives the resolver
FSM over an Esplora endpoint and prints the DID resolution result as JSON:

```bash
cargo run -p did-btcr2-cli -- resolve <did>
```

Flags (run `did-btcr2-cli --help` for the authoritative list):

- `--network <net>` — `testnet` (default), `signet`, `mainnet`, or `mutinynet`
- `--esplora-url <url>` — Esplora base URL override (no trailing slash)
- `--sidecar <file>` — path to a sidecar data JSON file

## One-time Setup

You must initialize the git submodules after cloning the repo:

```bash
git submodule init
git submodule update
```

## Design goals

- Strong types over stringly-typed data: don't stringify and reparse repeatedly.
- A pleasant API for Rustaceans.
- Mind unnecessary allocations.
