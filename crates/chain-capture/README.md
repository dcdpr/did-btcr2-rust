# chain-capture

A developer utility that produces the chain fixtures the core crate's on-chain
resolve tests replay offline, and mints the scenarios those fixtures record.

Two subcommands:

- **`capture`** resolves a test-suite vector against a real chain through a
  recording transport and keeps exactly what the resolver asked for — the
  per-address `/address/{a}/txs` bodies and `/blocks/tip/height` — in
  `fixtures/chain/`. It refuses to write unless the resolve reproduces the
  vector's own stated output, every sidecar update is announced on chain, and
  the captured tip reproduces the vector's `confirmations`.
- **`mint`** publishes a scenario no upstream vector covers: one DID that
  announces three updates from three different beacons and ends deactivated on
  chain, and a second DID carrying two conflicting version 2 announcements so
  the late-publishing anomaly is a historical fact rather than an arrangement
  assembled at replay time. Each scenario writes its own self-contained fixture,
  carrying its sidecar and its expectation alongside the captured bodies.

## Why it is `publish = false`

This crate is a tool for producing test data, not part of the `did:btcr2`
library. It is never a dependency of the published crate — the dependency runs
the other way, and only at test time, through the fixture files. It stays a
workspace member rather than a loose script so it is compiled, linted and
type-checked with everything else, and cannot silently rot against an API change
in the core crate or the client facade.

## Running it

Producing fixtures is a manual operator session against a live chain: it starts
containers, broadcasts transactions and handles a key. It is **not** part of
`cargo test`, which replays the committed fixtures offline and touches no
network.

The procedure — the order the parts must run in, the exact commands, and what to
do when a step fails — is **[RUNBOOK.md](./RUNBOOK.md)**.
