# Test-suite map

What the tests are, which fixtures drive them, and what each fixture is for.

This document maps **tests to fixtures**.
[CONFORMANCE.md](./CONFORMANCE.md) maps **spec requirements to tests** — every
did:btcr2 method-spec MUST/SHALL row and its coverage status. Neither document
repeats the other; for "is requirement X covered", read CONFORMANCE.md.

## 1. Running the suite

Run everything from the workspace root `did-btcr2-rust/`.

```bash
cargo test -p did-btcr2 -p did-btcr2-client -p did-btcr2-cli -p chain-capture
cargo test -p did-btcr2 --lib op_vectors -- --nocapture     # prints the coverage ledger
cargo test -p did-btcr2 --lib minted_chain -- --nocapture   # minted clean chain
cargo test -p did-btcr2 --lib minted_fork -- --nocapture    # minted fork
cargo fmt -p <crate> -- --check
cargo clippy -p <crate> --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p did-btcr2 --no-deps
```

Never use `cargo --all` or `--workspace`. The `smt-sim` workspace member fails
to build without a system fontconfig, which is unrelated to any of the crates
above. Always name crates with `-p`.

## 2. What ships

| Crate | Tests |
|---|---|
| `did-btcr2` | 268 lib + 4 conformance + 1 doctest |
| `did-btcr2-client` | 36 + 1 e2e |
| `did-btcr2-cli` | 42 + 2 broken-pipe |
| `chain-capture` | 170 |

No live-network test ships. There is no HTTP client anywhere in `src/` —
`grep -rn 'ureq\|reqwest\|TcpStream\|std::net' src/` returns nothing. Everything
on-chain replays from a captured fixture.

## 3. The operation-vector ledger

The upstream vectors live in the `test-suite/` submodule. The accounting unit is
a **row**: one (vector × assertion kind) pair, not one vector. A single vector
can contribute a driven row for one kind and a skipped row for another — most
commonly a driven `derivation` row and a skipped `resolve` row.

### The five assertion kinds

| Kind | What it asserts | Driver test (`src/resolver.rs`) |
|---|---|---|
| `derivation` | `create/input.json` → encoded DID equals `create/output.json.did` | `op_vectors_create_derives_expected_did` |
| `genesis-key` | `other.json.genesisKeys.secret` derives `genesisKeys.public`, and every update step signs with that same secret | `op_vectors_create_genesis_key_corroborated` |
| `resolve` | the resolver FSM resolves the vector to `resolve/output.json` | `op_vectors_resolve_matches_output` |
| `update-crypto` | each update step's content-bound triple and BIP340 proof re-derive from its own inputs and verify against its source document | `op_vectors_update_signs_to_expected_hashes` |
| `end-state` | applying every update step in order to the genesis document reproduces `resolve/output.json.didDocument` | `op_vectors_updates_apply_to_expected_end_state` |

### The live ledger

`cargo test -p did-btcr2 --lib op_vectors -- --nocapture` prints:

```
operation-vector coverage: 22 vectors, 100 rows
  kind            driven  skipped
  derivation          22        0
  genesis-key         22        0
  resolve             11       11
  update-crypto       17        0
  end-state           17        0
  skipped rows by reason (a row may carry several):
    unanchored (pending.json)                                                         6
    CAS-aggregated delivery not implemented                                           9
    SMT-aggregated delivery not implemented                                           4
    resolver cannot query this beacon type (CAS/SMT beacon requests unimplemented)    8
  fixture defects: 16 vector(s) encode versionId as a JSON number (the specification requires an ASCII string): mutinynet

minted-scenario coverage: 2 scenario(s) driven from in-repo fixtures (NOT counted in the upstream ledger above)
  minted/clean-rotating-beacons (minted on regtest)
    driven by minted_chain_sequences_updates_across_rotating_beacons
    covers: multi-update sequencing across rotating beacons
    covers: on-chain deactivation short-circuit
    covers: mid-walk version bounds on a four-version chain
  minted/late-publishing-fork (minted on regtest)
    driven by minted_fork_raises_late_publishing
    covers: late publishing detected against a real on-chain fork
  this coverage is fixture-driven: no live-network test ships in this crate. A real chain is contacted by the capture tool's own validation, and the CLI runbook covers live end-to-end resolve interactively.
```

100 rows is 22 vectors × 5 kinds, minus the 10 rows that do not exist: 5 vectors
are genesis-only and so have no `update-crypto` and no `end-state` row. That is
also why those two kinds show 17 driven rows rather than 22.

### The four skip reasons

Defined by `SkipReason` (`src/test_vectors.rs`) and derived from each vector's
own files by `derived_resolve_skip_reasons`. They are **additive**: a skipped row
carries every applicable reason, not the first match, which is why the four
counts above sum to more than the 11 skipped rows.

- **`Unanchored`** — `pending.json` present: the vector's own generator recorded
  update steps that were never delivered on chain.
- **`CasDelivery` / `SmtDelivery`** — the genesis document declares a `CASBeacon`
  / `SMTBeacon` service, or `scenario.json` declares `delivery.genesis` or
  `delivery.announcement` as `"cas"` / `"smt"`. That aggregation is
  unimplemented.
- **`UnsupportedBeaconType`** — the genesis document declares a CAS or SMT
  beacon, so building the next round of requests returns `Unsupported` before any
  transaction is read. Distinct from the delivery reasons: different problem,
  different code. Both are recorded when both apply.
- **`Override(&str)`** — a hand-written one-off. `SKIP_OVERRIDES` is currently
  **empty by design**, so every skip on disk today comes from a derived rule.

"Past genesis" is **not** a skip reason. A v2+ vector is driven from a captured
chain snapshot under `fixtures/chain/`.

### The coverage ratchet

`DRIVEN_FLOOR` (`src/test_vectors.rs`) records the minimum driven rows per kind:

```
Derivation 22, GenesisKey 22, Resolve 11, UpdateCrypto 17, EndState 17
```

It is compared with `>=`, so upstream adding vectors raises coverage without
failing the build. Only a silent coverage **loss** fails.

### The versionId fixture defect

`NUMBER_ENCODED_VERSION_ID` (`src/test_vectors.rs`) pins the 16 mutinynet
vectors whose `resolve/output.json.didDocumentMetadata.versionId` is a JSON
number where the specification requires an ASCII string. This is an **upstream
fixture defect** — not an implementation choice and not an interop question. No
regtest vector has it.

The pin is asserted in both directions: a number-encoded vector that is not
listed fails by name rather than being absorbed by the encoding-tolerant read,
and a listed vector that has since been fixed upstream also fails, telling the
reader to delete the entry.

## 4. The 22 upstream vectors

Measured from each vector's own files: `ver` / `conf` / `deact` from
`resolve/output.json.didDocumentMetadata`; `services` from the resolved
document; `pending` = `pending.json` present; `sidecar` = `resolve/input.json`
carries `resolutionOptions.sidecar.genesisDocument`; `delivery` from
`scenario.json`. `resolve` is whether the resolve row is driven.

| Vector | ver | conf | deact | services | pending | sidecar | delivery | resolve |
|---|---|---|---|---|---|---|---|---|
| mutinynet/k1/q5p6w9su | 2 | - | true | 3× Singleton | no | - | - | DRIVEN |
| mutinynet/k1/q5pgeu9z | 2 | - | - | 3× Singleton + DIDCommMessaging | no | - | - | DRIVEN |
| mutinynet/k1/q5puld7y | 1 | - | - | 3× Singleton | no | - | - | DRIVEN |
| mutinynet/x1/q425c5wf | 2 | - | - | 3× Singleton + SMT + DWN | no | yes | - | skipped |
| mutinynet/x1/q4lqu6gr | 2 | - | - | 3× Singleton + SMT + DIDComm | YES | - | genesis=cas | skipped |
| mutinynet/x1/q4rnhfhv | 2 | - | - | 3× Singleton + SMT + DWN | YES | - | genesis=cas | skipped |
| mutinynet/x1/q4x4pxl2 | 2 | - | - | 3× Singleton + CAS + DIDComm | YES | - | genesis=cas, announcement=cas | skipped |
| mutinynet/x1/q550pp4e | 2 | - | - | 3× Singleton + CAS + DWN | no | yes | - | skipped |
| mutinynet/x1/q59jnwfs | 2 | - | - | 3× Singleton + CAS + DWN | YES | - | genesis=cas, announcement=cas | skipped |
| mutinynet/x1/q5cfewep | 2 | - | - | 3× Singleton + SMT + DIDComm | no | yes | - | skipped |
| mutinynet/x1/q5g3smvu | 1 | - | - | 3× Singleton | no | yes | - | DRIVEN |
| mutinynet/x1/q5m2fh36 | 3 | - | true | 3× Singleton + DIDComm | YES | - | genesis=cas | skipped |
| mutinynet/x1/q5ugrf3w | 2 | - | - | 3× Singleton + DWN | no | yes | - | DRIVEN |
| mutinynet/x1/qh66uy2s | 1 | - | - | (none) | no | - | genesis=cas | skipped |
| mutinynet/x1/qkrrp544 | 2 | - | - | 3× Singleton + CAS + DIDComm | no | yes | - | skipped |
| mutinynet/x1/qky9e7qz | 4 | - | true | 3× Singleton + DIDComm + DWN | YES | - | genesis=cas | skipped |
| regtest/k1/qgpakaw4 | 1 | - | - | 3× Singleton | no | - | - | DRIVEN |
| regtest/k1/qgppexmy | 2 | 93 | - | 3× Singleton | no | - | - | DRIVEN |
| regtest/k1/qgpy0hmm | 2 | 78 | - | 4× Singleton | no | - | - | DRIVEN |
| regtest/x1/q26jeds9 | 2 | 65 | - | 2× Singleton | no | yes | - | DRIVEN |
| regtest/x1/q2fz9mz6 | 1 | - | - | 1× Singleton | no | yes | - | DRIVEN |
| regtest/x1/qfl7se8f | 2 | 53 | - | 1× Singleton | no | yes | - | DRIVEN |

### What distinguishes each vector

Skip reasons below are the derived ones, in the rule's own terms.

- **mutinynet/k1/q5p6w9su** — the only *driven* vector that ends deactivated;
  exercises the deactivation short-circuit against a captured chain.
- **mutinynet/k1/q5pgeu9z** — the only driven vector whose resolved document
  adds a DIDComm endpoint alongside its beacons: a non-beacon service does not
  disturb the beacon walk.
- **mutinynet/k1/q5puld7y** — the only key-based mutinynet vector that stays at
  version 1; genesis derived from the key, no update step, no sidecar.
- **mutinynet/x1/q425c5wf** — SMT beacon plus a web-node service, sidecar
  genesis, no pending updates and no delivery recipe: both its skip reasons
  (`SmtDelivery`, `UnsupportedBeaconType`) come from the beacon type alone. Its
  twin `q5cfewep` differs only in pairing the SMT beacon with DIDComm.
- **mutinynet/x1/q4lqu6gr** — one of the two rows carrying all four skip reasons
  at once (pending updates, a CAS-delivered genesis, an SMT beacon, and an
  unqueryable beacon type); pairs its SMT beacon with DIDComm.
- **mutinynet/x1/q4rnhfhv** — the other all-four-reasons row; identical to
  `q4lqu6gr` except that its non-beacon service is a web node.
- **mutinynet/x1/q4x4pxl2** — one of the two vectors whose *announcement* as well
  as genesis is CAS-aggregated, on top of a CAS beacon and pending updates;
  pairs with DIDComm.
- **mutinynet/x1/q550pp4e** — CAS beacon with a sidecar genesis and no pending
  updates and no recipe: skipped on beacon type alone, the CAS mirror of
  `q425c5wf`. Pairs its CAS beacon with a web node.
- **mutinynet/x1/q59jnwfs** — the other CAS-on-both-ends vector; identical to
  `q4x4pxl2` except that its non-beacon service is a web node.
- **mutinynet/x1/q5cfewep** — SMT beacon with a sidecar genesis, no pending and
  no recipe, paired with DIDComm; the DIDComm twin of `q425c5wf`.
- **mutinynet/x1/q5g3smvu** — the only driven *external* mutinynet vector that
  never leaves genesis: proof that an out-of-band genesis document resolves at
  version 1 with no chain data at all.
- **mutinynet/x1/q5m2fh36** — reaches version 3 through two numbered update steps
  and ends deactivated; one of only three skipped rows with no unsupported beacon
  type — it is skipped for pending updates and a CAS-delivered genesis only.
- **mutinynet/x1/q5ugrf3w** — the only driven vector whose resolved document
  carries a web-node service, and the only driven mutinynet vector that combines
  a sidecar genesis with an on-chain update.
- **mutinynet/x1/qh66uy2s** — the only vector whose resolved document declares no
  services at all, and the only row with exactly one skip reason: its genesis is
  CAS-delivered by recipe, with no beacon in the document to say so.
- **mutinynet/x1/qkrrp544** — CAS beacon with a sidecar genesis, no pending and
  no recipe, paired with DIDComm; the DIDComm twin of `q550pp4e`.
- **mutinynet/x1/qky9e7qz** — the deepest chain in the suite: version 4 through
  three numbered update steps, ending deactivated, and the only vector carrying
  both a DIDComm endpoint and a web node.
- **regtest/k1/qgpakaw4** — the only key-based regtest vector at version 1;
  genesis derived from the key, so it is driven with no chain capture at all.
- **regtest/k1/qgppexmy** — the earliest-anchored regtest signal (height 666) and
  therefore the largest stated confirmation count in the suite, 93.
- **regtest/k1/qgpy0hmm** — the only vector with four Singleton beacons; its 78
  confirmations pin the frozen regtest tip.
- **regtest/x1/q26jeds9** — the only vector with exactly two Singleton beacons;
  external DID resolved from a sidecar genesis, signal at height 694 for 65
  confirmations.
- **regtest/x1/q2fz9mz6** — the smallest document in the suite: one Singleton
  beacon, externally supplied genesis, no update step.
- **regtest/x1/qfl7se8f** — the single-beacon update case: one beacon address in
  its capture, the latest regtest signal (height 706) and the smallest stated
  confirmation count, 53.

### Driven versus skipped

All 6 regtest vectors are resolve-driven. The 16 mutinynet vectors split:

- **5 driven** — `q5p6w9su`, `q5pgeu9z`, `q5puld7y`, `q5g3smvu`, `q5ugrf3w`:
  plain Singleton beacons, nothing aggregated, nothing pending.
- **11 skipped** — a CAS or SMT beacon in the document, and/or an aggregated
  delivery recipe, and/or a `pending.json`.

Every skipped resolve row is mutinynet.

The four skip-reason counts attribute to rows exactly:

| Reason | Count | Rows |
|---|---|---|
| `Unanchored` | 6 | the 6 rows with `pending` = YES |
| `SmtDelivery` | 4 | the 4 rows with an SMT beacon (`q425c5wf`, `q4lqu6gr`, `q4rnhfhv`, `q5cfewep`); no vector declares an `smt` delivery recipe |
| `CasDelivery` | 9 | the 4 rows with a CAS beacon ∪ the 7 rows with a `cas` delivery recipe (`q4x4pxl2` and `q59jnwfs` are in both) |
| `UnsupportedBeaconType` | 8 | the 4 SMT-beacon rows + the 4 CAS-beacon rows |

Their union is the 11 skipped rows.

### `k1` versus `x1`

`k1` is a key-based DID: the genesis document is derived deterministically from
the key. `x1` is an external DID, whose genesis document must be supplied out of
band — which is why the external vectors carry
`resolutionOptions.sidecar.genesisDocument`.

Sidecar presence is **not** what decides whether a vector is driven:
`q425c5wf`, `q550pp4e`, `q5cfewep` and `qkrrp544` all carry a sidecar genesis and
are still skipped, on beacon-type grounds.

### Update-step layout

`q5m2fh36` has update steps `01 02`; `qky9e7qz` has `01 02 03`; every other
update-bearing vector has a single flat `update/input.json` +
`update/output.json` pair. Five vectors are genesis-only with no `update/` at
all: `q5puld7y`, `q5g3smvu`, `qh66uy2s`, `qgpakaw4`, `q2fz9mz6`.

## 5. Minted scenarios

Two scenarios are minted in-repo and are deliberately **not** counted in the
upstream ledger; `ledger_summary_never_mentions_a_minted_scenario`
(`src/test_vectors.rs`) enforces the exclusion. Both were minted on regtest, and
both fixtures are in-repo, so these two tests run even when the `test-suite/`
submodule is not checked out.

| Scenario | Driver test | Covers | Expected |
|---|---|---|---|
| `minted/clean-rotating-beacons` | `minted_chain_sequences_updates_across_rotating_beacons` | multi-update sequencing across rotating beacons; on-chain deactivation short-circuit; mid-walk version bounds on a four-version chain | `didDocumentMetadata` `{versionId: "4", deactivated: true}` |
| `minted/late-publishing-fork` | `minted_fork_raises_late_publishing` | late publishing detected against a real on-chain fork | `{"error": "LATE_PUBLISHING"}` |

## 6. Chain fixtures

`fixtures/chain/` holds 9 captures: 7 vendor captures, one per past-genesis
driven vector, plus the 2 minted scenarios. `addrs` is the number of beacon
addresses captured; `signals` is the number of OP_RETURN announcements found.

| Fixture | network | endpoint | tip | addrs | signals | signal heights |
|---|---|---|---|---|---|---|
| mutinynet/k1/q5p6w9su.json | mutinynet | https://mutinynet.com/api | 3307267 | 3 | 1 | 3190760 |
| mutinynet/k1/q5pgeu9z.json | mutinynet | https://mutinynet.com/api | 3307267 | 3 | 1 | 3190760 |
| mutinynet/x1/q5ugrf3w.json | mutinynet | https://mutinynet.com/api | 3307267 | 3 | 1 | 3190760 |
| regtest/k1/qgppexmy.json | regtest | http://localhost:3000 | 758 | 4 | 1 | 666 |
| regtest/k1/qgpy0hmm.json | regtest | http://localhost:3000 | 758 | 4 | 1 | 681 |
| regtest/x1/q26jeds9.json | regtest | http://localhost:3000 | 758 | 2 | 1 | 694 |
| regtest/x1/qfl7se8f.json | regtest | http://localhost:3000 | 758 | 1 | 1 | 706 |
| minted/clean-rotating-beacons.json | regtest | http://localhost:3000 | 764 | 3 | 3 | 760, 762, 764 |
| minted/late-publishing-fork.json | regtest | http://localhost:3000 | 768 | 3 | 2 | 766, 768 |

The other 4 driven vectors (`q5puld7y`, `q5g3smvu`, `qgpakaw4`, `q2fz9mz6`) are
genesis-only and need no capture.

### The regtest tip is frozen — do not mine

The four regtest vendor captures share one tip, 758, and that is exactly what
makes the vectors' stated confirmations reproduce. `tip - signal_height + 1`
gives 758−666+1 = 93, 758−681+1 = 78, 758−694+1 = 65 and 758−706+1 = 53,
matching the 93 / 78 / 65 / 53 in the vector table.

**The regtest chain behind these captures must not be mined further.** The "mine
6 blocks" step in `test-suite/regtest/README.md` would move the tip and break all
four captures at once.

The three mutinynet captures share tip 3307267 and all announce at height
3190760. Mutinynet vector outputs state no `confirmations`, so those rows assert
confirmations by provenance — derived from the most-recently-applied update's
captured block — rather than against a stated number.

To re-capture, see [crates/chain-capture/README.md](./crates/chain-capture/README.md)
and [crates/chain-capture/RUNBOOK.md](./crates/chain-capture/RUNBOOK.md).

### Spec-form fixtures

`fixtures/spec-form/` holds the sidecar and update payloads the offline unit
tests run against. Every one that any test reads is pulled in with
`include_str!`, so these are **compile-time inputs**: delete one and the test
build fails rather than a test failing.

`golden-signed-update.json` is the exception that proves the rule. It is
`include_str!`'d at three assertion sites, but `bless_or_assert` also opens it
at runtime through `CARGO_MANIFEST_DIR` (`src/document.rs:3426`), because a
blessed file has to be read back the same way it was written for `BLESS=1` to
round-trip. That constraint is spelled out at `tests/conformance.rs:770`.

| Fixture | Shape | What it pins |
|---|---|---|
| `golden-signed-update.json` | a signed update | The blessed update vector. Re-blessed by `BLESS=1`, never hand-edited; construction derives it from `source_documents()`. |
| `sidecar-two-updates.json` | 2 updates | The ordinary chained case, used for lookup-table build, apply order, and version walking. |
| `sidecar-empty.json` | 0 updates | A sidecar carrying no updates at all. |
| `sidecar-missing-update.json` | 0 updates | A beacon signal whose hash is absent from the lookup table, raising `MISSING_UPDATE_DATA`. |
| `sidecar-forward-compat.json` | 0 updates, plus `casUpdates`, `smtProofs`, `genesisDocument` | Not-yet-implemented sidecar members must parse and be ignored, not rejected. |
| `sidecar-empty-service-genesis.json` | `genesisDocument` only | A hostile external genesis whose `service` array is empty must return a typed error, not panic. |
| `sidecar-deactivated.json` | 2 updates | Currently referenced by no test. See below. |

`sidecar-deactivated.json` is **unused**. It was added alongside the other
spec-form sidecars when the resolver converged on the spec wire shape, but the
deactivation tests build their state in memory instead, so nothing reads it.
It is kept rather than deleted only because that is a call for a human to make;
it is not evidence of coverage.

### Unit fixtures

Three files sit at `fixtures/` directly.

| Fixture | Read by | How |
|---|---|---|
| `singleton-beacon-signal-txs.json` | `src/resolver.rs:1791`, as `UNCONFIRMED_FIXTURE` | `include_str!` |
| `k1qypa5t...l0mgs4-transactions.json` | `src/document.rs:1873`, in `test_document_from_did_components` | `include_str!`, and the test is gated behind the `old-spec-fixtures` feature |
| `initialDidDoc-missing-verificationMethod-id.json` | `src/document.rs:1809` | runtime `InitialDocument::from_file`, so a missing file fails the test rather than the build |

The first two are compile-time inputs like the spec-form set. The third is the
only fixture in the crate opened at runtime by path; it pins that a verification
method with no `id` is rejected with `JsonMissingKey("id")`.

## 7. The replay harness

Lives in `src/test_vectors.rs` and the test module of `src/resolver.rs`.

- **Fixtures are validated on every read.** `read_chain_fixture` calls
  `assert_signals_consistent` on each load, re-deriving every signal from the
  fixture's own `addresses`: the txid must be present under its own address, the
  block height and time must match, and the last output must be exactly
  `6a20<update_hash>`. A hand edit or a partial re-capture fails at load, not
  later at a confusing assertion.
- **An absent fixture panics**, naming the capture command. This is a deliberate
  divergence from the upstream test-suite reader, which legitimately *skips* when
  `test-suite/` is not checked out: an unchecked-out submodule is not a defect,
  an in-repo fixture going missing is.
- **The real FSM runs.** `drive_capture_within`, `drive_capture_rounds` and
  `drive_to_resolved_from_capture` drive the real `Resolver` through `resolve()`
  / `process_responses()`, routing the FSM's own request URIs to captured bodies.
  Routing is keyed on the **address**, not the host, so a fixture captured
  against `mutinynet.com` replays unchanged. An address the capture has no key
  for panics with the vector, the address and the round log — it does not default
  to an empty array.
- **No HTTP client is in the loop.**
  `grep -rn 'ureq\|reqwest\|TcpStream\|std::net' src/` returns nothing.

Tests worth grepping for:

| Test | What it guards |
|---|---|
| `op_vectors_every_row_is_driven_or_skipped_with_reason` | every row is accounted for, and prints the ledger |
| `a_live_skip_override_keeps_every_driver_green` | a hand-written `SKIP_OVERRIDES` entry does not break the drivers |
| `ledger_summary_never_mentions_a_minted_scenario` | minted scenarios stay out of the upstream ledger |
| `capture_pump_*` (`src/resolver.rs`) | replay routing and its fail-loud behaviour |
| `*_returns_unsupported` (`src/resolver.rs`, `src/document.rs`) | CAS and SMT beacons return `Unsupported` |

`src/resolver.rs` holds 42 `#[test]` functions; `src/test_vectors.rs` holds 57.

## 8. When `test-suite/` is absent

The operation-vector drivers **skip** rather than fail, via
`discovered_vectors_or_skip` (`src/resolver.rs`). The minted-scenario tests still
run, because their fixtures are in-repo.

To check the submodule out, see the one-time setup in
[README.md](./README.md): `git submodule init && git submodule update`.
