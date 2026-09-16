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
| `did-btcr2` | 353 lib + 9 conformance + 1 doctest |
| `did-btcr2-client` | 64 + 1 e2e |
| `did-btcr2-cli` | 44 + 2 broken-pipe |
| `chain-capture` | 185 |

Counts are copied from `cargo test` output; re-measure before editing them.

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
  resolve              4       18
  update-crypto       17        0
  end-state           17        0
  skipped rows by reason (a row may carry several):
    unanchored (pending.json)                                                                       6
    CAS-aggregated delivery not implemented                                                         9
    SMT-aggregated delivery not implemented                                                         4
    resolver cannot query this beacon type (CAS/SMT beacon requests unimplemented)                  8
    update @context predates the spec pin; regenerated upstream, absorbed at the test-suite bump   17
  fixture defects: 16 vector(s) encode versionId as a JSON number (the specification requires an ASCII string): mutinynet
  stale update @context: 17 vector(s) predate the spec's pinned update @context (regenerated upstream; Resolve rows skipped under StaleContext until the bump): mutinynet, regtest

minted-scenario coverage: 2 scenario(s) driven from in-repo fixtures (NOT counted in the upstream ledger above)
  minted/clean-rotating-beacons (minted on regtest)
    driven by minted_chain_sequences_updates_across_rotating_beacons
    covers: multi-update sequencing across rotating beacons
    covers: an update announced from a beacon an earlier update added, scanned mid-walk
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

### The five skip reasons

Defined by `SkipReason` (`src/test_vectors.rs`) and derived from each vector's
own files — four by `derived_resolve_skip_reasons`, the fifth in
`Vector::skip_reasons_with`. They are **additive**: a skipped row carries every
applicable reason, not the first match, which is why the five counts above sum
to more than the 18 skipped rows.

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
- **`StaleContext`** — at least one of the vector's own update files
  (`update/**/output.json` `signedUpdate` and its `proof`, or the
  `resolve/input.json` sidecar `updates[*]` and their proofs) carries an
  `@context` that is not the spec's pinned four-URL array
  (`did_btcr2::UPDATE_CONTEXT`). The vector predates the pin and is being
  regenerated upstream. **Resolve kind only**: the `update-crypto` and
  `end-state` drivers rebuild the update from `input.json` and compare document
  hashes, never reading the vector's `@context`, so those rows stay driven.
  Self-clearing — a regenerated vector stops matching the rule and its row is
  driven again — and pinned at exactly 17 vectors by `STALE_UPDATE_CONTEXT`,
  asserted in both directions (see below).
- **`Override(&str)`** — a hand-written one-off. `SKIP_OVERRIDES` is currently
  **empty by design**, so every skip on disk today comes from a derived rule.

"Past genesis" is **not** a skip reason. A v2+ vector is driven from a captured
chain snapshot under `fixtures/chain/`.

### The coverage ratchet

`DRIVEN_FLOOR` (`src/test_vectors.rs`) records the minimum driven rows per kind:

```
Derivation 22, GenesisKey 22, Resolve 4, UpdateCrypto 17, EndState 17
```

It is compared with `>=`, so upstream adding vectors raises coverage without
failing the build. Only a silent coverage **loss** fails.

Resolve is 4, not 11, while the stale update `@context` population is parked:
the four genesis-era rows (`mutinynet/k1/q5puld7y`, `mutinynet/x1/q5g3smvu`,
`regtest/k1/qgpakaw4`, `regtest/x1/q2fz9mz6`) are driven, and the seven anchored
past-genesis rows that `fixtures/chain/` fed are skipped under `StaleContext`.
`resolve_driven_set_is_the_expected_four_ids` pins those four by id. UpdateCrypto
and EndState stay at 17 because their drivers do not read the vector's
`@context`; every update-bearing vector is stale and every one of those 34 rows
is still driven. When the regenerated suite is absorbed, Resolve is re-raised to
11 or more by hand — the floor is a minimum, so nothing re-raises it
automatically.

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

### The stale update @context population

`STALE_UPDATE_CONTEXT` (`src/test_vectors.rs`) pins the 17 vectors — every
vector with an `update/` directory in the vendor suite as checked out — whose
update files carry an `@context` that predates the spec's pinned array. The
five without an `update/` directory (`mutinynet/k1/q5puld7y`,
`mutinynet/x1/q5g3smvu`, `mutinynet/x1/qh66uy2s`, `regtest/k1/qgpakaw4`,
`regtest/x1/q2fz9mz6`) carry no update and are not stale.

`live_vectors_record_their_update_context` asserts the pin in both directions
and asserts the count is exactly 17: a stale vector that is not listed fails by
name rather than being absorbed by the derived skip; a listed vector that is now
clean fails, telling the reader to delete the entry and re-raise
`DRIVEN_FLOOR`'s Resolve entry; a partial regeneration trips the count. At the
test-suite bump this list empties, the count pin drops, and the Resolve floor
goes back up — the regeneration cannot be absorbed silently. A regenerated
vector that still carries the old array stays honestly skipped rather than
failing.

Until the resolver rejects a non-pinned update `@context`, the seven anchored
Resolve rows parked here would still pass; the skip lands before the reject so
that no commit is red, and the label becomes literally true once the reject
lands.

While those rows are parked,
`cryptosuite::tests::stale_vectors_foreign_proofs_verify_under_this_cryptosuite`
verifies every update-step `proofValue` of the 17 vectors as shipped in
`output.json` (the key read from `sourceDocument`), so at least 17 proofs
produced by another implementation are still checked by this crate's BIP340
path; a flipped-byte control proves the assertion bites.

## 4. The 22 upstream vectors

Measured from each vector's own files: `ver` / `conf` / `deact` from
`resolve/output.json.didDocumentMetadata`; `services` from the resolved
document; `pending` = `pending.json` present; `sidecar` = `resolve/input.json`
carries `resolutionOptions.sidecar.genesisDocument`; `delivery` from
`scenario.json`. `resolve` is whether the resolve row is driven; `parked
(StaleContext)` marks a row that was driven from `fixtures/chain/` and is
skipped only until the regenerated suite is absorbed.

| Vector | ver | conf | deact | services | pending | sidecar | delivery | resolve |
|---|---|---|---|---|---|---|---|---|
| mutinynet/k1/q5p6w9su | 2 | - | true | 3× Singleton | no | - | - | parked (StaleContext) |
| mutinynet/k1/q5pgeu9z | 2 | - | - | 3× Singleton + DIDCommMessaging | no | - | - | parked (StaleContext) |
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
| mutinynet/x1/q5ugrf3w | 2 | - | - | 3× Singleton + DWN | no | yes | - | parked (StaleContext) |
| mutinynet/x1/qh66uy2s | 1 | - | - | (none) | no | - | genesis=cas | skipped |
| mutinynet/x1/qkrrp544 | 2 | - | - | 3× Singleton + CAS + DIDComm | no | yes | - | skipped |
| mutinynet/x1/qky9e7qz | 4 | - | true | 3× Singleton + DIDComm + DWN | YES | - | genesis=cas | skipped |
| regtest/k1/qgpakaw4 | 1 | - | - | 3× Singleton | no | - | - | DRIVEN |
| regtest/k1/qgppexmy | 2 | 93 | - | 3× Singleton | no | - | - | parked (StaleContext) |
| regtest/k1/qgpy0hmm | 2 | 78 | - | 4× Singleton | no | - | - | parked (StaleContext) |
| regtest/x1/q26jeds9 | 2 | 65 | - | 2× Singleton | no | yes | - | parked (StaleContext) |
| regtest/x1/q2fz9mz6 | 1 | - | - | 1× Singleton | no | yes | - | DRIVEN |
| regtest/x1/qfl7se8f | 2 | 53 | - | 1× Singleton | no | yes | - | parked (StaleContext) |

### What distinguishes each vector

Skip reasons below are the derived ones, in the rule's own terms.

- **mutinynet/k1/q5p6w9su** — the only vector that ends deactivated (parked
  under `StaleContext` until the regeneration lands); its deactivation
  short-circuit is exercised against a captured chain once driven.
- **mutinynet/k1/q5pgeu9z** — the only vector whose resolved document adds a
  DIDComm endpoint alongside its beacons (parked under `StaleContext` until the
  regeneration lands): a non-beacon service does not disturb the beacon walk.
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
- **mutinynet/x1/q5ugrf3w** — the only vector whose resolved document carries a
  web-node service, and the only mutinynet vector that combines a sidecar
  genesis with an on-chain update (parked under `StaleContext` until the
  regeneration lands).
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
  confirmations were captured against the export's tip, 758.
- **regtest/x1/q26jeds9** — the only vector with exactly two Singleton beacons;
  external DID resolved from a sidecar genesis, signal at height 694 for 65
  confirmations.
- **regtest/x1/q2fz9mz6** — the smallest document in the suite: one Singleton
  beacon, externally supplied genesis, no update step.
- **regtest/x1/qfl7se8f** — the single-beacon update case: one beacon address in
  its capture, the latest regtest signal (height 706) and the smallest stated
  confirmation count, 53.

### Driven versus skipped

Four resolve rows are driven: `mutinynet/k1/q5puld7y`, `mutinynet/x1/q5g3smvu`,
`regtest/k1/qgpakaw4`, `regtest/x1/q2fz9mz6` — the genesis-era vectors, which
carry no update and so cannot be stale. The other 18 are skipped:

- **11** — a CAS or SMT beacon in the document, and/or an aggregated delivery
  recipe, and/or a `pending.json` (all mutinynet; these carry `StaleContext`
  too, since every one has an `update/` directory).
- **7 newly parked** — plain Singleton beacons, nothing aggregated, nothing
  pending, formerly driven from `fixtures/chain/`: `q5p6w9su`, `q5pgeu9z`,
  `q5ugrf3w` on mutinynet and `qgppexmy`, `qgpy0hmm`, `q26jeds9`, `qfl7se8f` on
  regtest. Skipped under `StaleContext` alone until the regenerated suite is
  absorbed.

The four regtest rows `qgppexmy`, `qgpy0hmm`, `q26jeds9`, `qfl7se8f` are the
only skipped resolve rows that are not mutinynet.

The five skip-reason counts attribute to rows exactly:

| Reason | Count | Rows |
|---|---|---|
| `Unanchored` | 6 | the 6 rows with `pending` = YES |
| `SmtDelivery` | 4 | the 4 rows with an SMT beacon (`q425c5wf`, `q4lqu6gr`, `q4rnhfhv`, `q5cfewep`); no vector declares an `smt` delivery recipe |
| `CasDelivery` | 9 | the 4 rows with a CAS beacon ∪ the 7 rows with a `cas` delivery recipe (`q4x4pxl2` and `q59jnwfs` are in both) |
| `UnsupportedBeaconType` | 8 | the 4 SMT-beacon rows + the 4 CAS-beacon rows |
| `StaleContext` | 17 | every vector with an `update/` directory |

Their union is the 18 skipped rows: the 11 the first four reasons cover (each
of which also carries `StaleContext`), plus the 7 that `StaleContext` alone
parks.

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
| `minted/clean-rotating-beacons` | `minted_chain_sequences_updates_across_rotating_beacons` | multi-update sequencing across rotating beacons; an update announced from a beacon an earlier update added, scanned mid-walk; on-chain deactivation short-circuit; mid-walk version bounds on a four-version chain | `didDocumentMetadata` `{versionId: "4", deactivated: true}` |
| `minted/late-publishing-fork` | `minted_fork_raises_late_publishing` | late publishing detected against a real on-chain fork | `{"error": "LATE_PUBLISHING"}` |

## 6. Chain fixtures

`fixtures/chain/` holds 9 captures: 7 vendor captures,
one per anchored past-genesis vector (all seven parked under `StaleContext`
until the regeneration lands), plus the 2 minted scenarios. `addrs` is the number of beacon
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
| minted/clean-rotating-beacons.json | regtest | http://localhost:3000 | 769 | 4 | 3 | 760, 762, 764 |
| minted/late-publishing-fork.json | regtest | http://localhost:3000 | 778 | 3 | 2 | 771, 773 |

The other 4 driven vectors (`q5puld7y`, `q5g3smvu`, `qgpakaw4`, `q2fz9mz6`) are
genesis-only and need no capture.

### The vendor regtest captures share one tip

The four regtest vendor captures share one tip, 758 — the Polar export's tip as
shipped — and that is exactly what makes the vectors' stated confirmations agree.
`tip - signal_height + 1` gives 758−666+1 = 93, 758−681+1 = 78, 758−694+1 = 65
and 758−706+1 = 53, matching the 93 / 78 / 65 / 53 in the vector table.

Mining on a fresh unpack of that export is how the minted scenarios below are
produced; the vendor rows replay from their files regardless of what any live
chain does. Re-capturing a vendor regtest vector needs a fresh unpack, since its
`confirmations` only reproduce from the untouched tip.

The three mutinynet captures share tip 3307267 and all announce at height
3190760. Mutinynet vector outputs state no `confirmations`, so those rows assert
confirmations by provenance — derived from the most-recently-applied update's
captured block — rather than against a stated number.

### `versionTime` probes need the announcements' blocks

A `versionTime` bound is compared against the announcing block's `mediantime`
(resolve.md "Process Next Update" step 4, footnote 5), which only a
`/block/{hash}` body carries. The capture tool records that body for every
announcement it finds, whether or not the resolve asked for it. The two minted
captures carry their blocks, so their versionTime probes run. The seven vendor
captures predate that and hold no `blocks`, so the replay tests' versionTime
probe skips on each of them — printing `SKIP: … no /block/{hash} body` — and
the set is pinned in `test_vectors::FIXTURES_WITHOUT_SIGNAL_BLOCKS`, checked in
both directions by `chain_fixture_signal_block_ledger_is_exact`. Those seven
cannot be re-captured until the upstream regeneration lands: they are in
`STALE_UPDATE_CONTEXT`, and a live capture rejects their pre-pin update
`@context`. Once re-captured, the blocks fill in and the ledger test fails by
name; delete the id from the list and the probe runs again. The versionTime
rule itself is covered by the in-memory resolver tests (`version_time_*`) and
the client's `resolve_evaluates_version_time_against_the_fetched_mediantime`.

### `minConf` and the minted captures

The resolver processes a beacon signal only once it has
`resolutionOptions.minConf` confirmations — six by default — measured as
`tip - signal_height + 1` against the tip the fixture pins. Every vendor capture
clears that by a wide margin. The two minted captures are settled: the mint
tool mines `SETTLEMENT_BLOCKS` (5) past the last announcement before it
captures, so the committed tips (769 for the clean chain, whose last
announcement is at 764; 778 for the fork, whose last announcement is at 773)
give the last signal exactly six confirmations, and
`minted_chain_sequences_updates_across_rotating_beacons` and
`minted_fork_raises_late_publishing` run under the default. A re-mint that
skipped the settling step would stop the walk short under the default and fail
those replays. Re-mint with the Part 3 commands in
[crates/chain-capture/RUNBOOK.md](./crates/chain-capture/RUNBOOK.md).

To re-capture, see [crates/chain-capture/README.md](./crates/chain-capture/README.md)
and [crates/chain-capture/RUNBOOK.md](./crates/chain-capture/RUNBOOK.md).

### Spec-form fixtures

`fixtures/spec-form/` holds the sidecar and update payloads the offline unit
tests run against. Every one that any test reads is pulled in with
`include_str!`, so these are **compile-time inputs**: delete one and the test
build fails rather than a test failing.

`golden-signed-update.json` is the exception that proves the rule. It is
`include_str!`'d at three assertion sites, but `bless_or_assert` also opens it
at runtime through `CARGO_MANIFEST_DIR` (`bless_or_assert` in `src/document.rs`),
because a blessed file has to be read back the same way it was written for
`BLESS=1` to round-trip. That constraint is spelled out in the `bless_or_assert`
doc comment in `tests/conformance.rs`.

| Fixture | Shape | What it pins |
|---|---|---|
| `golden-signed-update.json` | a signed update | The blessed update vector. Re-blessed by `BLESS=1`, never hand-edited; construction derives it from `source_documents()`. |
| `sidecar-two-updates.json` | 2 updates | The ordinary chained case, used for lookup-table build, apply order, and version walking. Its `@context` arrays were hand-edited to the pinned array; its proofs are not verified by any test (parse / lookup / ordering only) and were not re-signed. |
| `sidecar-empty.json` | 0 updates | A sidecar carrying no updates at all. |
| `sidecar-missing-update.json` | 0 updates | A beacon signal whose hash is absent from the lookup table, raising `MISSING_UPDATE_DATA`. |
| `sidecar-forward-compat.json` | 0 updates, plus `casUpdates`, `smtProofs`, `genesisDocument` | Not-yet-implemented sidecar members must parse and be ignored, not rejected. |
| `sidecar-empty-service-genesis.json` | `genesisDocument` only | A hostile external genesis whose `service` array is empty must return a typed error, not panic. |

### Unit fixtures

Three files sit at `fixtures/` directly.

| Fixture | Read by | How |
|---|---|---|
| `singleton-beacon-signal-txs.json` | `src/resolver.rs`, as `UNCONFIRMED_FIXTURE` | `include_str!` |
| `k1qypa5t...l0mgs4-transactions.json` | `src/document.rs`, in `test_document_from_did_components` | `include_str!`, and the test is gated behind the `old-spec-fixtures` feature |
| `initialDidDoc-missing-verificationMethod-id.json` | `src/document.rs`, in `test_document_validation_missing_elements` | runtime `InitialDocument::from_file`, so a missing file fails the test rather than the build |

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

A resolver step may also return `ResolverState::BlockRequests` — one
`GET /block/{hash}` per block whose `mediantime` a proof's `expires` check
needs. The harness serves those from the fixture's optional `blocks` map (key:
the hash; value: the `/block/{hash}` body) and fails by name with a re-capture
hint if the map lacks the block. No committed fixture carries the key today: no
vector or minted proof carries `created` or `expires`.

Tests worth grepping for:

| Test | What it guards |
|---|---|
| `op_vectors_every_row_is_driven_or_skipped_with_reason` | every row is accounted for, and prints the ledger |
| `a_live_skip_override_keeps_every_driver_green` | a hand-written `SKIP_OVERRIDES` entry does not break the drivers |
| `ledger_summary_never_mentions_a_minted_scenario` | minted scenarios stay out of the upstream ledger |
| `capture_pump_*` (`src/resolver.rs`) | replay routing and its fail-loud behaviour |
| `interleaved_history_across_a_rotated_in_beacon_resolves` (`src/resolver.rs`) | a beacon an applied update introduces is scanned before the next tuple is processed |
| `*_returns_unsupported` (`src/resolver.rs`, `src/document.rs`) | CAS and SMT beacons return `Unsupported` |

`src/resolver.rs` holds 71 `#[test]` functions; `src/test_vectors.rs` holds 62.

## 8. When `test-suite/` is absent

The operation-vector drivers **skip** rather than fail, via
`discovered_vectors_or_skip` (`src/resolver.rs`). The minted-scenario tests still
run, because their fixtures are in-repo.

To check the submodule out, see the one-time setup in
[README.md](./README.md): `git submodule init && git submodule update`.
