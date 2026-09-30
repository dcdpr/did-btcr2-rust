# Test-suite map

What the tests are, which fixtures drive them, and what each fixture is for.

This document maps **tests to fixtures**.
[CONFORMANCE.md](./CONFORMANCE.md) maps **spec requirements to tests** — every
did:btcr2 method-spec MUST/SHALL row and its coverage status. Neither document
repeats the other; for "is requirement X covered", read CONFORMANCE.md.

## 1. Running the suite

Run everything from the workspace root `did-btcr2-rust/`.

```bash
BTCR2_REQUIRE_TEST_SUITE=1 cargo test --workspace --locked
cargo test -p did-btcr2-resolver-http --test conformance --test post --test guard --test schema --test smoke --test fixtures
cargo test -p did-btcr2 --lib op_vectors -- --nocapture     # prints the coverage ledger
cargo test -p did-btcr2 --lib minted_chain -- --nocapture   # minted clean chain
cargo test -p did-btcr2 --lib minted_fork -- --nocapture    # minted fork
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo +1.88 check --workspace --locked                      # the declared rust-version
cargo deny --locked --workspace check                       # cargo-deny 0.20.2 or later
```

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs the first line
and the last six as separate jobs, so one failure does not hide another.
cargo-deny's advisories check runs there only when `Cargo.lock`, a
`Cargo.toml` or `deny.toml` differs from the comparison base: the target
branch for a pull request, the previous commit for a push to `main`, and the
merge-base with `main` for a push to any other branch (so a branch whose
manifests differ from `main` is checked on every push). It also runs daily on
`main` on a schedule (`.github/workflows/advisories.yml`). Use
`cargo fmt --check`, not `cargo fmt --all`: `--all` also formats path
dependencies, and `vendor/bech32-rust` must stay byte-identical to its source
commit (`vendor/README.md`). `cargo deny` needs `--workspace`; without it only
the root crate's dependency graph is checked. The workflows pin the cargo-deny
version in `CARGO_DENY_VERSION`, once in `ci.yml` and once in `advisories.yml`.
Dependabot does not track it, so bump it by hand in both files together.

The HTTP binding's suite (`did-btcr2-resolver-http`, second line) runs offline
against a scripted resolver; only `smoke` opens a socket, on loopback at an
ephemeral port. `conformance` is the GET binding's rows against the W3C suite;
`post` is the POST binding's own rows — DID Resolution §12.1 makes POST a MAY
and the pinned suite issues GET only, so they claim no `CONFORMANCE.md` row
(the binding note there lists them; `guard` checks the list against the file).
See §9 for the vendored W3C suite that `guard` and `schema` read. `fixtures`
reads the committed `w3c/localConfig.cjs`, `FIXTURES.md`, the demo sidecar,
the minted `clean` fixture and the `chain-capture` RUNBOOK at compile time.

## 2. What ships

| Crate | Tests |
|---|---|
| `did-btcr2` | 502 lib + 9 conformance + 1 doctest |
| `did-btcr2-client` | 66 + 1 e2e |
| `did-btcr2-cli` | 45 + 2 broken-pipe |
| `chain-capture` | 286 |
| `did-btcr2-resolver-http` | 62 lib + 9 bin + 47 conformance + 10 fixtures + 12 guard + 11 post + 5 schema + 6 smoke |

Counts are copied from `cargo test` output; re-measure before editing them.

No live-network test ships. There is no HTTP client anywhere in `src/` —
`grep -rn 'ureq\|reqwest\|TcpStream\|std::net' src/` returns nothing. Everything
on-chain replays from a captured fixture.

## 3. The operation-vector ledger

The upstream vectors live in the `test-suite/` submodule: 59 sets on each of
regtest, mutinynet, signet and testnet4, 236 in all. The accounting unit is a
**row**: one (vector × assertion kind) pair, not one vector, and for the
`resolve-option` kind one (vector × `resolve/NN` case) pair. A single vector
can contribute a driven row for one kind and a skipped row for another — most
commonly a driven `derivation` row and a skipped `resolve` row.

Discovery takes an explicit corpus root (`discover_in(&Corpus)`): the ledger
walks `test-suite/` only, and the synthetic corpora under `fixtures/layout/`
(below) are walked by their own tests, so they never move these counts.

### The six assertion kinds

| Kind | What it asserts | Driver test (`src/resolver.rs`) |
|---|---|---|
| `derivation` | `create/input.json` → encoded DID equals `create/output.json.did` | `op_vectors_create_derives_expected_did` |
| `genesis-key` | `other.json.genesisKeys.secret` derives `genesisKeys.public`, and every update step signs with the genesis secret or an `other.json.extraKeys` secret whose public key is the one the step's `sourceDocument` names | `op_vectors_create_genesis_key_corroborated` |
| `resolve` | the resolver FSM resolves the vector's main pair (`resolve/input.json`) to `resolve/output.json`; a negative set's rejection carries its scenario's cause | `op_vectors_resolve_matches_output` |
| `update-crypto` | each step's own `signedUpdate` proof verifies under the key its source document names, first; then each step's content-bound triple and BIP340 proof re-derive from its own inputs and verify against its source document; a step over a deactivated source is refused, and the vendor's proof on it is verified instead. A negative set is held to its entry in the negative-set expectation table | `op_vectors_update_signs_to_expected_hashes` |
| `end-state` | applying the update steps in order to the genesis document reproduces `resolve/output.json.didDocument`; the walk stops at the resolved version, so a step no resolver applies (after deactivation, from a removed beacon, below the current height) is not applied | `op_vectors_updates_apply_to_expected_end_state` |
| `resolve-option` | one row per `resolve/NN/` case: the resolver, given that case's `resolutionOptions` (`versionId`, `versionTime`, both, `minConf`), produces its `output.json` | `op_vectors_resolve_cases_match_output` |

`resolve` and `resolve-option` share one per-case driver. An output carrying
`didResolutionMetadata.error` is asserted by its **code**, and, on the main pair
of a negative set of the checked-out suite, by its **cause** from the
negative-set expectation table; the `errorMessage` is never compared (it is the
generating implementation's text). A positive output is asserted on
`didDocument`, `versionId` (a string, no coercion), `deactivated`, and
`confirmations` compared as **at least** the recorded value. The resolver's
`confirmations` must also **equal** the derived count: `0` at genesis, where no
update was applied, and past genesis, on a set with `signals.json`, the count
the record gives, `recordedTip - blockHeight + 1` for the entry announcing the
resolved version (the earliest, for a repeated announcement). That pins the
block the resolver counts from, which the lower bound alone does not; at
genesis, where every set states `0`, the lower bound accepts any count. A set
that carries
`signals.json` is replayed only after the chain fixture's announcements equal
that file exactly (txid, block height, block hash, signal bytes, and an address
whose captured history carries the transaction). An unknown child under
`resolve/` (neither the main pair nor a numbered case) fails discovery loudly.

A `resolve-option` row inherits its set's `resolve` skip reasons: a case of a
CAS-delivered set is as undeliverable as the main pair.

### The live ledger

`cargo test -p did-btcr2 --lib op_vectors -- --nocapture` prints:

```
operation-vector coverage: 236 vectors, 1161 rows
  kind            driven  skipped
  derivation         236        0
  genesis-key        236        0
  resolve            164       72
  update-crypto      200        0
  end-state          108       92
  resolve-option      53        0
  skipped rows by reason (a row may carry several):
    CAS-aggregated delivery not implemented                                          40
    SMT-aggregated delivery not implemented                                          40
    resolver cannot query this beacon type (CAS/SMT beacon requests unimplemented)   56
    the set's expected result is an error; there is no end state to reproduce        92

minted-scenario coverage: 2 scenario(s) driven from in-repo fixtures (NOT counted in the upstream ledger above)
  minted/clean-rotating-beacons (minted on mutinynet)
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

1161 rows is 236 × 3 set-level kinds (`derivation`, `genesis-key`,
`resolve`), plus 200 `update-crypto` and 200 `end-state` rows (the 50 sets per
network that ship an `update/` directory; the other 9 are genesis-only), plus
the 53 `resolve/NN` cases. The 92 skipped rows are all `end-state` rows: the 23
negative sets per network that ship update steps. Their `update-crypto` rows are
driven, against the negative-set expectation table below.

### The four skip reasons

Defined by `SkipReason` (`src/test_vectors.rs`) and derived from each vector's
own files in `Vector::row_skip_reasons` — the delivery and beacon rules by
`derived_resolve_skip_reasons`, `ExpectedError` beside them. They are
**additive**: a skipped row carries every applicable reason, not the first
match, which is why the counts above sum to more than the skipped rows.

- **`CasDelivery` / `SmtDelivery`** — the genesis document declares a `CASBeacon`
  / `SMTBeacon` service, or the delivery derived from the set's files is CAS
  (see "Delivery is derived from the files" below). That aggregation is
  unimplemented.
- **`UnsupportedBeaconType`** — the genesis document declares a CAS or SMT
  beacon, so building the next round of requests returns `Unsupported` before any
  transaction is read. Distinct from the delivery reasons: different problem,
  different code. Both are recorded when both apply.
- **`ExpectedError`** — the set's main `resolve/output.json` carries
  `didResolutionMetadata.error`. **`end-state` only**: the set is built to fail
  resolution, so there is no end state to reproduce. Its `resolve` row asserts
  the error code, and its update steps are still driven by `update-crypto`
  against the negative-set expectation table. `derivation` and `genesis-key`
  stay driven, because `create/` still holds a valid DID. A negative
  `resolve/NN` case does not make its set negative.
- **`Override(&str)`** — a hand-written one-off. `SKIP_OVERRIDES` is currently
  **empty by design**, so every skip on disk today comes from a derived rule.
  An entry names exactly one row: a `resolve-option` entry names its case, and
  every other entry names none.

"Past genesis" is **not** a skip reason. A v2+ vector is driven from a captured
chain snapshot under `fixtures/chain/`.

### Delivery is derived from the files

`derive_delivery` reads each set's delivery from the files it ships, not from
any declaration:

- A **negative** set is read by id type alone (key-based genesis is
  deterministic, external genesis comes from the sidecar, updates come from the
  sidecar). A set that withholds data on purpose has the same files as one that
  delivers it through CAS, and only the expected error tells them apart.
- For a **positive** set the file shape decides: an external set without a
  sidecar `genesisDocument` has a CAS genesis, and update steps without sidecar
  `updates` are CAS announcements.

Discovery also parses `signals.json` where a set ships one (a bare array; one
`recordedTip` across all entries, with no `blockHeight` above it; `update`
optional only on a cohort entry; a
repeated `update` only with `duplicate: true`) and checks cohorts across sets:
each cohort member names exactly one sibling set's `scenarioId`, and every
member records the same cohort id and transaction. This is structure only:
cohort members declare an aggregate beacon, so their resolve rows skip under
the beacon-type rules.

### Error-code divergences

`ERROR_CODE_DIVERGENCES` (`src/test_vectors.rs`) pins pairs of (vector code →
specification code) where a negative vector records a code other than the one
the specification defines, each citing its upstream thread. A listed row stays
**driven** and asserts that the resolver emits the specification's code; it is
not a skip, and `SKIP_OVERRIDES` is never used for code drift. It is guarded in
both directions: an unlisted mismatch fails by name as a new divergence, and an
entry no driven negative row uses fails, telling the reader to delete it. Equal
codes and a vector code listed twice are rejected as malformed.

The table holds one entry: the suite records the late-publishing error as
`LATE_PUBLISHING_ERROR` where the specification names it `LATE_PUBLISHING`,
tracked in dcdpr/did-btcr2-js#204. It is used by the main rows of n21
(`invalid-update-version-skip`) and n28 (`late-publishing`) on every network,
eight driven rows that assert `LATE_PUBLISHING`;
`negative_vectors_carry_their_expected_error` pins that set. Once the suite is
regenerated with the specification's code, the unused-entry guard fails and the
entry is deleted. The `late-code` synthetic corpus below proves the mechanism
on its own.

### Negative-set expectation table

`NEGATIVE_SET_EXPECTATIONS` (`src/test_vectors.rs`) holds, for every negative
scenario of the checked-out suite (n01–n05, n10–n31), what the `update-crypto`
driver observes on its sets on every network: `Passes`, `FailsAt` with the
substrings the failure must carry (the check that failed and the reason it
gives), or `NoUpdateSteps` for a set that ships no update steps (n01–n04), to
which `update-crypto` does not apply; then the cause its Resolve rejection must carry, plus a note
where the outcome is not obvious from the scenario. A set expected to pass must pass; a set expected to fail must fail
with every substring. Either mismatch fails naming the set and its scenario, and
`a_flipped_negative_set_expectation_fails_naming_the_set` keeps that comparison
live. A negative set with no entry is refused by name.

The table covers the checked-out suite only; synthetic corpora have no entry.
`negative_set_table_matches_the_corpus` pins it to that corpus in both
directions: a negative set without an entry, or an entry with no set, fails by
name, and the 108 sets are counted. It also ties `NoUpdateSteps` to the set's
layout: an entry is `NoUpdateSteps` exactly when its set ships no update steps.
It refuses a `FailsAt` entry with an empty list or an empty substring, since
either matches any failure, the harness's own included; the driver refuses
such an entry again, and treats a panic whose payload is not text as a
mismatch rather than as an empty message.

On every set, positive and negative, `update-crypto` first checks each step's
own `signedUpdate` proof under the key its `sourceDocument` names, before any
other check, so a set that fails a later check still has each signature pinned.
A step over a deactivated source is left to the deactivated-source check, which
verifies the same proof.

The `cause` column lists substrings the problem-details `detail` of the set's
`resolve` rejection must contain, after its code matches. They are this crate's
own wording, taken from the details the resolver emits. The vector's
`errorMessage` is not used: it is another implementation's text, and matching it
would test that implementation's phrasing, not our reason. A cause names the
fault, never only the code; a fault-class substring may be shared between
scenarios (n10/n11, n16/n17, n26/n27 are rejected for the same stated reason).
The four invalid-DID scenarios are the exception: each cause names the fault
the scenario is built to test (n01 the bech32 checksum, n02 the padding, which
the bech32 decoder reports as a failed bit conversion, n03 the network
identifier, n04 the genesis-hash comparison) and is not contained in the detail
of the other three, so a set rejected on another parse path, or an n04 DID that
fails to parse before its genesis document is compared, fails. n01 and n02 pair
this crate's `Bech32 error:` wrapper with the decoder's own reason.
The list is empty exactly when the set's `resolve` row is not driven (n29–n31,
SMT-delivered); `negative_set_table_matches_the_corpus` enforces that in both
directions, with no waiver. `a_wrong_expected_cause_fails_naming_the_set` keeps
the comparison live: with n24's cause replaced (a set with update steps), and
again with n04's (a set without), the regtest set fails
naming the set, the scenario and the cause check, although its code still
matches. Cause mismatches are collected and reported together, so a wrong entry
names its set on every network.

Every live negative set has an entry. Only synthetic corpora (the reshaped fork
corpora) and keyed suites have none: their negative `resolve` rows keep the code
check and get no cause check.

An upstream change to a negative scenario is taken in by re-observing its sets
and editing the entry, never by editing the vector.

### The coverage ratchet

`DRIVEN_FLOOR` (`src/test_vectors.rs`) records the minimum driven rows per kind:

```
Derivation 236, GenesisKey 236, Resolve 164, UpdateCrypto 200, EndState 108, ResolveOption 53
```

It is compared with `>=`, so upstream adding vectors raises coverage without
failing the build. Only a silent coverage **loss** fails. The floor is a
minimum, so nothing raises it automatically: re-measure it by hand when the
corpus grows.

`resolve_driven_set_is_every_set_outside_the_cas_and_smt_scenarios` says which
row moved when the Resolve count does: it pins the driven Resolve set, 41 per
network, as every set except the 14 CAS/SMT-beacon scenarios and the four
CAS-delivered ones (05, 06, 08, 20).
`live_vectors_name_the_beacon_types_the_resolver_cannot_query` and
`live_vectors_derive_exactly_the_cas_delivery_set` pin those two groups by
scenario on every network.

### `versionId` is read strictly

`didDocumentMetadata.versionId` is read only as the ASCII string the
specification requires (`metadata_version_id`), and an update's
`targetVersionId` / `sourceVersionId` only as a JSON integer
(`update_version_number`); either reader panics naming the file and the field
on the other encoding. `NUMBER_ENCODED_VERSION_ID` is empty, and
`live_vectors_record_their_version_id_encoding` reads every raw main and
`resolve/NN` output and fails if a number-encoded `versionId` reappears.

### Vendor proofs

`cryptosuite::tests::vendor_update_proofs_verify_under_this_cryptosuite`
verifies every update-step `proofValue` of every positive, update-bearing
vector as shipped in `output.json` (the key read from `sourceDocument`), so
proofs produced by another implementation are checked by this crate's BIP340
path directly: at least 156, every step of the 27 positive update-bearing sets
on each network. The vectors are selected by that rule, not by an id list. A
flipped-byte control proves the assertion bites.

### Synthetic corpora (`fixtures/layout/`)

Small corpora in the suite's layout (`resolve/NN/` cases, negative sets,
`signals.json`) live under `fixtures/layout/`, each
`<name>/sets/{network}/{k1|x1}/{id}/` plus an optional
`<name>/chain/{network}/{k1|x1}/{id}.json`. They pin behaviour the checked-out
suite does not exercise, or not in isolation. `fixtures/layout/README.md`
records every set's provenance and what was copied, derived or hand-written.

| Corpus | Set | What it proves | Tests |
|---|---|---|---|
| `options` | `mutinynet/k1/q5pew2jc` | the main pair plus eleven `resolve/NN` cases (`versionId` ×3, an unreachable `versionId` → `NOT_FOUND`, `versionTime` ×3, both → `INVALID_OPTIONS`, `minConf` too high → v1, `minConf` = a signal's exact count, `versionId` past deactivation → `NOT_FOUND`), driven off a real replayed chain; `confirmations` exactly equal at the pinned tip | `synthetic_options_*` |
| `late-code` | `regtest/k1/qgph42l3` | a negative set recording `LATE_PUBLISHING_ERROR`: passes with the divergence table, fails without it | `synthetic_late_code_*`, `synthetic_unused_divergence_is_reported` |
| `withheld` | `regtest/k1/qgph42l3` | update steps present, sidecar without them, expected `MISSING_UPDATE_DATA`: classified negative, not CAS | `synthetic_withheld_update_is_negative_not_cas`, `synthetic_negative_sets_skip_update_rows_as_expected_error` |
| `below-min-conf` | `mutinynet/k1/q5pew2jc` | a positive set with `signals.json` whose main pair expects v1 (every signal below the default `minConf` at its recorded tip): its capture is replayed and cross-checked, and the walk probes, which need a version past genesis, do not run | `synthetic_signals_below_min_conf_resolve_at_genesis`, `walk_probes_apply_only_past_genesis` |
| `withheld-genesis` | `mutinynet/x1/qh66uy2s` | an external set with no sidecar `genesisDocument` expecting `NOT_FOUND`: classified negative, its Resolve row driven with no genesis source, not left unclassified | `synthetic_withheld_genesis_is_driven_not_unclassified`, `a_positive_external_set_without_a_sidecar_genesis_is_not_drivable` |
| `shapes` | four sets | classification from files alone: a CAS genesis, a CAS-announced update, and a two-member cohort, one member cohort-only with no `update/` | `shapes_corpus_classifies_from_files` |
| `shapes-unknown-resolve-child` | one set | an unknown `resolve/` child fails discovery | `shapes_unknown_resolve_child_fails_discovery` |
| `shapes-malformed-signals` | one set | a `signals.json` that is an object, not a bare array, fails discovery | `shapes_malformed_signals_fail_discovery` |
| `shapes-bad-cohort-member` | one set | a cohort member naming no sibling set fails discovery | `shapes_bad_cohort_member_fails_discovery` |

`options`, `late-code`, `withheld` and `below-min-conf` were reshaped from the
two minted captures (`minted/clean-rotating-beacons`,
`minted/late-publishing-fork`); the `shapes` and `withheld-genesis` sets from
sets of the test suite at `19f8d424`, which the checked-out suite no longer
ships. Nothing was minted for them.
`synthetic_chain_copies_equal_their_minted_source` holds each chain copy equal
to its minted source on every chain field, and
`synthetic_signals_record_the_capture_tip` holds the `options` set's
`recordedTip` equal to its chain copy's tip. The `below-min-conf` copy is read
at an earlier tip than its source:
`synthetic_chain_copies_at_an_earlier_tip_equal_their_source_below_it` holds it
equal to its source on every chain field but `tip_height`, with no source
transaction above that tip and `recordedTip` equal to it.

No synthetic set carries a signing key. Their `genesis-key`, `update-crypto`
and `end-state` rows are therefore asserted through classification only; those
kinds stay driven on the real vectors. The two negative fork sets (`late-code`,
`withheld`) have their `update-crypto` row classified as driven and their
`end-state` row skipped as `ExpectedError`; the update-crypto driver is never
called on them, and synthetic corpora have no entry in the negative-set
expectation table.

`fixtures/layout/vendor-19f8d424/` is not a corpus: it holds byte copies of a
few files of the test suite at `19f8d424`, read by unit tests that need a known
resolved document (`read_vendor_copy`).

## 4. The 59 upstream scenarios

Every network ships the same 59 scenarios, each under its own DIDs; the
scenario is the leading segment of `other.json.scenarioId`. The table gives
the regtest ids; the other networks' ids are in each network's `README.md`
under `test-suite/`. `resolve/NN` counts the numbered resolve cases.

| Scenarios | Expected | Class | resolve row | update rows |
|---|---|---|---|---|
| 01, 03 | v1 | genesis-only, no chain needed | driven | none |
| 02, 04, 07, 13–19, 21–24, 26 | v2–v4 | Singleton beacons, captured | driven off the capture | driven |
| 05 | v1 | external, no sidecar genesis, no beacon | `CasDelivery` | none |
| 06, 08, 20 | v2–v4 | CAS-delivered updates | `CasDelivery` | driven |
| 09a/b, 10a/b | v2 | `CASBeacon` | `CasDelivery`, `UnsupportedBeaconType` | driven |
| 11a/b | v2 | `SMTBeacon`, CAS-delivered update | `CasDelivery`, `SmtDelivery`, `UnsupportedBeaconType` | driven |
| 12a/b, 25a | v2 | `SMTBeacon` | `SmtDelivery`, `UnsupportedBeaconType` | driven |
| 25b, 25c | v1 | `SMTBeacon`, genesis-only | `SmtDelivery`, `UnsupportedBeaconType` | none |
| n01–n04 | `INVALID_DID` | genesis-only, raised before any request | driven, code and cause | none (`NoUpdateSteps` in the expectation table) |
| n05, n10–n28 | `MISSING_UPDATE_DATA`, `INVALID_DID_UPDATE`, `LATE_PUBLISHING_ERROR` | Singleton beacons, captured | driven off the capture | update-crypto driven against the expectation table; end-state `ExpectedError` |
| n29–n31 | `INVALID_SIGNAL_DATA`, `MISSING_UPDATE_DATA` | `SMTBeacon` | `SmtDelivery`, `UnsupportedBeaconType` | update-crypto driven against the expectation table; end-state `ExpectedError` |

The scenarios with `resolve/NN` cases: 21 (one), 22 (ten on regtest, nine
elsewhere; regtest's tenth is a `minConf` that holds only at `recordedTip`),
23 (one, `versionTime`), 24 (one) and 26 (one) — 53 rows over the four
networks. Every scenario ships `signals.json` except 01, 03, 05 and n01–n04;
the 14 CAS/SMT-beacon scenarios are all cohort members.

Regtest ids, by scenario:

| Scenario | Id | Scenario | Id | Scenario | Id |
|---|---|---|---|---|---|
| 01-k1-base | `k1/qgp45a3y` | 16-x1-beacon-add-then-use | `x1/qt04c7dn` | n10-k1-invalid-update-context-member | `k1/qgp040ju` |
| 02-k1-sidecar-update | `k1/qgph7nre` | 17-x1-vm-add-rotate-authentication | `x1/qg935lwg` | n11-k1-invalid-update-context-order | `k1/qgpejq0v` |
| 03-x1-base | `x1/qf5zrqc4` | 18-x1-embedded-invocation-key | `x1/qtrhj3w0` | n12-k1-invalid-update-proof-context | `k1/qgpnkuln` |
| 04-x1-sidecar-update | `x1/q2z78yxz` | 19-x1-relative-ids | `x1/qtk24dpv` | n13-k1-invalid-update-capability-action | `k1/qgpf5yjw` |
| 05-x1-no-beacon | `x1/qghp0w22` | 20-k1-cas-update | `k1/qgphrh53` | n14-k1-invalid-update-capability-encoding | `k1/qgpw65qy` |
| 06-x1-cas-3-updates | `x1/qfgeftze` | 21-k1-deactivate-then-update | `k1/qgpgm6kn` | n15-k1-invalid-update-proof-purpose | `k1/qgp6fp4d` |
| 07-k1-sidecar-deactivate | `k1/qgpx06u2` | 22-x1-three-updates-resolution-options | `x1/qg4zny9h` | n16-x1-invalid-update-unauthorized-method | `x1/qty0lp74` |
| 08-x1-cas-update-deactivate | `x1/qtg5vcwk` | 23-k1-duplicate-signal | `k1/qgp0enf0` | n17-k1-invalid-update-unknown-method | `k1/qgp5wcmx` |
| 09a-x1-cas-update-announcement | `x1/qg5kgjm0` | 24-k1-removed-beacon-signal | `k1/qgpz0cp4` | n18-k1-invalid-update-proof-value | `k1/qgp2ht79` |
| 09b-…-paired | `x1/qfmlfxut` | 25a-x1-smt-update-no-nonce | `x1/qfqxmcf0` | n19-k1-invalid-update-source-hash | `k1/qgpmreat` |
| 10a-x1-sidecar-update-cas-announcement | `x1/qgxluz9h` | 25b-x1-smt-nonce-no-update | `x1/qtcszm9j` | n20-k1-invalid-update-target-hash | `k1/qgp3e09g` |
| 10b-…-paired | `x1/qtxu0aj9` | 25c-x1-smt-empty-index | `x1/q2tyuy6t` | n21-k1-invalid-update-version-skip | `k1/qgpxl5uu` |
| 11a-x1-cas-update-smt-proof | `x1/qfgm2swr` | 26-k1-signal-below-current-height | `k1/qgpqx326` | n22-k1-invalid-update-patch-missing-path | `k1/qgp5fh0e` |
| 11b-…-paired | `x1/qfzppzx5` | n01-k1-invalid-did-checksum | `k1/qgp0hy8c` | n23-k1-invalid-update-patch-changes-id | `k1/qgpl0zen` |
| 12a-x1-sidecar-update-smt-proof | `x1/qfwwah7z` | n02-x1-invalid-did-padding | `x1/qfrgktt6` | n24-k1-invalid-update-patch-invalid-document | `k1/qgpq3zd0` |
| 12b-…-paired | `x1/qf9ruh87` | n03-k1-invalid-did-network-nibble | `k1/qcp0cg86` | n25-k1-invalid-update-created-after-block | `k1/qgpq4wrg` |
| 13-k1-update-p2wpkh | `k1/qgpseq0v` | n04-x1-genesis-hash-mismatch | `x1/qgaglc0d` | n26-k1-invalid-update-expires-before-mediantime | `k1/qgp33y4v` |
| 14-k1-update-p2tr | `k1/qgpw4847` | n05-x1-missing-update-data | `x1/qfuuz6h4` | n27-k1-invalid-update-expires-before-created | `k1/qgpp9e44` |
| 15-x1-beacon-rotation | `x1/qfaqdrxu` | | | n28-k1-late-publishing | `k1/qgpepnx0` |
| | | | | n29-x1-smt-proof-hash | `x1/qgncuznq` |
| | | | | n30-x1-smt-proof-root-id | `x1/qf0zm452` |
| | | | | n31-x1-smt-proof-withheld | `x1/qttq27ml` |

`negative_vectors_carry_their_expected_error` pins the 27 negative scenarios
per network (n01–n05, n10–n31) and checks each one's `resolve/output.json`
carries its `didResolutionMetadata.error` and no document.

### `k1` versus `x1`

`k1` is a key-based DID: the genesis document is derived deterministically from
the key. `x1` is an external DID, whose genesis document must be supplied out of
band — which is why the external vectors carry
`resolutionOptions.sidecar.genesisDocument`.

Sidecar presence is **not** what decides whether a vector is driven: the
`SMTBeacon` and `CASBeacon` scenarios with a sidecar genesis (10a/b, 12a/b,
25a–c, n29–n31) are still skipped, on beacon-type grounds.

### Update-step layout

Scenarios 08, 15, 16, 17, 21, 23, 24, 26 and n28 have update steps `01 02`;
06 and 22 have `01 02 03`; every other update-bearing scenario has a single
flat `update/input.json` + `update/output.json` pair.
Nine scenarios are genesis-only with no `update/` at all: 01, 03, 05, 25b, 25c
and n01–n04.

## 5. Minted scenarios

Two scenarios are minted in-repo and are deliberately **not** counted in the
upstream ledger; `ledger_summary_never_mentions_a_minted_scenario`
(`src/test_vectors.rs`) enforces the exclusion. `clean-rotating-beacons` was
re-minted on mutinynet (a public test network; the capture carries the endpoint
and tip it was read at, and a network reset means re-minting),
`late-publishing-fork` on the disposable Polar regtest chain; both fixtures are
in-repo, so these two tests run even when the `test-suite/` submodule is not
checked out.

| Scenario | Driver test | Covers | Expected |
|---|---|---|---|
| `minted/clean-rotating-beacons` | `minted_chain_sequences_updates_across_rotating_beacons` | multi-update sequencing across rotating beacons; an update announced from a beacon an earlier update added, scanned mid-walk; on-chain deactivation short-circuit; mid-walk version bounds on a four-version chain | `didDocumentMetadata` `{versionId: "4", deactivated: true}` |
| `minted/late-publishing-fork` | `minted_fork_raises_late_publishing` | late publishing detected against a real on-chain fork | `{"error": "LATE_PUBLISHING"}` |

## 6. Chain fixtures

`fixtures/chain/` holds 142 captures: 140 vendor captures, one for each of the
35 captured scenarios on each network (the 15 positive ones 02, 04, 07, 13–19,
21–24, 26 and the 20 negative ones n05, n10–n28), plus the 2 minted scenarios.
`ALL_CHAIN_FIXTURES` (`src/test_vectors.rs`) lists them, and the vendor part is
exactly `chain-capture`'s `DRIVABLE_VECTORS`.

| Network | endpoint | captures | tip | addrs | signals |
|---|---|---|---|---|---|
| regtest | http://localhost:3000 | 35 | 601 | 3–4 | 1–3 |
| mutinynet | https://mutinynet.com/api | 35 | 3449794–3449804, per set | 3–4 | 1–3 |
| signet | https://mempool.space/signet/api | 35 | 323394 | 3–4 | 1–3 |
| testnet4 | https://mempool.space/testnet4/api | 35 | 153720 | 3–4 | 1–3 |
| minted/clean-rotating-beacons | https://mutinynet.com/api | 1 | 3443751 | 4 | 3 (3443744, 3443745, 3443746) |
| minted/late-publishing-fork | http://localhost:3000 | 1 | 778 | 3 | 2 (771, 773) |

`addrs` is the number of beacon addresses captured; `signals` is the number of
OP_RETURN announcements found. The other scenarios need no capture: 01, 03 and
n01–n04 resolve without a chain, and the CAS/SMT scenarios are not driven.

### Captures pin to each set's `recordedTip`

Every set records its `recordedTip` in `signals.json`, the chain tip its outputs
were recorded against. The capture tool reads the chain with the tip pinned to
that value and writes it as the fixture's `tip_height`, so the replayed
`confirmations` reproduce what the set records however far the live chain has
moved. On regtest every set shares 601, the Polar export's tip as shipped; on
signet and testnet4 every set shares one tip; on mutinynet each set carries its
own. Every positive output records `confirmations`, compared as at least the
recorded value and as equal to the derived count (`0` at genesis, past it the
count `signals.json` gives); a replayed positive pair that records none fails by
name.

To re-capture, see [crates/chain-capture/README.md](./crates/chain-capture/README.md)
and [crates/chain-capture/RUNBOOK.md](./crates/chain-capture/RUNBOOK.md).

### `versionTime` probes need the announcements' blocks

A `versionTime` bound is compared against the announcing block's `mediantime`
(resolve.md "Process Next Update" step 4, footnote 5), which only a
`/block/{hash}` body carries. The capture tool records that body for every
announcement it finds, whether or not the resolve asked for it, and every
committed capture carries them. A capture missing one fails by name, naming the
set and the block (`version_time_probe_bound_panics_naming_a_missing_block`).
The versionTime rule itself is also covered by the in-memory resolver tests
(`version_time_*`) and the client's
`resolve_evaluates_version_time_against_the_fetched_mediantime`.

### `minConf` and the minted captures

The resolver processes a beacon signal only once it has
`resolutionOptions.minConf` confirmations — six by default — measured as
`tip - signal_height + 1` against the tip the fixture pins. The two minted
captures are settled: the mint tool mines (on regtest) or waits for (on a
public chain) `SETTLEMENT_BLOCKS` (5) past the last announcement before it
captures, so the committed tips (3443751 for the clean chain on mutinynet,
whose last announcement is at 3443746; 778 for the fork on regtest, whose last
announcement is at 773) give the last signal exactly six confirmations, and
`minted_chain_sequences_updates_across_rotating_beacons` and
`minted_fork_raises_late_publishing` run under the default. A re-mint that
skipped the settling step would stop the walk short under the default and fail
those replays. Re-mint with the Part 3 commands in
[crates/chain-capture/RUNBOOK.md](./crates/chain-capture/RUNBOOK.md).

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
hint if the map lacks the block. Every committed capture carries the map; the
n25–n27 scenarios' proofs carry `created` / `expires`.

Tests worth grepping for:

| Test | What it guards |
|---|---|
| `op_vectors_every_row_is_driven_or_skipped_with_reason` | every row is accounted for, and prints the ledger |
| `a_live_skip_override_keeps_every_driver_green` | a hand-written `SKIP_OVERRIDES` entry does not break the drivers |
| `ledger_summary_never_mentions_a_minted_scenario` | minted scenarios stay out of the upstream ledger |
| `capture_pump_*` (`src/resolver.rs`) | replay routing and its fail-loud behaviour |
| `interleaved_history_across_a_rotated_in_beacon_resolves` (`src/resolver.rs`) | a beacon an applied update introduces is scanned before the next tuple is processed |
| `*_returns_unsupported` (`src/resolver.rs`, `src/document.rs`) | CAS and SMT beacons return `Unsupported` |

`src/resolver.rs` holds 131 `#[test]` functions; `src/test_vectors.rs` holds 175.

## 8. When `test-suite/` is absent

The operation-vector drivers **skip** rather than fail, via
`discovered_vectors_or_skip` (`src/resolver.rs`). The minted-scenario tests still
run, because their fixtures are in-repo.

A skip is right for a local non-recursive clone and wrong in CI, where an empty
submodule would let every vector test pass vacuously. Set
`BTCR2_REQUIRE_TEST_SUITE=1` to turn the absence into a failure: the guard test
`test_suite_is_checked_out_when_required` (in `did-btcr2` and in `chain-capture`)
then fails, naming the variable and `git submodule update --init --recursive`.
The Actions `test` job sets it. Unset or empty, the drivers skip as before.

To check the submodule out, see the one-time setup in
[README.md](./README.md): `git submodule init && git submodule update`.

## 9. The W3C resolution suite (`w3c-resolution-suite/`)

`w3c/did-resolution-test-suite` is vendored as a git submodule pinned at
`c3fb2a88585da1dd6167dccd59a84700fa2383ed`. It is excluded from the crates.io
package by the root `Cargo.toml` `include` allowlist; `cargo package --list`
does not mention it.

Two test binaries of `did-btcr2-resolver-http` read it at runtime, and a third
guards the config the suite is pointed at (compiled in with `include_str!`; it
does not read the submodule):

- **`tests/guard.rs`** — the traceability guard. It extracts every `it()` title
  from the suite's `tests/4-did-resolution.js` and `tests/10-bindings.js` and
  requires each to be a row (title and line) of
  `crates/did-btcr2-resolver-http/CONFORMANCE.md`; every `Covered` row must name
  a `#[test]` that exists in `tests/conformance.rs` or `tests/schema.rs`; the
  per-file `it()` counts must match the pin; and the submodule's `HEAD` must be
  the recorded pin. The title extractor and the existence check carry their own
  negative tests, so the guard cannot pass vacuously.
- **`tests/schema.rs`** — compiles the suite's `did-schema.json` (draft-04, the
  schema the suite's `checkConformantDidDocument` feeds to Ajv) and validates a
  resolved `did:btcr2` document against it; three malformed shapes must fail.
- **`tests/fixtures.rs`** — the fixture guard. It parses the two mainnet DIDs
  out of `crates/did-btcr2-resolver-http/w3c/localConfig.cjs` (compiled in with
  `include_str!`) and asserts mainnet / version 1 / `k1` for `valid` and
  mainnet / version 1 / `x1` for `notFound`, that `notFound` is the README's
  one-entry array carrying the `x1` under a `did` key (the shape the pinned
  suite iterates), that the endpoint is the resolver
  path, and that both DIDs appear verbatim in `FIXTURES.md`, whose mainnet part
  must hold no 64-hex token. Its `FIXTURES.md` §7 rows cover the funded
  mutinynet demo DIDs: exactly two, mutinynet / version 1 / `k1`, every 64-hex
  token on a line labelled `txid`; `demo/updated-v2.sidecar.json` parses as
  `SidecarData`, holds one update and names the §7.1 DID; and the minted
  `fixtures/chain/minted/clean-rotating-beacons.json` holds the §7.2 DID on
  mutinynet at the recorded tip, with the recorded signal txids and heights,
  three sidecar updates and the `versionId "4"` / deactivated end state, the
  same DID the `chain-capture` RUNBOOK's "The minted DIDs" entry names. The
  extractors have their own negative tests.

**Absence behaviour.** When the submodule is absent or unpopulated the first
two **fail**, naming `git submodule update --init w3c-resolution-suite`. This
deliberately differs from §8: the operation-vector drivers skip because their
fixtures are upstream-owned and optional; the W3C rows are the binding's
conformance claim, and a claim that silently skips is not a claim. It is the
same stance §7 takes for in-repo fixtures — a missing input the suite depends on
is a defect, reported by name.

**Regeneration.** `BLESS=1 cargo test -p did-btcr2-resolver-http --test guard`
rewrites `CONFORMANCE.md` from the curated table. A pin bump means updating
`PIN` in `guard.rs`, re-checking every row's `Line (at pin)` column against the
new files, and re-blessing.

**Running the suite against a host.** The in-process suite is the development loop; the real mocha
suite against a deployed host is the acceptance gate. From the workspace root:

```bash
npm --prefix w3c-resolution-suite ci
cp crates/did-btcr2-resolver-http/w3c/localConfig.cjs w3c-resolution-suite/localConfig.cjs
npm --prefix w3c-resolution-suite test -- --reporter spec
```

The config names the host and the two fixtures in `crates/did-btcr2-resolver-http/FIXTURES.md`; the
copy is untracked inside the submodule and must never be committed there. `-- --reporter spec`
overrides the suite's `.mocharc.yaml` (`mocha-w3c-interop-reporter`, which prints no `N passing`
summary); mocha's exit code is the gate. Expected: `30 passing`, nothing failing or pending — the
`deactivated` and dereferencing rows are not generated for an empty config.
`crates/did-btcr2-resolver-http/DEPLOY.md` §9 has the same recipe and the runner variant.
