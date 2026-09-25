# Synthetic corpora in the regenerated test-suite layout

Each directory here is a small corpus of operation-vector sets laid out the
way the regenerated `did-btcr2-test-suite` lays them out:

```text
<name>/sets/{network}/{k1|x1}/{id}/    one set: create/, resolve/, update/, other.json, signals.json, ...
<name>/chain/{network}/{k1|x1}/{id}.json    optional captured chain snapshot of that set
```

The harness walks a corpus with `discover_in(&Corpus::synthetic("<name>"))`.
The production ledger walks only the `test-suite/` submodule, so nothing here
changes its counts. These files belong to this repository: an absent one is a
bug, and the tests that read them never skip.

Every set was reshaped from a set of the checked-out `test-suite/`; none was
minted. Reshaping removed:

- `scenario.json`, `funding.json` and `pending.json` (the regenerated layout
  ships none of them);
- every key: `other.json` keeps only `scenarioId` and, on `x1` sets,
  `genesisDocument` (`genesisKeys` and `newBeaconKeys` are gone), and each
  `update/**/input.json` lost its `signingMaterial`.

No set here carries a secret of any kind. None of these sets is driven past
classification, so nothing reads the removed members.

## `shapes`

Passes discovery. No `chain/` directory.

| Set | Scenario id | Source | Reshape |
|-----|-------------|--------|---------|
| `mutinynet/x1/qh66uy2s` | `shape-x1-cas-genesis` | `test-suite/mutinynet/x1/qh66uy2s` | metadata and keys removed, `scenarioId` added. No sidecar `genesisDocument`, so its genesis is CAS-delivered. |
| `regtest/k1/qgppexmy` | `shape-k1-cas-update` | `test-suite/regtest/k1/qgppexmy` | `resolve/input.json` `resolutionOptions.sidecar.updates` deleted (the sidecar object kept), so its flat `update/` is CAS-announced. |
| `mutinynet/x1/q5cfewep` | `shape-cohort-a` | `test-suite/mutinynet/x1/q5cfewep` | Keeps its flat `update/`. Hand-written `signals.json`: one entry with `update: 1` and the cohort. |
| `mutinynet/x1/q425c5wf` | `shape-cohort-b` | `test-suite/mutinynet/x1/q425c5wf` | The cohort-only shape: its `update/` directory and the sidecar `updates` were deleted on purpose (the sidecar object kept). Hand-written `signals.json`: one entry with the cohort and no `update`. |

The two cohort members declare the same `SMTBeacon` address in their genesis
documents. Their `signals.json` entries share cohort `shape-cohort`, whose
members are `shape-cohort-a` and `shape-cohort-b`, and one transaction. The
`txid`, `blockHash`, `blockHeight`, times, `signalBytes` and `recordedTip` in
those files are hand-written shape data: they are never replayed and name no
real transaction. `beaconId` and `address` are read from each set's own DID and
`SMTBeacon` service.

## `shapes-unknown-resolve-child`

Fails discovery. `regtest/k1/qgpakaw4` from `test-suite/`, metadata and keys
removed, plus a hand-written `resolve/notes.md`: a `resolve/` child that is
neither the main pair nor a numbered case.

## `shapes-malformed-signals`

Fails discovery. `regtest/k1/qgpakaw4` from `test-suite/`, metadata and keys
removed, plus a hand-written `signals.json` holding `{"entries": []}`: an
object, not the bare array the layout specifies.

## `shapes-bad-cohort-member`

Fails discovery. `shape-cohort-a` from `shapes` (the reshaped
`mutinynet/x1/q5cfewep`) alone, without its partner, so its cohort's member
`shape-cohort-b` matches no set.

## `options`

Passes discovery, and its Resolve and ResolveOption rows are driven end to end
off a real chain. One set, `mutinynet/k1/q5pew2jc`, scenario id
`reshaped-clean-rotating-beacons`. Unlike the sets above, it was reshaped from
a minted capture, not from a `test-suite/` set:
`fixtures/chain/minted/clean-rotating-beacons.json` (the four-version
mutinynet chain: v2 at block 3443744, v3 at 3443745, v4 at 3443746, which
deactivates; tip 3443751).

Copied verbatim from the capture:

- `chain/mutinynet/k1/q5pew2jc.json` is the capture with `vector` renamed and
  `sidecar` and `expected` removed. `tip_height`, `addresses`, `blocks`,
  `signals`, `did`, `network`, `endpoint` and `captured_at` are unchanged, and
  a test holds the copy equal to its source on every chain field.
- The three sidecar updates, as `update/NN/output.json` `signedUpdate` and as
  `resolutionOptions.sidecar.updates` in every resolve input.
- `signals.json`: each entry's `txid`, `blockHeight`, `blockHash` and
  `blockTime` from the announcing transaction's recorded status, `mediantime`
  from the captured block body, `signalBytes` from its `OP_RETURN` push, and
  `recordedTip` = the capture's `tip_height`, 3443751. `beaconId` is the
  service whose `serviceEndpoint` is `bitcoin:<address>` in the document
  version current when the signal is read.

Derived, never taken from the resolver under test:

- The v1 document is the create path's deterministic genesis document for the
  DID. v2, v3 and v4 are successive `json-patch` applications of the three
  sidecar patches to v1. The v4 so built equals the capture's own
  `expected.didDocument`, which is the proof that the chain of documents is
  the minted one. `update/NN/input.json` carries the source document, the
  patch, `sourceVersionId`, the `initialKey` verification method and the
  announcing `beaconId`, and no signing material.
- `confirmations` = `3443751 - height + 1` of the last applied update's
  block: v2 8, v3 7, v4 6, and 0 at genesis.
- The `versionTime` cases are RFC 3339 renderings of the captured block
  mediantimes: one second before v2's (`2026-09-21T07:06:58Z`, v1), one
  second after it (`2026-09-21T07:07:00Z`, v2), and exactly v3's
  (`2026-09-21T07:07:31Z`, v3).

The main input passes no `minConf`, as the regenerated test suite's main
inputs do. Its v4 signal has exactly 6 confirmations at the recorded tip,
which is exactly the resolver's default `minConf` of 6; a change to that
default changes this set's expected main result.

| Case | Option | Expected |
|------|--------|----------|
| main | none | v4, deactivated, 6 confirmations |
| `01` | `versionId "1"` | v1, 0 confirmations |
| `02` | `versionId "2"` | v2, 8 |
| `03` | `versionId "3"` | v3, 7 |
| `04` | `versionId "9"` | `NOT_FOUND` |
| `05` | `versionTime 2026-09-21T07:06:58Z` | v1, 0 |
| `06` | `versionTime 2026-09-21T07:07:00Z` | v2, 8 |
| `07` | `versionTime 2026-09-21T07:07:31Z` | v3, 7 |
| `08` | `versionId "2"` and `versionTime` | `INVALID_OPTIONS` |
| `09` | `minConf 1000000` | v1, 0 |
| `10` | `minConf 7` | v3, 7 |
| `11` | `versionId "5"` (past the deactivation) | `NOT_FOUND` |

Positive outputs carry `didResolutionMetadata.contentType: application/did`,
as the regenerated suite's do. Negative outputs carry `didDocument: null`, an
empty `didDocumentMetadata`, and the code with an explanatory `errorMessage`.

Nothing about the chain was invented. The only hand-written values are the
option matrix, the scenario id and the error messages.

The set carries no minting secret: the keys of the minted chain were produced
outside this repository and stay there. Its genesis-key, update-crypto and
end-state rows are therefore asserted through classification only.

Recipe, for a re-mint of the source capture: generate v1 through the create
path for the capture's DID, apply the sidecar patches in `targetVersionId`
order with `json-patch`, check the result against `expected.didDocument`, then
write the files above from the capture and those documents.
