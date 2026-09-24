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
