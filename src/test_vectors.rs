//! Runtime discovery and classification of the operation-conformance vectors
//! shipped in the nested `test-suite/` submodule.
//!
//! The vectors are discovered from the filesystem rather than listed in code,
//! so adding a vector upstream needs no edit here to be seen. Every discovered
//! (vector x assertion-kind) row must end up either driven by a test or
//! skipped with a stated reason; this module owns the discovery and the
//! bookkeeping, and the driver tests in `resolver.rs` reconcile against it.
#![cfg(test)]

use crate::identifier::Network;
use esploda::esplora::{Status, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

/// Absolute path of the nested `test-suite/` submodule. `CARGO_MANIFEST_DIR`
/// resolves to the `did-btcr2` crate root, so this is stable regardless of the
/// caller's working directory.
pub(crate) fn test_suite_root() -> PathBuf {
    PathBuf::from(format!("{}/test-suite", env!("CARGO_MANIFEST_DIR")))
}

/// Absolute path of the in-crate captured-chain fixture tree.
///
/// Sibling of [`test_suite_root`], and deliberately NOT in the submodule: these
/// fixtures are ours, so they are always present and an absence is a bug.
pub(crate) fn chain_fixture_root() -> PathBuf {
    PathBuf::from(format!("{}/fixtures/chain", env!("CARGO_MANIFEST_DIR")))
}

/// `regtest/k1/qgph7nre` -> `<crate>/fixtures/chain/regtest/k1/qgph7nre.json`.
pub(crate) fn chain_fixture_path(vector_id: &str) -> PathBuf {
    chain_fixture_root().join(format!("{vector_id}.json"))
}

/// One corpus of operation vectors in the test-suite layout, together with the
/// captured chain snapshots that go with it.
///
/// Discovery takes the corpus explicitly, so every caller names the tree it
/// walks. The production ledger walks [`Corpus::test_suite`] and nothing else;
/// the synthetic corpora under `fixtures/layout/` exercise layout shapes the
/// checked-out suite does not ship, and are walked only by their own tests, so
/// none of their rows can reach the production counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Corpus {
    /// The vector sets, as `{network}/{k1|x1}/{id}/`.
    pub(crate) sets: PathBuf,
    /// The captured chain snapshots, as `{network}/{k1|x1}/{id}.json`.
    pub(crate) chain: PathBuf,
}

impl Corpus {
    /// The vendor suite in the `test-suite/` submodule and this repository's
    /// captures of it under `fixtures/chain/`.
    pub(crate) fn test_suite() -> Self {
        Self {
            sets: test_suite_root(),
            chain: chain_fixture_root(),
        }
    }

    /// A hand-built corpus under `fixtures/layout/{name}/`: its sets in
    /// `sets/` and its captures, if it has any, in `chain/`. These fixtures
    /// live in this repository, so an absent one is a bug.
    pub(crate) fn synthetic(name: &str) -> Self {
        let root = PathBuf::from(format!(
            "{}/fixtures/layout/{name}",
            env!("CARGO_MANIFEST_DIR")
        ));
        Self {
            sets: root.join("sets"),
            chain: root.join("chain"),
        }
    }
}

/// Every captured chain fixture committed to this repository.
///
/// Written down on purpose, unlike the `test-suite/` vectors, which are
/// discovered: a fixture that vanished from disk would simply stop being walked
/// by a directory scan, which is the silent-coverage-loss this whole module
/// exists to prevent. Listing them makes a deletion fail by name.
pub(crate) const ALL_CHAIN_FIXTURES: &[&str] = &[
    "regtest/k1/qgp040ju",
    "regtest/k1/qgp0enf0",
    "regtest/k1/qgp2ht79",
    "regtest/k1/qgp33y4v",
    "regtest/k1/qgp3e09g",
    "regtest/k1/qgp5fh0e",
    "regtest/k1/qgp5wcmx",
    "regtest/k1/qgp6fp4d",
    "regtest/k1/qgpejq0v",
    "regtest/k1/qgpepnx0",
    "regtest/k1/qgpf5yjw",
    "regtest/k1/qgpgm6kn",
    "regtest/k1/qgph7nre",
    "regtest/k1/qgpl0zen",
    "regtest/k1/qgpmreat",
    "regtest/k1/qgpnkuln",
    "regtest/k1/qgpp9e44",
    "regtest/k1/qgpq3zd0",
    "regtest/k1/qgpq4wrg",
    "regtest/k1/qgpqx326",
    "regtest/k1/qgpseq0v",
    "regtest/k1/qgpw4847",
    "regtest/k1/qgpw65qy",
    "regtest/k1/qgpx06u2",
    "regtest/k1/qgpxl5uu",
    "regtest/k1/qgpz0cp4",
    "regtest/x1/q2z78yxz",
    "regtest/x1/qfaqdrxu",
    "regtest/x1/qfuuz6h4",
    "regtest/x1/qg4zny9h",
    "regtest/x1/qg935lwg",
    "regtest/x1/qt04c7dn",
    "regtest/x1/qtk24dpv",
    "regtest/x1/qtrhj3w0",
    "regtest/x1/qty0lp74",
    "mutinynet/k1/q5p08ynf",
    "mutinynet/k1/q5p0w6a9",
    "mutinynet/k1/q5p4s0y9",
    "mutinynet/k1/q5p8svrz",
    "mutinynet/k1/q5p97uqz",
    "mutinynet/k1/q5p9uafd",
    "mutinynet/k1/q5p9zf8s",
    "mutinynet/k1/q5paaduz",
    "mutinynet/k1/q5pduhpu",
    "mutinynet/k1/q5pe44p3",
    "mutinynet/k1/q5petkk0",
    "mutinynet/k1/q5pfvsce",
    "mutinynet/k1/q5pggxe7",
    "mutinynet/k1/q5pkk6xt",
    "mutinynet/k1/q5pmrprx",
    "mutinynet/k1/q5ppjlgm",
    "mutinynet/k1/q5pqhkks",
    "mutinynet/k1/q5pqp5tn",
    "mutinynet/k1/q5pqss3y",
    "mutinynet/k1/q5pt9ln3",
    "mutinynet/k1/q5ptfnef",
    "mutinynet/k1/q5pueuxw",
    "mutinynet/k1/q5puvng8",
    "mutinynet/k1/q5py5sz0",
    "mutinynet/k1/q5pyz053",
    "mutinynet/k1/q5pzmjfx",
    "mutinynet/x1/q4d3qyze",
    "mutinynet/x1/q4nw2tdl",
    "mutinynet/x1/q4typvtp",
    "mutinynet/x1/q5pzvvxz",
    "mutinynet/x1/q5rp7phe",
    "mutinynet/x1/qhfjzym7",
    "mutinynet/x1/qhwufjvy",
    "mutinynet/x1/qk58te4e",
    "mutinynet/x1/qkj4a5xu",
    "signet/k1/qyp0nl7q",
    "signet/k1/qyp2ju95",
    "signet/k1/qyp3yvm3",
    "signet/k1/qyp527dr",
    "signet/k1/qyp5h7kz",
    "signet/k1/qyp7s8n5",
    "signet/k1/qypc0v9c",
    "signet/k1/qypcaw4m",
    "signet/k1/qypdef8c",
    "signet/k1/qypdscmf",
    "signet/k1/qype9x7f",
    "signet/k1/qyph2fjv",
    "signet/k1/qyphftn0",
    "signet/k1/qyphkqcy",
    "signet/k1/qyphxahc",
    "signet/k1/qypjcajt",
    "signet/k1/qypkdal6",
    "signet/k1/qyplj6cu",
    "signet/k1/qypljzfn",
    "signet/k1/qypp2qva",
    "signet/k1/qyprgq5l",
    "signet/k1/qypv877a",
    "signet/k1/qypws7tm",
    "signet/k1/qypxn45q",
    "signet/k1/qypxr0l9",
    "signet/k1/qypyl83s",
    "signet/x1/q84gyrkg",
    "signet/x1/q8y5x5f3",
    "signet/x1/q98uadmd",
    "signet/x1/q99qwj9u",
    "signet/x1/q9j6lwt5",
    "signet/x1/q9rxnv97",
    "signet/x1/qx6ld2rx",
    "signet/x1/qxkut6n0",
    "signet/x1/qyzmtprn",
    "testnet4/k1/qsp2x348",
    "testnet4/k1/qsp3k0pq",
    "testnet4/k1/qsp472vc",
    "testnet4/k1/qsp622hd",
    "testnet4/k1/qsp854zk",
    "testnet4/k1/qsp8g0tw",
    "testnet4/k1/qsp9820e",
    "testnet4/k1/qspaj3wh",
    "testnet4/k1/qspe8u25",
    "testnet4/k1/qspf02mv",
    "testnet4/k1/qspk7udk",
    "testnet4/k1/qspm6rmq",
    "testnet4/k1/qspmajv6",
    "testnet4/k1/qspmsf53",
    "testnet4/k1/qspn3pvr",
    "testnet4/k1/qspq6yml",
    "testnet4/k1/qspqm6j2",
    "testnet4/k1/qspqn994",
    "testnet4/k1/qspqqxgv",
    "testnet4/k1/qsps5avm",
    "testnet4/k1/qsptz2u9",
    "testnet4/k1/qspurjp5",
    "testnet4/k1/qspxna3u",
    "testnet4/k1/qspxpjr0",
    "testnet4/k1/qspz5wep",
    "testnet4/k1/qspzu0kw",
    "testnet4/x1/q359fq2n",
    "testnet4/x1/qjmhfkyx",
    "testnet4/x1/qjszxrzd",
    "testnet4/x1/qjw0t0e4",
    "testnet4/x1/qnenf7q8",
    "testnet4/x1/qnwp673e",
    "testnet4/x1/qsryv830",
    "testnet4/x1/qsukh94m",
    "testnet4/x1/qsvpyve8",
    "minted/clean-rotating-beacons",
    "minted/late-publishing-fork",
];

/// Every captured chain fixture of a synthetic corpus, as `(corpus, set id,
/// source capture)`: the corpus under `fixtures/layout/`, the set whose chain
/// snapshot it is, and the [`ALL_CHAIN_FIXTURES`] capture it was copied from.
///
/// Written down for the same reason as [`ALL_CHAIN_FIXTURES`]: a deletion
/// fails by name. The source column is what keeps the copy honest — the copy
/// must equal its source on everything the chain says, so no chain data in a
/// synthetic corpus is invented.
pub(crate) const SYNTHETIC_CHAIN_FIXTURES: &[(&str, &str, &str)] = &[
    (
        "options",
        "mutinynet/k1/q5pew2jc",
        "minted/clean-rotating-beacons",
    ),
    (
        "late-code",
        "regtest/k1/qgph42l3",
        "minted/late-publishing-fork",
    ),
    (
        "withheld",
        "regtest/k1/qgph42l3",
        "minted/late-publishing-fork",
    ),
];

/// Chain copies of a synthetic corpus read at an EARLIER tip than their source,
/// as `(corpus, set id, source capture, tip)`.
///
/// Such a copy is what a capture pinned to `recordedTip = tip` would have
/// written, provided every transaction the source recorded confirmed at or
/// below `tip`: the address histories, blocks and signals are then the same,
/// and only `tip_height` differs. A test holds each copy to exactly that, and
/// its set's `signals.json` to `recordedTip = tip`.
pub(crate) const SYNTHETIC_CHAIN_FIXTURES_AT_EARLIER_TIP: &[(&str, &str, &str, u32)] = &[(
    "below-min-conf",
    "mutinynet/k1/q5pew2jc",
    "minted/clean-rotating-beacons",
    3_443_748,
)];

/// One captured chain snapshot: what the beacon addresses returned, the tip they
/// were read against, and the signals found in them.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ChainFixture {
    /// The Esplora endpoint the snapshot was read from. Recorded, not used as a
    /// routing key: replay keys on the ADDRESS, because the resolver builds its
    /// request URIs from its own `rpc_host`.
    pub(crate) endpoint: String,
    /// The chain the snapshot came from. Read, never assumed: each rung of the
    /// minting ladder re-mints the minted fixtures on a different network.
    pub(crate) network: String,
    pub(crate) tip_height: u32,
    pub(crate) signals: Vec<CapturedSignal>,
    /// A key present with an empty vector means captured-and-empty; a key ABSENT
    /// means never captured, and only the latter is a replay failure.
    pub(crate) addresses: BTreeMap<String, Vec<Transaction>>,
    /// The DID the capture resolved.
    #[serde(default)]
    pub(crate) did: Option<String>,
    /// Minted scenarios only.
    #[serde(default)]
    pub(crate) sidecar: Option<serde_json::Value>,
    /// Minted scenarios only.
    #[serde(default)]
    pub(crate) expected: Option<serde_json::Value>,
    /// `GET /block/{hash}` bodies keyed by block hash, present only when a
    /// replay needs a block's mediantime (an update proof carrying `expires`).
    #[serde(default)]
    pub(crate) blocks: BTreeMap<String, serde_json::Value>,
}

/// One beacon signal found in a captured snapshot: which address announced it,
/// in which transaction and block, and the update hash it pushed.
///
/// DERIVED from [`ChainFixture::addresses`] at capture time and committed next
/// to its source; [`assert_signals_consistent`] re-derives it on every read.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct CapturedSignal {
    pub(crate) address: String,
    pub(crate) txid: String,
    pub(crate) block_height: u32,
    pub(crate) block_time: i64,
    pub(crate) update_hash: String,
}

/// A group of sets whose announcements share one aggregated Beacon Signal.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub(crate) struct Cohort {
    /// The cohort's own name, e.g. `"cas-09"`.
    pub(crate) id: String,
    /// The scenario ids (`other.json.scenarioId`) of every member set,
    /// including the set this entry belongs to.
    pub(crate) members: Vec<String>,
}

/// One entry of a set's `signals.json`: a Beacon Signal on chain that belongs
/// to this set.
///
/// Members upstream adds later are ignored rather than rejected: the file is
/// extended additively.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignalEntry {
    /// The 1-based update step this signal announces, `update/{NN}`. Absent on
    /// an entry that announces no update of this set — a cohort member whose
    /// share of the aggregated signal carries no update of its own — which
    /// must then name its `cohort`.
    #[serde(default)]
    pub(crate) update: Option<u64>,
    /// A later announcement of an update an earlier entry already announced.
    #[serde(default)]
    pub(crate) duplicate: bool,
    /// The beacon service, as `{did}#{service id}`.
    pub(crate) beacon_id: String,
    /// The beacon address the signal was spent to.
    pub(crate) address: String,
    /// The signalling transaction, 64 lowercase hex.
    pub(crate) txid: String,
    /// The height of the block confirming it.
    pub(crate) block_height: u32,
    /// The hash of the block confirming it, 64 lowercase hex.
    pub(crate) block_hash: String,
    /// That block's header time.
    pub(crate) block_time: i64,
    /// That block's median time past.
    pub(crate) mediantime: i64,
    /// The 32 signal bytes the transaction's last output pushes, 64 lowercase
    /// hex.
    pub(crate) signal_bytes: String,
    /// The chain tip the set's expected outputs were recorded against.
    pub(crate) recorded_tip: u32,
    /// The cohort this signal is shared with, when it is aggregated.
    #[serde(default)]
    pub(crate) cohort: Option<Cohort>,
}

/// A set's `signals.json`: the upstream record of every Beacon Signal of the
/// set, and the tip its expected outputs were recorded against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Signals {
    /// The `recordedTip` every entry agrees on: the chain tip the set's
    /// expected outputs (their `confirmations` in particular) were recorded
    /// against.
    pub(crate) recorded_tip: u32,
    /// The entries, in file order.
    pub(crate) entries: Vec<SignalEntry>,
}

/// True for 64 lowercase hex characters: a txid, a block hash, 32 signal bytes.
fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse and validate a set's `signals.json` against the update steps the set
/// ships. `ctx` names the file in every message.
///
/// The file is a bare array of entries, at least one, all agreeing on
/// `recordedTip`, none with a `blockHeight` above it. An entry's `update` N,
/// when present, must name an update step the set has — `update/{NN}` in a
/// numbered layout, or N = 1 for a flat `update/` — and an entry without
/// `update` must name its `cohort`. The `txid`, `blockHash` and `signalBytes`
/// are 64 lowercase hex, and no two entries share a `txid`.
///
/// Duplicates are keyed on `update` alone: an entry repeating an earlier
/// entry's `update` must set `duplicate: true`, push the same `signalBytes`,
/// and sit in a strictly higher block. `duplicate: true` on a first
/// announcement, or on an entry without `update`, is an error. Entries without
/// `update` are never duplicates of one another. The capture tool reads the
/// same file with the same keying.
pub(crate) fn parse_signals(
    raw: &str,
    ctx: &str,
    layout: &UpdateLayout,
) -> Result<Signals, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("{ctx}: not valid JSON: {e}"))?;
    let Some(array) = value.as_array() else {
        return Err(format!(
            "{ctx}: signals.json must be a bare array of signal entries, got {}",
            match value {
                serde_json::Value::Object(_) => "an object",
                _ => "a scalar",
            }
        ));
    };
    if array.is_empty() {
        return Err(format!(
            "{ctx}: signals.json holds no entry, so it records no recordedTip — a set with no \
             Beacon Signal ships no signals.json"
        ));
    }

    let mut entries = Vec::with_capacity(array.len());
    for (index, raw_entry) in array.iter().enumerate() {
        let entry: SignalEntry = serde_json::from_value(raw_entry.clone())
            .map_err(|e| format!("{ctx}: entry {index} is not a signal entry: {e}"))?;
        entries.push(entry);
    }

    let recorded_tip = entries[0].recorded_tip;
    if let Some((index, entry)) = entries
        .iter()
        .enumerate()
        .find(|(_, e)| e.recorded_tip != recorded_tip)
    {
        return Err(format!(
            "{ctx}: entry {index} records recordedTip {} but entry 0 records {recorded_tip} — \
             every entry of one file is recorded against the same tip",
            entry.recorded_tip
        ));
    }
    if let Some((index, entry)) = entries
        .iter()
        .enumerate()
        .find(|(_, e)| e.block_height > recorded_tip)
    {
        return Err(format!(
            "{ctx}: entry {index} records blockHeight {} above the recordedTip {recorded_tip} — \
             a signal the set records was confirmed at or below the tip it was recorded \
             against",
            entry.block_height
        ));
    }

    let mut first_announcement: BTreeMap<u64, usize> = BTreeMap::new();
    let mut first_txid: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        for (member, value) in [
            ("txid", &entry.txid),
            ("blockHash", &entry.block_hash),
            ("signalBytes", &entry.signal_bytes),
        ] {
            if !is_hex64(value) {
                return Err(format!(
                    "{ctx}: entry {index} {member} must be 64 lowercase hex characters, got \
                     {value:?}"
                ));
            }
        }
        if let Some(first) = first_txid.insert(&entry.txid, index) {
            return Err(format!(
                "{ctx}: entries {first} and {index} both record transaction {} — one \
                 transaction carries one Beacon Signal, so it has one entry; a repeated \
                 announcement is a later transaction",
                entry.txid
            ));
        }

        let Some(update) = entry.update else {
            if entry.cohort.is_none() {
                return Err(format!(
                    "{ctx}: entry {index} carries neither `update` nor `cohort` — an entry \
                     announcing no update step of this set must name the cohort it shares a \
                     signal with"
                ));
            }
            if entry.duplicate {
                return Err(format!(
                    "{ctx}: entry {index} sets `duplicate` but carries no `update` — only a \
                     repeated announcement of an update step can be a duplicate"
                ));
            }
            continue;
        };

        let has_step = match layout {
            UpdateLayout::None => false,
            UpdateLayout::Flat => update == 1,
            UpdateLayout::Numbered(steps) => steps.iter().any(|s| s.parse::<u64>() == Ok(update)),
        };
        if !has_step {
            return Err(format!(
                "{ctx}: entry {index} announces update {update}, but the set has no \
                 `update/{update:02}` step"
            ));
        }

        match first_announcement.get(&update) {
            None => {
                if entry.duplicate {
                    return Err(format!(
                        "{ctx}: entry {index} sets `duplicate` on the first announcement of \
                         update {update}"
                    ));
                }
                first_announcement.insert(update, index);
            }
            Some(&first) => {
                let original = &entries[first];
                if !entry.duplicate {
                    return Err(format!(
                        "{ctx}: entry {index} announces update {update} again (entry {first} \
                         announced it first) without `duplicate: true`"
                    ));
                }
                if entry.signal_bytes != original.signal_bytes {
                    return Err(format!(
                        "{ctx}: entry {index} is a duplicate of entry {first} but pushes \
                         signalBytes {} instead of {}",
                        entry.signal_bytes, original.signal_bytes
                    ));
                }
                if entry.block_height <= original.block_height {
                    return Err(format!(
                        "{ctx}: entry {index} is a duplicate of entry {first} at blockHeight {}, \
                         not above the first announcement's {}",
                        entry.block_height, original.block_height
                    ));
                }
            }
        }
    }

    Ok(Signals {
        recorded_tip,
        entries,
    })
}

/// Check every cohort the discovered sets record.
///
/// Each member scenario id of a cohort must be the `other.json.scenarioId` of
/// exactly one set on the same network, and that set's own `signals.json` must
/// record the same cohort id in the same transaction. Structure only: the
/// aggregated signal is not replayed.
pub(crate) fn check_cohorts(vectors: &[Vector]) -> Result<(), String> {
    for vector in vectors {
        let Some(signals) = &vector.signals else {
            continue;
        };
        for entry in &signals.entries {
            let Some(cohort) = &entry.cohort else {
                continue;
            };
            for member in &cohort.members {
                let matches: Vec<&Vector> = vectors
                    .iter()
                    .filter(|other| {
                        other.network_dir == vector.network_dir
                            && other.scenario_id.as_deref() == Some(member.as_str())
                    })
                    .collect();
                let [partner] = matches[..] else {
                    let ids: Vec<&str> = matches.iter().map(|v| v.id.as_str()).collect();
                    return Err(format!(
                        "{}: cohort `{}` names member `{member}`, which matches {} set(s) on \
                         {} by other.json.scenarioId (exactly one is required): {ids:?}",
                        vector.id,
                        cohort.id,
                        matches.len(),
                        vector.network_dir
                    ));
                };
                let recorded = partner.signals.iter().flat_map(|s| &s.entries).any(|e| {
                    e.txid == entry.txid && e.cohort.as_ref().is_some_and(|c| c.id == cohort.id)
                });
                if !recorded {
                    return Err(format!(
                        "{}: cohort `{}` member `{member}` ({}) records no signals.json entry for \
                         that cohort in transaction {}",
                        vector.id, cohort.id, partner.id, entry.txid
                    ));
                }
            }
        }
    }
    Ok(())
}

impl ChainFixture {
    /// The signal carrying the most-recently-applied update — the one
    /// `confirmations` is computed from (`resolver.rs`, the
    /// `current_block_height` set when an update applies).
    ///
    /// The signal announcing the update with the highest `targetVersionId`, the
    /// lowest block among them where it was announced more than once. That is
    /// the block the resolver measures from only because
    /// [`assert_version_and_height_agree`] holds on every fixture read: every
    /// announcement of the last update sits in one block, at or above every
    /// other announcement. Without that, a lower announcement on a beacon added
    /// by a later update would be below the `current_block_height` the beacon is
    /// scanned at, Find Beacon Signals would not find it, and the resolver would
    /// measure from a higher block. The capture-time gate enforces the same rule
    /// and picks the same signal.
    ///
    /// A fixture that carries no sidecar of its own (every vendor row: the
    /// sidecar lives in the test-suite tree) falls back to the highest block.
    /// [`assert_signals_consistent`] requires the two rules to agree on every
    /// fixture that can be checked, so the fallback is never a different answer —
    /// and a fixture where they diverged would fail as a fixture problem rather
    /// than as a resolver one.
    pub(crate) fn latest_signal(&self) -> Option<&CapturedSignal> {
        match self.applied_update_hash() {
            Some(hash) => self
                .signals
                .iter()
                .filter(|signal| signal.update_hash == hash)
                .min_by_key(|signal| signal.block_height),
            None => self.signals.iter().max_by_key(|signal| signal.block_height),
        }
    }

    /// The announcement hash of the sidecar update with the highest
    /// `targetVersionId`, when this fixture carries its own sidecar.
    ///
    /// The hash is recomputed here — JCS then SHA-256 over the full signed
    /// update, through the core's own `Update` — rather than read from
    /// `signals`, so the pairing of "which update is last" with "which signal
    /// announced it" is derived from the update itself.
    fn applied_update_hash(&self) -> Option<String> {
        use crate::canonical_hash::CanonicalHash as _;

        let updates = self.sidecar.as_ref()?.get("updates")?.as_array()?;
        let last = updates.iter().max_by_key(|update| {
            update
                .get("targetVersionId")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        })?;
        let parsed = crate::Update::from_json_value(last.clone()).ok()?;
        Some(hex::encode(parsed.hash().as_bytes()))
    }

    /// `(announcement hash, targetVersionId)` for every sidecar update this
    /// fixture carries, hashed the same way as [`Self::applied_update_hash`].
    /// Empty when the fixture has no sidecar of its own; an update the core
    /// cannot parse is left out, because no signal can announce it.
    fn sidecar_update_versions(&self) -> Vec<(String, u64)> {
        use crate::canonical_hash::CanonicalHash as _;

        let Some(updates) = self
            .sidecar
            .as_ref()
            .and_then(|sidecar| sidecar.get("updates"))
            .and_then(serde_json::Value::as_array)
        else {
            return Vec::new();
        };
        updates
            .iter()
            .filter_map(|update| {
                let version = update.get("targetVersionId")?.as_u64()?;
                let parsed = crate::Update::from_json_value(update.clone()).ok()?;
                Some((hex::encode(parsed.hash().as_bytes()), version))
            })
            .collect()
    }

    /// The minimum `block_time` across the signals — the anchor for a
    /// `versionTime` probe that must land BEFORE the first update.
    pub(crate) fn earliest_block_time(&self) -> Option<i64> {
        self.signals.iter().map(|signal| signal.block_time).min()
    }

    /// The hash of the block confirming each captured signal, read off the
    /// address body the signal was scanned from.
    pub(crate) fn signal_block_hashes(&self) -> BTreeSet<String> {
        self.signals
            .iter()
            .filter_map(|signal| {
                self.addresses
                    .get(&signal.address)?
                    .iter()
                    .find(|tx| tx.txid.to_string() == signal.txid)
                    .and_then(|tx| match &tx.status {
                        Status::Confirmed { block_hash, .. } => Some(block_hash.to_string()),
                        Status::Unconfirmed => None,
                    })
            })
            .collect()
    }

    /// The earliest `mediantime` among the blocks confirming the captured
    /// signals, or the first such block the fixture holds no `/block/{hash}`
    /// body for. A `versionTime` probe is a comparison against these
    /// mediantimes, so a fixture missing one cannot host the probe.
    pub(crate) fn earliest_signal_mediantime(&self) -> Result<i64, String> {
        let mut earliest: Option<i64> = None;
        for hash in self.signal_block_hashes() {
            let mediantime = self
                .blocks
                .get(&hash)
                .and_then(|body| body["mediantime"].as_i64())
                .ok_or(hash)?;
            earliest = Some(earliest.map_or(mediantime, |e| e.min(mediantime)));
        }
        earliest.ok_or_else(|| "no captured signal".to_string())
    }
}

/// The command that (re)produces the fixture for `vector_id`, for the panic
/// messages. Vendor vectors are captured off a chain; the two minted scenarios
/// are published onto one first.
fn chain_capture_command(vector_id: &str) -> String {
    let network = vector_id.split('/').next().unwrap_or(vector_id);
    if network == "minted" {
        let scenario = match vector_id {
            "minted/clean-rotating-beacons" => "clean",
            "minted/late-publishing-fork" => "poisoned",
            _ => "clean | poisoned",
        };
        format!("cargo run -p chain-capture -- mint --scenario {scenario} --network <net>")
    } else {
        format!("cargo run -p chain-capture -- capture --network {network} --vector {vector_id}")
    }
}

/// Re-derive every `signals` entry from `addresses` and require agreement.
///
/// `signals` is DERIVED data committed next to its source, which is convenient
/// for the assertions but means a hand edit or a partial re-capture could
/// desynchronize the two — and then a confirmations assertion would be comparing
/// resolver output against a stale parallel copy. Checking on read gives the
/// fixture one source of truth without giving up the convenience.
fn assert_signals_consistent(fixture: &ChainFixture, vector_id: &str) {
    let rerun = chain_capture_command(vector_id);
    for signal in &fixture.signals {
        let address = &signal.address;
        let txid = &signal.txid;

        let txs = fixture.addresses.get(address).unwrap_or_else(|| {
            panic!(
                "{vector_id}: signal {txid} names address {address}, which the capture holds \
                 no response for — `signals` is derived from `addresses`, so re-run \
                 `{rerun}` rather than editing the fixture"
            )
        });
        let tx = txs
            .iter()
            .find(|tx| tx.txid.to_string() == *txid)
            .unwrap_or_else(|| {
                panic!(
                    "{vector_id}: signal txid {txid} is not among the {} transaction(s) \
                     captured for address {address} — re-run `{rerun}` rather than editing \
                     the fixture",
                    txs.len()
                )
            });

        let Status::Confirmed {
            block_height,
            block_time,
            ..
        } = &tx.status
        else {
            panic!(
                "{vector_id}: signal txid {txid} is unconfirmed in the capture, so it cannot \
                 carry a block_height — re-run `{rerun}`"
            )
        };
        assert_eq!(
            *block_height, signal.block_height,
            "{vector_id}: signal {txid} records block_height {} but its captured transaction \
             confirmed at {block_height} — re-run `{rerun}` rather than editing the fixture",
            signal.block_height
        );
        assert_eq!(
            block_time.timestamp(),
            signal.block_time,
            "{vector_id}: signal {txid} records block_time {} but its captured transaction \
             confirmed at {} — re-run `{rerun}` rather than editing the fixture",
            signal.block_time,
            block_time.timestamp()
        );

        // The LAST output only, mirroring `find_next_signals`: the spec puts the
        // Signal Bytes there, so a signal derived from any other output would be
        // one the resolver will never read.
        let script = tx
            .outputs
            .last()
            .map(|txout| hex::encode(txout.script_pubkey.as_bytes()))
            .unwrap_or_default();
        assert_eq!(
            script,
            format!("6a20{}", signal.update_hash),
            "{vector_id}: signal {txid} records update_hash {} but its captured transaction's \
             LAST output is {script} — re-run `{rerun}` rather than editing the fixture",
            signal.update_hash
        );
    }

    assert_version_and_height_agree(fixture, vector_id, &rerun);
}

/// Require the fixture's signals to be ordered the same way by version and by
/// height.
///
/// Two rules, the same two the capture-time gate enforces:
///
/// - every announcement of an update sits at or above every announcement of an
///   update with a lower `targetVersionId`; and
/// - every announcement of the last update sits in one block, at or above every
///   other announcement.
///
/// Find Beacon Signals does not find a transaction below the
/// `current_block_height` in force when its beacon is scanned — the block of
/// the update that introduced the beacon, for any beacon but a genesis one. A
/// fixture breaking the first rule could have an update the resolver never
/// finds; one breaking the second could have its last update applied from a
/// higher block than [`ChainFixture::latest_signal`] names. Either way a replay
/// would assert against something the resolver never saw, producing a failure
/// that pointed at the resolver. On any chain minted step by step both rules
/// hold; a reorg, a mempool race on a public chain, or a hand-edited fixture can
/// break them.
///
/// Checked here so it fails as what it is: a problem with the fixture. Updates
/// sharing a `targetVersionId` (a late-publishing fork) are not ordered against
/// each other.
///
/// A set that carries `signals.json` is checked by the exact match of its
/// replayed announcements against that file ([`signals_match`]) instead, and
/// its capture carries no sidecar, so this check does not run for it: the
/// regenerated suite ships sets that break this ordering on purpose (a
/// duplicate at a later height, an announcement below the current height).
fn assert_version_and_height_agree(fixture: &ChainFixture, vector_id: &str, rerun: &str) {
    let Some(applied) = fixture.applied_update_hash() else {
        return;
    };
    let heights = |hash: &str| -> Vec<u32> {
        fixture
            .signals
            .iter()
            .filter(|signal| signal.update_hash == hash)
            .map(|signal| signal.block_height)
            .collect()
    };
    let versions = fixture.sidecar_update_versions();
    for (earlier_hash, earlier_version) in &versions {
        let Some(earlier_top) = heights(earlier_hash).into_iter().max() else {
            continue;
        };
        for (later_hash, later_version) in versions.iter().filter(|(_, v)| v > earlier_version) {
            if let Some(later_bottom) = heights(later_hash).into_iter().min() {
                assert!(
                    later_bottom >= earlier_top,
                    "{vector_id}: update {later_hash} (targetVersionId {later_version}) is \
                     announced in block {later_bottom}, below block {earlier_top}, which \
                     announces update {earlier_hash} (targetVersionId {earlier_version}) — the \
                     announcements are not ordered by version and height alike, so the resolver \
                     may never find the later one. Re-run `{rerun}` rather than editing the \
                     fixture"
                );
            }
        }
    }
    let Some(by_version) = fixture
        .signals
        .iter()
        .filter(|signal| signal.update_hash == applied)
        .min_by_key(|signal| signal.block_height)
    else {
        panic!(
            "{vector_id}: the sidecar's highest-version update {applied} is announced by no \
             captured signal — re-run `{rerun}` rather than editing the fixture"
        );
    };
    let highest = fixture
        .signals
        .iter()
        .map(|signal| signal.block_height)
        .max()
        .unwrap_or_default();
    assert_eq!(
        by_version.block_height, highest,
        "{vector_id}: the last update ({applied}) is announced in block {}, but the highest \
         captured signal is in block {highest} — the announcements are not ordered by \
         version and height alike, so `confirmations` would be asserted against a block \
         the resolver never measured from. Re-run `{rerun}` rather than editing the fixture",
        by_version.block_height
    );
}

/// Read a captured chain fixture. **Panics** when it is not there, or when its
/// derived `signals` no longer agree with its source `addresses`.
///
/// Deliberately unlike [`read_fixture_or_skip`], whose absent arm returns `None`
/// for the legitimately-absent test-suite submodule. These fixtures live in this
/// repository: a missing one for a row the ledger says is driven is a bug, and
/// skipping would let on-chain coverage vanish while the suite stayed green.
pub(crate) fn read_chain_fixture(vector_id: &str) -> ChainFixture {
    read_chain_fixture_in(&chain_fixture_root(), vector_id)
}

/// [`read_chain_fixture`] under an explicit chain-fixture root: a corpus's
/// [`Corpus::chain`] directory, so a synthetic corpus replays its own captures.
/// The same checks run on read.
pub(crate) fn read_chain_fixture_in(chain_root: &Path, vector_id: &str) -> ChainFixture {
    let path = chain_root.join(format!("{vector_id}.json"));
    let rerun = chain_capture_command(vector_id);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{vector_id}: no captured chain fixture at {} ({e}). These fixtures live in this \
             repository, not a submodule, so an absent one is a bug — run `{rerun}` (see \
             crates/chain-capture/RUNBOOK.md).",
            path.display()
        )
    });
    let fixture: ChainFixture = serde_json::from_str(&raw).unwrap_or_else(|e| {
        panic!(
            "{vector_id}: {} does not deserialize as a capture envelope ({e}) — re-run \
             `{rerun}` rather than editing the fixture.",
            path.display()
        )
    });
    assert_signals_consistent(&fixture, vector_id);
    fixture
}

/// Root of the in-repository copies of the vendor documents the unit tests
/// read, taken from the test-suite at `19f8d424`.
fn vendor_copy_root() -> PathBuf {
    PathBuf::from(format!(
        "{}/fixtures/layout/vendor-19f8d424",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Read one in-repository copy of a vendor document, by its path relative to
/// the test-suite root (e.g. `regtest/k1/qgp45a3y/resolve/output.json`).
/// **Panics** when the file is absent or is not JSON.
///
/// Unlike [`read_fixture_or_skip`], this never skips: the copies live in this
/// repository, so the unit tests that read them keep running whatever commit
/// the test-suite submodule is at, or whether it is checked out at all.
pub(crate) fn read_vendor_copy(rel: &str) -> serde_json::Value {
    read_vendor_copy_in(&vendor_copy_root(), rel)
}

fn read_vendor_copy_in(root: &Path, rel: &str) -> serde_json::Value {
    let path = root.join(rel);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "no vendor copy at {} ({e}): these copies live in this repository, so an absent \
             one is a bug",
            path.display()
        )
    });
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("vendor copy {} is not JSON ({e})", path.display()))
}

/// One Beacon Signal on chain, as the exact-match check between a set's
/// `signals.json` and its replayed chain compares it: which transaction, in
/// which block, pushing which 32 bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Announcement {
    /// The signalling transaction, 64 lowercase hex.
    pub(crate) txid: String,
    /// The height of the block confirming it.
    pub(crate) block_height: u32,
    /// The hash of the block confirming it, 64 lowercase hex.
    pub(crate) block_hash: String,
    /// The 32 bytes its last output pushes, 64 lowercase hex.
    pub(crate) signal_bytes: String,
}

impl fmt::Display for Announcement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "txid {} at block {} ({}) pushing {}",
            self.txid, self.block_height, self.block_hash, self.signal_bytes
        )
    }
}

/// One announcement the replayed chain serves, with every captured address
/// whose history lists its transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChainAnnouncement {
    /// The announcement, as the multiset balance compares it.
    pub(crate) announcement: Announcement,
    /// Every captured address whose history lists the transaction.
    pub(crate) addresses: BTreeSet<String>,
}

impl From<&SignalEntry> for Announcement {
    fn from(entry: &SignalEntry) -> Self {
        Self {
            txid: entry.txid.clone(),
            block_height: entry.block_height,
            block_hash: entry.block_hash.clone(),
            signal_bytes: entry.signal_bytes.clone(),
        }
    }
}

/// The 32 bytes `tx` announces, when its LAST output is exactly
/// `OP_RETURN <32 bytes>`.
///
/// Mirrors the resolver's Find Beacon Signals and the capture tool's gate: last
/// output only, the whole script must parse cleanly, and it must be exactly two
/// instructions pushing exactly 32 bytes.
fn announced_bytes(tx: &Transaction) -> Option<[u8; 32]> {
    use esploda::bitcoin::{opcodes::all::OP_RETURN, script::Instruction};

    let txout = tx.outputs.last()?;
    let ops = txout
        .script_pubkey
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let [Instruction::Op(OP_RETURN), Instruction::PushBytes(bytes)] = ops[..] else {
        return None;
    };
    <[u8; 32]>::try_from(bytes.as_bytes()).ok()
}

/// Every announcement the replayed chain serves: one per confirmed transaction
/// whose last output is `OP_RETURN <32 bytes>`, counted once however many
/// captured addresses list it, and carrying the set of those addresses. An
/// unconfirmed announcement is left out, as the resolver leaves it out. The
/// result is sorted by announcement.
///
/// Keyed by txid, as the capture tool's signals gate keys it: a transaction
/// that spends from one beacon and pays change to another sits in both address
/// histories, and it is still one announcement with one `signals.json` entry.
/// Counting it per address would make this cross-check reject a capture the
/// gate accepted, and a re-capture would reproduce the same fixture.
pub(crate) fn fixture_announcements(fixture: &ChainFixture) -> Vec<ChainAnnouncement> {
    let mut by_txid: BTreeMap<String, ChainAnnouncement> = BTreeMap::new();
    for (address, txs) in &fixture.addresses {
        for tx in txs {
            let Some(bytes) = announced_bytes(tx) else {
                continue;
            };
            let Status::Confirmed {
                block_height,
                block_hash,
                ..
            } = &tx.status
            else {
                continue;
            };
            by_txid
                .entry(tx.txid.to_string())
                .or_insert_with(|| ChainAnnouncement {
                    announcement: Announcement {
                        txid: tx.txid.to_string(),
                        block_height: *block_height,
                        block_hash: block_hash.to_string(),
                        signal_bytes: hex::encode(bytes),
                    },
                    addresses: BTreeSet::new(),
                })
                .addresses
                .insert(address.clone());
        }
    }
    let mut announcements: Vec<ChainAnnouncement> = by_txid.into_values().collect();
    announcements.sort_by(|a, b| a.announcement.cmp(&b.announcement));
    announcements
}

/// `signals.json` and the replayed chain agree exactly: the same announcements,
/// counted with multiplicity, on `txid`, `blockHeight`, `blockHash` and
/// `signalBytes`; and each entry's `address` is one whose captured history
/// carries its transaction (a transaction that spends from one beacon and pays
/// change to another is carried by both).
///
/// Multiset equality is what makes a flagged duplicate — a second entry for an
/// update already announced — a real claim: it must be matched by a second
/// announcement on chain, and a chain holding only the first fails. `Err` names
/// the first announcement one side has and the other lacks, or the first entry
/// whose address does not carry its transaction together with the addresses
/// that do.
pub(crate) fn signals_match(
    entries: &[SignalEntry],
    on_chain: &[ChainAnnouncement],
) -> Result<(), String> {
    let mut balance: BTreeMap<Announcement, i64> = BTreeMap::new();
    for entry in entries {
        *balance.entry(Announcement::from(entry)).or_default() += 1;
    }
    for chain in on_chain {
        *balance.entry(chain.announcement.clone()).or_default() -= 1;
    }
    match balance.into_iter().find(|(_, count)| *count != 0) {
        None => {}
        Some((announcement, count)) if count > 0 => {
            return Err(format!(
                "signals.json records {announcement}, which the replayed chain does not serve \
                 ({count} more in signals.json than on chain)"
            ));
        }
        Some((announcement, count)) => {
            return Err(format!(
                "the replayed chain serves {announcement}, which signals.json does not record \
                 ({} more on chain than in signals.json)",
                -count
            ));
        }
    }

    let carriers: BTreeMap<&str, &BTreeSet<String>> = on_chain
        .iter()
        .map(|chain| (chain.announcement.txid.as_str(), &chain.addresses))
        .collect();
    for entry in entries {
        let addresses = carriers
            .get(entry.txid.as_str())
            .expect("the balance above matched every entry's txid to an announcement");
        if !addresses.contains(&entry.address) {
            return Err(format!(
                "signals.json names address {} for transaction {}, but the replayed chain \
                 carries that transaction only at {}",
                entry.address,
                entry.txid,
                addresses
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    Ok(())
}

/// A resolved `confirmations` is at least the recorded one.
///
/// The recorded value was taken at the set's recorded tip; a replay served at
/// that tip or later can only see as many confirmations or more, so below is a
/// failure and above is not. `recorded` absent asserts nothing here: the
/// older layout states no number on some sets, and the driver checks those by
/// provenance instead.
pub(crate) fn confirmations_at_least(
    resolved: Option<u32>,
    recorded: Option<u64>,
) -> Result<(), String> {
    let Some(recorded) = recorded else {
        return Ok(());
    };
    match resolved {
        Some(resolved) if u64::from(resolved) >= recorded => Ok(()),
        Some(resolved) => Err(format!(
            "resolved confirmations {resolved} is below the recorded {recorded}"
        )),
        None => Err(format!(
            "resolved confirmations is absent; the output records {recorded}"
        )),
    }
}

/// A resolved `confirmations` equals the recorded one: the stricter check for a
/// set whose replay tip is pinned to the recorded tip, where the value is fixed
/// and an over-report is as wrong as an under-report.
pub(crate) fn confirmations_exact(
    resolved: Option<u32>,
    recorded: Option<u64>,
) -> Result<(), String> {
    if resolved.map(u64::from) == recorded {
        Ok(())
    } else {
        Err(format!(
            "resolved confirmations {} must equal the recorded {}",
            resolved.map_or("absent".to_string(), |r| r.to_string()),
            recorded.map_or("absent".to_string(), |r| r.to_string()),
        ))
    }
}

/// The `confirmations` a replayed resolve that ends at `version_id` reports at
/// the set's `recordedTip`.
///
/// At genesis the count is `0` whatever the set records: no update was
/// applied, and the resolver starts its count at `0` (`terminal_state` in
/// `resolver.rs`). Past genesis it is derived from `signals.json` alone:
/// `recordedTip - blockHeight + 1`, where `blockHeight` is that of the entry
/// announcing the update that produced the version (update step
/// `version_id - 1`), the earliest one when the update was announced again.
///
/// `Ok(None)` past genesis on a set without `signals.json`, which gives no
/// block to count from. A version past genesis whose update no entry
/// announces is an error: the record cannot say where the count starts.
///
/// TWIN: the capture tool derives the same count from its own reading of the
/// file, in `CaptureSignals::derived_confirmations`
/// (`crates/chain-capture/src/targets.rs`). Neither crate can call the
/// other's, so the rule lives twice; a change to one (the genesis value, the
/// anchor entry, the arithmetic) must be made to both. Both also refuse a
/// stated count above the derived one, and a nonzero stated count at genesis,
/// as a set defect: the capture tool in that function, this harness in
/// [`replayed_confirmations`] before its lower bound.
pub(crate) fn derived_confirmations(
    signals: Option<&Signals>,
    version_id: u64,
) -> Result<Option<u64>, String> {
    if version_id <= 1 {
        return Ok(Some(0));
    }
    let Some(signals) = signals else {
        return Ok(None);
    };
    let update = version_id - 1;
    let height = signals
        .entries
        .iter()
        .filter(|entry| entry.update == Some(update))
        .map(|entry| entry.block_height)
        .min()
        .ok_or_else(|| {
            format!(
                "the resolve reached version {version_id}, but signals.json records no \
                 announcement of update {update}, which produced it"
            )
        })?;
    let below_tip = signals.recorded_tip.checked_sub(height).ok_or_else(|| {
        format!(
            "signals.json announces update {update} in block {height}, above its recordedTip {}",
            signals.recorded_tip
        )
    })?;
    Ok(Some(u64::from(below_tip) + 1))
}

/// Judge a replayed positive resolve's `confirmations`: at least the count the
/// set states ([`confirmations_at_least`]), and equal to the count derived for
/// the version it reached ([`derived_confirmations`]) wherever one can be
/// derived — always at genesis, and past it on a set with `signals.json`.
///
/// The equality pins the block the resolver counts from. The lower bound
/// alone accepts a resolver that anchors its count on an earlier block, and at
/// genesis, where every set states `0`, it accepts any count at all.
///
/// Before the lower bound, a stated count above the derived one — any nonzero
/// count at genesis — is refused as a set inconsistent with its own record,
/// so it does not read as a resolver reporting too few.
pub(crate) fn replayed_confirmations(
    resolved: Option<u32>,
    stated: Option<u64>,
    signals: Option<&Signals>,
    version_id: u64,
) -> Result<(), String> {
    let derived = derived_confirmations(signals, version_id)?;
    if let (Some(stated), Some(derived)) = (stated, derived)
        && stated > derived
    {
        let given = match signals {
            Some(signals) if version_id > 1 => format!(
                "its signals.json gives {derived} (recordedTip {} - the block announcing \
                 version {version_id} + 1)",
                signals.recorded_tip
            ),
            _ => "a resolve that applies no update counts 0".to_string(),
        };
        return Err(format!(
            "the set states {stated} confirmations at version {version_id}, but {given}: \
             the set is inconsistent with its own record, not a resolver shortfall"
        ));
    }
    confirmations_at_least(resolved, stated)?;
    let Some(derived) = derived else {
        return Ok(());
    };
    confirmations_exact(resolved, Some(derived)).map_err(|e| match signals {
        Some(signals) if version_id > 1 => format!(
            "{e}, derived from signals.json as recordedTip {} - the block announcing version \
             {version_id} + 1",
            signals.recorded_tip
        ),
        _ => format!("{e}: a resolve that applies no update counts 0"),
    })
}

/// The resolved `versionId` matches an expected positive outcome.
///
/// The output records `versionId` as the ASCII string the specification
/// requires, and the comparison is between strings, with no numeric coercion: a
/// recorded `"03"` does not match a resolved 3. An error outcome never matches.
pub(crate) fn version_id_matches(resolved: u64, expected: &Outcome) -> Result<(), String> {
    match expected {
        Outcome::Positive {
            version_id_string: recorded,
            ..
        } => {
            let resolved = resolved.to_string();
            (resolved == *recorded).then_some(()).ok_or_else(|| {
                format!("resolved versionId \"{resolved}\" must equal the recorded \"{recorded}\"")
            })
        }
        Outcome::Error { code } => Err(format!(
            "resolved versionId {resolved}, but the output records error {code}"
        )),
    }
}

/// Read `dir`, distinguishing "the path is not there" from "the path is there
/// and something went wrong".
///
/// A missing directory is the legitimate absent-submodule case and yields
/// `None`. Every other error — a permission denial, a broken symlink, a
/// transient filesystem failure — panics. Collapsing those into "nothing here"
/// would silently drop vectors from the ledger while the submodule probe still
/// reported PRESENT (a failure on `test-suite/mutinynet/` alone removes 16
/// vectors), and every driver would then reconcile against the shrunken set and
/// pass green.
fn read_dir_or_absent(dir: &Path) -> Option<std::fs::ReadDir> {
    match std::fs::read_dir(dir) {
        Ok(entries) => Some(entries),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!(
            "{}: directory exists but could not be read ({e}) — an I/O failure must fail \
             the suite, not silently shrink the vector ledger",
            dir.display()
        ),
    }
}

/// True for repository metadata that is never a vector, network or step: any
/// dot-prefixed entry. `.git` is the motivating case (in a standalone clone its
/// `objects/pack` child satisfies the "holds vector dirs" shape), but a stray
/// `.DS_Store` or `.gitkeep` under an `update/` directory would be just as
/// fatal — `classify_operation_dirs` would reject it and discovery would panic
/// on a purely local artifact.
fn is_dot_entry(name: &str) -> bool {
    name.starts_with('.')
}

/// Sorted names of the direct child directories of `dir`, dot entries excluded.
/// An absent directory yields an empty list; an unreadable one panics.
fn sorted_child_dirs(dir: &Path) -> Vec<String> {
    let Some(entries) = read_dir_or_absent(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|entry| {
            entry.unwrap_or_else(|e| {
                panic!(
                    "{}: a directory entry could not be read: {e}",
                    dir.display()
                )
            })
        })
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !is_dot_entry(name))
        .collect();
    names.sort();
    names
}

/// True iff `network_dir` holds at least one `<kind>/<short-id>/` pair — i.e.
/// at least one of its child directories has a child directory of its own.
fn holds_vector_dirs(network_dir: &Path) -> bool {
    sorted_child_dirs(network_dir)
        .iter()
        .any(|kind| !sorted_child_dirs(&network_dir.join(kind)).is_empty())
}

/// Direct children of `test-suite/` that actually hold vector directories,
/// sorted. See [`network_dirs_with_vectors_in`].
pub(crate) fn network_dirs_with_vectors() -> Vec<String> {
    network_dirs_with_vectors_in(&test_suite_root())
}

/// Direct children of `root` that actually hold vector directories, sorted.
/// Content-based on purpose: `test-suite/signet/` ships only a `README.md` and
/// a `TODO` today, and must contribute nothing without being named in a
/// hardcoded exclusion list.
///
/// `read_dir` order is OS-dependent, so the result is sorted — discovery must
/// be deterministic. An absent root is the submodule-absent case and yields an
/// empty list; a present-but-unreadable one panics.
pub(crate) fn network_dirs_with_vectors_in(root: &Path) -> Vec<String> {
    let Some(entries) = read_dir_or_absent(root) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| {
            panic!(
                "{}: a directory entry could not be read: {e}",
                root.display()
            )
        });
        let name = entry.file_name().to_string_lossy().into_owned();
        // `.git` is a directory whose `objects/pack` child satisfies the
        // "holds vector dirs" shape, and it would then reach
        // `network_from_dir` and hard-panic as an unknown network.
        if is_dot_entry(&name) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() && holds_vector_dirs(&path) {
            names.push(name);
        }
    }
    names.sort();
    names
}

/// True iff the `test-suite/` submodule is checked out with real content — at
/// least one network directory holding at least one `<kind>/<short-id>/`
/// vector directory. A non-recursive clone leaves `test-suite/` empty, and a
/// network directory that ships only documentation (`signet/`) does not count.
pub(crate) fn test_suite_checked_out() -> bool {
    !network_dirs_with_vectors().is_empty()
}

/// Read a fixture from the nested `test-suite/` submodule at RUNTIME.
///
/// Distinguishes two cases:
/// - the submodule is **entirely absent** (non-recursive clone): return `None`
///   with a SKIP note so the caller can cleanly skip;
/// - the submodule is **present but this specific fixture is missing**
///   (partial checkout, upstream rename of one vector): `panic!`, because a
///   silent `return` here would skip every later vector in the loop and pass
///   the test vacuously — a guard that no-ops without failing.
pub(crate) fn read_fixture_or_skip(rel: &str) -> Option<String> {
    let path = test_suite_root().join(rel).display().to_string();
    match std::fs::read_to_string(&path) {
        Ok(s) => Some(s),
        Err(e) if !test_suite_checked_out() => {
            eprintln!(
                "SKIP: test-suite submodule absent ({path}: {e}); \
                 run `git submodule update --init --recursive` to enable"
            );
            None
        }
        Err(e) => panic!(
            "test-suite submodule is checked out but fixture is missing: {path} ({e}). \
             A partial checkout or an upstream rename must fail the suite, not skip it \
             silently."
        ),
    }
}

/// `read_fixture_or_skip` + `serde_json` parse. Panics with the fixture path on
/// malformed JSON (a corrupt fixture must fail, not skip).
pub(crate) fn read_fixture_json(rel: &str) -> Option<serde_json::Value> {
    let raw = read_fixture_or_skip(rel)?;
    Some(
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("test-suite/{rel} is not valid JSON: {e}")),
    )
}

/// Read and parse a JSON file that must exist. **Panics** naming `ctx` and the
/// path when it is missing, unreadable, or not JSON.
///
/// Used for every file of a set discovery has already walked into: the
/// directory is there, so an absent file is a malformed set, never an absent
/// corpus.
fn read_json_at(path: &Path, ctx: &str) -> serde_json::Value {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{ctx}: {} is missing or unreadable: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{ctx}: {} is not valid JSON: {e}", path.display()))
}

/// Map a network name onto a `Network`.
///
/// Two call sites read the same vocabulary from different places — the
/// `test-suite/` directory segment and the vector's own
/// `create/input.json.network` — so `ctx` names which one is at fault instead
/// of the message asserting a directory that may not be involved.
///
/// Test-local on purpose: `Network` has no string conversion in the core crate
/// today (only `TryFrom<u8>`), and adding one is a public-API change that does
/// not belong in a test-harness change.
pub(crate) fn network_from_dir(name: &str, ctx: &str) -> Network {
    match name {
        "mainnet" => Network::Mainnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        "mutinynet" => Network::Mutinynet,
        "testnet" | "testnet3" => Network::TestnetV3,
        "testnet4" => Network::TestnetV4,
        other => panic!(
            "unknown network `{other}` in {ctx}: add it to `network_from_dir` \
             (and confirm the crate models that network)"
        ),
    }
}

/// The id-type segment of a vector's directory path, and the
/// `create/input.json.idType` it must agree with.
///
/// A raw `"x1"` string comparison is what two drivers used to branch on, so an
/// upstream rename (`x1` -> `ext`) or a third id type would have silently
/// reclassified every affected vector as key-based: `is_drivable(Resolve)`
/// would become `true` with no sidecar requirement, and the resolve driver
/// would stop supplying a genesis document. Both directions are now mapped
/// through this enum and cross-checked against each other at discovery time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VectorIdType {
    /// `k1` / `"KEY"`: `genesisBytes` is a 33-byte compressed public key, and
    /// the genesis document is generated deterministically from it.
    Key,
    /// `x1` / `"EXTERNAL"`: `genesisBytes` is the 32-byte hash of an
    /// intermediate document that must be supplied out of band.
    External,
}

impl fmt::Display for VectorIdType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key => f.write_str("KEY"),
            Self::External => f.write_str("EXTERNAL"),
        }
    }
}

/// Map the `<kind>/` directory segment of a vector path onto its id type.
/// An unknown segment is a deliberate code change, not a silent default.
pub(crate) fn id_type_from_kind(kind: &str) -> VectorIdType {
    match kind {
        "k1" => VectorIdType::Key,
        "x1" => VectorIdType::External,
        other => panic!(
            "unknown test-suite id-type directory `{other}`: add it to `id_type_from_kind` \
             (and teach the drivers what genesis source it implies)"
        ),
    }
}

/// Map a `create/input.json.idType` wire string onto its id type.
pub(crate) fn id_type_from_create_input(declared: &str, ctx: &str) -> VectorIdType {
    match declared {
        "KEY" => VectorIdType::Key,
        "EXTERNAL" => VectorIdType::External,
        other => panic!(
            "{ctx}: unknown create/input.json.idType `{other}`: add it to \
             `id_type_from_create_input` (and teach the drivers what it means)"
        ),
    }
}

/// Walk a dotted JSON path (`"genesisKeys.secret"`, `"verificationMethod.0.id"`)
/// from `value`. A numeric segment indexes an array; anything else indexes an
/// object. A missing segment yields `Value::Null`, which the `field_*` readers
/// turn into a named panic.
fn json_at<'a>(value: &'a serde_json::Value, path: &str) -> &'a serde_json::Value {
    let mut node = value;
    for segment in path.split('.') {
        node = match segment.parse::<usize>() {
            Ok(index) => &node[index],
            Err(_) => &node[segment],
        };
    }
    node
}

/// Read a required string field, naming the vector and the JSON path on
/// failure.
///
/// Every `assert!` in the drivers carries the vector id; the field extraction
/// that runs before those asserts used to be a bare `.unwrap()`, so a malformed
/// fixture reported `called Option::unwrap() on a None value` at a line number
/// with no indication which of twenty-odd vectors was at fault.
pub(crate) fn field_str<'a>(value: &'a serde_json::Value, path: &str, ctx: &str) -> &'a str {
    let node = json_at(value, path);
    node.as_str()
        .unwrap_or_else(|| panic!("{ctx}: {path} must be a string, got {node}"))
}

/// Read a required non-negative integer field, naming the vector and the JSON
/// path on failure.
pub(crate) fn field_u64(value: &serde_json::Value, path: &str, ctx: &str) -> u64 {
    let node = json_at(value, path);
    node.as_u64()
        .unwrap_or_else(|| panic!("{ctx}: {path} must be a non-negative integer, got {node}"))
}

/// Read a required boolean field, naming the vector and the JSON path on
/// failure.
pub(crate) fn field_bool(value: &serde_json::Value, path: &str, ctx: &str) -> bool {
    let node = json_at(value, path);
    node.as_bool()
        .unwrap_or_else(|| panic!("{ctx}: {path} must be a bool, got {node}"))
}

/// Read a required hex-encoded byte string, naming the vector and the JSON path
/// on failure.
pub(crate) fn field_hex(value: &serde_json::Value, path: &str, ctx: &str) -> Vec<u8> {
    let raw = field_str(value, path, ctx);
    hex::decode(raw).unwrap_or_else(|e| panic!("{ctx}: {path} must be hex, got {raw:?}: {e}"))
}

/// Read one of an update payload's integer version numbers
/// (`signedUpdate.targetVersionId`, `input.json` `sourceVersionId`) through
/// [`update_version_number`], naming the vector and the JSON path on failure.
pub(crate) fn field_version_id(value: &serde_json::Value, path: &str, ctx: &str) -> u64 {
    update_version_number(json_at(value, path), &format!("{ctx} {path}"))
}

/// Read an update version number that the crate models as a `NonZeroU64`.
///
/// The integer reader accepts `0`, which the crate's `NonZeroU64` cannot hold,
/// so a fixture stating `targetVersionId: 0` fails here by name rather than on
/// a bare `NonZeroU64::new(..).unwrap()`.
pub(crate) fn field_nonzero_version_id(
    value: &serde_json::Value,
    path: &str,
    ctx: &str,
) -> NonZeroU64 {
    let raw = field_version_id(value, path, ctx);
    NonZeroU64::new(raw)
        .unwrap_or_else(|| panic!("{ctx}: {path} must be greater than zero, got {raw}"))
}

/// Read a resolution output's `didDocumentMetadata.versionId` as a `u64`.
///
/// The specification makes it a string, and the vectors record it as one
/// (`"2"`): only a non-empty ASCII-decimal JSON string that fits `u64` is
/// accepted. A JSON number, or any other type, is a corrupt fixture and panics
/// naming `ctx`, so the file at fault names itself. The crate's own
/// emit-a-string / reject-a-number contract is pinned separately by the
/// `DocumentMetadata` round-trip test in `document.rs`.
pub(crate) fn metadata_version_id(value: &serde_json::Value, ctx: &str) -> u64 {
    match value {
        serde_json::Value::String(s) => {
            assert!(
                !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()),
                "{ctx}: versionId string must be ASCII decimal, got {s:?}"
            );
            s.parse()
                .unwrap_or_else(|e| panic!("{ctx}: versionId {s:?} does not fit u64: {e}"))
        }
        serde_json::Value::Number(n) => {
            panic!("{ctx}: versionId must be a string, found a number {n}")
        }
        other => panic!("{ctx}: versionId must be a string, got {other}"),
    }
}

/// Read an update payload's version number (`targetVersionId`,
/// `sourceVersionId`) as a `u64`.
///
/// Unlike the metadata `versionId`, these are JSON integers: the specification's
/// example writes `"targetVersionId": 2`, and the crate parses the field into a
/// `NonZeroU64`. Only a JSON number that fits `u64` is accepted; a string, a
/// float, a negative number, a bool or null panics naming `ctx`.
pub(crate) fn update_version_number(value: &serde_json::Value, ctx: &str) -> u64 {
    match value {
        serde_json::Value::Number(n) => n
            .as_u64()
            .unwrap_or_else(|| panic!("{ctx}: must be a non-negative JSON integer, got {n}")),
        serde_json::Value::String(s) => {
            panic!("{ctx}: must be a JSON integer, found a string {s:?}")
        }
        other => panic!("{ctx}: must be a JSON integer, got {other}"),
    }
}

/// One discovered operation-vector directory plus the raw facts later
/// classification rules consume.
#[derive(Clone, Debug)]
pub(crate) struct Vector {
    /// `"regtest/x1/qfaqdrxu"` — the row key and the message prefix.
    pub(crate) id: String,
    /// `"mutinynet"` / `"regtest"`.
    pub(crate) network_dir: String,
    /// `"k1"` / `"x1"` — the directory segment, kept verbatim for messages.
    pub(crate) kind: String,
    /// `"qfaqdrxu"`.
    pub(crate) short_id: String,
    /// `id_type_from_kind(&kind)`, cross-checked against the vector's own
    /// `create/input.json.idType`. Every branch on "is this vector external?"
    /// reads this rather than comparing `kind` to a literal.
    pub(crate) id_type: VectorIdType,
    /// `network_from_dir(&network_dir, ..)`, cross-checked against the vector's
    /// own `create/input.json.network`.
    pub(crate) network: Network,
    /// The corpus this set was discovered in.
    pub(crate) corpus: Corpus,
    /// The set's own directory, `{corpus.sets}/{network}/{k1|x1}/{id}/`. Every
    /// fixture read for this set goes through here ([`Vector::fixture`]), so no
    /// driver rebuilds a path from the id and a root of its own.
    pub(crate) dir: PathBuf,
    /// How this vector ships its update steps.
    pub(crate) update_layout: UpdateLayout,
    /// The expected outcome of the main resolve pair, from
    /// `resolve/output.json`: `didResolutionMetadata.error` when present,
    /// otherwise `didDocumentMetadata`.
    pub(crate) outcome: Outcome,
    /// The numbered resolve cases, `resolve/01/`, `resolve/02/`, …, in the
    /// order of the number each names, each with the outcome its own
    /// `output.json` expects. Empty when `resolve/` holds only the main pair.
    pub(crate) resolve_cases: Vec<ResolveCase>,
    /// How the genesis document and the announcements reach a resolver,
    /// derived from the files present ([`derive_delivery`]).
    pub(crate) delivery: Delivery,
    /// Every `type` string in `other.json.genesisDocument.service[]`.
    pub(crate) genesis_service_types: Vec<String>,
    /// `resolve/input.json.resolutionOptions.sidecar.genesisDocument` is a
    /// non-null JSON value.
    pub(crate) has_sidecar_genesis_document: bool,
    /// `signals.json`, parsed and validated against the update steps; `None`
    /// when the set ships no such file.
    pub(crate) signals: Option<Signals>,
    /// `other.json.scenarioId`: the name a cohort's `members` use for this set.
    pub(crate) scenario_id: Option<String>,
}

/// Where a resolver gets the genesis document from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenesisDelivery {
    /// Generated from the identifier's key (`k1`).
    Deterministic,
    /// Supplied in `resolve/input.json` as the sidecar `genesisDocument`.
    Sidecar,
    /// Neither: an external set whose genesis document the sidecar does not
    /// carry must be fetched from content-addressed storage.
    Cas,
}

/// Where a resolver gets the announced updates from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnnouncementDelivery {
    /// Supplied in `resolve/input.json` as the sidecar `updates`.
    Sidecar,
    /// Not in the sidecar: fetched from content-addressed storage.
    Cas,
}

/// A set's delivery mechanisms, derived from its files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Delivery {
    /// How the genesis document is delivered.
    pub(crate) genesis: GenesisDelivery,
    /// How the updates are delivered; `None` when the set has no update step.
    pub(crate) announcement: Option<AnnouncementDelivery>,
    /// The main resolve pair expects an error.
    pub(crate) negative: bool,
}

/// Derive a set's delivery mechanisms from the files it ships.
///
/// Precedence: a negative set (the main `resolve/output.json` carries
/// `didResolutionMetadata.error`) is read by id type alone — a key-based
/// genesis is deterministic, an external one comes from the sidecar, and update
/// steps are sidecar-delivered — because a set that withholds data on purpose
/// has the same files as one that delivers it through CAS, and only the
/// expected error tells them apart. For a positive set the file shape decides:
/// an external set without a sidecar `genesisDocument` has a CAS genesis, and
/// update steps without a non-empty sidecar `updates` array are CAS
/// announcements.
pub(crate) fn derive_delivery(
    id_type: VectorIdType,
    negative: bool,
    has_sidecar_genesis_document: bool,
    has_update_steps: bool,
    sidecar_has_updates: bool,
) -> Delivery {
    let genesis = match id_type {
        VectorIdType::Key => GenesisDelivery::Deterministic,
        VectorIdType::External if negative || has_sidecar_genesis_document => {
            GenesisDelivery::Sidecar
        }
        VectorIdType::External => GenesisDelivery::Cas,
    };
    let announcement = has_update_steps.then_some(if negative || sidecar_has_updates {
        AnnouncementDelivery::Sidecar
    } else {
        AnnouncementDelivery::Cas
    });
    Delivery {
        genesis,
        announcement,
        negative,
    }
}

/// The outcome a resolve `output.json` expects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A resolved document, described by `didDocumentMetadata`.
    Positive {
        /// `didDocumentMetadata.versionId`, as a number.
        version_id: u64,
        /// The same field verbatim, the ASCII string the specification
        /// requires. Compared as a string, so a recorded `"03"` is not 3.
        version_id_string: String,
        /// `didDocumentMetadata.deactivated`.
        deactivated: bool,
        /// `didDocumentMetadata.confirmations`; `None` when absent or null.
        confirmations: Option<u64>,
    },
    /// A failed resolution: `didResolutionMetadata.error`.
    Error {
        /// The error code, e.g. `NOT_FOUND`.
        code: String,
    },
}

/// One numbered resolve case, `resolve/{name}/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolveCase {
    /// The directory name verbatim, e.g. `"01"`.
    pub(crate) name: String,
    /// What `resolve/{name}/output.json` expects.
    pub(crate) outcome: Outcome,
}

/// Read the outcome a resolve `output.json` expects, naming `ctx` on failure.
///
/// An output carrying `didResolutionMetadata.error` is an expected error, and
/// its code must be a string. Anything else is a resolved document, whose
/// `versionId` is read through [`metadata_version_id`] (a string only),
/// `deactivated` must be a bool, and `confirmations`, when present and non-null,
/// must be a non-negative integer.
pub(crate) fn parse_outcome(output: &serde_json::Value, ctx: &str) -> Outcome {
    if !json_at(output, "didResolutionMetadata.error").is_null() {
        return Outcome::Error {
            code: field_str(output, "didResolutionMetadata.error", ctx).to_string(),
        };
    }
    let version_id_node = json_at(output, "didDocumentMetadata.versionId");
    let confirmations = match json_at(output, "didDocumentMetadata.confirmations") {
        serde_json::Value::Null => None,
        node => Some(node.as_u64().unwrap_or_else(|| {
            panic!(
                "{ctx}: didDocumentMetadata.confirmations must be a non-negative integer, \
                 got {node}"
            )
        })),
    };
    let version_id = metadata_version_id(
        version_id_node,
        &format!("{ctx} didDocumentMetadata.versionId"),
    );
    Outcome::Positive {
        version_id,
        version_id_string: version_id_node
            .as_str()
            .expect("metadata_version_id accepted only a string")
            .to_string(),
        deactivated: field_bool(output, "didDocumentMetadata.deactivated", ctx),
        confirmations,
    }
}

impl Vector {
    /// Read `rel` (e.g. `"create/input.json"`) from this set's own directory.
    /// **Panics** naming `{id}/{rel}` when it is missing or not JSON: the set
    /// was discovered, so its files are there.
    pub(crate) fn fixture(&self, rel: &str) -> serde_json::Value {
        read_json_at(&self.dir.join(rel), &format!("{}/{rel}", self.id))
    }

    /// The expected `versionId` of the main resolve pair, when it expects a
    /// resolved document.
    pub(crate) fn expected_version_id(&self) -> Option<u64> {
        match &self.outcome {
            Outcome::Positive { version_id, .. } => Some(*version_id),
            Outcome::Error { .. } => None,
        }
    }

    /// The main resolve pair expects an error rather than a document.
    pub(crate) fn is_negative(&self) -> bool {
        matches!(self.outcome, Outcome::Error { .. })
    }
}

/// How a vector ships its update steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UpdateLayout {
    /// No `update/` directory.
    None,
    /// `update/input.json` + `update/output.json`.
    Flat,
    /// `update/01/`, `update/02/`, … — the step names, ordered by the number
    /// each names rather than by string comparison.
    Numbered(Vec<String>),
}

impl UpdateLayout {
    /// Relative fixture prefixes for each update step, in order:
    /// `Flat` -> `["update"]`; `Numbered(["01","02"])` ->
    /// `["update/01", "update/02"]`; `None` -> `[]`.
    pub(crate) fn step_prefixes(&self) -> Vec<String> {
        match self {
            Self::None => Vec::new(),
            Self::Flat => vec!["update".to_string()],
            Self::Numbered(steps) => steps.iter().map(|s| format!("update/{s}")).collect(),
        }
    }
}

/// Operation sub-directories the harness models. Anything else is an operation
/// we do not drive, and classification fails loud rather than ignoring it.
const KNOWN_OPERATION_DIRS: &[&str] = &["create", "resolve", "update"];

/// Validate one vector directory's *sub-directory* names and derive its update
/// layout.
///
/// Recognized operation sub-directories are exactly `create/`, `resolve/` and
/// `update/`; anything else (a future `revoke/` or `recover/`) is an operation
/// we do not model and must fail loud rather than be silently ignored.
/// Unknown *flat sibling files* are deliberately NOT policed: they are
/// generator metadata the harness does not read, and an unknown-file rule
/// would go red on pure generator output.
///
/// Pure over entry names on purpose: every rejection path is unit-testable
/// without mutating a checked-in fixture.
pub(crate) fn classify_operation_dirs(
    sub_dirs: &[String],
    update_children: &[String],
) -> Result<UpdateLayout, String> {
    for name in sub_dirs {
        if !KNOWN_OPERATION_DIRS.contains(&name.as_str()) {
            return Err(format!(
                "unrecognized operation sub-directory `{name}`: this vector exercises \
                 an operation the harness does not model — add a driver for it or teach \
                 `classify_operation_dirs` to reject it deliberately"
            ));
        }
    }

    if !sub_dirs.iter().any(|d| d == "update") {
        if let Some(name) = update_children.first() {
            return Err(format!(
                "`update/` child `{name}` found but the vector has no `update/` \
                 sub-directory — the directory listing and the layout disagree"
            ));
        }
        return Ok(UpdateLayout::None);
    }

    let children: BTreeSet<&str> = update_children.iter().map(String::as_str).collect();
    if children.contains("input.json") && children.contains("output.json") {
        // Detected by PRESENCE, not by an exact child count: the same reasoning
        // that leaves unknown flat sibling files unpoliced applies inside
        // `update/`. An added `update/metadata.json` is generator output, and a
        // count-based rule would fall through to the numbered branch, fail the
        // all-digits check and hard-panic discovery on it.
        //
        // The one thing a flat layout may NOT also carry is a numbered step:
        // then the directory holds two layouts and does not say which is
        // authoritative.
        if let Some(step) = update_children.iter().find(|c| is_step_name(c)) {
            return Err(format!(
                "`update/` holds the flat `input.json` + `output.json` pair AND the numbered \
                 step `{step}`: the layout is ambiguous — one of the two is authoritative and \
                 the directory does not say which"
            ));
        }
        return Ok(UpdateLayout::Flat);
    }

    if !update_children.is_empty() && update_children.iter().all(|c| is_step_name(c)) {
        return numbered_names("`update/`", update_children).map(UpdateLayout::Numbered);
    }

    let offender = update_children
        .iter()
        .find(|c| !is_step_name(c))
        .cloned()
        .unwrap_or_default();
    Err(format!(
        "unrecognized `update/` child `{offender}`: expected either \
         `input.json` + `output.json` or numbered step directories"
    ))
}

/// True for a numbered-step directory name: non-empty and all ASCII digits.
fn is_step_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|ch| ch.is_ascii_digit())
}

/// Order numbered step directories by the number they name, and reject a set
/// whose names collide numerically. `label` names the parent directory in the
/// messages (`` `update/` `` or `` `resolve/` ``); the names come back verbatim.
///
/// Lexicographic order is wrong the moment a vector reaches ten steps —
/// `["1", "2", "10"]` sorts to `["1", "10", "2"]` — and the update-crypto
/// driver would then report an opaque `sourceVersionId` mismatch while the
/// end-state driver reported an opaque target-hash mismatch, both naming the
/// symptom rather than the cause. Mixed widths (`["1", "02"]`) order correctly
/// once parsed; genuine numeric duplicates (`["1", "01"]`) name the same step
/// twice and are rejected here, at classification time, where the message can
/// say so.
fn numbered_names(label: &str, names: &[String]) -> Result<Vec<String>, String> {
    let mut steps: Vec<(u64, String)> = Vec::with_capacity(names.len());
    for name in names {
        let number = name
            .parse::<u64>()
            .map_err(|e| format!("{label} step directory `{name}` is not a step number: {e}"))?;
        steps.push((number, name.clone()));
    }
    steps.sort();
    for pair in steps.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(format!(
                "{label} step directories `{}` and `{}` both name step {} — the walk order \
                 would be ambiguous",
                pair[0].1, pair[1].1, pair[0].0
            ));
        }
    }
    Ok(steps.into_iter().map(|(_, name)| name).collect())
}

/// Validate the children of a set's `resolve/` directory and return its
/// numbered case directories in the order of the number each names.
///
/// `resolve/` holds the main pair, `input.json` and `output.json`, both
/// required, plus zero or more numbered case directories (`01`, …, `10`), each
/// a resolution of the same DID under different options. Anything else fails
/// loud, as an unknown `update/` child does: a case the harness never reads
/// would otherwise pass as covered. `resolve/10` exists upstream, so the order
/// is numeric, and `1` beside `01` names the same case twice and is rejected.
///
/// Pure over entry names, so every rejection path is unit-testable.
pub(crate) fn classify_resolve_children(children: &[String]) -> Result<Vec<String>, String> {
    let mut cases = Vec::new();
    for child in children {
        match child.as_str() {
            "input.json" | "output.json" => {}
            name if is_step_name(name) => cases.push(child.clone()),
            offender => {
                return Err(format!(
                    "unrecognized `resolve/` child `{offender}`: expected `input.json` + \
                     `output.json` plus numbered case directories"
                ));
            }
        }
    }
    for required in ["input.json", "output.json"] {
        if !children.iter().any(|c| c == required) {
            return Err(format!(
                "`resolve/` has no `{required}`: every set carries the main resolve pair \
                 `input.json` + `output.json`"
            ));
        }
    }
    numbered_names("`resolve/`", &cases)
}

/// Sorted names of every direct child of `dir`, files and directories alike,
/// dot entries excluded. An absent directory yields an empty list; an
/// unreadable one panics.
fn sorted_children(dir: &Path) -> Vec<String> {
    let Some(entries) = read_dir_or_absent(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|entry| {
            entry.unwrap_or_else(|e| {
                panic!(
                    "{}: a directory entry could not be read: {e}",
                    dir.display()
                )
            })
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !is_dot_entry(name))
        .collect();
    names.sort();
    names
}

/// Discover every operation vector in `corpus`, in deterministic sorted order.
///
/// Returns an empty vector when the corpus root is absent (the test-suite
/// submodule on a non-recursive clone); callers pair this with
/// `test_suite_checked_out()` so an absent submodule skips green while a
/// present-but-empty one cannot pass vacuously. There is deliberately no
/// root-less convenience form: a caller names the corpus it walks, so the
/// production ledger visibly walks [`Corpus::test_suite`] and nothing else.
///
/// Every file is read from the set's own directory, never from a path rebuilt
/// out of the id.
///
/// Deliberately uncached. Each caller walks the tree afresh (roughly a hundred
/// small file reads per call, six callers). Caching it in a process-wide
/// `OnceLock` would introduce exactly the shared mutable state the
/// observed-not-declared coverage design forbids between drivers: each driver
/// must derive its own view of the vector set independently, so that a driver
/// and the ledger cannot agree by construction. Do not "optimize" this.
pub(crate) fn discover_in(corpus: &Corpus) -> Vec<Vector> {
    let root = &corpus.sets;
    let mut vectors = Vec::new();

    for network_dir in network_dirs_with_vectors_in(root) {
        let network_path = root.join(&network_dir);
        let network = network_from_dir(&network_dir, "the test-suite network directory name");

        for kind in sorted_child_dirs(&network_path) {
            let kind_path = network_path.join(&kind);
            let id_type = id_type_from_kind(&kind);

            for short_id in sorted_child_dirs(&kind_path) {
                let id = format!("{network_dir}/{kind}/{short_id}");
                let vector_path = kind_path.join(&short_id);

                let sub_dirs = sorted_child_dirs(&vector_path);
                let update_children = if sub_dirs.iter().any(|d| d == "update") {
                    sorted_children(&vector_path.join("update"))
                } else {
                    Vec::new()
                };
                let update_layout = classify_operation_dirs(&sub_dirs, &update_children)
                    .unwrap_or_else(|msg| panic!("{id}: {msg}"));

                // Discovery walked into this directory, so its fixtures exist.
                // A missing one fails loud naming the file: discarding every
                // vector found so far and returning an empty set would be read
                // by all five drivers as "corpus absent" and pass green — the
                // exact silent-coverage-loss failure this module exists to
                // prevent.
                let create_input = read_json_at(&vector_path.join("create/input.json"), &id);
                let declared_network = field_str(&create_input, "network", &id);
                assert_eq!(
                    network_from_dir(declared_network, &format!("{id}/create/input.json.network")),
                    network,
                    "{id}: create/input.json declares network `{declared_network}` but the \
                     vector is filed under `{network_dir}` — a misfiled vector"
                );
                let declared_id_type = field_str(&create_input, "idType", &id);
                assert_eq!(
                    id_type_from_create_input(declared_id_type, &id),
                    id_type,
                    "{id}: create/input.json declares idType `{declared_id_type}` but the \
                     vector is filed under `{kind}` — a misfiled vector"
                );

                // `resolve/` is policed like `update/`: the main pair plus
                // numbered case directories, nothing else.
                let resolve_path = vector_path.join("resolve");
                let case_names = classify_resolve_children(&sorted_children(&resolve_path))
                    .unwrap_or_else(|msg| panic!("{id}: {msg}"));
                let resolve_output = read_json_at(&resolve_path.join("output.json"), &id);
                let outcome = parse_outcome(&resolve_output, &format!("{id}/resolve/output.json"));
                let resolve_cases = case_names
                    .into_iter()
                    .map(|name| {
                        let case_path = resolve_path.join(&name);
                        assert!(
                            case_path.join("input.json").is_file(),
                            "{id}: resolve/{name}/input.json is missing — every resolve case \
                             pairs an input with its expected output"
                        );
                        let ctx = format!("{id}/resolve/{name}/output.json");
                        let output = read_json_at(&case_path.join("output.json"), &ctx);
                        ResolveCase {
                            outcome: parse_outcome(&output, &ctx),
                            name,
                        }
                    })
                    .collect();

                let resolve_input = read_json_at(&resolve_path.join("input.json"), &id);
                let has_sidecar_genesis_document =
                    !resolve_input["resolutionOptions"]["sidecar"]["genesisDocument"].is_null();

                let other = read_json_at(&vector_path.join("other.json"), &id);
                let genesis_service_types: Vec<String> = other["genesisDocument"]["service"]
                    .as_array()
                    .map(|services| {
                        services
                            .iter()
                            .filter_map(|s| s["type"].as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let scenario_id = (!other["scenarioId"].is_null())
                    .then(|| field_str(&other, "scenarioId", &format!("{id}/other.json")))
                    .map(str::to_string);

                // Delivery comes from the files alone.
                let delivery = derive_delivery(
                    id_type,
                    matches!(outcome, Outcome::Error { .. }),
                    has_sidecar_genesis_document,
                    update_layout != UpdateLayout::None,
                    // An empty `updates` delivers nothing, so it is not a
                    // sidecar delivery; the capture tool's classification
                    // reads it the same way.
                    resolve_input["resolutionOptions"]["sidecar"]["updates"]
                        .as_array()
                        .is_some_and(|updates| !updates.is_empty()),
                );

                let signals_path = vector_path.join("signals.json");
                let signals = signals_path.is_file().then(|| {
                    let raw = std::fs::read_to_string(&signals_path).unwrap_or_else(|e| {
                        panic!("{id}: {} is unreadable: {e}", signals_path.display())
                    });
                    parse_signals(&raw, &format!("{id}/signals.json"), &update_layout)
                        .unwrap_or_else(|msg| panic!("{id}: {msg}"))
                });

                vectors.push(Vector {
                    id,
                    network_dir: network_dir.clone(),
                    kind: kind.clone(),
                    short_id,
                    id_type,
                    network,
                    corpus: corpus.clone(),
                    dir: vector_path,
                    update_layout,
                    outcome,
                    resolve_cases,
                    delivery,
                    genesis_service_types,
                    has_sidecar_genesis_document,
                    signals,
                    scenario_id,
                });
            }
        }
    }

    vectors.sort_by(|a, b| a.id.cmp(&b.id));
    check_cohorts(&vectors).unwrap_or_else(|msg| panic!("{msg}"));
    vectors
}

/// The six assertions the harness can make about an operation vector.
///
/// Accounting is per row rather than per vector: a vector whose derivation is
/// asserted but whose resolve cannot be driven offline must show up as one
/// driven row and one skipped row, not as a single "covered" vector. A row is
/// one (vector x kind) pair ([`RowKey::set`]), except for `ResolveOption`,
/// which has one row per numbered resolve case ([`RowKey::case`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum AssertionKind {
    /// `create/input.json` -> the encoded DID equals `create/output.json.did`.
    Derivation,
    /// `other.json.genesisKeys.secret` derives `genesisKeys.public` and the
    /// genesis key, and every update step signs with a declared secret that
    /// derives the key of the method its `verificationMethodId` names.
    GenesisKey,
    /// The resolver FSM resolves the vector to `resolve/output.json`.
    Resolve,
    /// Each update step's content-bound triple and BIP340 proof re-derive from
    /// its own inputs and verify against its source document.
    UpdateCrypto,
    /// Applying every update step in order to the genesis document reproduces
    /// `resolve/output.json.didDocument`.
    EndState,
    /// One resolve case under `resolve/NN/`, driven with that case's own
    /// options; `Resolve` stays the main `resolve/input.json`/`output.json`
    /// pair, so its count stays comparable across corpus revisions.
    ResolveOption,
}

impl AssertionKind {
    /// Every kind, in report order.
    pub(crate) const ALL: [AssertionKind; 6] = [
        Self::Derivation,
        Self::GenesisKey,
        Self::Resolve,
        Self::UpdateCrypto,
        Self::EndState,
        Self::ResolveOption,
    ];
}

impl fmt::Display for AssertionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Derivation => f.write_str("derivation"),
            Self::GenesisKey => f.write_str("genesis-key"),
            Self::Resolve => f.write_str("resolve"),
            Self::UpdateCrypto => f.write_str("update-crypto"),
            Self::EndState => f.write_str("end-state"),
            Self::ResolveOption => f.write_str("resolve-option"),
        }
    }
}

/// The ledger's unit of accounting: one row per (set, kind), except
/// [`AssertionKind::ResolveOption`], which has one row per `resolve/NN` case of
/// the set.
///
/// Drivers insert the key of every row they actually asserted against, and the
/// ledger derives the keys it expects; the two sets are compared per kind.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RowKey {
    /// The set's id, e.g. `"regtest/x1/qfaqdrxu"`.
    pub(crate) vector: String,
    /// The `resolve/NN` case name for a resolve-option row; `None` otherwise.
    pub(crate) case: Option<String>,
}

impl RowKey {
    /// The row of a set-level kind.
    pub(crate) fn set(vector: impl Into<String>) -> Self {
        Self {
            vector: vector.into(),
            case: None,
        }
    }

    /// The row of one `resolve/{case}` case of a set.
    pub(crate) fn case(vector: impl Into<String>, case: impl Into<String>) -> Self {
        Self {
            vector: vector.into(),
            case: Some(case.into()),
        }
    }
}

impl fmt::Display for RowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.case {
            None => f.write_str(&self.vector),
            Some(case) => write!(f, "{} resolve/{case}", self.vector),
        }
    }
}

/// Why a (vector x kind) row is not driven.
///
/// A skipped row carries EVERY applicable reason, not a first-match winner, so
/// each downstream body of work has a mechanically derivable target set: rows
/// carrying `UnsupportedBeaconType` are what the aggregation milestone unlocks
/// — the resolver refuses to issue a request for a CAS or SMT beacon at all —
/// and the `CasDelivery` / `SmtDelivery` rows are what an implemented
/// aggregated delivery unlocks.
///
/// "Past genesis" is no longer among these. A vector whose expected resolution
/// is version 2 or later is driven from a captured chain snapshot under
/// `fixtures/chain/`, so its beacon signals are replayed offline like any other
/// input.
///
/// There is deliberately no derived reason for "this vector is v2+ but its
/// chain data cannot be captured" any more. If a new v2+ Singleton
/// vector arrives whose beacon transactions are gone — a mutinynet reset, say —
/// it becomes a driven row with no fixture and `read_chain_fixture` panics. The
/// remedy is a `SKIP_OVERRIDES` entry with the reason stated, not resurrecting
/// a derived rule: an override is visible in the summary and
/// redundancy-checked, whereas a derived rule would silently re-skip every
/// future v2 vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum SkipReason {
    /// The vector's genesis document or delivery recipe uses CAS aggregation.
    CasDelivery,
    /// The vector's genesis document or delivery recipe uses SMT aggregation.
    SmtDelivery,
    /// The genesis document declares a beacon the resolver cannot query at all:
    /// building the next round of requests returns `Unsupported` on the first
    /// CAS or SMT beacon, before any transaction is read. Distinct from
    /// `CasDelivery`/`SmtDelivery`, which are about how the genesis document or
    /// an announcement is DELIVERED — a different problem fixed in different
    /// code. Both are recorded when both apply.
    UnsupportedBeaconType,
    /// The set's main `resolve/output.json` carries
    /// `didResolutionMetadata.error`. Applies to UpdateCrypto and EndState: the
    /// set is built to fail resolution, so its Resolve row asserts the error
    /// code and there is no expected end state to reproduce. Derivation and
    /// GenesisKey stay driven, because `create/` still holds a valid DID.
    ExpectedError,
    /// A one-off no derived rule expresses; the payload is the stated reason.
    Override(&'static str),
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CasDelivery => f.write_str("CAS-aggregated delivery not implemented"),
            Self::SmtDelivery => f.write_str("SMT-aggregated delivery not implemented"),
            Self::UnsupportedBeaconType => f.write_str(
                "resolver cannot query this beacon type (CAS/SMT beacon requests unimplemented)",
            ),
            Self::ExpectedError => f.write_str(
                "the set's expected result is an error; its Resolve row asserts the code",
            ),
            Self::Override(reason) => f.write_str(reason),
        }
    }
}

/// A hand-written skip for a row no derived rule can express — a malformed
/// upstream vector, or a known crate limitation. Each entry states a reason in
/// plain terms; the reason string is printed in the summary table.
///
/// An entry here does two things at once: it stops the matching driver from
/// asserting against the row (drivers gate on `Vector::should_drive`, which
/// consults these), and it stops the ledger from expecting that row to be
/// driven. Both sides must move together or the override would turn the suite
/// red instead of yielding a stated skip.
pub(crate) struct SkipOverride {
    /// The set's id, e.g. `"regtest/x1/qghp0w22"`.
    pub(crate) vector: &'static str,
    /// The assertion this entry suppresses.
    pub(crate) kind: AssertionKind,
    /// The `resolve/NN` case this entry suppresses, for a
    /// [`AssertionKind::ResolveOption`] entry; `None` for every other kind.
    /// An entry matches exactly one row, so a resolve-option entry without a
    /// case, or a set-level entry with one, matches nothing and is reported
    /// stale.
    pub(crate) case: Option<&'static str>,
    /// Why, in plain domain language.
    pub(crate) reason: &'static str,
}

/// Empty by design: every skipped row on disk today is covered by a derived
/// rule. An entry added here must match a discovered row or the
/// suite fails — additions cannot hide, and neither can removals.
pub(crate) const SKIP_OVERRIDES: &[SkipOverride] = &[];

/// The vectors whose `didDocumentMetadata.versionId` is a JSON number rather
/// than the ASCII string the specification requires.
///
/// Empty, and expected to stay so: the corpus encodes every `versionId` as a
/// string. Its guard, `live_vectors_record_their_version_id_encoding`, reads
/// the raw output files and fails if a number-encoded vector reappears, which
/// discovery would already refuse through [`metadata_version_id`].
pub(crate) const NUMBER_ENCODED_VERSION_ID: &[&str] = &[];

/// An error code a test vector records where the specification names a different one.
pub(crate) struct CodeDivergence {
    /// The code in the vector's `didResolutionMetadata.error`.
    pub(crate) vector_code: &'static str,
    /// The code the specification defines, which the resolver emits.
    pub(crate) spec_code: &'static str,
    /// The upstream issue or pull request that tracks reconciling the two.
    pub(crate) issue: &'static str,
}

/// The error codes where a vector and the specification disagree, each with
/// the upstream thread tracking the reconciliation.
///
/// Pinned in BOTH directions:
/// - a negative row whose emitted code differs from its vector's code and is
///   not listed here fails as a NEW divergence, instead of being absorbed;
/// - a listed entry that no driven negative case uses fails too
///   ([`unused_divergences`]), telling the reader to delete the entry.
///
/// A listed row stays DRIVEN and asserts that the resolver emits the
/// specification's code ([`expected_emitted_code`]). This is not a skip:
/// `SKIP_OVERRIDES` must never be used for code drift, because a skipped row
/// asserts nothing and a later regression in the emitted code would pass.
///
/// The test suite records the late-publishing error under the code
/// `LATE_PUBLISHING_ERROR`, where the specification names it `LATE_PUBLISHING`.
/// Once the suite is regenerated with the specification's code, no driven row
/// records `LATE_PUBLISHING_ERROR` any more and [`unused_divergences`] fails,
/// telling the reader to drop the entry.
pub(crate) const ERROR_CODE_DIVERGENCES: &[CodeDivergence] = &[CodeDivergence {
    vector_code: "LATE_PUBLISHING_ERROR",
    spec_code: "LATE_PUBLISHING",
    issue: "dcdpr/did-btcr2-js#204",
}];

/// The code the resolver must emit for a row whose vector records
/// `vector_code`: the specification's code when the pair is listed in
/// `divergences`, the vector's own code otherwise.
pub(crate) fn expected_emitted_code<'a>(
    vector_code: &'a str,
    divergences: &'a [CodeDivergence],
) -> &'a str {
    divergences
        .iter()
        .find(|d| d.vector_code == vector_code)
        .map_or(vector_code, |d| d.spec_code)
}

/// Divergence entries no driven negative row uses.
///
/// A use is a row the drive gate admits — a set's main resolve pair or one of
/// its `resolve/NN` cases — whose expected outcome is an error with the
/// entry's `vector_code`. A matching row that is skipped does not count: it
/// asserts nothing, so it cannot justify keeping the entry.
pub(crate) fn unused_divergences(
    vectors: &[Vector],
    overrides: &[SkipOverride],
    divergences: &[CodeDivergence],
) -> Vec<String> {
    let records = |outcome: &Outcome, code: &str| matches!(outcome, Outcome::Error { code: recorded } if recorded == code);
    divergences
        .iter()
        .filter(|d| {
            !vectors.iter().any(|v| {
                let main = v.should_drive_row_with(AssertionKind::Resolve, None, overrides)
                    && records(&v.outcome, d.vector_code);
                let case = v.resolve_cases.iter().any(|c| {
                    v.should_drive_row_with(AssertionKind::ResolveOption, Some(&c.name), overrides)
                        && records(&c.outcome, d.vector_code)
                });
                main || case
            })
        })
        .map(|d| {
            format!(
                "  {} -> {} ({}) — no driven negative case records this code; delete the entry",
                d.vector_code, d.spec_code, d.issue
            )
        })
        .collect()
}

/// Divergence entries that cannot be right on their face: a vector code equal
/// to its specification code (no divergence at all), and a vector code listed
/// more than once (two answers for one code).
pub(crate) fn malformed_divergences(divergences: &[CodeDivergence]) -> Vec<String> {
    let mut rows = Vec::new();
    for d in divergences {
        if d.vector_code == d.spec_code {
            rows.push(format!(
                "  {} -> {} ({}) — the vector and specification codes are equal; this is not a \
                 divergence, delete the entry",
                d.vector_code, d.spec_code, d.issue
            ));
        }
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for d in divergences {
        *counts.entry(d.vector_code).or_default() += 1;
    }
    for (code, count) in counts {
        if count > 1 {
            rows.push(format!(
                "  {code} is listed {count} times — keep one entry per vector code"
            ));
        }
    }
    rows
}

/// The number of rows each assertion kind must drive, at minimum.
///
/// A coverage ratchet, not a census: `reconcile_driven_with` passes trivially
/// when both the expected and the observed set are empty, so upstream churn
/// that made every row of a kind skipped-with-a-reason would zero that kind's
/// coverage without failing anything — only the stderr summary would change.
/// Resolve is the live exposure: its rows depend on fixture properties outside
/// this repository (for an external vector, the presence of
/// `resolve/input.json.resolutionOptions.sidecar.genesisDocument`) AND, for
/// past-genesis rows, on captured chain fixtures inside it. Either kind of
/// loss — an upstream vector losing its sidecar genesis document, or a deleted
/// capture — must fail here rather than shrink coverage quietly.
///
/// The counts are the rows the regenerated corpus drives on its four networks
/// (regtest, mutinynet, signet and testnet4). Resolve counts both genesis-era
/// sets, which resolve without a chain, and past-genesis sets, which replay
/// their captured snapshot from `fixtures/chain/`; ResolveOption counts the
/// `resolve/NN` cases.
///
/// Compared with `>=`, so upstream ADDING vectors raises coverage without
/// failing; only silent coverage LOSS fails.
///
/// Evaluated against `expected_driven_with(kind, vectors, &[])` and never
/// against the live override table: a legitimate hand-written skip would
/// otherwise trip the ratchet, which is the very failure mode that makes the
/// escape hatch unusable.
pub(crate) const DRIVEN_FLOOR: &[(AssertionKind, usize)] = &[
    (AssertionKind::Derivation, 236),
    (AssertionKind::GenesisKey, 236),
    (AssertionKind::Resolve, 164),
    (AssertionKind::UpdateCrypto, 108),
    (AssertionKind::EndState, 108),
    (AssertionKind::ResolveOption, 53),
];

/// Derive the reasons a vector's `resolve` row cannot be driven, from the
/// vector's own files.
///
/// Two rules, both additive — a row keeps every reason that applies:
/// 1. a `CASBeacon` / `SMTBeacon` service in the genesis document
///    -> `CasDelivery` / `SmtDelivery`, AND `UnsupportedBeaconType`
/// 2. the derived genesis or announcement delivery is CAS -> `CasDelivery`
///
/// Rule 2 reads the delivery [`derive_delivery`] reads off the files (an
/// external set with no sidecar genesis document; update steps with no sidecar
/// updates). It is what accounts for a set whose genesis document is
/// CAS-delivered while it carries no beacon-type signal at all (an empty
/// `service` array).
///
/// Rule 1 applies to every set, negative sets included, and is what makes the
/// aggregation milestone's target set mechanically derivable: a CAS or SMT
/// beacon in the genesis document blocks resolve twice over — the delivery
/// mechanism is unimplemented, and the resolver refuses to issue a request for
/// that beacon type at all — and those are fixed in different code. Rows
/// carrying `UnsupportedBeaconType` are the ones that stay skipped now that
/// every anchored update can be replayed off a captured chain.
///
/// The expected `versionId` is deliberately NOT read. A past-genesis vector is
/// driven from its captured chain snapshot, so "past genesis" is no longer a
/// reason to skip; see [`SkipReason`] for the escape route a v2+ vector whose
/// chain data cannot be captured takes instead.
pub(crate) fn derived_resolve_skip_reasons(
    delivery: &Delivery,
    genesis_service_types: &[String],
) -> BTreeSet<SkipReason> {
    let mut reasons = BTreeSet::new();

    // Rule 1: the genesis document's beacon services, by their wire strings.
    // A CAS or SMT beacon blocks resolve TWICE over: the delivery mechanism is
    // unimplemented, AND the resolver refuses to issue a request for that beacon
    // type at all. Recording both keeps each downstream target set precise.
    for service_type in genesis_service_types {
        match service_type.as_str() {
            "CASBeacon" => {
                reasons.insert(SkipReason::CasDelivery);
                reasons.insert(SkipReason::UnsupportedBeaconType);
            }
            "SMTBeacon" => {
                reasons.insert(SkipReason::SmtDelivery);
                reasons.insert(SkipReason::UnsupportedBeaconType);
            }
            // `SingletonBeacon` is drivable, and a non-beacon service
            // (DIDComm, a web node) says nothing about delivery OR about
            // whether the resolver can query a beacon.
            _ => {}
        }
    }

    // Rule 2: a CAS delivery the files show.
    if delivery.genesis == GenesisDelivery::Cas
        || delivery.announcement == Some(AnnouncementDelivery::Cas)
    {
        reasons.insert(SkipReason::CasDelivery);
    }

    reasons
}

impl Vector {
    /// The kinds this vector has files for. `UpdateCrypto` and `EndState` exist
    /// only for update-bearing vectors, `ResolveOption` only for a set with at
    /// least one `resolve/NN` case; the other three exist for every vector.
    pub(crate) fn applicable_kinds(&self) -> Vec<AssertionKind> {
        AssertionKind::ALL
            .into_iter()
            .filter(|kind| match kind {
                AssertionKind::Derivation | AssertionKind::GenesisKey | AssertionKind::Resolve => {
                    true
                }
                AssertionKind::UpdateCrypto | AssertionKind::EndState => {
                    self.update_layout != UpdateLayout::None
                }
                AssertionKind::ResolveOption => !self.resolve_cases.is_empty(),
            })
            .collect()
    }

    /// This vector's rows of `kind`: none when the kind does not apply, one
    /// per `resolve/NN` case (in case order) for `ResolveOption`, and the one
    /// set-level row otherwise.
    pub(crate) fn rows(&self, kind: AssertionKind) -> Vec<RowKey> {
        if !self.applicable_kinds().contains(&kind) {
            return Vec::new();
        }
        match kind {
            AssertionKind::ResolveOption => self
                .resolve_cases
                .iter()
                .map(|case| RowKey::case(self.id.as_str(), case.name.as_str()))
                .collect(),
            _ => vec![RowKey::set(self.id.as_str())],
        }
    }

    /// Whether the harness can actually assert this kind against this vector,
    /// judged from the inputs the driver dereferences.
    ///
    /// Deliberately independent of `skip_reasons`: if drivability were defined
    /// as "no reason applies", a row could never be unclassified and the
    /// invariant would be vacuous. A row that is not drivable and carries no
    /// reason is the failure the suite exists to raise.
    pub(crate) fn is_drivable(&self, kind: AssertionKind) -> bool {
        match kind {
            AssertionKind::Derivation | AssertionKind::GenesisKey => true,
            // The resolve driver needs a genesis source and, past genesis, a
            // captured chain fixture to feed the beacon signals from. A
            // resolve case resolves the same set with other options, so it
            // needs exactly the same inputs.
            //
            // For an external vector the genesis source is
            // `resolve/input.json.resolutionOptions.sidecar.genesisDocument`;
            // reading `other.json.genesisDocument` instead would hand the
            // resolver a document the vector intends to be fetched from CAS,
            // asserting resolve logic while bypassing the delivery mechanism
            // and leaving no row marking the gap.
            //
            // A NEGATIVE set needs no genesis source: it asserts an error,
            // and a withheld genesis document is itself one (the resolver
            // answers `NOT_FOUND` without it). This is the precedence
            // `derive_delivery` applies — an expected error is read before
            // any file-shape CAS inference — so such a set carries no CAS
            // reason and must be driven, not left unclassified.
            //
            // The captured fixture is NOT a drivability condition. Every
            // anchored past-genesis vector on disk has one, and an absent
            // capture for a row this says is drivable is a bug that
            // `read_chain_fixture` raises by name — not a reason to quietly
            // drop the row.
            AssertionKind::Resolve | AssertionKind::ResolveOption => {
                self.is_negative()
                    || self.id_type != VectorIdType::External
                    || self.has_sidecar_genesis_document
            }
            AssertionKind::UpdateCrypto | AssertionKind::EndState => {
                self.update_layout != UpdateLayout::None
            }
        }
    }

    /// Every reason this set-level row is skipped. Empty means the row is
    /// expected to be driven. The `case: None` form of
    /// [`Vector::row_skip_reasons`].
    ///
    /// The override table is always explicit. There is deliberately no
    /// live-table convenience wrapper: one existed, most call sites used it out
    /// of habit, and a single hand-written skip then broke tests that had
    /// nothing to do with the override — the escape hatch turned the suite red
    /// exactly when it was needed. Callers that mean the live table name
    /// `SKIP_OVERRIDES`; everything reasoning about the derived rules alone
    /// passes `&[]`.
    ///
    /// The slice is borrowed for any lifetime, not `'static`. Only
    /// `SkipReason::Override` needs a `'static` string, and that comes from the
    /// `SkipOverride::reason` FIELD type; requiring it of the slice as well
    /// would force every caller through a `const` and block building a table at
    /// runtime.
    pub(crate) fn skip_reasons_with(
        &self,
        kind: AssertionKind,
        overrides: &[SkipOverride],
    ) -> BTreeSet<SkipReason> {
        self.row_skip_reasons(kind, None, overrides)
    }

    /// Every reason one row is skipped: the set-level row when `case` is
    /// `None`, the `resolve/{case}` row of `ResolveOption` otherwise. Empty
    /// means the row is expected to be driven.
    ///
    /// Derived reasons by kind:
    /// - `Resolve` and `ResolveOption`: the delivery, anchoring and beacon
    ///   rules of [`derived_resolve_skip_reasons`]. A
    ///   resolve case inherits exactly its set's reasons: a case of a
    ///   CAS-delivered set is as undeliverable as the main pair.
    /// - `UpdateCrypto` and `EndState`: `ExpectedError` when the set's main
    ///   resolve pair expects an error. The delivery reasons say nothing about
    ///   whether a patch sequence reproduces a document, so a CAS-delivered
    ///   set still drives both.
    /// - `Derivation` and `GenesisKey`: none.
    ///
    /// An override applies when it names this set, this kind and this case.
    pub(crate) fn row_skip_reasons(
        &self,
        kind: AssertionKind,
        case: Option<&str>,
        overrides: &[SkipOverride],
    ) -> BTreeSet<SkipReason> {
        let mut reasons = BTreeSet::new();
        match kind {
            AssertionKind::Resolve | AssertionKind::ResolveOption => {
                reasons.extend(derived_resolve_skip_reasons(
                    &self.delivery,
                    &self.genesis_service_types,
                ));
            }
            AssertionKind::UpdateCrypto | AssertionKind::EndState => {
                if self.is_negative() {
                    reasons.insert(SkipReason::ExpectedError);
                }
            }
            AssertionKind::Derivation | AssertionKind::GenesisKey => {}
        }

        for entry in overrides {
            if entry.vector == self.id && entry.kind == kind && entry.case == case {
                reasons.insert(SkipReason::Override(entry.reason));
            }
        }

        reasons
    }

    /// Whether a driver for `kind` should assert against this vector's
    /// set-level row. The `case: None` form of [`Vector::should_drive_row_with`].
    pub(crate) fn should_drive_with(
        &self,
        kind: AssertionKind,
        overrides: &[SkipOverride],
    ) -> bool {
        self.should_drive_row_with(kind, None, overrides)
    }

    /// Whether a driver for `kind` should assert against one row of this
    /// vector (`case` names the `resolve/NN` case of a resolve-option row).
    ///
    /// The conjunction of "the harness structurally can" and "nothing says not
    /// to". Every driver loop gates on exactly this, and `expected_driven`
    /// filters on exactly this, so the two sides of the reconciliation cannot
    /// disagree about what a hand-written skip means. Without the second half,
    /// a skip entry on a structurally-drivable kind would leave the driver
    /// still asserting against the row and then fail reconciliation as "driven
    /// but not expected" — the escape hatch would turn the suite red exactly
    /// when it is needed.
    ///
    /// This does NOT weaken the observed-not-declared property. `observed` is
    /// still accumulated from what each loop actually asserted, so a `continue`
    /// or an early return *inside* a loop body — the silent-coverage-loss
    /// failure the reconciliation exists to catch — still fails
    /// `reconcile_driven`. Do not "restore" a gate on `is_drivable` alone.
    ///
    /// Takes the override table explicitly so a driver and the ledger can both
    /// be exercised against a synthetic table while the live one is empty.
    pub(crate) fn should_drive_row_with(
        &self,
        kind: AssertionKind,
        case: Option<&str>,
        overrides: &[SkipOverride],
    ) -> bool {
        self.is_drivable(kind) && self.row_skip_reasons(kind, case, overrides).is_empty()
    }
}

/// The rows the ledger expects a driver for `kind` to have asserted against:
/// every row of `kind` that `should_drive_row_with` admits under the given
/// override table.
pub(crate) fn expected_driven_with(
    kind: AssertionKind,
    vectors: &[Vector],
    overrides: &[SkipOverride],
) -> BTreeSet<RowKey> {
    vectors
        .iter()
        .flat_map(|v| {
            v.rows(kind)
                .into_iter()
                .filter(move |row| v.should_drive_row_with(kind, row.case.as_deref(), overrides))
        })
        .collect()
}

/// Assert that a driver's observed set equals the ledger's expected set for its
/// own kind.
///
/// "Driven" is observed, not declared: the caller passes the rows it actually
/// asserted against. A driver that skipped a row the ledger expects it to drive
/// fails here, as does a driver that asserted against a row the ledger has
/// classified as skipped.
///
/// Sharing `should_drive_row_with` with the driver loop gates does not make
/// this vacuous. The gate runs once per row at the top of the loop; `observed`
/// is filled at the bottom, after the assertions. Any early exit in between — a
/// `continue`, a `?`, a conditional that quietly walks past a step — leaves the
/// row out of `observed` and fails here.
///
/// The override table must match the one the driver gated on, or the two tell
/// different stories about the same run.
pub(crate) fn reconcile_driven_with(
    kind: AssertionKind,
    vectors: &[Vector],
    observed: &BTreeSet<RowKey>,
    overrides: &[SkipOverride],
) {
    let expected = expected_driven_with(kind, vectors, overrides);
    let missing: Vec<String> = expected
        .difference(observed)
        .map(RowKey::to_string)
        .collect();
    let extra: Vec<String> = observed
        .difference(&expected)
        .map(RowKey::to_string)
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{kind} coverage diverged from the vector ledger.\n  \
         expected but not driven ({}): {:?}\n  \
         driven but not expected ({}): {:?}\n  \
         Drive the missing rows, or give them a skip reason.",
        missing.len(),
        missing,
        extra.len(),
        extra,
    );
}

/// Rows that are neither drivable nor skipped-with-a-reason.
///
/// This is the invariant's whole point: a vector directory that appears
/// upstream and that the harness cannot assert anything about must force an
/// explicit decision rather than passing green unexercised.
///
/// Scope, so this is not over-trusted as a six-kind guard: `is_drivable` is
/// unconditionally `true` for `Derivation` and `GenesisKey`, and is exactly
/// "the vector has an `update/` directory" for `UpdateCrypto` and `EndState` —
/// which is also what makes those kinds applicable at all. So only a `Resolve`
/// or `ResolveOption` row can currently reach this report, and only in the
/// narrow shape "external id type, no sidecar genesis document, and no derived
/// reason". Derived reasons now reach Resolve, ResolveOption, UpdateCrypto and
/// EndState, but only the two resolve kinds have a conditional drivability
/// rule. A new *operation* arriving upstream is caught by
/// `classify_operation_dirs`, not here. Widen this report if a future kind
/// gains a conditional drivability rule.
///
/// Deliberately reads `is_drivable`, not the combined drive gate: a row with a
/// reason is classified, and a row without one that the harness cannot drive is
/// the failure. The combined gate would collapse both cases and make the report
/// vacuous.
pub(crate) fn unclassified_rows_with(
    vectors: &[Vector],
    overrides: &[SkipOverride],
) -> Vec<String> {
    let mut rows = Vec::new();
    for v in vectors {
        for kind in v.applicable_kinds() {
            for row in v.rows(kind) {
                if !v.is_drivable(kind)
                    && v.row_skip_reasons(kind, row.case.as_deref(), overrides)
                        .is_empty()
                {
                    rows.push(format!(
                        "  {row} :: {kind} — classify it: drive it, add a derived skip rule, \
                         or add a SKIP_OVERRIDES entry with a reason"
                    ));
                }
            }
        }
    }
    rows
}

/// Overrides that match no discovered row.
///
/// The symmetric half of the set invariant: additions to the test suite cannot
/// hide behind an unexercised harness, and removals cannot hide behind a skip
/// entry nobody deleted. An entry matches when a discovered set has a row of
/// its kind with its case, so a resolve-option entry naming a case the set
/// does not ship is stale.
pub(crate) fn stale_overrides(overrides: &[SkipOverride], vectors: &[Vector]) -> Vec<String> {
    overrides
        .iter()
        .filter(|o| {
            let key = RowKey {
                vector: o.vector.to_string(),
                case: o.case.map(str::to_string),
            };
            !vectors
                .iter()
                .any(|v| v.id == o.vector && v.rows(o.kind).contains(&key))
        })
        .map(|o| {
            let key = RowKey {
                vector: o.vector.to_string(),
                case: o.case.map(str::to_string),
            };
            format!(
                "  {key} :: {} — stale SKIP override: the vector, the case or the assertion no \
                 longer exists; delete the entry",
                o.kind
            )
        })
        .collect()
}

/// Hand-written skips that a derived rule already covers.
///
/// The genuinely contradictory state, and the only one worth asserting over: a
/// row that a named rule already skips for a stated reason does not also need a
/// hand-written entry, and the entry will outlive the rule that made it
/// redundant. A hand-written skip on a row with no derived reason is not
/// contradictory — it is exactly what the escape hatch is for, and the drive
/// gate is a conjunction precisely so that such a row yields a stated skip
/// rather than a reconciliation failure.
///
/// Scope: derived reasons now reach Resolve, ResolveOption (the delivery,
/// anchoring, beacon and stale-context rules), and UpdateCrypto and EndState
/// (`ExpectedError` on a negative set). `Derivation` and `GenesisKey` carry no
/// derived reason, so the loop `continue`s for those rows unconditionally.
pub(crate) fn redundant_overrides(vectors: &[Vector], overrides: &[SkipOverride]) -> Vec<String> {
    let mut rows = Vec::new();
    for v in vectors {
        for kind in v.applicable_kinds() {
            for row in v.rows(kind) {
                let case = row.case.as_deref();
                let derived = v.row_skip_reasons(kind, case, &[]);
                if derived.is_empty() {
                    continue;
                }
                let redundant: Vec<SkipReason> = v
                    .row_skip_reasons(kind, case, overrides)
                    .into_iter()
                    .filter(|reason| matches!(reason, SkipReason::Override(_)))
                    .collect();
                if !redundant.is_empty() {
                    rows.push(format!(
                        "  {row} :: {kind} — hand-written skip {redundant:?} is redundant: a \
                         derived rule already skips this row for {derived:?}; delete the entry"
                    ));
                }
            }
        }
    }
    rows
}

/// A compact coverage table for stderr.
///
/// Answers "what does this suite actually check?" without reading the
/// classification code. A row may carry several reasons, so the reason counts
/// sum past the skipped-row total.
///
/// The driven column counts the rows the drive gate admits and the skipped
/// column the applicable rows it does not — the same split `expected_driven_with`
/// makes, so the table and the reconciliation can never tell different stories.
/// Every count is computed from the discovered set; none is written down.
///
/// The override table is explicit for the same reason it is everywhere else in
/// this module: a helper that silently reads `SKIP_OVERRIDES` makes every caller
/// depend on the live table's contents, which is what made the escape hatch
/// unusable in an earlier revision.
pub(crate) fn render_summary_with(vectors: &[Vector], overrides: &[SkipOverride]) -> String {
    let mut total_rows = 0usize;
    let mut per_kind: Vec<(AssertionKind, usize, usize)> = Vec::new();
    let mut by_reason: BTreeMap<SkipReason, usize> = BTreeMap::new();

    for kind in AssertionKind::ALL {
        let (mut driven, mut skipped) = (0usize, 0usize);
        for v in vectors {
            for row in v.rows(kind) {
                let case = row.case.as_deref();
                total_rows += 1;
                if v.should_drive_row_with(kind, case, overrides) {
                    driven += 1;
                } else {
                    skipped += 1;
                    for reason in v.row_skip_reasons(kind, case, overrides) {
                        *by_reason.entry(reason).or_default() += 1;
                    }
                }
            }
        }
        per_kind.push((kind, driven, skipped));
    }

    let mut out = format!(
        "operation-vector coverage: {} vectors, {total_rows} rows\n",
        vectors.len()
    );
    out.push_str(&format!(
        "  {:<14}{:>8}{:>9}\n",
        "kind", "driven", "skipped"
    ));
    for (kind, driven, skipped) in per_kind {
        out.push_str(&format!(
            "  {:<14}{driven:>8}{skipped:>9}\n",
            kind.to_string()
        ));
    }

    out.push_str("  skipped rows by reason (a row may carry several):\n");
    let width = by_reason
        .keys()
        .map(|reason| reason.to_string().len())
        .max()
        .unwrap_or(0);
    for (reason, count) in by_reason {
        out.push_str(&format!("    {:<width$}{count:>5}\n", reason.to_string()));
    }

    out
}

/// A scenario this project minted onto a chain of its own, driven from an
/// in-repo fixture rather than from the vendor conformance suite.
pub(crate) struct MintedScenario {
    /// Fixture id under `fixtures/chain/`.
    pub(crate) fixture: &'static str,
    /// The test that drives it.
    pub(crate) test: &'static str,
    /// What it covers that no upstream vector can.
    pub(crate) covers: &'static [&'static str],
}

/// The minted scenarios, written down for the same reason
/// [`ALL_CHAIN_FIXTURES`] is: a scenario that stopped being driven would
/// otherwise just stop appearing.
pub(crate) const MINTED_SCENARIOS: &[MintedScenario] = &[
    MintedScenario {
        fixture: "minted/clean-rotating-beacons",
        test: "minted_chain_sequences_updates_across_rotating_beacons",
        covers: &[
            "multi-update sequencing across rotating beacons",
            "an update announced from a beacon an earlier update added, scanned mid-walk",
            "on-chain deactivation short-circuit",
            "mid-walk version bounds on a four-version chain",
        ],
    },
    MintedScenario {
        fixture: "minted/late-publishing-fork",
        test: "minted_fork_raises_late_publishing",
        covers: &["late publishing detected against a real on-chain fork"],
    },
];

/// The minted scenarios' coverage, as a section of its own.
///
/// Deliberately NOT folded into [`render_summary_with`]: the vector ledger
/// answers exactly one question — what of the UPSTREAM conformance suite does
/// this crate exercise — so fixtures we authored must not inflate that number.
/// They are still the most interesting coverage in the suite (the only real
/// multi-update chain, the only on-chain deactivation, the only real
/// late-publishing fork), so they get a section rather than a footnote.
///
/// The recording network is READ from each fixture, so this section says which
/// chain the data currently comes from without anything here naming one.
pub(crate) fn render_minted_summary() -> String {
    let mut out = format!(
        "minted-scenario coverage: {} scenario(s) driven from in-repo fixtures \
         (NOT counted in the upstream ledger above)\n",
        MINTED_SCENARIOS.len()
    );
    for scenario in MINTED_SCENARIOS {
        let fixture = read_chain_fixture(scenario.fixture);
        out.push_str(&format!(
            "  {} (minted on {})\n    driven by {}\n",
            scenario.fixture, fixture.network, scenario.test
        ));
        for covers in scenario.covers {
            out.push_str(&format!("    covers: {covers}\n"));
        }
    }
    out.push_str(
        "  this coverage is fixture-driven: no live-network test ships in this crate. A real \
         chain is contacted by the capture tool's own validation, and the CLI runbook covers \
         live end-to-end resolve interactively.\n",
    );
    out
}

/// Every listed scenario's fixture is on disk and says what it is for. An entry
/// whose `covers` was left empty would render a scenario that claims nothing.
#[test]
fn minted_scenarios_name_a_present_fixture_and_its_coverage() {
    assert!(
        !MINTED_SCENARIOS.is_empty(),
        "the minted section must describe at least one scenario"
    );
    for scenario in MINTED_SCENARIOS {
        let path = chain_fixture_path(scenario.fixture);
        assert!(
            path.is_file(),
            "{}: the minted scenario's fixture must be present at {}",
            scenario.fixture,
            path.display()
        );
        assert!(
            !scenario.covers.is_empty(),
            "{}: a minted scenario must say what it covers that no upstream vector can",
            scenario.fixture
        );
        assert!(
            ALL_CHAIN_FIXTURES.contains(&scenario.fixture),
            "{}: a minted scenario's fixture must also be listed in ALL_CHAIN_FIXTURES, or a \
             deletion would only fail in one of the two places",
            scenario.fixture
        );
    }
}

/// The rendered section names every scenario, the test that drives it, and each
/// coverage claim — a section that summarized them away would leave the reader
/// no better off than the count it replaced.
#[test]
fn minted_summary_names_every_scenario_its_test_and_its_coverage() {
    let summary = render_minted_summary();
    for scenario in MINTED_SCENARIOS {
        assert!(
            summary.contains(scenario.fixture),
            "{} must appear in the minted section:\n{summary}",
            scenario.fixture
        );
        assert!(
            summary.contains(scenario.test),
            "{} must appear in the minted section:\n{summary}",
            scenario.test
        );
        for covers in scenario.covers {
            assert!(
                summary.contains(covers),
                "`{covers}` must appear in the minted section:\n{summary}"
            );
        }
        // The chain the fixture records, read from the fixture.
        let fixture = read_chain_fixture(scenario.fixture);
        assert!(
            summary.contains(&fixture.network),
            "{}: the minted section must name the chain the fixture was minted on:\n{summary}",
            scenario.fixture
        );
    }
    assert!(
        summary.contains("no live-network test ships"),
        "the minted section must say where a real chain IS contacted:\n{summary}"
    );
}

/// The upstream ledger and the minted section cannot blur. A fixture this
/// project authored must never appear in the count that answers "how much of the
/// VENDOR suite do we exercise".
#[test]
fn ledger_summary_never_mentions_a_minted_scenario() {
    let summary = render_summary_with(&synthetic_ledger(), &[]);
    assert!(
        !summary.contains("minted"),
        "the upstream ledger summary must not mention minted coverage:\n{summary}"
    );
    for scenario in MINTED_SCENARIOS {
        assert!(
            !summary.contains(scenario.fixture),
            "{} must not appear in the upstream ledger summary:\n{summary}",
            scenario.fixture
        );
    }
}

/// `read_fixture_or_skip` must NOT no-op silently when the submodule
/// is present but a specific fixture is missing — that path must panic, so a
/// partial checkout (or an upstream rename of one vector) fails the suite
/// rather than skipping every later vector and passing vacuously.
///
/// This test only asserts the panic when the submodule is actually checked
/// out (the normal CI / dev state); on a non-recursive clone the helper is
/// expected to skip, so the test skips too — matching the skip contract for
/// the surrounding op-vector tests.
#[test]
fn missing_fixture_under_checked_out_submodule_panics() {
    if !test_suite_checked_out() {
        eprintln!("SKIP: test-suite submodule absent; panic path not exercised");
        return;
    }
    // A path that cannot exist under a checked-out submodule.
    let result = std::panic::catch_unwind(|| {
        read_fixture_or_skip("regtest/k1/__nonexistent_vector__/create/input.json")
    });
    assert!(
        result.is_err(),
        "a missing fixture under a checked-out submodule must panic, not return None"
    );
}

/// Every network directory name the test-suite ships (or plausibly will) maps
/// onto the `Network` the crate models.
#[test]
fn network_from_dir_maps_known_directories() {
    let ctx = "the network map test";
    assert_eq!(network_from_dir("mainnet", ctx), Network::Mainnet);
    assert_eq!(network_from_dir("signet", ctx), Network::Signet);
    assert_eq!(network_from_dir("regtest", ctx), Network::Regtest);
    assert_eq!(network_from_dir("mutinynet", ctx), Network::Mutinynet);
    assert_eq!(network_from_dir("testnet3", ctx), Network::TestnetV3);
    assert_eq!(network_from_dir("testnet4", ctx), Network::TestnetV4);
}

/// An unknown network fails loud rather than being silently mapped or skipped —
/// a new upstream network must be a deliberate code change — and the message
/// names WHERE the offending value came from, because the same map reads both a
/// directory segment and a `create/input.json.network` field.
#[test]
fn network_from_dir_rejects_unknown_and_names_its_context() {
    let payload = std::panic::catch_unwind(|| {
        network_from_dir("dogecoin", "regtest/k1/qgpakaw4/create/input.json.network")
    })
    .expect_err("an unknown network must panic, not resolve to a default network");
    let message = panic_message(payload);
    assert!(
        message.contains("dogecoin")
            && message.contains("regtest/k1/qgpakaw4/create/input.json.network"),
        "the message names the value and the source that supplied it: {message}"
    );
}

/// The two id-type vocabularies — the `<kind>/` directory segment and
/// `create/input.json.idType` — both map onto the same enum, and an unknown
/// value on either side is a deliberate code change rather than a silent
/// reclassification as key-based.
#[test]
fn id_type_maps_both_vocabularies_and_rejects_unknown() {
    assert_eq!(id_type_from_kind("k1"), VectorIdType::Key);
    assert_eq!(id_type_from_kind("x1"), VectorIdType::External);
    assert_eq!(id_type_from_create_input("KEY", "ctx"), VectorIdType::Key);
    assert_eq!(
        id_type_from_create_input("EXTERNAL", "ctx"),
        VectorIdType::External
    );

    let payload = std::panic::catch_unwind(|| id_type_from_kind("ext"))
        .expect_err("an unknown id-type directory must panic");
    assert!(
        panic_message(payload).contains("ext"),
        "the message names the offending directory segment"
    );

    let payload = std::panic::catch_unwind(|| id_type_from_create_input("HYBRID", "ctx"))
        .expect_err("an unknown create/input.json.idType must panic");
    assert!(
        panic_message(payload).contains("HYBRID"),
        "the message names the offending wire string"
    );
}

/// The in-repository copy of the k1 resolved document is the document the
/// helper tests expect, read with no dependence on the submodule.
#[test]
fn read_vendor_copy_reads_the_in_repo_k1_document() {
    let output = read_vendor_copy("regtest/k1/qgpakaw4/resolve/output.json");
    assert_eq!(
        output["didDocument"]["id"],
        "did:btcr2:k1qgpakaw4lwemekywf0lyth9hf6j8r2td7gqtrs4aztqfky50jnx7s8gfapup6"
    );
}

/// An absent copy panics naming the full path and why that is a bug, rather
/// than skipping.
#[test]
fn read_vendor_copy_panics_on_a_missing_copy() {
    let rel = "regtest/k1/qnotthere/resolve/output.json";
    let payload = std::panic::catch_unwind(|| read_vendor_copy(rel))
        .expect_err("an absent vendor copy must panic");
    let message = panic_message(payload);
    let full = vendor_copy_root().join(rel);
    assert!(
        message.contains(&full.display().to_string()),
        "the message names the full path: {message}"
    );
    assert!(
        message.contains("in this repository"),
        "the message says the copies are in-repo: {message}"
    );
}

/// A copy that is not JSON panics naming its path.
#[test]
fn read_vendor_copy_panics_on_invalid_json() {
    let dir = std::env::temp_dir().join(format!("vendor-copy-bad-json-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("bad.json"), "{ not json").unwrap();
    let payload = std::panic::catch_unwind(|| read_vendor_copy_in(&dir, "bad.json"))
        .expect_err("a copy that is not JSON must panic");
    let message = panic_message(payload);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        message.contains("bad.json") && message.contains("is not JSON"),
        "the message names the file: {message}"
    );
}

/// The panic payload of a `catch_unwind`, as a string.
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_default()
}

/// The field readers name the vector AND the JSON path, so a malformed fixture
/// says which of twenty-odd vectors is at fault instead of reporting
/// `called Option::unwrap() on a None value` at a line number.
#[test]
fn field_readers_name_the_vector_and_the_path() {
    let value = serde_json::json!({
        "genesisKeys": { "secret": "0a0b", "public": 7 },
        "signedUpdate": {
            "targetVersionId": 2,
            "stringVersionId": "2",
            "zeroVersionId": 0,
        },
        "deactivated": true,
    });

    assert_eq!(field_str(&value, "genesisKeys.secret", "ctx"), "0a0b");
    assert_eq!(field_hex(&value, "genesisKeys.secret", "ctx"), vec![10, 11]);
    assert_eq!(field_u64(&value, "genesisKeys.public", "ctx"), 7);
    assert!(field_bool(&value, "deactivated", "ctx"));
    assert_eq!(
        field_version_id(&value, "signedUpdate.targetVersionId", "ctx"),
        2
    );
    assert_eq!(
        field_nonzero_version_id(&value, "signedUpdate.targetVersionId", "ctx").get(),
        2
    );

    // A wrong type, an absent path, a zero version number and a
    // string-encoded version number each name themselves.
    let cases: [(&str, &dyn Fn()); 5] = [
        ("genesisKeys.public", &|| {
            field_str(&value, "genesisKeys.public", "regtest/k1/qgpakaw4");
        }),
        ("genesisKeys.absent", &|| {
            field_str(&value, "genesisKeys.absent", "regtest/k1/qgpakaw4");
        }),
        ("signedUpdate.zeroVersionId", &|| {
            field_nonzero_version_id(&value, "signedUpdate.zeroVersionId", "regtest/k1/qgpakaw4");
        }),
        ("signedUpdate.stringVersionId", &|| {
            field_version_id(
                &value,
                "signedUpdate.stringVersionId",
                "regtest/k1/qgpakaw4",
            );
        }),
        ("signedUpdate.stringVersionId", &|| {
            field_nonzero_version_id(
                &value,
                "signedUpdate.stringVersionId",
                "regtest/k1/qgpakaw4",
            );
        }),
    ];
    for (path, reader) in cases {
        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(reader))
            .expect_err("a malformed field must panic, not be coerced");
        let message = panic_message(payload);
        assert!(
            message.contains("regtest/k1/qgpakaw4") && message.contains(path),
            "{path}: the message must name the vector and the path: {message}"
        );
    }
}

/// `didDocumentMetadata.versionId` is read from an ASCII-decimal string, and a
/// JSON number is refused: the specification makes the field a string.
#[test]
fn metadata_version_id_accepts_ascii_string_and_rejects_number() {
    assert_eq!(metadata_version_id(&serde_json::json!("3"), "ctx"), 3);
    let payload = std::panic::catch_unwind(|| {
        metadata_version_id(&serde_json::json!(3), "regtest/k1/qgpakaw4")
    })
    .expect_err("a number-encoded versionId must be rejected");
    let message = panic_message(payload);
    assert!(
        message.contains("regtest/k1/qgpakaw4") && message.contains("must be a string"),
        "{message}"
    );
}

/// Anything but a non-empty ASCII-decimal string is a corrupt `versionId` and
/// panics naming the context.
#[test]
fn metadata_version_id_rejects_non_decimal_forms() {
    for bad in [
        serde_json::json!(""),
        serde_json::json!("v2"),
        serde_json::json!("-1"),
        serde_json::json!(1.5),
        serde_json::json!(true),
        serde_json::json!(null),
    ] {
        let payload = std::panic::catch_unwind(|| metadata_version_id(&bad, "ctx-marker"))
            .expect_err("a non-decimal versionId must be rejected, not coerced");
        assert!(
            panic_message(payload).contains("ctx-marker"),
            "versionId {bad} must be rejected naming the context"
        );
    }
}

/// An update's version numbers are read from a JSON integer, and a string is
/// refused: the crate parses `targetVersionId` into a `NonZeroU64`.
#[test]
fn update_version_number_accepts_integer_and_rejects_string() {
    assert_eq!(update_version_number(&serde_json::json!(3), "ctx"), 3);
    let payload = std::panic::catch_unwind(|| {
        update_version_number(&serde_json::json!("3"), "regtest/k1/qgpakaw4")
    })
    .expect_err("a string-encoded version number must be rejected");
    let message = panic_message(payload);
    assert!(
        message.contains("regtest/k1/qgpakaw4") && message.contains("integer"),
        "{message}"
    );
}

/// Anything but a non-negative JSON integer is a corrupt version number and
/// panics naming the context.
#[test]
fn update_version_number_rejects_non_integer_forms() {
    for bad in [
        serde_json::json!(1.5),
        serde_json::json!(-1),
        serde_json::json!(true),
        serde_json::json!(null),
    ] {
        let payload = std::panic::catch_unwind(|| update_version_number(&bad, "ctx-marker"))
            .expect_err("a non-integer version number must be rejected, not coerced");
        assert!(
            panic_message(payload).contains("ctx-marker"),
            "version number {bad} must be rejected naming the context"
        );
    }
}

/// The present/absent probe and the discovery walk agree, and discovery is
/// content-based: exactly the four networks the suite ships vectors for are
/// found, and no dot-prefixed entry (notably `.git`) is ever treated as a
/// network.
#[test]
fn test_suite_probe_matches_network_dirs() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let dirs = network_dirs_with_vectors();
    let mut sorted = dirs.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        ["mutinynet", "regtest", "signet", "testnet4"],
        "the suite ships vector directories on exactly these four networks"
    );
    assert!(
        !dirs.iter().any(|d| d.starts_with('.')),
        "a dot-prefixed entry is repository metadata, not a network: {dirs:?}"
    );
}

/// The JSON wrapper reads and parses a real fixture.
#[test]
fn read_fixture_json_parses_a_known_fixture() {
    let Some(value) = read_fixture_json("regtest/k1/qgp45a3y/create/output.json") else {
        return;
    };
    assert!(
        value["did"].is_string(),
        "create/output.json carries the derived DID as a string"
    );
}

/// The three layouts the test-suite ships today are all recognized, and the
/// numbered steps come back sorted regardless of `read_dir` order.
#[test]
fn operation_dirs_accept_the_three_known_layouts() {
    assert_eq!(
        classify_operation_dirs(&["create".into(), "resolve".into()], &[]),
        Ok(UpdateLayout::None)
    );
    assert_eq!(
        classify_operation_dirs(
            &["create".into(), "resolve".into(), "update".into()],
            &["input.json".into(), "output.json".into()]
        ),
        Ok(UpdateLayout::Flat)
    );
    assert_eq!(
        classify_operation_dirs(
            &["create".into(), "update".into()],
            &["02".into(), "01".into()]
        ),
        Ok(UpdateLayout::Numbered(vec!["01".into(), "02".into()]))
    );
}

/// A vector exercising an operation the harness does not model must fail loud,
/// not be silently ignored.
#[test]
fn operation_dirs_reject_unknown_operation() {
    let err = classify_operation_dirs(&["create".into(), "revoke".into()], &[])
        .expect_err("an unmodelled operation sub-directory must be rejected");
    assert!(err.contains("revoke"), "message names the offender: {err}");
}

/// An `update/` child that is neither the flat pair nor a numbered step is a
/// layout we do not understand.
#[test]
fn operation_dirs_reject_unknown_update_child() {
    let err = classify_operation_dirs(&["update".into()], &["notes.md".into()])
        .expect_err("an unrecognized update/ child must be rejected");
    assert!(
        err.contains("notes.md"),
        "message names the offender: {err}"
    );
}

/// A half-flat, half-numbered `update/` directory is ambiguous — reject it
/// rather than guessing which half is authoritative. Both shapes are rejected:
/// a numbered step alongside a partial flat pair, and one alongside a complete
/// flat pair (which presence-based flat detection would otherwise swallow).
#[test]
fn operation_dirs_reject_mixed_update_layout() {
    let err = classify_operation_dirs(&["update".into()], &["01".into(), "input.json".into()])
        .expect_err("a mixed flat/numbered update/ layout must be rejected");
    assert!(
        err.contains("input.json"),
        "message names the offender: {err}"
    );

    let err = classify_operation_dirs(
        &["update".into()],
        &["01".into(), "input.json".into(), "output.json".into()],
    )
    .expect_err("a numbered step alongside a complete flat pair must be rejected");
    assert!(
        err.contains("01") && err.contains("ambiguous"),
        "message names the offending step and says why: {err}"
    );
}

/// A flat `update/` layout is detected by the PRESENCE of the input/output
/// pair, not by an exact child count: an added `update/metadata.json` is
/// generator output, and a count-based rule fell through to the numbered branch
/// and hard-panicked discovery on it.
#[test]
fn operation_dirs_accept_extra_flat_siblings() {
    assert_eq!(
        classify_operation_dirs(
            &["update".into()],
            &[
                "input.json".into(),
                "metadata.json".into(),
                "output.json".into()
            ]
        ),
        Ok(UpdateLayout::Flat)
    );
}

/// Numbered steps are ordered by the NUMBER they name, not by string
/// comparison: `["1", "2", "10"]` must not walk as `1, 10, 2`. Mixed widths
/// order correctly too.
#[test]
fn operation_dirs_order_numbered_steps_numerically() {
    assert_eq!(
        classify_operation_dirs(&["update".into()], &["10".into(), "2".into(), "1".into()]),
        Ok(UpdateLayout::Numbered(vec![
            "1".into(),
            "2".into(),
            "10".into()
        ]))
    );
    assert_eq!(
        classify_operation_dirs(&["update".into()], &["02".into(), "1".into()]),
        Ok(UpdateLayout::Numbered(vec!["1".into(), "02".into()]))
    );
}

/// Two step directories naming the same number are ambiguous about walk order,
/// and are rejected at classification time where the message can say so — not
/// left to surface as an opaque hash mismatch inside a driver.
#[test]
fn operation_dirs_reject_numerically_colliding_steps() {
    let err = classify_operation_dirs(&["update".into()], &["1".into(), "01".into()])
        .expect_err("numerically colliding step directories must be rejected");
    assert!(
        err.contains("01") && err.contains("both name step 1"),
        "message names the collision: {err}"
    );
}

/// Names for the `resolve/` classification tests.
fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// A `resolve/` holding only the main pair has no numbered cases.
#[test]
fn resolve_children_accept_the_main_pair_alone() {
    assert_eq!(
        classify_resolve_children(&names(&["input.json", "output.json"])),
        Ok(Vec::new())
    );
}

/// Numbered cases come back in the order of the number each names, verbatim:
/// `resolve/10` walks after `resolve/9`, not between `01` and `02`.
#[test]
fn resolve_children_order_cases_numerically() {
    assert_eq!(
        classify_resolve_children(&names(&[
            "input.json",
            "output.json",
            "01",
            "02",
            "10",
            "9"
        ])),
        Ok(names(&["01", "02", "9", "10"]))
    );
}

/// A `resolve/` child that is neither the main pair nor a numbered case is a
/// layout the harness does not read, and fails naming the offender.
#[test]
fn resolve_children_reject_an_unknown_child() {
    let err = classify_resolve_children(&names(&["input.json", "notes.md", "output.json"]))
        .expect_err("an unrecognized resolve/ child must be rejected");
    assert!(
        err.contains("notes.md") && err.contains("resolve/"),
        "message names the offender and the directory: {err}"
    );
}

/// `1` and `01` name the same case twice.
#[test]
fn resolve_children_reject_numerically_colliding_cases() {
    let err = classify_resolve_children(&names(&["input.json", "output.json", "1", "01"]))
        .expect_err("numerically colliding case directories must be rejected");
    assert!(
        err.contains("`1`") && err.contains("`01`") && err.contains("resolve/"),
        "message names both directories and the parent: {err}"
    );
}

/// The main pair is required: numbered cases do not replace it.
#[test]
fn resolve_children_require_the_main_pair() {
    let err = classify_resolve_children(&names(&["input.json", "01"]))
        .expect_err("a resolve/ without output.json must be rejected");
    assert!(err.contains("output.json"), "message names the file: {err}");

    let err = classify_resolve_children(&names(&["output.json"]))
        .expect_err("a resolve/ without input.json must be rejected");
    assert!(err.contains("input.json"), "message names the file: {err}");
}

/// An output carrying `didResolutionMetadata.error` is an expected error and
/// yields its code, with no `didDocumentMetadata` required.
#[test]
fn outcome_reads_an_expected_error_code() {
    let output = serde_json::json!({
        "didDocument": null,
        "didResolutionMetadata": { "error": "NOT_FOUND", "errorMessage": "no such version" },
        "didDocumentMetadata": {},
    });
    assert_eq!(
        parse_outcome(&output, "ctx"),
        Outcome::Error {
            code: "NOT_FOUND".into()
        }
    );
}

/// A resolved-document output yields its string `versionId` verbatim alongside
/// the coerced number, `deactivated`, and `confirmations`.
#[test]
fn outcome_reads_a_positive_document() {
    let output = serde_json::json!({
        "didDocument": { "id": "did:btcr2:k1q" },
        "didResolutionMetadata": { "contentType": "application/did" },
        "didDocumentMetadata": { "versionId": "3", "deactivated": false, "confirmations": 7 },
    });
    assert_eq!(
        parse_outcome(&output, "ctx"),
        Outcome::Positive {
            version_id: 3,
            version_id_string: "3".into(),
            deactivated: false,
            confirmations: Some(7),
        }
    );
}

/// A number-encoded `versionId` is refused, naming the file and saying it must
/// be a string; the specification makes it one.
#[test]
fn outcome_rejects_a_number_encoded_version_id() {
    let output = serde_json::json!({
        "didDocumentMetadata": { "versionId": 2, "deactivated": true },
    });
    let payload = std::panic::catch_unwind(|| {
        parse_outcome(&output, "regtest/k1/qgpakaw4/resolve/output.json")
    })
    .expect_err("a number-encoded versionId must panic, not be coerced");
    let message = panic_message(payload);
    assert!(
        message.contains("regtest/k1/qgpakaw4/resolve/output.json")
            && message.contains("didDocumentMetadata.versionId")
            && message.contains("must be a string"),
        "{message}"
    );
}

/// An absent `confirmations` reads as `None`.
#[test]
fn outcome_reads_an_absent_confirmations_as_none() {
    let output = serde_json::json!({
        "didDocumentMetadata": { "versionId": "2", "deactivated": true },
    });
    assert_eq!(
        parse_outcome(&output, "ctx"),
        Outcome::Positive {
            version_id: 2,
            version_id_string: "2".into(),
            deactivated: true,
            confirmations: None,
        }
    );
}

/// Malformed outcome fields panic naming the file and the JSON path: an error
/// code that is not a string, a missing `deactivated`, and a non-integer
/// `confirmations`.
#[test]
fn outcome_rejects_malformed_fields_by_name() {
    let cases = [
        (
            serde_json::json!({ "didResolutionMetadata": { "error": 404 } }),
            "didResolutionMetadata.error",
        ),
        (
            serde_json::json!({ "didDocumentMetadata": { "versionId": "1" } }),
            "didDocumentMetadata.deactivated",
        ),
        (
            serde_json::json!({ "didDocumentMetadata": {
                "versionId": "1", "deactivated": false, "confirmations": "7"
            } }),
            "didDocumentMetadata.confirmations",
        ),
    ];
    for (output, path) in cases {
        let payload = std::panic::catch_unwind(|| {
            parse_outcome(&output, "regtest/k1/qgpakaw4/resolve/output.json")
        })
        .expect_err("a malformed outcome must panic, not be coerced");
        let message = panic_message(payload);
        assert!(
            message.contains("regtest/k1/qgpakaw4/resolve/output.json") && message.contains(path),
            "{path}: the message must name the file and the path: {message}"
        );
    }
}

/// The accessors over the main outcome: a positive set has a version; a
/// negative set has none.
#[test]
fn outcome_accessors_track_the_main_pair() {
    let mut v = synthetic_vector("regtest/k1/qgpakaw4", "k1");
    assert_eq!(v.expected_version_id(), Some(1));
    assert!(!v.is_negative());

    v.outcome = positive_outcome(4);
    assert_eq!(v.expected_version_id(), Some(4));

    v.outcome = Outcome::Error {
        code: "INVALID_DID".into(),
    };
    assert_eq!(v.expected_version_id(), None);
    assert!(v.is_negative());
}

/// The production corpus is the submodule plus this repository's captures, and
/// a synthetic corpus sits under `fixtures/layout/`, apart from both.
#[test]
fn corpus_roots_name_their_sets_and_chain_trees() {
    let live = Corpus::test_suite();
    assert_eq!(live.sets, test_suite_root());
    assert_eq!(live.chain, chain_fixture_root());

    let shapes = Corpus::synthetic("shapes");
    assert!(
        shapes.sets.ends_with("fixtures/layout/shapes/sets")
            && shapes.chain.ends_with("fixtures/layout/shapes/chain"),
        "unexpected synthetic roots: {shapes:?}"
    );
    assert!(!shapes.sets.starts_with(test_suite_root()));
    assert!(!shapes.chain.starts_with(chain_fixture_root()));
}

/// Discovery sees every vector directory on disk, in deterministic order, with
/// every classification input populated from the vector's own files.
#[test]
fn discovery_finds_every_vector_directory() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    // Vacuity guard: never assert over an empty discovered set.
    assert!(
        !vectors.is_empty(),
        "the submodule probe reports PRESENT, so discovery must yield vectors"
    );
    for network_dir in network_dirs_with_vectors() {
        assert!(
            vectors.iter().any(|v| v.network_dir == network_dir),
            "network directory {network_dir} was probed as holding vectors but contributed none"
        );
    }
    // Every network ships the same 59 scenarios, each under its own ids.
    for network_dir in ["regtest", "mutinynet", "signet", "testnet4"] {
        assert_eq!(
            vectors
                .iter()
                .filter(|v| v.network_dir == network_dir)
                .count(),
            59,
            "{network_dir} ships 59 sets"
        );
    }
    for pair in vectors.windows(2) {
        assert!(
            pair[0].id < pair[1].id,
            "discovery order must be strictly ascending: {} then {}",
            pair[0].id,
            pair[1].id
        );
    }
    // Each set owns its directory inside the corpus it was discovered in, and
    // every numbered resolve case it lists is a directory there.
    for v in &vectors {
        assert_eq!(v.corpus, Corpus::test_suite(), "{}", v.id);
        assert_eq!(v.dir, v.corpus.sets.join(&v.id), "{}", v.id);
        for case in &v.resolve_cases {
            assert!(
                v.dir.join("resolve").join(&case.name).is_dir(),
                "{}: resolve/{} is listed as a case",
                v.id,
                case.name
            );
        }
    }

    let by_id = |want: &str| {
        vectors
            .iter()
            .find(|v| v.id == want)
            .unwrap_or_else(|| panic!("{want} must be discovered"))
    };

    // Update layouts.
    assert_eq!(
        by_id("regtest/x1/qfaqdrxu").update_layout,
        UpdateLayout::Numbered(vec!["01".into(), "02".into()])
    );
    assert_eq!(
        by_id("regtest/x1/qg4zny9h").update_layout,
        UpdateLayout::Numbered(vec!["01".into(), "02".into(), "03".into()])
    );
    assert_eq!(
        by_id("regtest/k1/qgp45a3y").update_layout,
        UpdateLayout::None
    );
    assert_eq!(
        by_id("regtest/k1/qgph7nre").update_layout,
        UpdateLayout::Flat
    );

    // Genesis-only CAS-delivered vector: no update, CAS genesis,
    // and no sidecar genesis document to resolve from.
    let qghp0w22 = by_id("regtest/x1/qghp0w22");
    assert_eq!(qghp0w22.expected_version_id(), Some(1));
    assert_eq!(qghp0w22.delivery.genesis, GenesisDelivery::Cas);
    assert_eq!(qghp0w22.delivery.announcement, None);
    assert!(!qghp0w22.has_sidecar_genesis_document);

    // versionId is read from its string encoding.
    assert_eq!(by_id("regtest/k1/qgp45a3y").expected_version_id(), Some(1));
    assert_eq!(by_id("regtest/x1/qg4zny9h").expected_version_id(), Some(4));

    // Beacon service types are collected from other.json.genesisDocument.
    assert!(
        by_id("regtest/x1/qfwwah7z")
            .genesis_service_types
            .iter()
            .any(|t| t == "SMTBeacon"),
        "qfwwah7z declares an SMT beacon in its genesis document"
    );
    // Update steps with no sidecar updates are CAS-announced; with them, the
    // sidecar delivers them, and a key-based genesis is deterministic.
    assert_eq!(
        by_id("regtest/x1/qfgeftze").delivery.announcement,
        Some(AnnouncementDelivery::Cas)
    );
    let qgph7nre = by_id("regtest/k1/qgph7nre");
    assert_eq!(qgph7nre.delivery.genesis, GenesisDelivery::Deterministic);
    assert_eq!(
        qgph7nre.delivery.announcement,
        Some(AnnouncementDelivery::Sidecar)
    );
    // Every set names its scenario, and a set that anchors an update ships its
    // signals record while a genesis-only one does not.
    assert!(
        vectors.iter().all(|v| v.scenario_id.is_some()),
        "every set carries other.json.scenarioId"
    );
    assert!(qgph7nre.signals.is_some(), "qgph7nre ships signals.json");
    assert!(
        by_id("regtest/k1/qgp45a3y").signals.is_none(),
        "qgp45a3y is genesis-only and ships no signals.json"
    );
    // The directory name maps to a Network, and the id-type segment is kept.
    assert_eq!(by_id("mutinynet/x1/q4typvtp").network, Network::Mutinynet);
    assert_eq!(by_id("mutinynet/x1/q4typvtp").kind, "x1");
    assert_eq!(by_id("signet/k1/qyp5h7kz").network, Network::Signet);
    assert_eq!(by_id("testnet4/k1/qspz5wep").network, Network::TestnetV4);
    // short_id is the leaf segment of the id.
    assert_eq!(by_id("regtest/k1/qgp45a3y").short_id, "qgp45a3y");
    // step_prefixes() is the shape every update-walking driver iterates.
    assert_eq!(
        by_id("regtest/x1/qfaqdrxu").update_layout.step_prefixes(),
        vec!["update/01".to_string(), "update/02".to_string()]
    );
}

/// A `Vector` with plausible defaults, for the classification tests: a
/// genesis-era vector that carries a sidecar genesis document, ships no
/// updates, and triggers no derived skip rule. Each test perturbs only the
/// fields its rule reads, so what drives the outcome is visible at the call
/// site.
fn synthetic_vector(id: &str, kind: &str) -> Vector {
    let segments: Vec<&str> = id.split('/').collect();
    let network_dir = segments.first().copied().unwrap_or("mutinynet").to_string();
    let short_id = segments.last().copied().unwrap_or(id).to_string();
    Vector {
        id: id.to_string(),
        network: network_from_dir(&network_dir, "a synthetic vector id"),
        network_dir,
        kind: kind.to_string(),
        short_id,
        id_type: id_type_from_kind(kind),
        corpus: Corpus::test_suite(),
        dir: test_suite_root().join(id),
        update_layout: UpdateLayout::None,
        outcome: positive_outcome(1),
        resolve_cases: Vec::new(),
        delivery: Delivery {
            genesis: match id_type_from_kind(kind) {
                VectorIdType::Key => GenesisDelivery::Deterministic,
                VectorIdType::External => GenesisDelivery::Sidecar,
            },
            announcement: None,
            negative: false,
        },
        signals: None,
        scenario_id: None,
        genesis_service_types: Vec::new(),
        has_sidecar_genesis_document: true,
    }
}

/// A resolved-document outcome at `version`, not deactivated, with no
/// confirmations, recording `versionId` as the specification's ASCII string.
fn positive_outcome(version: u64) -> Outcome {
    Outcome::Positive {
        version_id: version,
        version_id_string: version.to_string(),
        deactivated: false,
        confirmations: None,
    }
}

/// A positive set's delivery, for the classification tests.
fn delivery_of(genesis: GenesisDelivery, announcement: Option<AnnouncementDelivery>) -> Delivery {
    Delivery {
        genesis,
        announcement,
        negative: false,
    }
}

/// Each of the two derived rules fires on its own input, and they accumulate
/// rather than electing a first-match winner.
#[test]
fn derived_reasons_cover_the_two_rules() {
    use AnnouncementDelivery as A;
    use GenesisDelivery as G;

    // Nothing applies: an anchored, sidecar-delivered vector.
    assert_eq!(
        derived_resolve_skip_reasons(&delivery_of(G::Sidecar, Some(A::Sidecar)), &[]),
        BTreeSet::new()
    );
    // Rule 2 alone — the `qh66uy2s` shape: genesis-era, but CAS-delivered.
    assert_eq!(
        derived_resolve_skip_reasons(&delivery_of(G::Cas, None), &[]),
        BTreeSet::from([SkipReason::CasDelivery])
    );
    // Rule 2 on the announcements alone.
    assert_eq!(
        derived_resolve_skip_reasons(&delivery_of(G::Deterministic, Some(A::Cas)), &[]),
        BTreeSet::from([SkipReason::CasDelivery])
    );
    // Rules 1 and 2 together, with the duplicate CAS signal collapsing.
    assert_eq!(
        derived_resolve_skip_reasons(
            &delivery_of(G::Cas, Some(A::Cas)),
            &["SingletonBeacon".into(), "CASBeacon".into()]
        ),
        BTreeSet::from([SkipReason::CasDelivery, SkipReason::UnsupportedBeaconType])
    );
    // Rule 1 on the beacon type, with `SingletonBeacon` contributing nothing.
    // An SMT beacon in the genesis document blocks resolve twice over: the
    // delivery mechanism is unimplemented, AND the resolver will not issue a
    // request for that beacon type at all.
    assert_eq!(
        derived_resolve_skip_reasons(
            &delivery_of(G::Sidecar, None),
            &["SingletonBeacon".into(), "SMTBeacon".into()]
        ),
        BTreeSet::from([SkipReason::SmtDelivery, SkipReason::UnsupportedBeaconType,])
    );
    // Rule 1 applies to a negative set too: its beacons are what they are.
    let negative = Delivery {
        negative: true,
        ..delivery_of(G::Sidecar, Some(A::Sidecar))
    };
    assert_eq!(
        derived_resolve_skip_reasons(&negative, &["SMTBeacon".into()]),
        BTreeSet::from([SkipReason::SmtDelivery, SkipReason::UnsupportedBeaconType])
    );
}

/// The delivery and beacon reasons say nothing about whether a patch
/// sequence reproduces a document, so they scope to the resolve kinds — a
/// CAS-delivered, SMT-beaconed vector still drives its update assertions.
#[test]
fn delivery_reasons_scope_to_resolve_only() {
    let mut v = synthetic_vector("mutinynet/x1/q5m2fh36", "x1");
    v.delivery.genesis = GenesisDelivery::Cas;
    v.genesis_service_types = vec!["SMTBeacon".into()];
    v.outcome = positive_outcome(3);
    v.update_layout = UpdateLayout::Numbered(vec!["01".into(), "02".into()]);

    assert_eq!(
        v.skip_reasons_with(AssertionKind::Resolve, &[]),
        BTreeSet::from([
            SkipReason::CasDelivery,
            SkipReason::SmtDelivery,
            SkipReason::UnsupportedBeaconType,
        ])
    );
    for kind in [
        AssertionKind::Derivation,
        AssertionKind::GenesisKey,
        AssertionKind::UpdateCrypto,
        AssertionKind::EndState,
    ] {
        assert!(
            v.skip_reasons_with(kind, &[]).is_empty(),
            "{kind} must not inherit the resolve-scoped reasons: {:?}",
            v.skip_reasons_with(kind, &[])
        );
    }
}

/// `UpdateCrypto` and `EndState` are applicable exactly to the update-bearing
/// vectors; the other three kinds apply to every vector.
#[test]
fn applicable_kinds_track_the_update_layout() {
    let mut v = synthetic_vector("regtest/k1/qgpakaw4", "k1");
    assert_eq!(
        v.applicable_kinds(),
        vec![
            AssertionKind::Derivation,
            AssertionKind::GenesisKey,
            AssertionKind::Resolve,
        ]
    );

    for layout in [
        UpdateLayout::Flat,
        UpdateLayout::Numbered(vec!["01".into(), "02".into()]),
    ] {
        v.update_layout = layout;
        assert_eq!(
            v.applicable_kinds(),
            vec![
                AssertionKind::Derivation,
                AssertionKind::GenesisKey,
                AssertionKind::Resolve,
                AssertionKind::UpdateCrypto,
                AssertionKind::EndState,
            ]
        );
    }

    // A numbered resolve case makes the resolve-option kind apply too.
    v.resolve_cases = vec![ResolveCase {
        name: "01".into(),
        outcome: positive_outcome(1),
    }];
    assert_eq!(v.applicable_kinds(), AssertionKind::ALL.to_vec());
}

/// The resolve driver sources an external vector's genesis document from
/// `resolve/input.json.resolutionOptions.sidecar.genesisDocument`, so a
/// vector without one is not drivable no matter how simple its history. A
/// key-based vector needs no sidecar at all.
#[test]
fn resolve_drivability_requires_a_genesis_source_for_external_vectors() {
    let mut external = synthetic_vector("mutinynet/x1/qh66uy2s", "x1");
    external.has_sidecar_genesis_document = false;
    assert!(
        !external.is_drivable(AssertionKind::Resolve),
        "an external vector with no sidecar genesis document has no genesis source"
    );

    external.has_sidecar_genesis_document = true;
    assert!(
        external.is_drivable(AssertionKind::Resolve),
        "the same vector with a sidecar genesis document is drivable"
    );

    let mut key_based = synthetic_vector("mutinynet/k1/q5puld7y", "k1");
    key_based.has_sidecar_genesis_document = false;
    assert!(
        key_based.is_drivable(AssertionKind::Resolve),
        "a key-based vector derives its genesis document from the identifier"
    );

    // Past genesis is no longer a drivability condition on either id type: the
    // beacon signals come from a captured chain snapshot.
    key_based.outcome = positive_outcome(2);
    assert!(key_based.is_drivable(AssertionKind::Resolve));
    external.outcome = positive_outcome(2);
    assert!(external.is_drivable(AssertionKind::Resolve));
}

/// The escape hatch has to actually suppress driving. Drivability stays
/// structural, but the gate the drivers and the ledger share reads the override
/// table, so a hand-written skip yields a stated skip rather than a
/// "driven but not expected" reconciliation failure.
#[test]
fn an_override_stops_a_structurally_drivable_row_from_being_driven() {
    const OVERRIDES: &[SkipOverride] = &[SkipOverride {
        vector: "regtest/x1/q2fz9mz6",
        kind: AssertionKind::Derivation,
        case: None,
        reason: "upstream vector encodes its genesis bytes at the wrong length",
    }];

    let v = synthetic_vector("regtest/x1/q2fz9mz6", "x1");

    assert!(
        v.is_drivable(AssertionKind::Derivation),
        "drivability is structural and an override must not change it"
    );
    assert!(
        v.skip_reasons_with(AssertionKind::Derivation, OVERRIDES)
            .contains(&SkipReason::Override(
                "upstream vector encodes its genesis bytes at the wrong length"
            )),
        "the override reason is carried verbatim"
    );
    assert!(
        !(v.is_drivable(AssertionKind::Derivation)
            && v.skip_reasons_with(AssertionKind::Derivation, OVERRIDES)
                .is_empty()),
        "the drive gate must be false once an override matches the row"
    );
    // An override on one kind leaves the others alone.
    assert!(
        v.skip_reasons_with(AssertionKind::GenesisKey, OVERRIDES)
            .is_empty(),
        "an override names one kind and suppresses only that kind"
    );
    // Suppression comes from the table and nowhere else: with no entries, the
    // same row drives. Read against an explicit empty table rather than the live
    // one, so adding a real hand-written skip for this row cannot turn this
    // unrelated unit test red — the escape hatch has to stay usable.
    assert!(
        v.should_drive_with(AssertionKind::Derivation, &[]),
        "with no entries in play the gate suppresses nothing"
    );
}

/// Every discovered row classifies under the derived rules alone, and the two
/// vectors whose classification the rules were written for come out as stated.
#[test]
fn live_vectors_classify_without_overrides() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    assert!(
        !vectors.is_empty(),
        "the submodule probe reports PRESENT, so discovery must yield vectors"
    );
    let by_id = |want: &str| {
        vectors
            .iter()
            .find(|v| v.id == want)
            .unwrap_or_else(|| panic!("{want} must be discovered"))
    };

    // Genesis-era, anchored, no beacon-type signal: classified solely by the
    // delivery rule, and therefore not an unclassified row.
    let qghp0w22 = by_id("regtest/x1/qghp0w22");
    assert_eq!(
        qghp0w22.skip_reasons_with(AssertionKind::Resolve, &[]),
        BTreeSet::from([SkipReason::CasDelivery])
    );
    assert!(!qghp0w22.should_drive_with(AssertionKind::Resolve, &[]));

    // A CAS-delivered, multi-update vector still drives both update assertions.
    let qfgeftze = by_id("regtest/x1/qfgeftze");
    assert!(qfgeftze.should_drive_with(AssertionKind::UpdateCrypto, &[]));
    assert!(qfgeftze.should_drive_with(AssertionKind::EndState, &[]));
    assert!(!qfgeftze.should_drive_with(AssertionKind::Resolve, &[]));
}

/// Every main and `resolve/NN` output under `root` (a sets root in the
/// vendor layout) whose `didDocumentMetadata.versionId` is a JSON number, as
/// `{network}/{kind}/{short-id}/{rel}`.
///
/// Walks the files directly rather than through [`discover_in`], which
/// refuses such a file through [`metadata_version_id`] before it could be
/// counted.
fn number_encoded_version_ids_in(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for network in network_dirs_with_vectors_in(root) {
        for kind in sorted_child_dirs(&root.join(&network)) {
            for short_id in sorted_child_dirs(&root.join(&network).join(&kind)) {
                let id = format!("{network}/{kind}/{short_id}");
                let set_dir = root.join(&network).join(&kind).join(&short_id);
                let rels = std::iter::once("resolve/output.json".to_string()).chain(
                    sorted_child_dirs(&set_dir.join("resolve"))
                        .into_iter()
                        .map(|case| format!("resolve/{case}/output.json")),
                );
                for rel in rels {
                    let path = set_dir.join(&rel);
                    if !path.is_file() {
                        continue;
                    }
                    let output = read_json_at(&path, &format!("{id}/{rel}"));
                    if output["didDocumentMetadata"]["versionId"].is_number() {
                        found.push(format!("{id}/{rel}"));
                    }
                }
            }
        }
    }
    found
}

/// No vector encodes `didDocumentMetadata.versionId` as a number, and
/// [`NUMBER_ENCODED_VERSION_ID`] is empty.
///
/// Reads the raw main and `resolve/NN` output files
/// ([`number_encoded_version_ids_in`]) rather than the discovered vectors, so
/// the guard stands on its own and does not lean on the strict reader it
/// backs up.
#[test]
fn live_vectors_record_their_version_id_encoding() {
    assert!(
        NUMBER_ENCODED_VERSION_ID.is_empty(),
        "no number-encoded versionId is expected: {NUMBER_ENCODED_VERSION_ID:?}"
    );
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let root = Corpus::test_suite().sets;
    assert!(!network_dirs_with_vectors_in(&root).is_empty());
    let number_encoded = number_encoded_version_ids_in(&root);
    assert!(
        number_encoded.is_empty(),
        "these outputs encode didDocumentMetadata.versionId as a JSON number, but the \
         specification requires an ASCII string: {number_encoded:?}"
    );
}

/// A directory under the system temp directory, removed when dropped (also
/// when the test panics).
struct TempRoot(PathBuf);

impl TempRoot {
    /// A fresh root; `tag` names the test in the directory name.
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("did-btcr2-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        Self(root)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A `TempRoot` is removed when the test holding it panics, so a failing
/// assertion leaves no directory behind.
#[test]
fn temp_root_is_removed_when_its_test_panics() {
    let path = TempRoot::new("temp-root-panic").0.clone();
    let inner = path.clone();
    let result = std::panic::catch_unwind(move || {
        let root = TempRoot::new("temp-root-panic");
        assert_eq!(root.0, inner);
        std::fs::create_dir_all(root.0.join("sets")).unwrap();
        std::fs::write(root.0.join("sets/marker"), "x").unwrap();
        panic!("a failing assertion");
    });
    assert!(result.is_err(), "the closure panicked");
    assert!(!path.exists(), "{} was left behind", path.display());
}

/// A positive set whose sidecar carries an empty `updates` array is
/// CAS-delivered, not sidecar-delivered: an empty list delivers nothing.
#[test]
fn an_empty_sidecar_updates_array_is_not_a_sidecar_delivery() {
    let root = TempRoot::new("empty-sidecar-updates");
    let set = "mutinynet/k1/q5pew2jc";
    let set_dir = root.0.join("sets").join(set);
    copy_tree(
        &Corpus::synthetic("below-min-conf").sets.join(set),
        &set_dir,
    );
    let corpus = Corpus {
        sets: root.0.join("sets"),
        chain: root.0.join("chain"),
    };
    let announcement = |corpus: &Corpus| {
        let vectors = discover_in(corpus);
        assert_eq!(vectors.len(), 1, "the temp corpus holds its one set");
        assert!(!vectors[0].is_negative(), "the set expects a document");
        vectors[0].delivery.announcement
    };
    assert_eq!(announcement(&corpus), Some(AnnouncementDelivery::Sidecar));

    let input_path = set_dir.join("resolve/input.json");
    let mut input = read_json_at(&input_path, "the copied input");
    input["resolutionOptions"]["sidecar"]["updates"] = serde_json::json!([]);
    std::fs::write(&input_path, input.to_string()).unwrap();
    assert_eq!(announcement(&corpus), Some(AnnouncementDelivery::Cas));
}

/// The raw walk finds a number-encoded `versionId` in a main output and in a
/// `resolve/NN` case, the shapes discovery would refuse before counting them.
#[test]
fn number_encoded_version_ids_are_found_without_discovery() {
    let root = TempRoot::new("number-version-id-walk");
    let set = "mutinynet/x1/qh66uy2s";
    let set_dir = root.0.join(set);
    copy_tree(&Corpus::synthetic("shapes").sets.join(set), &set_dir);
    assert_eq!(number_encoded_version_ids_in(&root.0), Vec::<String>::new());

    let main = set_dir.join("resolve/output.json");
    let mut output = read_json_at(&main, "the copied output");
    output["didDocumentMetadata"]["versionId"] = serde_json::json!(2);
    std::fs::write(&main, output.to_string()).unwrap();
    std::fs::create_dir_all(set_dir.join("resolve/01")).unwrap();
    std::fs::write(set_dir.join("resolve/01/output.json"), output.to_string()).unwrap();

    assert_eq!(
        number_encoded_version_ids_in(&root.0),
        vec![
            format!("{set}/resolve/output.json"),
            format!("{set}/resolve/01/output.json"),
        ]
    );
}

/// Three synthetic vectors spanning the shapes the ledger has to tell apart: a
/// fully drivable genesis-era vector, a multi-update vector whose genesis
/// document declares an SMT beacon, and a genesis-era vector classified solely
/// by its delivery.
fn synthetic_ledger() -> Vec<Vector> {
    let genesis_era = synthetic_vector("regtest/k1/qgpakaw4", "k1");

    let mut multi_update = synthetic_vector("mutinynet/x1/q5m2fh36", "x1");
    multi_update.update_layout = UpdateLayout::Numbered(vec!["01".into(), "02".into()]);
    multi_update.genesis_service_types = vec!["SMTBeacon".into()];
    multi_update.delivery.genesis = GenesisDelivery::Cas;
    multi_update.outcome = positive_outcome(3);

    let mut cas_genesis = synthetic_vector("mutinynet/x1/qh66uy2s", "x1");
    cas_genesis.has_sidecar_genesis_document = false;
    cas_genesis.delivery.genesis = GenesisDelivery::Cas;
    cas_genesis.outcome = positive_outcome(1);

    vec![genesis_era, multi_update, cas_genesis]
}

/// The panic message of a `reconcile_driven` call that is expected to fail.
fn reconcile_panic_message(
    kind: AssertionKind,
    vectors: &[Vector],
    observed: &BTreeSet<RowKey>,
) -> String {
    let payload = std::panic::catch_unwind(|| reconcile_driven_with(kind, vectors, observed, &[]))
        .expect_err("reconcile_driven must panic when the sets diverge");
    panic_message(payload)
}

/// The ledger's expectation and the drivers' gate are one predicate — a skip
/// entry cannot suppress driving without also suppressing the expectation.
#[test]
fn expected_driven_tracks_should_drive() {
    let vectors = synthetic_ledger();
    for kind in AssertionKind::ALL {
        let want: BTreeSet<RowKey> = vectors
            .iter()
            .flat_map(|v| {
                v.rows(kind)
                    .into_iter()
                    .filter(|row| v.should_drive_row_with(kind, row.case.as_deref(), &[]))
            })
            .collect();
        assert_eq!(
            expected_driven_with(kind, &vectors, &[]),
            want,
            "{kind}: expected_driven must filter on the same predicate the drivers gate on"
        );
    }
    // Vacuity guard: the fixture actually exercises both columns.
    assert_eq!(
        expected_driven_with(AssertionKind::Resolve, &vectors, &[]),
        BTreeSet::from([RowKey::set("regtest/k1/qgpakaw4")])
    );
    assert_eq!(
        expected_driven_with(AssertionKind::UpdateCrypto, &vectors, &[]),
        BTreeSet::from([RowKey::set("mutinynet/x1/q5m2fh36")])
    );
}

/// A driver that asserted against exactly the expected rows reconciles.
#[test]
fn reconcile_passes_on_an_exact_observed_set() {
    let vectors = synthetic_ledger();
    for kind in AssertionKind::ALL {
        let observed = expected_driven_with(kind, &vectors, &[]);
        reconcile_driven_with(kind, &vectors, &observed, &[]);
    }
}

/// The failure this reconciliation exists for: a driver that quietly walked
/// past a row the ledger expects it to drive.
#[test]
fn reconcile_fails_when_a_drivable_row_was_skipped() {
    let vectors = synthetic_ledger();
    let mut observed = expected_driven_with(AssertionKind::Derivation, &vectors, &[]);
    let dropped = RowKey::set("mutinynet/x1/qh66uy2s");
    assert!(
        observed.remove(&dropped),
        "the dropped row must have been expected in the first place"
    );

    let message = reconcile_panic_message(AssertionKind::Derivation, &vectors, &observed);
    assert!(
        message.contains(&dropped.to_string()) && message.contains("expected but not driven"),
        "the message must name the missing row: {message}"
    );
}

/// The symmetric failure: a driver asserted against a row the ledger classified
/// as skipped, so one of the two is stale.
#[test]
fn reconcile_fails_on_an_unexpected_driven_row() {
    let vectors = synthetic_ledger();
    let mut observed = expected_driven_with(AssertionKind::Resolve, &vectors, &[]);
    let extra = RowKey::set("mutinynet/x1/qh66uy2s");
    observed.insert(extra.clone());

    let message = reconcile_panic_message(AssertionKind::Resolve, &vectors, &observed);
    assert!(
        message.contains(&extra.to_string()) && message.contains("driven but not expected"),
        "the message must name the unexpected row: {message}"
    );
}

/// A row the harness cannot drive and that no rule explains is reported with an
/// actionable message. Adding the delivery declaration classifies it — the rule
/// that keeps the live suite green.
#[test]
fn unclassified_row_is_reported_with_a_classify_message() {
    let mut orphan = synthetic_vector("mutinynet/x1/__unclassified__", "x1");
    orphan.has_sidecar_genesis_document = false;

    let rows = unclassified_rows_with(std::slice::from_ref(&orphan), &[]);
    assert_eq!(rows.len(), 1, "exactly one unclassified row: {rows:?}");
    assert!(
        rows[0].contains("mutinynet/x1/__unclassified__") && rows[0].contains("classify it"),
        "the message names the row and says what to do: {}",
        rows[0]
    );

    orphan.delivery.genesis = GenesisDelivery::Cas;
    assert!(
        unclassified_rows_with(std::slice::from_ref(&orphan), &[]).is_empty(),
        "a delivery declaration classifies the row"
    );
}

/// Drivable rows and reason-carrying rows are both classified and contribute
/// nothing to the report.
#[test]
fn classified_rows_are_not_reported() {
    assert!(unclassified_rows_with(&synthetic_ledger(), &[]).is_empty());
}

/// An override that matches nothing is reported, whether the vector is
/// gone or the assertion no longer applies to it. One that matches a discovered
/// row is not.
#[test]
fn stale_override_is_reported() {
    let vectors = synthetic_ledger();

    const GONE: &[SkipOverride] = &[SkipOverride {
        vector: "mutinynet/x1/__gone__",
        kind: AssertionKind::Resolve,
        case: None,
        reason: "the vector was removed upstream",
    }];
    let rows = stale_overrides(GONE, &vectors);
    assert_eq!(rows.len(), 1, "a vanished vector is reported: {rows:?}");
    assert!(
        rows[0].contains("stale SKIP override") && rows[0].contains("__gone__"),
        "the message names the entry: {}",
        rows[0]
    );

    // The vector exists, but it ships no `update/` directory, so the named
    // assertion is not one of its rows.
    const WRONG_KIND: &[SkipOverride] = &[SkipOverride {
        vector: "regtest/k1/qgpakaw4",
        kind: AssertionKind::UpdateCrypto,
        case: None,
        reason: "the update walk cannot be driven for this vector",
    }];
    let rows = stale_overrides(WRONG_KIND, &vectors);
    assert_eq!(
        rows.len(),
        1,
        "an inapplicable assertion is reported: {rows:?}"
    );
    assert!(rows[0].contains("stale SKIP override"), "{}", rows[0]);

    // A live entry reports nothing.
    const LIVE: &[SkipOverride] = &[SkipOverride {
        vector: "mutinynet/x1/q5m2fh36",
        kind: AssertionKind::UpdateCrypto,
        case: None,
        reason: "the update walk cannot be driven for this vector",
    }];
    assert!(stale_overrides(LIVE, &vectors).is_empty());
}

/// The summary answers "what does this suite check?" — every kind on its own
/// line, and the skips broken out by reason.
#[test]
fn summary_names_every_assertion_kind() {
    let summary = render_summary_with(&synthetic_ledger(), &[]);
    for kind in AssertionKind::ALL {
        assert!(
            summary.contains(&kind.to_string()),
            "{kind} must appear in the summary:\n{summary}"
        );
    }
    assert!(summary.contains("skipped rows by reason"), "{summary}");
    for reason in [
        SkipReason::CasDelivery,
        SkipReason::SmtDelivery,
        SkipReason::UnsupportedBeaconType,
    ] {
        assert!(
            summary.contains(&reason.to_string()),
            "{reason} applies to the synthetic ledger and must be broken out:\n{summary}"
        );
    }
}

/// A hand-written skip on a row a derived rule already covers is reported: the
/// entry is redundant the day it is written and stale the day the rule changes.
#[test]
fn redundant_override_on_a_derived_skip_row_is_reported() {
    const OVERRIDES: &[SkipOverride] = &[SkipOverride {
        vector: "mutinynet/x1/qh66uy2s",
        kind: AssertionKind::Resolve,
        case: None,
        reason: "genesis document is delivered out of band",
    }];

    let mut cas_genesis = synthetic_vector("mutinynet/x1/qh66uy2s", "x1");
    cas_genesis.delivery.genesis = GenesisDelivery::Cas;
    // Precondition: a derived rule already skips this row.
    assert!(
        !cas_genesis
            .skip_reasons_with(AssertionKind::Resolve, &[])
            .is_empty()
    );

    let rows = redundant_overrides(std::slice::from_ref(&cas_genesis), OVERRIDES);
    assert_eq!(rows.len(), 1, "exactly one redundant override: {rows:?}");
    assert!(
        rows[0].contains("mutinynet/x1/qh66uy2s") && rows[0].contains("redundant"),
        "the message names the row and says what to do: {}",
        rows[0]
    );
}

/// The escape hatch's whole purpose: a hand-written skip on a row no derived
/// rule covers is legitimate, suppresses driving, and is reported by nothing.
#[test]
fn override_on_a_row_no_rule_covers_is_not_redundant() {
    const OVERRIDES: &[SkipOverride] = &[SkipOverride {
        vector: "regtest/x1/q2fz9mz6",
        kind: AssertionKind::Derivation,
        case: None,
        reason: "upstream vector encodes its genesis bytes at the wrong length",
    }];

    let v = synthetic_vector("regtest/x1/q2fz9mz6", "x1");
    let ledger = std::slice::from_ref(&v);

    assert!(v.is_drivable(AssertionKind::Derivation));
    assert!(
        redundant_overrides(ledger, OVERRIDES).is_empty(),
        "an override on a row no derived rule skips is the intended use"
    );
    assert!(
        !v.should_drive_with(AssertionKind::Derivation, OVERRIDES),
        "the override suppresses driving"
    );
    assert!(
        !expected_driven_with(AssertionKind::Derivation, ledger, OVERRIDES)
            .contains(&RowKey::set("regtest/x1/q2fz9mz6")),
        "and suppresses the ledger's expectation in the same step"
    );
    assert!(
        unclassified_rows_with(ledger, OVERRIDES).is_empty(),
        "a row with a stated reason is classified, not unclassified"
    );
}

// --- Captured chain fixtures -------------------------------------------------

/// A confirmed esplora transaction whose LAST output is `OP_RETURN <32-byte
/// push>`, in the JSON shape a captured fixture stores it in.
///
/// The synthetic-envelope tests build their bodies here rather than reading a
/// fixture off disk: every consistency failure they assert is one no committed
/// fixture may ever have, so provoking it must not mean editing one.
fn chain_signal_tx_json(
    update_hash: &str,
    txid: &str,
    block_height: u32,
    block_time: i64,
) -> serde_json::Value {
    serde_json::json!({
        "txid": txid,
        "version": 2,
        "locktime": 0,
        "vin": [],
        "vout": [{ "scriptpubkey": format!("6a20{update_hash}"), "value": 0 }],
        "size": 0,
        "weight": 0,
        "fee": 0,
        "status": {
            "confirmed": true,
            "block_height": block_height,
            "block_hash": "00".repeat(32),
            "block_time": block_time,
        },
    })
}

/// A `ChainFixture` in the captured envelope's shape, deserialized the same way
/// a real one is — so a test perturbing `signals` exercises the very code path
/// `read_chain_fixture` runs on load.
fn chain_fixture_envelope(
    signals: serde_json::Value,
    addresses: serde_json::Value,
) -> ChainFixture {
    serde_json::from_value(serde_json::json!({
        "captured_at": "2026-07-31T00:00:00Z",
        "endpoint": "http://localhost:3000",
        "network": "regtest",
        "vector": "regtest/k1/synthetic",
        "tip_height": 758,
        "signals": signals,
        "addresses": addresses,
    }))
    .expect("the synthetic envelope matches the captured fixture shape")
}

/// A vector id resolves under the crate's own `fixtures/chain/` tree, not the
/// `test-suite/` submodule.
#[test]
fn chain_fixture_path_lands_under_the_in_crate_tree() {
    let path = chain_fixture_path("regtest/k1/qgph7nre");
    assert!(
        path.ends_with("fixtures/chain/regtest/k1/qgph7nre.json"),
        "unexpected fixture path: {}",
        path.display()
    );
    assert!(
        path.starts_with(env!("CARGO_MANIFEST_DIR")),
        "the path must be absolute against the crate root: {}",
        path.display()
    );
    assert!(
        !path.starts_with(test_suite_root()),
        "the chain fixtures are ours, not the submodule's: {}",
        path.display()
    );
}

/// A committed vendor capture reads back with its tip, its endpoint and at
/// least one signal.
#[test]
fn chain_fixture_reads_a_captured_vendor_snapshot() {
    let fixture = read_chain_fixture("regtest/k1/qgph7nre");

    assert_eq!(fixture.network, "regtest");
    assert_eq!(fixture.endpoint, "http://localhost:3000");
    assert_ne!(fixture.tip_height, 0, "a capture always pins a real tip");
    assert!(
        !fixture.signals.is_empty(),
        "this vector announced at least one update on chain"
    );
    assert!(
        fixture
            .did
            .as_deref()
            .is_some_and(|did| did.starts_with("did:btcr2:k1")),
        "the capture records the DID it resolved: {:?}",
        fixture.did
    );
}

/// An address captured with no transactions is a captured state, not an error:
/// it must deserialize as an empty vector under a present key.
#[test]
fn chain_fixture_addresses_keep_captured_and_empty_keys() {
    let fixture = read_chain_fixture("regtest/k1/qgph7nre");

    assert!(
        fixture.addresses.len() > 1,
        "this vector queried several beacon addresses"
    );
    assert!(
        fixture.addresses.values().any(|txs| txs.is_empty()),
        "at least one captured address returned no transactions"
    );
    assert!(
        fixture.addresses.values().any(|txs| !txs.is_empty()),
        "and at least one returned some"
    );
}

/// The minted-only fields are absent on a vendor capture and present on a
/// minted one.
#[test]
fn chain_fixture_minted_only_fields_are_absent_on_a_vendor_capture() {
    let vendor = read_chain_fixture("regtest/k1/qgph7nre");
    assert!(
        vendor.sidecar.is_none(),
        "a vendor capture ships no sidecar"
    );
    assert!(
        vendor.expected.is_none(),
        "a vendor capture states no expected resolution of its own"
    );

    let minted = read_chain_fixture("minted/clean-rotating-beacons");
    assert!(
        minted.sidecar.is_some(),
        "a minted scenario ships the sidecar its updates need"
    );
    assert!(
        minted.expected.is_some(),
        "and the resolution it was minted to produce"
    );
}

/// `latest_signal` announces the highest-`targetVersionId` update — the one
/// `confirmations` derives from — and `earliest_block_time` is the minimum across
/// all signals. Both scan every entry rather than trusting the capture's order.
#[test]
fn chain_fixture_latest_signal_and_earliest_block_time_scan_every_signal() {
    let mut fixture = read_chain_fixture("minted/clean-rotating-beacons");
    assert!(
        fixture.signals.len() >= 3,
        "the clean scenario announces three updates"
    );

    // The capture writes signals in address order, which may or may not agree
    // with height order on any given mint. Put them out of height order HERE,
    // so a `latest_signal` that trusted the recorded order would pick the
    // wrong one no matter what the capture happened to produce.
    fixture
        .signals
        .sort_by_key(|s| std::cmp::Reverse(s.block_height));
    let heights: Vec<u32> = fixture.signals.iter().map(|s| s.block_height).collect();
    let mut sorted = heights.clone();
    sorted.sort_unstable();
    assert_ne!(
        heights, sorted,
        "the signals under test are not in height order, which is what makes the scan \
         load-bearing: {heights:?}"
    );

    let applied = fixture
        .applied_update_hash()
        .expect("a minted fixture carries its own sidecar");
    let signal = fixture
        .latest_signal()
        .expect("the clean scenario announces every update it minted");
    assert_eq!(
        signal.update_hash, applied,
        "the signal is chosen by which update it announces — the resolver's rule — \
         not by which block it sits in"
    );

    // On this fixture the two rules agree, which `assert_signals_consistent`
    // requires of every fixture; asserted here too so the agreement is stated
    // where the accessor is tested.
    let highest = heights.iter().copied().max().expect("signals is non-empty");
    assert_eq!(signal.block_height, highest);

    let earliest = fixture
        .signals
        .iter()
        .map(|s| s.block_time)
        .min()
        .expect("signals is non-empty");
    assert_eq!(fixture.earliest_block_time(), Some(earliest));

    // And on an empty signal set both are `None` rather than a panic.
    let empty = chain_fixture_envelope(serde_json::json!([]), serde_json::json!({}));
    assert!(empty.latest_signal().is_none());
    assert!(empty.earliest_block_time().is_none());
}

/// A capture in which a later version confirmed in an EARLIER block fails as a
/// fixture problem, naming the two blocks, rather than surfacing later as a
/// confirmations mismatch that points at the resolver.
#[test]
#[should_panic(expected = "not ordered by version and height alike")]
fn chain_fixture_rejects_signals_whose_version_and_height_order_disagree() {
    let mut fixture = read_chain_fixture("minted/clean-rotating-beacons");
    let applied = fixture
        .applied_update_hash()
        .expect("a minted fixture carries its own sidecar");
    let lowest = fixture
        .signals
        .iter()
        .map(|signal| signal.block_height)
        .min()
        .expect("signals is non-empty");

    // Move the last update's announcement below every earlier one, the way a
    // reorg or a mempool race on a public chain would.
    for signal in &mut fixture.signals {
        if signal.update_hash == applied {
            signal.block_height = lowest - 1;
        }
    }
    assert_version_and_height_agree(&fixture, "minted/clean-rotating-beacons", "<rerun>");
}

/// An intermediate update announced below an earlier one fails, even though the
/// last update still sits in the highest block: the resolver scans a beacon
/// added by the earlier update at that update's block and would never find the
/// intermediate one, so it would stop before the last update.
#[test]
#[should_panic(expected = "may never find the later one")]
fn chain_fixture_rejects_an_intermediate_update_below_an_earlier_one() {
    let mut fixture = read_chain_fixture("minted/clean-rotating-beacons");
    let mut versions = fixture.sidecar_update_versions();
    versions.sort_by_key(|(_, version)| *version);
    let [(first, _), (middle, _), ..] = &versions[..] else {
        panic!("the clean scenario announces three updates: {versions:?}");
    };
    let first_height = fixture
        .signals
        .iter()
        .find(|signal| signal.update_hash == *first)
        .map(|signal| signal.block_height)
        .expect("the first update is announced");
    for signal in &mut fixture.signals {
        if signal.update_hash == *middle {
            signal.block_height = first_height - 1;
        }
    }
    // The last update is untouched and still in the highest block, so only
    // the version-order rule can reject this.
    let applied = fixture.applied_update_hash().expect("a minted sidecar");
    let highest = fixture.signals.iter().map(|s| s.block_height).max();
    assert_eq!(
        fixture.latest_signal().map(|s| s.block_height),
        highest,
        "{applied} still sits in the highest block"
    );
    assert_version_and_height_agree(&fixture, "minted/clean-rotating-beacons", "<rerun>");
}

/// v2 adds a beacon; v3 is announced on an older beacon in the highest block
/// and again on the new beacon below v2's block. The resolver scans the new
/// beacon at v2's block, never finds the lower copy, and measures from the
/// higher one — so the lowest announcement of the last update is not the
/// applied one, and the fixture is refused rather than asserted against it.
#[test]
#[should_panic(expected = "not ordered by version and height alike")]
fn chain_fixture_rejects_a_lower_copy_of_the_last_update() {
    let mut fixture = read_chain_fixture("minted/clean-rotating-beacons");
    let applied = fixture
        .applied_update_hash()
        .expect("a minted fixture carries its own sidecar");
    let lowest = fixture
        .signals
        .iter()
        .map(|signal| signal.block_height)
        .min()
        .expect("signals is non-empty");
    fixture.signals.push(CapturedSignal {
        address: "bcrt1qaddedbeacon".to_string(),
        txid: "d3".repeat(32),
        block_height: lowest - 1,
        block_time: 0,
        update_hash: applied,
    });
    assert_version_and_height_agree(&fixture, "minted/clean-rotating-beacons", "<rerun>");
}

/// An absent fixture stops the suite and the message says how to make it exist.
#[test]
#[should_panic(expected = "no captured chain fixture")]
fn chain_fixture_read_panics_on_an_unknown_vector_id() {
    let _ = read_chain_fixture("regtest/k1/nosuchvector");
}

/// A `signals` entry naming an address the capture never recorded cannot be
/// re-derived, so it fails on read.
#[test]
#[should_panic(expected = "the capture holds no response for")]
fn chain_fixture_signals_consistent_rejects_an_unknown_address() {
    let hash = "7a".repeat(32);
    let fixture = chain_fixture_envelope(
        serde_json::json!([{
            "address": "bcrt1qnever",
            "txid": "a1".repeat(32),
            "block_height": 660,
            "block_time": 1_774_015_945i64,
            "update_hash": hash,
        }]),
        serde_json::json!({ "bcrt1qcaptured": [] }),
    );
    assert_signals_consistent(&fixture, "regtest/k1/synthetic");
}

/// A `signals` entry naming a txid that is not under its own address is a
/// desynchronized fixture, not a resolvable one.
#[test]
#[should_panic(expected = "is not among the")]
fn chain_fixture_signals_consistent_rejects_an_absent_txid() {
    let hash = "7a".repeat(32);
    let fixture = chain_fixture_envelope(
        serde_json::json!([{
            "address": "bcrt1qcaptured",
            "txid": "b2".repeat(32),
            "block_height": 660,
            "block_time": 1_774_015_945i64,
            "update_hash": hash.clone(),
        }]),
        serde_json::json!({
            "bcrt1qcaptured": [
                chain_signal_tx_json(&hash, &"a1".repeat(32), 660, 1_774_015_945),
            ],
        }),
    );
    assert_signals_consistent(&fixture, "regtest/k1/synthetic");
}

/// A `signals` height that disagrees with the transaction's own confirmation
/// height would make a confirmations assertion compare against a stale copy.
#[test]
#[should_panic(expected = "block_height")]
fn chain_fixture_signals_consistent_rejects_a_block_height_mismatch() {
    let hash = "7a".repeat(32);
    let txid = "a1".repeat(32);
    let fixture = chain_fixture_envelope(
        serde_json::json!([{
            "address": "bcrt1qcaptured",
            "txid": txid,
            "block_height": 661,
            "block_time": 1_774_015_945i64,
            "update_hash": hash.clone(),
        }]),
        serde_json::json!({
            "bcrt1qcaptured": [chain_signal_tx_json(&hash, &txid, 660, 1_774_015_945)],
        }),
    );
    assert_signals_consistent(&fixture, "regtest/k1/synthetic");
}

/// The recorded `update_hash` must be exactly the LAST output's `6a20` push —
/// the same rule the resolver reads a signal by.
#[test]
#[should_panic(expected = "update_hash")]
fn chain_fixture_signals_consistent_rejects_a_wrong_update_hash() {
    let hash = "7a".repeat(32);
    let txid = "a1".repeat(32);
    let fixture = chain_fixture_envelope(
        serde_json::json!([{
            "address": "bcrt1qcaptured",
            "txid": txid,
            "block_height": 660,
            "block_time": 1_774_015_945i64,
            "update_hash": "cc".repeat(32),
        }]),
        serde_json::json!({
            "bcrt1qcaptured": [chain_signal_tx_json(&hash, &txid, 660, 1_774_015_945)],
        }),
    );
    assert_signals_consistent(&fixture, "regtest/k1/synthetic");
}

/// The consistency check passes on a well-formed synthetic envelope, so the
/// three rejection tests above are pinning the perturbation and not a check
/// that rejects everything.
#[test]
fn chain_fixture_signals_consistent_accepts_a_matching_envelope() {
    let hash = "7a".repeat(32);
    let txid = "a1".repeat(32);
    let fixture = chain_fixture_envelope(
        serde_json::json!([{
            "address": "bcrt1qcaptured",
            "txid": txid,
            "block_height": 660,
            "block_time": 1_774_015_945i64,
            "update_hash": hash.clone(),
        }]),
        serde_json::json!({
            "bcrt1qcaptured": [chain_signal_tx_json(&hash, &txid, 660, 1_774_015_945)],
            "bcrt1qempty": [],
        }),
    );
    assert_signals_consistent(&fixture, "regtest/k1/synthetic");
    assert_eq!(fixture.latest_signal().map(|s| s.block_height), Some(660));
}

/// Every committed chain fixture re-derives its own `signals` from its own
/// `addresses`. A hand edit or a partial re-capture fails here rather than in
/// whichever assertion happened to read the stale field.
#[test]
fn chain_fixture_every_committed_capture_is_self_consistent() {
    for id in ALL_CHAIN_FIXTURES {
        // `read_chain_fixture` runs `assert_signals_consistent` itself; a
        // fixture that no longer re-derives fails here, named.
        let fixture = read_chain_fixture(id);
        assert_ne!(fixture.tip_height, 0, "{id}: every capture pins a real tip");
    }
}

/// Every synthetic chain snapshot is its source capture, field for field, on
/// everything the chain says: the tip, the address histories, the block bodies,
/// the derived signals and the DID. Only the envelope differs — the vector name,
/// and no sidecar or expected result, because the set's own files carry those.
/// A copy that drifted from its source, or a hand-edited transaction, fails here
/// by name, so no chain data in a synthetic corpus can be invented.
#[test]
fn synthetic_chain_copies_equal_their_minted_source() {
    assert!(
        !SYNTHETIC_CHAIN_FIXTURES.is_empty(),
        "the synthetic chain list must name at least the options corpus"
    );
    let raw = |path: &Path| -> serde_json::Value {
        serde_json::from_str(
            &std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display())),
        )
        .unwrap_or_else(|e| panic!("{} must be JSON: {e}", path.display()))
    };
    for (corpus, id, source) in SYNTHETIC_CHAIN_FIXTURES {
        assert!(
            ALL_CHAIN_FIXTURES.contains(source),
            "{corpus}/{id}: its source {source} is not a committed capture"
        );
        let chain_root = Corpus::synthetic(corpus).chain;
        // Parsed through the replay's own reader, so the copy also passes the
        // on-read signal checks.
        let copy = read_chain_fixture_in(&chain_root, id);
        assert!(
            copy.sidecar.is_none() && copy.expected.is_none(),
            "{corpus}/{id}: a synthetic chain copy carries no sidecar or expected result; the \
             set's own files carry those"
        );

        let copy_raw = raw(&chain_root.join(format!("{id}.json")));
        let source_raw = raw(&chain_fixture_path(source));
        for field in [
            "tip_height",
            "addresses",
            "blocks",
            "signals",
            "did",
            "network",
        ] {
            assert_eq!(
                copy_raw[field], source_raw[field],
                "{corpus}/{id}: `{field}` must equal the source capture {source}"
            );
        }
        assert_eq!(
            copy_raw["vector"], *id,
            "{corpus}/{id}: the copy is named for its set"
        );
    }
}

/// A chain copy at an earlier tip equals its source on every chain field but
/// `tip_height`, holds no transaction above that tip, and its set's
/// `signals.json` records that tip.
#[test]
fn synthetic_chain_copies_at_an_earlier_tip_equal_their_source_below_it() {
    let raw = |path: &Path| -> serde_json::Value {
        serde_json::from_str(
            &std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display())),
        )
        .unwrap_or_else(|e| panic!("{} must be JSON: {e}", path.display()))
    };
    for (corpus, id, source, tip) in SYNTHETIC_CHAIN_FIXTURES_AT_EARLIER_TIP {
        assert!(
            ALL_CHAIN_FIXTURES.contains(source),
            "{corpus}/{id}: its source {source} is not a committed capture"
        );
        let synthetic = Corpus::synthetic(corpus);
        let copy = read_chain_fixture_in(&synthetic.chain, id);
        assert!(copy.sidecar.is_none() && copy.expected.is_none());
        assert_eq!(copy.tip_height, *tip, "{corpus}/{id}: the copy's tip");

        let source_fixture = read_chain_fixture(source);
        assert!(
            *tip < source_fixture.tip_height,
            "{corpus}/{id}: {tip} is not earlier than the source's {}",
            source_fixture.tip_height
        );
        for tx in source_fixture.addresses.values().flatten() {
            let Status::Confirmed { block_height, .. } = &tx.status else {
                panic!(
                    "{corpus}/{id}: source transaction {} is unconfirmed",
                    tx.txid
                );
            };
            assert!(
                block_height <= tip,
                "{corpus}/{id}: source transaction {} confirmed at {block_height}, above the \
                 copy's tip {tip}, so a capture at that tip would not hold it as recorded",
                tx.txid
            );
        }

        let copy_raw = raw(&synthetic.chain.join(format!("{id}.json")));
        let source_raw = raw(&chain_fixture_path(source));
        for field in ["addresses", "blocks", "signals", "did", "network"] {
            assert_eq!(
                copy_raw[field], source_raw[field],
                "{corpus}/{id}: `{field}` must equal the source capture {source}"
            );
        }
        assert_eq!(copy_raw["vector"], *id);

        let vectors = discover_in(&synthetic);
        let vector = vectors
            .iter()
            .find(|v| v.id == *id)
            .unwrap_or_else(|| panic!("{corpus}: the set {id} is discovered"));
        let signals = vector.signals.as_ref().expect("the set ships signals.json");
        assert_eq!(
            signals.recorded_tip, *tip,
            "{corpus}/{id}: signals.json records the copy's tip"
        );
    }
}

/// The options corpus's `signals.json` records the tip its expected outputs
/// were computed against, and that tip is the tip its chain copy was read at.
/// If they differed, every recorded `confirmations` would be measured against
/// a chain the replay does not serve.
#[test]
fn synthetic_signals_record_the_capture_tip() {
    let corpus = Corpus::synthetic("options");
    let vectors = discover_in(&corpus);
    assert_eq!(vectors.len(), 1, "the options corpus holds one set");
    for vector in &vectors {
        let signals = vector
            .signals
            .as_ref()
            .unwrap_or_else(|| panic!("{}: the options set carries signals.json", vector.id));
        let fixture = read_chain_fixture_in(&corpus.chain, &vector.id);
        assert_eq!(
            signals.recorded_tip, fixture.tip_height,
            "{}: signals.json recordedTip must equal the chain copy's tip_height",
            vector.id
        );
    }
}

/// `signal_block_hashes` reads each signal's confirming block off its address
/// body, and `earliest_signal_mediantime` is the minimum over the `/block`
/// bodies for those hashes — or names the first hash the fixture lacks.
#[test]
fn chain_fixture_signal_blocks_and_earliest_mediantime() {
    let hash_a = "aa".repeat(32);
    let hash_b = "bb".repeat(32);
    let mut tx1 = chain_signal_tx_json(&"11".repeat(32), &"01".repeat(32), 100, 1_700_000_000);
    tx1["status"]["block_hash"] = serde_json::json!(hash_a);
    let mut tx2 = chain_signal_tx_json(&"22".repeat(32), &"02".repeat(32), 101, 1_700_000_100);
    tx2["status"]["block_hash"] = serde_json::json!(hash_b);
    let signals = serde_json::json!([
        { "address": "bcrt1qa", "txid": "01".repeat(32), "block_height": 100,
          "block_time": 1_700_000_000, "update_hash": "11".repeat(32) },
        { "address": "bcrt1qa", "txid": "02".repeat(32), "block_height": 101,
          "block_time": 1_700_000_100, "update_hash": "22".repeat(32) },
    ]);
    let addresses = serde_json::json!({ "bcrt1qa": [tx1, tx2] });

    let mut fixture = chain_fixture_envelope(signals, addresses);
    assert_eq!(
        fixture.signal_block_hashes(),
        BTreeSet::from([hash_a.clone(), hash_b.clone()])
    );
    assert_eq!(
        fixture.earliest_signal_mediantime(),
        Err(hash_a.clone()),
        "with no block bodies the first missing hash is named"
    );

    fixture.blocks.insert(
        hash_a.clone(),
        serde_json::json!({ "id": hash_a, "mediantime": 1_699_999_000 }),
    );
    assert_eq!(
        fixture.earliest_signal_mediantime(),
        Err(hash_b.clone()),
        "one block is not enough: the other is named"
    );
    fixture.blocks.insert(
        hash_b.clone(),
        serde_json::json!({ "id": hash_b, "mediantime": 1_699_998_000 }),
    );
    assert_eq!(
        fixture.earliest_signal_mediantime(),
        Ok(1_699_998_000),
        "the earliest mediantime, which is not the earliest header time's block"
    );

    let empty = chain_fixture_envelope(serde_json::json!([]), serde_json::json!({}));
    assert!(empty.signal_block_hashes().is_empty());
    assert!(empty.earliest_signal_mediantime().is_err());
}

/// A CAS or SMT beacon in the genesis document is TWO distinct blockers: how
/// the document or announcement is delivered, and whether the resolver will
/// issue a request for that beacon type at all. Both are recorded, because each
/// is fixed in different code.
#[test]
fn unsupported_beacon_type_is_recorded_alongside_the_delivery_reason() {
    assert_eq!(
        derived_resolve_skip_reasons(
            &delivery_of(GenesisDelivery::Sidecar, None),
            &["SingletonBeacon".into(), "SMTBeacon".into()]
        ),
        BTreeSet::from([SkipReason::SmtDelivery, SkipReason::UnsupportedBeaconType])
    );
    assert_eq!(
        derived_resolve_skip_reasons(
            &delivery_of(GenesisDelivery::Sidecar, None),
            &["CASBeacon".into()]
        ),
        BTreeSet::from([SkipReason::CasDelivery, SkipReason::UnsupportedBeaconType])
    );
}

/// A drivable beacon and a service that is not a beacon at all say nothing
/// about whether the resolver can query a beacon, so neither contributes a
/// reason.
#[test]
fn unsupported_beacon_type_ignores_singleton_and_non_beacon_services() {
    assert_eq!(
        derived_resolve_skip_reasons(
            &delivery_of(GenesisDelivery::Sidecar, None),
            &[
                "SingletonBeacon".into(),
                "DIDCommMessaging".into(),
                "DecentralizedWebNode".into(),
            ]
        ),
        BTreeSet::new()
    );
}

/// The DELIVERY rule is about a mechanism, not about a beacon the document
/// declares: a CAS-delivered genesis document with no CAS beacon service leaves
/// the resolver perfectly able to query the beacons it does declare.
#[test]
fn unsupported_beacon_type_does_not_follow_from_a_delivery_declaration() {
    assert_eq!(
        derived_resolve_skip_reasons(
            &delivery_of(GenesisDelivery::Cas, Some(AnnouncementDelivery::Cas)),
            &[]
        ),
        BTreeSet::from([SkipReason::CasDelivery])
    );
}

/// The scenario number of a discovered set: the leading segment of its
/// `other.json.scenarioId` (`09a` for `09a-x1-cas-update-announcement`). Every
/// network ships the same scenarios under different ids, so the corpus pins
/// below name scenarios and check them on every network.
fn scenario_number(v: &Vector) -> &str {
    let id = v
        .scenario_id
        .as_deref()
        .unwrap_or_else(|| panic!("{}: other.json must name its scenario", v.id));
    id.split('-').next().unwrap_or(id)
}

/// The networks the checked-out suite ships vectors for.
const LIVE_NETWORKS: [&str; 4] = ["mutinynet", "regtest", "signet", "testnet4"];

/// `(network, scenario)` pairs for every live network and each named scenario.
fn on_every_network(scenarios: &[&str]) -> BTreeSet<(String, String)> {
    LIVE_NETWORKS
        .iter()
        .flat_map(|n| {
            scenarios
                .iter()
                .map(move |s| (n.to_string(), s.to_string()))
        })
        .collect()
}

/// The scenarios whose genesis document declares a CAS or SMT beacon.
const CAS_OR_SMT_BEACON_SCENARIOS: [&str; 14] = [
    "09a", "09b", "10a", "10b", "11a", "11b", "12a", "12b", "25a", "25b", "25c", "n29", "n30",
    "n31",
];

/// The scenarios whose genesis or updates are CAS-delivered while their genesis
/// document declares no CAS or SMT beacon.
const CAS_DELIVERY_ONLY_SCENARIOS: [&str; 4] = ["05", "06", "08", "20"];

/// The reason fires on exactly the discovered vectors whose genesis document
/// declares a CAS or SMT beacon, and on no others. Pinned as an exact scenario
/// set on every network so an upstream vector gaining or losing such a beacon
/// fails by name rather than quietly moving the aggregation milestone's target
/// set.
#[test]
fn live_vectors_name_the_beacon_types_the_resolver_cannot_query() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    assert!(!vectors.is_empty());

    let observed: BTreeSet<(String, String)> = vectors
        .iter()
        .filter(|v| {
            v.skip_reasons_with(AssertionKind::Resolve, &[])
                .contains(&SkipReason::UnsupportedBeaconType)
        })
        .map(|v| (v.network_dir.clone(), scenario_number(v).to_string()))
        .collect();

    assert_eq!(
        observed,
        on_every_network(&CAS_OR_SMT_BEACON_SCENARIOS),
        "the scenarios whose genesis document declares a CAS or SMT beacon"
    );
    assert_eq!(observed.len(), 56, "14 scenarios on each of four networks");

    // And the reason scopes to Resolve, like every other derived reason.
    for v in &vectors {
        for kind in [
            AssertionKind::Derivation,
            AssertionKind::GenesisKey,
            AssertionKind::UpdateCrypto,
            AssertionKind::EndState,
        ] {
            assert!(
                !v.skip_reasons_with(kind, &[])
                    .contains(&SkipReason::UnsupportedBeaconType),
                "{}: {kind} must not inherit a resolve-scoped reason",
                v.id
            );
        }
    }
}

/// The rows the resolve driver is expected to drive, pinned BY SCENARIO on
/// every network: every set except the CAS/SMT-beacon ones and the
/// CAS-delivered ones, 41 per network.
///
/// [`DRIVEN_FLOOR`] alone would say only that the number moved. This says WHICH
/// row moved. A vector losing its sidecar genesis document, or an upstream
/// vector arriving with a shape the rules classify differently, fails here
/// naming the difference, instead of being absorbed by a `>=` ratchet.
#[test]
fn resolve_driven_set_is_every_set_outside_the_cas_and_smt_scenarios() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    assert!(!vectors.is_empty());

    let observed = expected_driven_with(AssertionKind::Resolve, &vectors, &[]);

    let expected: BTreeSet<RowKey> = vectors
        .iter()
        .filter(|v| {
            let scenario = scenario_number(v);
            !CAS_OR_SMT_BEACON_SCENARIOS.contains(&scenario)
                && !CAS_DELIVERY_ONLY_SCENARIOS.contains(&scenario)
        })
        .map(|v| RowKey::set(v.id.clone()))
        .collect();

    let missing: Vec<&RowKey> = expected.difference(&observed).collect();
    let extra: Vec<&RowKey> = observed.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "the resolve driven set moved.\n  \
         expected but not driven ({}): {missing:?}\n  \
         driven but not expected ({}): {extra:?}\n  \
         Update the scenario lists together with DRIVEN_FLOOR, or restore the row.",
        missing.len(),
        extra.len(),
    );
    for network in LIVE_NETWORKS {
        assert_eq!(
            observed
                .iter()
                .filter(|row| row.vector.starts_with(&format!("{network}/")))
                .count(),
            41,
            "{network} drives 41 resolve rows"
        );
    }
    assert_eq!(observed.len(), 164, "the floor and this set must agree");
}

/// `Override` stays LAST in the derived ordering: `PartialOrd`/`Ord` are derived
/// and the summary keys a `BTreeMap` on this enum, so variant order is report
/// order and a hand-written skip belongs at the bottom of the table.
#[test]
fn override_still_sorts_after_every_derived_reason() {
    let ordered: Vec<SkipReason> = BTreeSet::from([
        SkipReason::Override("a one-off"),
        SkipReason::ExpectedError,
        SkipReason::UnsupportedBeaconType,
        SkipReason::SmtDelivery,
        SkipReason::CasDelivery,
    ])
    .into_iter()
    .collect();

    assert_eq!(
        ordered,
        vec![
            SkipReason::CasDelivery,
            SkipReason::SmtDelivery,
            SkipReason::UnsupportedBeaconType,
            SkipReason::ExpectedError,
            SkipReason::Override("a one-off"),
        ]
    );
}

// --- Rows, resolve cases and expected errors ----------------------------------

/// A `ResolveCase` named `name` expecting a version-1 document.
fn positive_case(name: &str) -> ResolveCase {
    ResolveCase {
        name: name.to_string(),
        outcome: positive_outcome(1),
    }
}

/// A set whose main resolve pair expects `NOT_FOUND`, with one update step, so
/// every kind but the resolve-option one applies.
fn negative_vector(id: &str, kind: &str) -> Vector {
    let mut v = synthetic_vector(id, kind);
    v.outcome = Outcome::Error {
        code: "NOT_FOUND".into(),
    };
    v.delivery.negative = true;
    v.delivery.announcement = Some(AnnouncementDelivery::Sidecar);
    v.update_layout = UpdateLayout::Flat;
    v
}

/// A set-level row prints as the set id, a case row as `{id} resolve/{NN}`,
/// and set rows sort before the case rows of the same set.
#[test]
fn row_key_displays_a_set_and_a_case() {
    assert_eq!(RowKey::set("a/k1/x").to_string(), "a/k1/x");
    assert_eq!(
        RowKey::case("a/k1/x", "03").to_string(),
        "a/k1/x resolve/03"
    );
    assert!(RowKey::set("a/k1/x") < RowKey::case("a/k1/x", "01"));
    assert!(RowKey::case("a/k1/x", "01") < RowKey::case("a/k1/x", "02"));
    assert_ne!(RowKey::set("a/k1/x"), RowKey::case("a/k1/x", "01"));
}

/// One resolve-option row per `resolve/NN` case, in case order; none when the
/// set ships only the main pair. Every other kind keeps its one set-level row.
#[test]
fn resolve_option_has_one_row_per_case() {
    let mut v = synthetic_vector("mutinynet/k1/q5puld7y", "k1");
    assert!(v.rows(AssertionKind::ResolveOption).is_empty());
    assert!(!v.applicable_kinds().contains(&AssertionKind::ResolveOption));

    v.resolve_cases = vec![positive_case("01"), positive_case("02")];
    assert_eq!(
        v.rows(AssertionKind::ResolveOption),
        vec![
            RowKey::case("mutinynet/k1/q5puld7y", "01"),
            RowKey::case("mutinynet/k1/q5puld7y", "02"),
        ]
    );
    assert_eq!(
        v.rows(AssertionKind::Resolve),
        vec![RowKey::set("mutinynet/k1/q5puld7y")]
    );
    // Not applicable: no update steps, so no rows.
    assert!(v.rows(AssertionKind::UpdateCrypto).is_empty());

    // Both cases are driven; the ledger counts each.
    assert_eq!(
        expected_driven_with(AssertionKind::ResolveOption, std::slice::from_ref(&v), &[]),
        BTreeSet::from([
            RowKey::case("mutinynet/k1/q5puld7y", "01"),
            RowKey::case("mutinynet/k1/q5puld7y", "02"),
        ])
    );
}

/// A resolve case inherits exactly its set's derived Resolve reasons: a case of
/// a set with a CAS beacon is as undeliverable as the main pair, and so is a
/// case of a set whose genesis document is CAS-delivered.
#[test]
fn resolve_option_inherits_the_sets_resolve_reasons() {
    let mut v = synthetic_vector("mutinynet/x1/q4lqu6gr", "x1");
    v.resolve_cases = vec![positive_case("01"), positive_case("02")];
    v.genesis_service_types = vec!["CASBeacon".into()];

    let set_reasons = v.skip_reasons_with(AssertionKind::Resolve, &[]);
    assert!(set_reasons.contains(&SkipReason::CasDelivery));
    for case in ["01", "02"] {
        let case_reasons = v.row_skip_reasons(AssertionKind::ResolveOption, Some(case), &[]);
        assert!(case_reasons.contains(&SkipReason::CasDelivery), "{case}");
        assert_eq!(
            case_reasons, set_reasons,
            "case {case} inherits the set's reasons"
        );
        assert!(!v.should_drive_row_with(AssertionKind::ResolveOption, Some(case), &[]));
    }

    v.genesis_service_types = vec!["SMTBeacon".into()];
    v.delivery.genesis = GenesisDelivery::Cas;
    assert_eq!(
        v.row_skip_reasons(AssertionKind::ResolveOption, Some("01"), &[]),
        BTreeSet::from([
            SkipReason::CasDelivery,
            SkipReason::SmtDelivery,
            SkipReason::UnsupportedBeaconType,
        ])
    );

    // Summary: two skipped resolve-option rows, each counted under every reason.
    let summary = render_summary_with(std::slice::from_ref(&v), &[]);
    assert!(
        summary
            .lines()
            .any(|line| line.trim_start().starts_with("resolve-option")
                && line.split_whitespace().collect::<Vec<_>>() == ["resolve-option", "0", "2"]),
        "{summary}"
    );
}

/// A resolve case needs the same inputs as the main pair: an external set with
/// no sidecar genesis document cannot drive either, and with no derived reason
/// both rows are reported unclassified, the case row by its case key.
#[test]
fn resolve_option_drivability_follows_resolve() {
    let mut v = synthetic_vector("mutinynet/x1/__orphan__", "x1");
    v.resolve_cases = vec![positive_case("01")];
    assert!(v.is_drivable(AssertionKind::ResolveOption));

    v.has_sidecar_genesis_document = false;
    assert!(!v.is_drivable(AssertionKind::Resolve));
    assert!(!v.is_drivable(AssertionKind::ResolveOption));

    let rows = unclassified_rows_with(std::slice::from_ref(&v), &[]);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter()
            .any(|r| r.contains("mutinynet/x1/__orphan__ resolve/01 :: resolve-option")),
        "{rows:?}"
    );
}

/// A driver that walked past one resolve case fails reconciliation naming the
/// case, not just the set.
#[test]
fn resolve_option_reconcile_names_the_missing_case() {
    let mut v = synthetic_vector("regtest/k1/qgpakaw4", "k1");
    v.resolve_cases = vec![positive_case("01"), positive_case("02")];
    let vectors = vec![v];

    let observed = BTreeSet::from([RowKey::case("regtest/k1/qgpakaw4", "01")]);
    let message = reconcile_panic_message(AssertionKind::ResolveOption, &vectors, &observed);
    assert!(
        message.contains("regtest/k1/qgpakaw4 resolve/02")
            && message.contains("expected but not driven"),
        "{message}"
    );
    // A set-level key is not a resolve-option row.
    let mut observed = expected_driven_with(AssertionKind::ResolveOption, &vectors, &[]);
    observed.insert(RowKey::set("regtest/k1/qgpakaw4"));
    let message = reconcile_panic_message(AssertionKind::ResolveOption, &vectors, &observed);
    assert!(message.contains("driven but not expected"), "{message}");
}

/// An override naming one resolve case skips that case alone. One naming a
/// case the set does not ship, a resolve-option entry without a case, and a
/// set-level entry with a case all match nothing and are reported stale.
#[test]
fn resolve_option_override_names_one_case() {
    const REASON: &str = "the case's options exercise an unimplemented feature";
    const ONE_CASE: &[SkipOverride] = &[SkipOverride {
        vector: "regtest/k1/qgpakaw4",
        kind: AssertionKind::ResolveOption,
        case: Some("02"),
        reason: REASON,
    }];
    let mut v = synthetic_vector("regtest/k1/qgpakaw4", "k1");
    v.resolve_cases = vec![positive_case("01"), positive_case("02")];
    let vectors = vec![v.clone()];

    assert!(v.should_drive_row_with(AssertionKind::ResolveOption, Some("01"), ONE_CASE));
    assert!(!v.should_drive_row_with(AssertionKind::ResolveOption, Some("02"), ONE_CASE));
    assert_eq!(
        v.row_skip_reasons(AssertionKind::ResolveOption, Some("02"), ONE_CASE),
        BTreeSet::from([SkipReason::Override(REASON)])
    );
    assert!(
        v.should_drive_with(AssertionKind::Resolve, ONE_CASE),
        "the main pair is untouched"
    );
    assert_eq!(
        expected_driven_with(AssertionKind::ResolveOption, &vectors, ONE_CASE),
        BTreeSet::from([RowKey::case("regtest/k1/qgpakaw4", "01")])
    );
    assert!(stale_overrides(ONE_CASE, &vectors).is_empty());
    assert!(unclassified_rows_with(&vectors, ONE_CASE).is_empty());
    assert!(redundant_overrides(&vectors, ONE_CASE).is_empty());

    const MISSING_CASE: &[SkipOverride] = &[SkipOverride {
        vector: "regtest/k1/qgpakaw4",
        kind: AssertionKind::ResolveOption,
        case: Some("99"),
        reason: REASON,
    }];
    let rows = stale_overrides(MISSING_CASE, &vectors);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0].contains("regtest/k1/qgpakaw4 resolve/99") && rows[0].contains("stale SKIP"),
        "{}",
        rows[0]
    );

    const NO_CASE: &[SkipOverride] = &[SkipOverride {
        vector: "regtest/k1/qgpakaw4",
        kind: AssertionKind::ResolveOption,
        case: None,
        reason: REASON,
    }];
    assert_eq!(stale_overrides(NO_CASE, &vectors).len(), 1);

    const CASE_ON_SET_KIND: &[SkipOverride] = &[SkipOverride {
        vector: "regtest/k1/qgpakaw4",
        kind: AssertionKind::Resolve,
        case: Some("01"),
        reason: REASON,
    }];
    assert_eq!(stale_overrides(CASE_ON_SET_KIND, &vectors).len(), 1);
    assert!(
        v.should_drive_with(AssertionKind::Resolve, CASE_ON_SET_KIND),
        "a case-bearing entry never matches the set-level row"
    );
}

/// On a negative set, the update-crypto and end-state rows skip with
/// `ExpectedError`; the Resolve row carries the assertion, and derivation and
/// genesis-key stay driven because `create/` still holds a valid DID.
#[test]
fn expected_error_skips_the_update_rows_of_a_negative_set() {
    let v = negative_vector("regtest/k1/qgppexmy", "k1");
    assert!(v.is_negative());

    for kind in [AssertionKind::UpdateCrypto, AssertionKind::EndState] {
        assert_eq!(
            v.skip_reasons_with(kind, &[]),
            BTreeSet::from([SkipReason::ExpectedError]),
            "{kind}"
        );
        assert!(!v.should_drive_with(kind, &[]), "{kind}");
    }
    for kind in [
        AssertionKind::Derivation,
        AssertionKind::GenesisKey,
        AssertionKind::Resolve,
    ] {
        assert!(
            v.skip_reasons_with(kind, &[]).is_empty(),
            "{kind}: {:?}",
            v.skip_reasons_with(kind, &[])
        );
        assert!(v.should_drive_with(kind, &[]), "{kind}");
    }

    // A derived reason, so the summary counts it and a hand-written skip on
    // the same row is redundant.
    let summary = render_summary_with(std::slice::from_ref(&v), &[]);
    assert!(
        summary.contains(&SkipReason::ExpectedError.to_string()),
        "{summary}"
    );
    const OVERRIDES: &[SkipOverride] = &[SkipOverride {
        vector: "regtest/k1/qgppexmy",
        kind: AssertionKind::EndState,
        case: None,
        reason: "the set fails resolution",
    }];
    let rows = redundant_overrides(std::slice::from_ref(&v), OVERRIDES);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].contains("end-state") && rows[0].contains("redundant"));
}

/// A positive set never carries `ExpectedError`, on any kind, whatever else
/// applies to it.
#[test]
fn expected_error_never_applies_to_a_positive_set() {
    let mut v = synthetic_vector("mutinynet/x1/q5m2fh36", "x1");
    v.update_layout = UpdateLayout::Numbered(vec!["01".into(), "02".into()]);
    v.resolve_cases = vec![positive_case("01")];
    v.delivery.genesis = GenesisDelivery::Cas;
    v.genesis_service_types = vec!["CASBeacon".into()];
    // A negative resolve CASE does not make the set negative: only the main
    // pair decides.
    v.resolve_cases.push(ResolveCase {
        name: "02".into(),
        outcome: Outcome::Error {
            code: "INVALID_DID".into(),
        },
    });
    assert!(!v.is_negative());

    for kind in AssertionKind::ALL {
        for row in v.rows(kind) {
            assert!(
                !v.row_skip_reasons(kind, row.case.as_deref(), &[])
                    .contains(&SkipReason::ExpectedError),
                "{row} :: {kind}"
            );
        }
    }
}

/// The resolve-option kind is the last line of the kind table, after end-state.
#[test]
fn resolve_option_is_listed_after_end_state_in_the_summary() {
    let summary = render_summary_with(&synthetic_ledger(), &[]);
    let end_state = summary.find("  end-state ").expect("end-state line");
    let resolve_option = summary
        .find("  resolve-option ")
        .expect("resolve-option line");
    assert!(end_state < resolve_option, "{summary}");
    assert!(
        summary.contains("  resolve-option       0        0\n"),
        "no case in the synthetic ledger:\n{summary}"
    );
}

// --- Error-code divergences ---------------------------------------------------

/// A one-entry divergence table for the guard tests.
const LATE: &[CodeDivergence] = &[CodeDivergence {
    vector_code: "LATE_PUBLISHING_ERROR",
    spec_code: "LATE_PUBLISHING",
    issue: "x",
}];

/// A driven set whose main resolve pair expects `code`.
fn negative_main(id: &str, kind: &str, code: &str) -> Vector {
    let mut v = synthetic_vector(id, kind);
    v.outcome = Outcome::Error {
        code: code.to_string(),
    };
    v.delivery.negative = true;
    v
}

/// A listed vector code maps to the specification's code.
#[test]
fn divergence_maps_a_listed_code_to_the_spec_code() {
    assert_eq!(
        expected_emitted_code("LATE_PUBLISHING_ERROR", LATE),
        "LATE_PUBLISHING"
    );
}

/// An unlisted code is expected verbatim, and an empty table changes nothing.
#[test]
fn divergence_leaves_an_unlisted_code_alone() {
    assert_eq!(expected_emitted_code("NOT_FOUND", LATE), "NOT_FOUND");
    assert_eq!(
        expected_emitted_code("LATE_PUBLISHING_ERROR", &[]),
        "LATE_PUBLISHING_ERROR"
    );
}

/// An entry no vector records is reported by name and told to go.
#[test]
fn divergence_unused_by_any_negative_case_is_reported() {
    let vectors = vec![synthetic_vector("regtest/k1/qgpakaw4", "k1")];
    let rows = unused_divergences(&vectors, &[], LATE);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0].contains("LATE_PUBLISHING_ERROR")
            && rows[0].contains("LATE_PUBLISHING (x)")
            && rows[0].contains("delete the entry"),
        "{}",
        rows[0]
    );

    // A negative set with a different code does not use it either.
    let other = vec![negative_main("regtest/k1/qgpakaw4", "k1", "NOT_FOUND")];
    assert_eq!(unused_divergences(&other, &[], LATE).len(), 1);
}

/// A driven main pair recording the vector code is a use.
#[test]
fn divergence_used_by_a_driven_main_pair_is_not_reported() {
    let vectors = vec![negative_main(
        "regtest/k1/qgpakaw4",
        "k1",
        "LATE_PUBLISHING_ERROR",
    )];
    assert!(vectors[0].should_drive_with(AssertionKind::Resolve, &[]));
    assert!(unused_divergences(&vectors, &[], LATE).is_empty());
}

/// A driven `resolve/NN` case recording the vector code is a use, even when
/// the set's main pair is positive.
#[test]
fn divergence_used_by_a_driven_resolve_case_is_not_reported() {
    let mut v = synthetic_vector("regtest/k1/qgpakaw4", "k1");
    v.resolve_cases = vec![
        ResolveCase {
            name: "01".into(),
            outcome: positive_outcome(1),
        },
        ResolveCase {
            name: "02".into(),
            outcome: Outcome::Error {
                code: "LATE_PUBLISHING_ERROR".into(),
            },
        },
    ];
    let vectors = vec![v];
    assert!(unused_divergences(&vectors, &[], LATE).is_empty());

    // Skipping that case by hand removes the only use.
    const SKIP_CASE: &[SkipOverride] = &[SkipOverride {
        vector: "regtest/k1/qgpakaw4",
        kind: AssertionKind::ResolveOption,
        case: Some("02"),
        reason: "stands in for a hand-written skip",
    }];
    assert_eq!(unused_divergences(&vectors, SKIP_CASE, LATE).len(), 1);
}

/// A matching outcome on a skipped row asserts nothing, so it does not keep
/// the entry alive: a CAS-delivered set's main pair, and the same set's case.
#[test]
fn divergence_on_a_skipped_row_does_not_count_as_a_use() {
    let mut v = negative_main("mutinynet/x1/q4lqu6gr", "x1", "LATE_PUBLISHING_ERROR");
    v.genesis_service_types = vec!["CASBeacon".into()];
    v.resolve_cases = vec![ResolveCase {
        name: "01".into(),
        outcome: Outcome::Error {
            code: "LATE_PUBLISHING_ERROR".into(),
        },
    }];
    assert!(
        v.skip_reasons_with(AssertionKind::Resolve, &[])
            .contains(&SkipReason::CasDelivery)
    );
    let rows = unused_divergences(std::slice::from_ref(&v), &[], LATE);
    assert_eq!(rows.len(), 1, "{rows:?}");

    // The same set, driven, uses it.
    v.genesis_service_types.clear();
    assert!(unused_divergences(std::slice::from_ref(&v), &[], LATE).is_empty());
}

/// An entry whose two codes are equal is not a divergence, and two entries for
/// one vector code give two answers; both are reported. A well-formed table
/// reports nothing.
#[test]
fn divergence_table_malformations_are_reported() {
    assert!(malformed_divergences(LATE).is_empty());
    assert!(malformed_divergences(&[]).is_empty());

    const EQUAL: &[CodeDivergence] = &[CodeDivergence {
        vector_code: "NOT_FOUND",
        spec_code: "NOT_FOUND",
        issue: "y",
    }];
    let rows = malformed_divergences(EQUAL);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0].contains("NOT_FOUND") && rows[0].contains("equal"),
        "{}",
        rows[0]
    );

    const DUPLICATE: &[CodeDivergence] = &[
        CodeDivergence {
            vector_code: "LATE_PUBLISHING_ERROR",
            spec_code: "LATE_PUBLISHING",
            issue: "x",
        },
        CodeDivergence {
            vector_code: "LATE_PUBLISHING_ERROR",
            spec_code: "INVALID_DID_UPDATE",
            issue: "z",
        },
    ];
    let rows = malformed_divergences(DUPLICATE);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0].contains("LATE_PUBLISHING_ERROR is listed 2 times"),
        "{}",
        rows[0]
    );
}

/// The live table is well formed and every entry in it is used by a driven
/// negative case of the checked-out suite.
#[test]
fn live_error_code_divergences_are_used_and_well_formed() {
    let malformed = malformed_divergences(ERROR_CODE_DIVERGENCES);
    assert!(
        malformed.is_empty(),
        "malformed ERROR_CODE_DIVERGENCES entries:\n{}",
        malformed.join("\n")
    );

    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    assert!(!vectors.is_empty());
    let unused = unused_divergences(&vectors, SKIP_OVERRIDES, ERROR_CODE_DIVERGENCES);
    assert!(
        unused.is_empty(),
        "unused ERROR_CODE_DIVERGENCES entries:\n{}",
        unused.join("\n")
    );
}

// --- signals.json -------------------------------------------------------------

/// One well-formed `signals.json` entry. `update` and `cohort` are the members
/// the rules key on; each test perturbs the rest by hand.
fn signal_entry(
    update: Option<u64>,
    block_height: u32,
    cohort: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "beaconId": "did:btcr2:k1qsynthetic#initialP2WPKH",
        "address": "bcrt1qsyntheticbeacon",
        "txid": "a1".repeat(32),
        "blockHeight": block_height,
        "blockHash": "b2".repeat(32),
        "blockTime": 1_789_000_000i64,
        "mediantime": 1_788_999_900i64,
        "signalBytes": "c3".repeat(32),
        "recordedTip": 601,
    });
    if let Some(update) = update {
        entry["update"] = serde_json::json!(update);
    }
    if let Some(cohort) = cohort {
        entry["cohort"] = cohort;
    }
    entry
}

/// A two-member cohort object.
fn cohort_json() -> serde_json::Value {
    serde_json::json!({ "id": "cas-09", "members": ["09a-first", "09b-second"] })
}

/// `parse_signals` over `entries`, with the context the tests look for.
fn signals_from(entries: serde_json::Value, layout: &UpdateLayout) -> Result<Signals, String> {
    parse_signals(
        &entries.to_string(),
        "regtest/k1/synthetic/signals.json",
        layout,
    )
}

/// Two numbered update steps.
fn two_steps() -> UpdateLayout {
    UpdateLayout::Numbered(vec!["01".into(), "02".into()])
}

/// A single well-formed entry parses, every member lands in its field, and the
/// file's tip is the entry's `recordedTip`.
#[test]
fn signals_parse_a_single_entry() {
    let signals = signals_from(
        serde_json::json!([signal_entry(Some(1), 300, None)]),
        &two_steps(),
    )
    .expect("a well-formed entry parses");
    assert_eq!(signals.recorded_tip, 601);
    assert_eq!(signals.entries.len(), 1);
    let entry = &signals.entries[0];
    assert_eq!(entry.update, Some(1));
    assert!(!entry.duplicate);
    assert_eq!(entry.beacon_id, "did:btcr2:k1qsynthetic#initialP2WPKH");
    assert_eq!(entry.address, "bcrt1qsyntheticbeacon");
    assert_eq!(entry.txid, "a1".repeat(32));
    assert_eq!(entry.block_height, 300);
    assert_eq!(entry.block_hash, "b2".repeat(32));
    assert_eq!(entry.block_time, 1_789_000_000);
    assert_eq!(entry.mediantime, 1_788_999_900);
    assert_eq!(entry.signal_bytes, "c3".repeat(32));
    assert_eq!(entry.recorded_tip, 601);
    assert_eq!(entry.cohort, None);
}

/// The file is a bare array; the wrapper object an earlier proposal used is
/// rejected by name.
#[test]
fn signals_reject_an_object() {
    let err = signals_from(serde_json::json!({ "entries": [] }), &two_steps())
        .expect_err("an object is not the file's shape");
    assert!(
        err.contains("bare array") && err.contains("regtest/k1/synthetic/signals.json"),
        "{err}"
    );
}

/// An empty array has no entry to carry `recordedTip`.
#[test]
fn signals_reject_an_empty_array() {
    let err = signals_from(serde_json::json!([]), &two_steps())
        .expect_err("an empty file records nothing");
    assert!(err.contains("recordedTip"), "{err}");
}

/// Every entry of one file is recorded against one tip.
#[test]
fn signals_reject_disagreeing_recorded_tips() {
    let mut second = signal_entry(Some(2), 326, None);
    second["recordedTip"] = serde_json::json!(602);
    let err = signals_from(
        serde_json::json!([signal_entry(Some(1), 300, None), second]),
        &two_steps(),
    )
    .expect_err("two tips in one file must be rejected");
    assert!(err.contains("601") && err.contains("602"), "{err}");
}

/// An entry confirmed above the tip the set was recorded against is refused,
/// naming both heights; one at the tip is accepted.
#[test]
fn signals_reject_an_entry_above_the_recorded_tip() {
    let err = signals_from(
        serde_json::json!([signal_entry(Some(1), 602, None)]),
        &two_steps(),
    )
    .expect_err("an entry above recordedTip must be rejected");
    assert!(err.contains("602") && err.contains("601"), "{err}");
    signals_from(
        serde_json::json!([signal_entry(Some(1), 601, None)]),
        &two_steps(),
    )
    .expect("an entry at recordedTip is accepted");
}

/// A record built past the parser with an entry above its tip fails the
/// derivation rather than counting 1.
#[test]
fn derived_confirmations_refuse_an_entry_above_the_recorded_tip() {
    let signals = Signals {
        recorded_tip: 320,
        entries: vec![parsed_entry(1, false, &"a1".repeat(32), 325)],
    };
    let err = derived_confirmations(Some(&signals), 2).expect_err("325 is above the tip 320");
    assert!(err.contains("325") && err.contains("320"), "{err}");
}

/// `recordedTip` is required on every entry.
#[test]
fn signals_reject_an_entry_without_recorded_tip() {
    let mut entry = signal_entry(Some(1), 300, None);
    entry
        .as_object_mut()
        .expect("an entry is an object")
        .remove("recordedTip");
    let err = signals_from(serde_json::json!([entry]), &two_steps())
        .expect_err("an entry without recordedTip must be rejected");
    assert!(err.contains("recordedTip"), "{err}");
}

/// An `update` number the set ships no step for is named as the missing step.
#[test]
fn signals_reject_an_update_with_no_matching_step() {
    let err = signals_from(
        serde_json::json!([signal_entry(Some(3), 300, None)]),
        &two_steps(),
    )
    .expect_err("update 3 names no step of a two-step set");
    assert!(err.contains("update/03"), "{err}");
}

/// A flat `update/` is update 1.
#[test]
fn signals_accept_update_one_under_a_flat_layout() {
    signals_from(
        serde_json::json!([signal_entry(Some(1), 300, None)]),
        &UpdateLayout::Flat,
    )
    .expect("update 1 is the flat step");
}

/// A flat `update/` has no second step.
#[test]
fn signals_reject_update_two_under_a_flat_layout() {
    let err = signals_from(
        serde_json::json!([signal_entry(Some(2), 300, None)]),
        &UpdateLayout::Flat,
    )
    .expect_err("a flat layout has only update 1");
    assert!(err.contains("update/02"), "{err}");
}

/// The cohort-only shape: a set with no `update/` whose entry names its cohort
/// and no update.
#[test]
fn signals_accept_a_cohort_entry_without_update() {
    let signals = signals_from(
        serde_json::json!([signal_entry(None, 300, Some(cohort_json()))]),
        &UpdateLayout::None,
    )
    .expect("a cohort member with no update of its own parses");
    let cohort = signals.entries[0]
        .cohort
        .as_ref()
        .expect("the cohort is carried");
    assert_eq!(cohort.id, "cas-09");
    assert_eq!(cohort.members, vec!["09a-first", "09b-second"]);
}

/// An entry that announces no update must say which cohort it belongs to.
#[test]
fn signals_reject_an_entry_with_neither_update_nor_cohort() {
    let err = signals_from(
        serde_json::json!([signal_entry(None, 300, None)]),
        &UpdateLayout::None,
    )
    .expect_err("an entry with neither update nor cohort must be rejected");
    assert!(err.contains("update") && err.contains("cohort"), "{err}");
}

/// A set with no `update/` directory has no step for any `update` to name.
#[test]
fn signals_reject_an_update_under_no_update_directory() {
    let err = signals_from(
        serde_json::json!([signal_entry(Some(1), 300, None)]),
        &UpdateLayout::None,
    )
    .expect_err("update 1 names no step of an update-less set");
    assert!(err.contains("update/01"), "{err}");
}

/// Only a repeated announcement of an update can be a duplicate.
#[test]
fn signals_reject_duplicate_without_update() {
    let mut entry = signal_entry(None, 300, Some(cohort_json()));
    entry["duplicate"] = serde_json::json!(true);
    let err = signals_from(serde_json::json!([entry]), &UpdateLayout::None)
        .expect_err("duplicate without update must be rejected");
    assert!(err.contains("duplicate"), "{err}");
}

/// Entries without `update` are never duplicates of one another, even when they
/// push the same bytes.
#[test]
fn signals_never_pair_entries_without_update() {
    let mut second = signal_entry(None, 300, Some(cohort_json()));
    second["txid"] = serde_json::json!("a9".repeat(32));
    let signals = signals_from(
        serde_json::json!([signal_entry(None, 300, Some(cohort_json())), second]),
        &UpdateLayout::None,
    )
    .expect("two update-less cohort entries are independent");
    assert_eq!(signals.entries.len(), 2);
}

/// `txid`, `blockHash` and `signalBytes` are 64 lowercase hex, each named when
/// it is not.
#[test]
fn signals_reject_malformed_hex() {
    for (member, bad) in [
        ("signalBytes", "c3".repeat(31)),
        ("signalBytes", "C3".repeat(32)),
        ("txid", "zz".repeat(32)),
        ("blockHash", "b2".repeat(33)),
    ] {
        let mut entry = signal_entry(Some(1), 300, None);
        entry[member] = serde_json::json!(bad);
        let err = signals_from(serde_json::json!([entry]), &two_steps())
            .expect_err("malformed hex must be rejected");
        assert!(err.contains(member), "{member}: {err}");
    }
}

/// A later announcement of the same update, flagged, with the same bytes, in a
/// higher block, is accepted.
#[test]
fn signals_accept_a_flagged_duplicate() {
    let mut repeat = signal_entry(Some(1), 326, None);
    repeat["duplicate"] = serde_json::json!(true);
    repeat["txid"] = serde_json::json!("a9".repeat(32));
    let signals = signals_from(
        serde_json::json!([signal_entry(Some(1), 300, None), repeat]),
        &two_steps(),
    )
    .expect("a flagged later duplicate parses");
    assert!(signals.entries[1].duplicate);
}

/// The same repeat without the flag is rejected.
/// Two entries recording one transaction are malformed, named by both
/// indices, whatever else they carry — a repeated announcement is a later
/// transaction, so even a flagged duplicate needs its own txid.
#[test]
fn signals_reject_a_repeated_txid() {
    let mut repeat = signal_entry(Some(1), 326, None);
    repeat["duplicate"] = serde_json::json!(true);
    let err = signals_from(
        serde_json::json!([signal_entry(Some(1), 300, None), repeat]),
        &two_steps(),
    )
    .expect_err("two entries cannot record one transaction");
    assert!(
        err.contains("entries 0 and 1") && err.contains(&"a1".repeat(32)),
        "the message names both entries and the transaction: {err}"
    );

    let err = signals_from(
        serde_json::json!([
            signal_entry(None, 300, Some(cohort_json())),
            signal_entry(None, 300, Some(cohort_json())),
        ]),
        &UpdateLayout::None,
    )
    .expect_err("cohort entries cannot share a transaction either");
    assert!(err.contains("entries 0 and 1"), "{err}");
}

#[test]
fn signals_reject_an_unflagged_repeat() {
    let mut repeat = signal_entry(Some(1), 326, None);
    repeat["txid"] = serde_json::json!("a9".repeat(32));
    let err = signals_from(
        serde_json::json!([signal_entry(Some(1), 300, None), repeat]),
        &two_steps(),
    )
    .expect_err("a repeated update needs duplicate: true");
    assert!(err.contains("duplicate"), "{err}");
}

/// `duplicate: true` on the only announcement of an update is rejected.
#[test]
fn signals_reject_duplicate_on_a_first_occurrence() {
    let mut entry = signal_entry(Some(1), 300, None);
    entry["duplicate"] = serde_json::json!(true);
    let err = signals_from(serde_json::json!([entry]), &two_steps())
        .expect_err("a first announcement cannot be a duplicate");
    assert!(
        err.contains("duplicate") && err.contains("first announcement"),
        "{err}"
    );
}

/// A duplicate pushes the same signal bytes as the first announcement.
#[test]
fn signals_reject_a_duplicate_with_different_signal_bytes() {
    let mut repeat = signal_entry(Some(1), 326, None);
    repeat["duplicate"] = serde_json::json!(true);
    repeat["txid"] = serde_json::json!("a9".repeat(32));
    repeat["signalBytes"] = serde_json::json!("d4".repeat(32));
    let err = signals_from(
        serde_json::json!([signal_entry(Some(1), 300, None), repeat]),
        &two_steps(),
    )
    .expect_err("a duplicate with other bytes must be rejected");
    assert!(err.contains("signalBytes"), "{err}");
}

/// A duplicate sits strictly above the first announcement.
#[test]
fn signals_reject_a_duplicate_not_above_the_first() {
    for height in [300, 299] {
        let mut repeat = signal_entry(Some(1), height, None);
        repeat["duplicate"] = serde_json::json!(true);
        repeat["txid"] = serde_json::json!("a9".repeat(32));
        let err = signals_from(
            serde_json::json!([signal_entry(Some(1), 300, None), repeat]),
            &two_steps(),
        )
        .expect_err("a duplicate not above the first must be rejected");
        assert!(err.contains("blockHeight"), "{height}: {err}");
    }
}

/// Upstream extends entries additively; an unknown member is ignored.
#[test]
fn signals_tolerate_unknown_members() {
    let mut entry = signal_entry(Some(1), 300, None);
    entry["futureField"] = serde_json::json!({ "anything": true });
    signals_from(serde_json::json!([entry]), &two_steps())
        .expect("an unknown member is not an error");
}

// --- cohorts -----------------------------------------------------------------

/// A set on `network` named `scenario` whose one signal belongs to `cohort` in
/// `txid`.
fn cohort_member(id: &str, scenario: &str, cohort: &serde_json::Value, txid: &str) -> Vector {
    let mut v = synthetic_vector(id, "x1");
    v.scenario_id = Some(scenario.to_string());
    let mut entry = signal_entry(None, 500, Some(cohort.clone()));
    entry["txid"] = serde_json::json!(txid);
    v.signals = Some(
        signals_from(serde_json::json!([entry]), &UpdateLayout::None)
            .expect("the cohort member's entry parses"),
    );
    v
}

/// The two members of `cohort_json()` on mutinynet, sharing one transaction.
fn cohort_pair() -> Vec<Vector> {
    let txid = "e5".repeat(32);
    vec![
        cohort_member("mutinynet/x1/qfirst00", "09a-first", &cohort_json(), &txid),
        cohort_member("mutinynet/x1/qsecond0", "09b-second", &cohort_json(), &txid),
    ]
}

/// Both members found, each recording the cohort in the shared transaction.
#[test]
fn cohorts_accept_a_matching_pair() {
    check_cohorts(&cohort_pair()).expect("a consistent pair passes");
}

/// A member scenario id no set carries is named.
#[test]
fn cohorts_reject_an_unmatched_member() {
    let pair = cohort_pair();
    let err = check_cohorts(&pair[..1]).expect_err("a missing partner must be rejected");
    assert!(err.contains("09b-second"), "{err}");
}

/// A member scenario id two sets carry is ambiguous.
#[test]
fn cohorts_reject_a_member_matching_two_sets() {
    let mut vectors = cohort_pair();
    let mut twin = vectors[1].clone();
    twin.id = "mutinynet/x1/qtwin000".to_string();
    vectors.push(twin);
    let err = check_cohorts(&vectors).expect_err("an ambiguous member must be rejected");
    assert!(
        err.contains("09b-second") && err.contains("matches 2"),
        "{err}"
    );
}

/// A set on another network is not a sibling, even with the right scenario id.
#[test]
fn cohorts_ignore_a_sibling_on_another_network() {
    let mut vectors = cohort_pair();
    vectors[1].id = "regtest/x1/qsecond0".to_string();
    vectors[1].network_dir = "regtest".to_string();
    let err = check_cohorts(&vectors).expect_err("a cross-network partner does not count");
    assert!(err.contains("09b-second"), "{err}");
}

/// The partner's own `signals.json` must record the cohort: here it has no
/// signals at all.
#[test]
fn cohorts_reject_a_member_without_the_cohort_entry() {
    let mut vectors = cohort_pair();
    vectors[1].signals = None;
    let err = check_cohorts(&vectors).expect_err("the partner must record the cohort");
    assert!(
        err.contains("09b-second") && err.contains("cas-09"),
        "{err}"
    );
}

/// The partner records the cohort, but in another transaction.
#[test]
fn cohorts_reject_a_member_recording_another_txid() {
    let mut vectors = cohort_pair();
    vectors[1] = cohort_member(
        "mutinynet/x1/qsecond0",
        "09b-second",
        &cohort_json(),
        &"f6".repeat(32),
    );
    let err = check_cohorts(&vectors).expect_err("the partner must share the transaction");
    assert!(err.contains(&"e5".repeat(32)), "{err}");
}

// --- delivery ----------------------------------------------------------------

/// A negative set is read by id type alone: the file-shape CAS inferences that
/// would otherwise fire on an external set with no sidecar genesis document and
/// updates with no sidecar copies do not.
#[test]
fn delivery_negative_skips_the_file_shape_cas_rules() {
    let external = derive_delivery(VectorIdType::External, true, false, true, false);
    assert!(external.negative);
    assert_eq!(external.genesis, GenesisDelivery::Sidecar);
    assert_eq!(external.announcement, Some(AnnouncementDelivery::Sidecar));

    let key = derive_delivery(VectorIdType::Key, true, false, false, false);
    assert_eq!(key.genesis, GenesisDelivery::Deterministic);
    assert_eq!(key.announcement, None);
}

/// A positive external set with no sidecar genesis document has a CAS genesis;
/// with one, the sidecar delivers it.
#[test]
fn delivery_external_genesis_follows_the_sidecar() {
    let cas = derive_delivery(VectorIdType::External, false, false, false, false);
    assert_eq!(cas.genesis, GenesisDelivery::Cas);
    assert!(!cas.negative);

    let sidecar = derive_delivery(VectorIdType::External, false, true, false, false);
    assert_eq!(sidecar.genesis, GenesisDelivery::Sidecar);
}

/// Update steps with no sidecar `updates` are CAS-announced; with them, the
/// sidecar delivers them; with no update steps there is no announcement.
#[test]
fn delivery_announcement_follows_the_sidecar_updates() {
    let cas = derive_delivery(VectorIdType::Key, false, false, true, false);
    assert_eq!(cas.announcement, Some(AnnouncementDelivery::Cas));

    let sidecar = derive_delivery(VectorIdType::Key, false, false, true, true);
    assert_eq!(sidecar.announcement, Some(AnnouncementDelivery::Sidecar));

    let none = derive_delivery(VectorIdType::Key, false, false, false, true);
    assert_eq!(none.announcement, None);
}

/// A key-based genesis is deterministic whatever the sidecar says.
#[test]
fn delivery_key_genesis_is_deterministic() {
    for has_sidecar_genesis in [false, true] {
        let d = derive_delivery(VectorIdType::Key, false, has_sidecar_genesis, false, false);
        assert_eq!(d.genesis, GenesisDelivery::Deterministic);
    }
}

/// The derived CAS delivery set on the checked-out suite, pinned by scenario on
/// every network: the four sets whose files alone show CAS delivery (05, 06, 08,
/// 20), plus the six whose genesis document declares a `CASBeacon` or whose
/// updates carry no sidecar (09a/b, 10a/b, 11a/b).
#[test]
fn live_vectors_derive_exactly_the_cas_delivery_set() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    assert!(!vectors.is_empty());

    let observed: BTreeSet<(String, String)> = vectors
        .iter()
        .filter(|v| {
            v.skip_reasons_with(AssertionKind::Resolve, &[])
                .contains(&SkipReason::CasDelivery)
        })
        .map(|v| (v.network_dir.clone(), scenario_number(v).to_string()))
        .collect();
    assert_eq!(
        observed,
        on_every_network(&[
            "05", "06", "08", "20", "09a", "09b", "10a", "10b", "11a", "11b"
        ]),
        "the sets whose files (or genesis beacons) show CAS delivery"
    );

    // The four CAS-delivery-only scenarios carry that reason and no other.
    for v in vectors
        .iter()
        .filter(|v| CAS_DELIVERY_ONLY_SCENARIOS.contains(&scenario_number(v)))
    {
        assert_eq!(
            v.skip_reasons_with(AssertionKind::Resolve, &[]),
            BTreeSet::from([SkipReason::CasDelivery]),
            "{}",
            v.id
        );
    }
}

/// The suite ships its negative sets, exactly the named scenarios on every
/// network, and each one's `resolve/output.json` records the error code it
/// expects in `didResolutionMetadata.error`.
///
/// A negative scenario whose output lost its code would parse as positive and
/// drop out of the observed set, failing the scenario comparison by name; the
/// raw read then checks the code and the absent document on the file itself.
#[test]
fn negative_vectors_carry_their_expected_error() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    assert!(!vectors.is_empty());

    let negative: Vec<&Vector> = vectors.iter().filter(|v| v.is_negative()).collect();
    let observed: BTreeSet<(String, String)> = negative
        .iter()
        .map(|v| (v.network_dir.clone(), scenario_number(v).to_string()))
        .collect();
    let scenarios: Vec<String> = (1..=5).chain(10..=31).map(|n| format!("n{n:02}")).collect();
    let scenarios: Vec<&str> = scenarios.iter().map(String::as_str).collect();
    assert_eq!(
        observed,
        on_every_network(&scenarios),
        "the negative scenarios are n01-n05 and n10-n31 on every network"
    );
    assert_eq!(
        negative.len(),
        108,
        "27 negative sets on each of four networks"
    );

    for v in &negative {
        let output = v.fixture("resolve/output.json");
        let code = &output["didResolutionMetadata"]["error"];
        assert!(
            code.as_str().is_some_and(|c| !c.is_empty()),
            "{}: resolve/output.json must carry didResolutionMetadata.error, found {code}",
            v.id
        );
        assert!(
            output["didDocument"].is_null(),
            "{}: a negative output carries no didDocument",
            v.id
        );
    }

    // The one recorded code that diverges from the specification is carried by
    // n21 and n28 on every network, and each of those rows is driven, so the
    // divergence entry asserts the specification's code on all eight.
    let late: BTreeSet<(String, String)> = negative
        .iter()
        .filter(|v| {
            ERROR_CODE_DIVERGENCES
                .iter()
                .any(|d| matches!(&v.outcome, Outcome::Error { code } if code == d.vector_code))
        })
        .map(|v| (v.network_dir.clone(), scenario_number(v).to_string()))
        .collect();
    assert_eq!(late, on_every_network(&["n21", "n28"]));
    let driven = expected_driven_with(AssertionKind::Resolve, &vectors, &[]);
    for (network, scenario) in &late {
        let v = negative
            .iter()
            .find(|v| &v.network_dir == network && scenario_number(v) == scenario)
            .expect("the set was just observed");
        assert!(
            driven.contains(&RowKey::set(v.id.clone())),
            "{}: its Resolve row is driven",
            v.id
        );
    }
}

// --- Synthetic shape corpora ---------------------------------------------------
//
// These corpora live in this repository under `fixtures/layout/`, so the tests
// below never skip: an absent corpus is a bug.

/// The panic message of a discovery walk over a synthetic corpus that must fail.
fn discovery_panic(corpus: &str) -> String {
    let payload = std::panic::catch_unwind(|| discover_in(&Corpus::synthetic(corpus)))
        .expect_err("discovery over this corpus must fail");
    panic_message(payload)
}

/// The passing shapes corpus classifies every set from its files alone: a CAS
/// genesis, a CAS-announced update, and an SMT cohort whose second member ships
/// no `update/` and names no update in its signal.
#[test]
fn shapes_corpus_classifies_from_files() {
    let corpus = Corpus::synthetic("shapes");
    let vectors = discover_in(&corpus);
    let ids: Vec<&str> = vectors.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "mutinynet/x1/q425c5wf",
            "mutinynet/x1/q5cfewep",
            "mutinynet/x1/qh66uy2s",
            "regtest/k1/qgppexmy",
        ]
    );
    for v in &vectors {
        assert_eq!(v.corpus, corpus, "{}", v.id);
        assert!(v.dir.starts_with(&corpus.sets), "{}", v.id);
        assert!(!v.is_negative(), "{}", v.id);
    }
    let by_id = |want: &str| {
        vectors
            .iter()
            .find(|v| v.id == want)
            .unwrap_or_else(|| panic!("{want} must be discovered"))
    };

    // The exact reasons each set's files derive.
    let reasons = |id: &str| by_id(id).skip_reasons_with(AssertionKind::Resolve, &[]);
    assert_eq!(
        reasons("mutinynet/x1/qh66uy2s"),
        BTreeSet::from([SkipReason::CasDelivery])
    );
    assert_eq!(
        reasons("regtest/k1/qgppexmy"),
        BTreeSet::from([SkipReason::CasDelivery])
    );
    assert_eq!(
        reasons("mutinynet/x1/q5cfewep"),
        BTreeSet::from([SkipReason::SmtDelivery, SkipReason::UnsupportedBeaconType])
    );
    assert_eq!(
        reasons("mutinynet/x1/q425c5wf"),
        BTreeSet::from([SkipReason::SmtDelivery, SkipReason::UnsupportedBeaconType])
    );

    // Delivery as the files show it.
    assert_eq!(
        by_id("mutinynet/x1/qh66uy2s").delivery.genesis,
        GenesisDelivery::Cas
    );
    let k1 = by_id("regtest/k1/qgppexmy");
    assert_eq!(k1.delivery.genesis, GenesisDelivery::Deterministic);
    assert_eq!(k1.delivery.announcement, Some(AnnouncementDelivery::Cas));
    assert!(k1.signals.is_none());

    // The cohort pair: one member with a flat update/ announcing update 1, one
    // cohort-only member with no update/ and no `update` in its entry.
    let a = by_id("mutinynet/x1/q5cfewep");
    assert_eq!(a.scenario_id.as_deref(), Some("shape-cohort-a"));
    assert_eq!(a.update_layout, UpdateLayout::Flat);
    let a_signals = a
        .signals
        .as_ref()
        .expect("shape-cohort-a ships signals.json");
    assert_eq!(a_signals.recorded_tip, 1010);
    assert_eq!(a_signals.entries[0].update, Some(1));

    let b = by_id("mutinynet/x1/q425c5wf");
    assert_eq!(b.scenario_id.as_deref(), Some("shape-cohort-b"));
    assert_eq!(b.update_layout, UpdateLayout::None);
    assert_eq!(b.delivery.announcement, None);
    let b_signals = b
        .signals
        .as_ref()
        .expect("shape-cohort-b ships signals.json");
    assert_eq!(b_signals.entries.len(), 1);
    assert_eq!(b_signals.entries[0].update, None);
    assert_eq!(
        b_signals.entries[0].cohort.as_ref().map(|c| c.id.as_str()),
        Some("shape-cohort")
    );
    assert_eq!(a_signals.entries[0].txid, b_signals.entries[0].txid);
    check_cohorts(&vectors).expect("the pair is a consistent cohort");
}

/// A `resolve/` child that is neither the main pair nor a numbered case fails
/// discovery, naming the child.
#[test]
fn shapes_unknown_resolve_child_fails_discovery() {
    let message = discovery_panic("shapes-unknown-resolve-child");
    assert!(
        message.contains("unrecognized `resolve/` child")
            && message.contains("notes.md")
            && message.contains("regtest/k1/qgpakaw4"),
        "{message}"
    );
}

/// A `signals.json` that is an object rather than a bare array fails discovery.
#[test]
fn shapes_malformed_signals_fail_discovery() {
    let message = discovery_panic("shapes-malformed-signals");
    assert!(
        message.contains("bare array") && message.contains("regtest/k1/qgpakaw4/signals.json"),
        "{message}"
    );
}

/// A cohort whose member matches no set fails discovery, naming the member.
#[test]
fn shapes_bad_cohort_member_fails_discovery() {
    let message = discovery_panic("shapes-bad-cohort-member");
    assert!(
        message.contains("shape-cohort-b") && message.contains("shape-cohort"),
        "{message}"
    );
}

/// Copy the directory tree at `from` to `to`, creating `to`.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Discovery refuses a set whose main `resolve/output.json` encodes
/// `didDocumentMetadata.versionId` as a JSON number, naming the file and saying
/// the field must be a string.
#[test]
fn discovery_rejects_a_number_encoded_version_id_by_path() {
    // Removed on drop, so a failing assertion below leaves nothing behind.
    let guard = TempRoot::new("number-version-id");
    let root = &guard.0;
    let set = "mutinynet/x1/qh66uy2s";
    copy_tree(
        &Corpus::synthetic("shapes").sets.join(set),
        &root.join("sets").join(set),
    );
    let output_path = root.join("sets").join(set).join("resolve/output.json");
    let mut output = read_json_at(&output_path, "the copied output");
    output["didDocumentMetadata"]["versionId"] = serde_json::json!(2);
    std::fs::write(&output_path, output.to_string()).unwrap();

    let corpus = Corpus {
        sets: root.join("sets"),
        chain: root.join("chain"),
    };
    let payload = std::panic::catch_unwind(|| discover_in(&corpus))
        .expect_err("discovery over a number-encoded versionId must fail");
    let message = panic_message(payload);
    assert!(
        message.contains(&format!("{set}/resolve/output.json"))
            && message.contains("didDocumentMetadata.versionId")
            && message.contains("string"),
        "the message names the file, the field and the required encoding: {message}"
    );
}

// --- resolve comparison rules ---------------------------------------------------

#[test]
fn confirmations_at_least_accepts_equal_and_above() {
    assert_eq!(confirmations_at_least(Some(7), Some(7)), Ok(()));
    assert_eq!(confirmations_at_least(Some(8), Some(7)), Ok(()));
}

#[test]
fn confirmations_at_least_rejects_below_naming_both_values() {
    let err = confirmations_at_least(Some(6), Some(7)).expect_err("6 is below the recorded 7");
    assert!(
        err.contains("confirmations") && err.contains('6') && err.contains('7'),
        "the message names both values: {err}"
    );
}

#[test]
fn confirmations_at_least_rejects_an_absent_resolved_value() {
    let err = confirmations_at_least(None, Some(7)).expect_err("absent is not at least 7");
    assert!(
        err.contains('7'),
        "the message names the recorded value: {err}"
    );
}

#[test]
fn confirmations_at_least_asserts_nothing_without_a_recorded_value() {
    assert_eq!(confirmations_at_least(None, None), Ok(()));
    assert_eq!(confirmations_at_least(Some(3), None), Ok(()));
}

/// A version's count starts at the block announcing the update that produced
/// it, the earliest announcement when the update was announced again.
#[test]
fn derived_confirmations_count_from_the_earliest_announcement_of_the_version() {
    let signals = Signals {
        recorded_tip: 320,
        entries: vec![
            parsed_entry(1, false, &"a1".repeat(32), 300),
            parsed_entry(2, false, &"a2".repeat(32), 305),
            parsed_entry(1, true, &"a3".repeat(32), 310),
        ],
    };
    assert_eq!(derived_confirmations(Some(&signals), 2), Ok(Some(21)));
    assert_eq!(derived_confirmations(Some(&signals), 3), Ok(Some(16)));
}

/// Genesis counts 0 with or without a record; past genesis a set without
/// `signals.json` derives nothing, and a version with no announcing entry
/// fails, naming the version and the update.
#[test]
fn derived_confirmations_are_zero_at_genesis_and_refused_without_an_entry() {
    let signals = Signals {
        recorded_tip: 320,
        entries: vec![parsed_entry(1, false, &"a1".repeat(32), 300)],
    };
    assert_eq!(derived_confirmations(Some(&signals), 1), Ok(Some(0)));
    assert_eq!(derived_confirmations(None, 1), Ok(Some(0)));
    assert_eq!(derived_confirmations(None, 2), Ok(None));
    let err = derived_confirmations(Some(&signals), 3).expect_err("no entry announces update 2");
    assert!(
        err.contains("version 3") && err.contains("update 2"),
        "got: {err}"
    );
}

/// A genesis resolve that reports a nonzero count fails, though every set
/// states `0` there and the lower bound alone would accept it; `0` passes.
#[test]
fn replayed_confirmations_refuse_a_nonzero_count_at_genesis() {
    let signals = Signals {
        recorded_tip: 320,
        entries: vec![parsed_entry(1, false, &"a1".repeat(32), 300)],
    };
    for record in [Some(&signals), None] {
        assert_eq!(replayed_confirmations(Some(0), Some(0), record, 1), Ok(()));
        let err = replayed_confirmations(Some(21), Some(0), record, 1)
            .expect_err("a genesis resolve applied no update, so it counts 0");
        assert!(
            err.contains("21") && err.contains("applies no update"),
            "got: {err}"
        );
    }
}

/// Past genesis the count must equal the derived one in both directions, and
/// may not fall below the stated one; a set without `signals.json` is held to
/// the stated lower bound only.
#[test]
fn replayed_confirmations_past_genesis_require_the_derived_count() {
    let signals = Signals {
        recorded_tip: 320,
        entries: vec![parsed_entry(1, false, &"a1".repeat(32), 300)],
    };
    assert_eq!(
        replayed_confirmations(Some(21), Some(20), Some(&signals), 2),
        Ok(())
    );
    let above = replayed_confirmations(Some(25), Some(20), Some(&signals), 2)
        .expect_err("25 is not the derived 21");
    assert!(above.contains("recordedTip 320"), "got: {above}");
    assert!(replayed_confirmations(Some(19), Some(20), Some(&signals), 2).is_err());
    assert_eq!(replayed_confirmations(Some(25), Some(20), None, 2), Ok(()));
    assert!(replayed_confirmations(Some(19), Some(20), None, 2).is_err());
}

/// A set that states more than its record gives is refused as a set defect,
/// before the lower bound, whatever the resolver reported: even a report below
/// the stated count names the set, not the resolver.
#[test]
fn replayed_confirmations_refuse_a_stated_count_above_the_derived_one() {
    let signals = Signals {
        recorded_tip: 320,
        entries: vec![parsed_entry(1, false, &"a1".repeat(32), 300)],
    };
    for resolved in [Some(21), Some(20), None] {
        let err = replayed_confirmations(resolved, Some(22), Some(&signals), 2)
            .expect_err("the set states 22 but its record gives 21");
        assert!(
            err.contains("states 22")
                && err.contains("gives 21")
                && err.contains("inconsistent with its own record")
                && !err.contains("below the recorded"),
            "got: {err}"
        );
    }
}

/// A set that states a nonzero count at its genesis version is refused as a
/// set defect, with or without a record, whatever the resolver reported.
#[test]
fn replayed_confirmations_refuse_a_nonzero_stated_count_at_genesis() {
    let signals = Signals {
        recorded_tip: 320,
        entries: vec![parsed_entry(1, false, &"a1".repeat(32), 300)],
    };
    for record in [Some(&signals), None] {
        for resolved in [Some(0), Some(2)] {
            let err = replayed_confirmations(resolved, Some(3), record, 1)
                .expect_err("a genesis set may not state more than 0");
            assert!(
                err.contains("states 3")
                    && err.contains("applies no update counts 0")
                    && err.contains("inconsistent with its own record")
                    && !err.contains("below the recorded"),
                "got: {err}"
            );
        }
    }
}

#[test]
fn exact_confirmations_reject_above_and_below() {
    assert_eq!(confirmations_exact(Some(6), Some(6)), Ok(()));
    let above = confirmations_exact(Some(6), Some(5)).expect_err("6 is not 5");
    assert!(
        above.contains("confirmations") && above.contains('6') && above.contains('5'),
        "{above}"
    );
    assert!(confirmations_exact(Some(4), Some(5)).is_err());
    assert!(confirmations_exact(None, Some(0)).is_err());
}

/// A positive outcome with the given numeric and recorded `versionId`.
fn positive(version_id: u64, version_id_string: &str) -> Outcome {
    Outcome::Positive {
        version_id,
        version_id_string: version_id_string.to_string(),
        deactivated: false,
        confirmations: None,
    }
}

#[test]
fn version_id_matches_compares_the_string_encoding() {
    assert_eq!(version_id_matches(3, &positive(3, "3")), Ok(()));
    assert!(version_id_matches(3, &positive(2, "2")).is_err());
}

#[test]
fn version_id_matches_does_not_coerce_a_string() {
    // `version_id` 3 is what a numeric read of "03" yields; the string compare
    // must still refuse it.
    let err = version_id_matches(3, &positive(3, "03")).expect_err("\"3\" is not \"03\"");
    assert!(err.contains("\"03\"") && err.contains("\"3\""), "{err}");
}

#[test]
fn version_id_matches_refuses_an_error_outcome() {
    let err = version_id_matches(
        2,
        &Outcome::Error {
            code: "NOT_FOUND".to_string(),
        },
    )
    .expect_err("an expected error never matches a resolved version");
    assert!(err.contains("NOT_FOUND"), "{err}");
}

/// A parsed `signals.json` entry for `update`, announced in `txid` at
/// `block_height`, pushing `bytes`.
fn parsed_entry(update: u64, duplicate: bool, txid: &str, block_height: u32) -> SignalEntry {
    let mut json = signal_entry(Some(update), block_height, None);
    json["txid"] = serde_json::json!(txid);
    json["duplicate"] = serde_json::json!(duplicate);
    serde_json::from_value(json).expect("the synthetic entry deserializes")
}

/// The announcement an entry claims, as the chain would serve it at the
/// address the entry names.
fn announcement_of(entry: &SignalEntry) -> ChainAnnouncement {
    ChainAnnouncement {
        announcement: Announcement::from(entry),
        addresses: BTreeSet::from([entry.address.clone()]),
    }
}

#[test]
fn signals_match_accepts_equal_sets_in_any_order() {
    let first = parsed_entry(1, false, &"a1".repeat(32), 300);
    let second = parsed_entry(2, false, &"a2".repeat(32), 310);
    let chain = vec![announcement_of(&second), announcement_of(&first)];
    assert_eq!(signals_match(&[first, second], &chain), Ok(()));
}

#[test]
fn signals_match_accepts_a_flagged_duplicate_matched_on_chain() {
    let first = parsed_entry(1, false, &"a1".repeat(32), 300);
    let again = parsed_entry(1, true, &"a9".repeat(32), 326);
    let chain = vec![announcement_of(&first), announcement_of(&again)];
    assert_eq!(signals_match(&[first, again], &chain), Ok(()));
}

#[test]
fn signals_match_rejects_a_chain_announcement_the_file_lacks() {
    let first = parsed_entry(1, false, &"a1".repeat(32), 300);
    let again = parsed_entry(1, true, &"a9".repeat(32), 326);
    let chain = vec![announcement_of(&first), announcement_of(&again)];
    let err = signals_match(&[first], &chain).expect_err("the duplicate is unrecorded");
    assert!(
        err.contains("signals.json") && err.contains(&"a9".repeat(32)) && err.contains("326"),
        "the message names the extra announcement: {err}"
    );
}

#[test]
fn signals_match_rejects_an_entry_the_chain_does_not_serve() {
    let first = parsed_entry(1, false, &"a1".repeat(32), 300);
    let second = parsed_entry(2, false, &"a2".repeat(32), 310);
    let chain = vec![announcement_of(&first)];
    let err = signals_match(&[first, second], &chain).expect_err("entry 2 is not on chain");
    assert!(
        err.contains("signals.json") && err.contains(&"a2".repeat(32)),
        "the message names the missing announcement: {err}"
    );
}

#[test]
fn signals_match_compares_the_block_hash_too() {
    let entry = parsed_entry(1, false, &"a1".repeat(32), 300);
    let mut moved = announcement_of(&entry);
    moved.announcement.block_hash = "ff".repeat(32);
    assert!(signals_match(&[entry], &[moved]).is_err());
}

#[test]
fn fixture_announcements_reads_every_address_and_only_signals() {
    let hash_a = "7a".repeat(32);
    let hash_b = "7b".repeat(32);
    let mut unconfirmed = chain_signal_tx_json(&"7c".repeat(32), &"c3".repeat(32), 0, 0);
    unconfirmed["status"] = serde_json::json!({ "confirmed": false });
    let mut not_a_signal = chain_signal_tx_json(&hash_a, &"c4".repeat(32), 661, 1_774_015_990);
    not_a_signal["vout"] = serde_json::json!([
        { "scriptpubkey": format!("6a20{hash_a}"), "value": 0 },
        { "scriptpubkey": "0014441b9e2ed446093690fb5cb19cb58932c5b1a3ea", "value": 1000 },
    ]);
    let fixture = chain_fixture_envelope(
        serde_json::json!([]),
        serde_json::json!({
            "bcrt1qfirst": [chain_signal_tx_json(&hash_a, &"a1".repeat(32), 660, 1_774_015_945)],
            "bcrt1qsecond": [
                chain_signal_tx_json(&hash_b, &"b1".repeat(32), 662, 1_774_016_000),
                unconfirmed,
                not_a_signal,
            ],
            "bcrt1qempty": [],
        }),
    );
    let got = fixture_announcements(&fixture);
    assert_eq!(
        got,
        vec![
            ChainAnnouncement {
                announcement: Announcement {
                    txid: "a1".repeat(32),
                    block_height: 660,
                    block_hash: "00".repeat(32),
                    signal_bytes: hash_a,
                },
                addresses: BTreeSet::from(["bcrt1qfirst".to_string()]),
            },
            ChainAnnouncement {
                announcement: Announcement {
                    txid: "b1".repeat(32),
                    block_height: 662,
                    block_hash: "00".repeat(32),
                    signal_bytes: hash_b,
                },
                addresses: BTreeSet::from(["bcrt1qsecond".to_string()]),
            },
        ],
        "one announcement per confirmed OP_RETURN-last transaction, across addresses"
    );
}

/// The capture tool's written shape for one announcing transaction that sits in
/// two captured address histories — it spends from one beacon and pays change
/// to another: the transaction body under both addresses, and one `signals`
/// record naming the address `signals.json` names. The capture tool is a
/// binary crate, so its writer cannot be called from here; this builds the same
/// envelope and reads it through the replay's own deserializer.
fn fixture_with_one_tx_at_two_addresses(extra: Option<serde_json::Value>) -> ChainFixture {
    let hash = "7d".repeat(32);
    let txid = "d1".repeat(32);
    let tx = chain_signal_tx_json(&hash, &txid, 660, 1_774_015_945);
    let mut change_history = vec![tx.clone()];
    change_history.extend(extra);
    chain_fixture_envelope(
        serde_json::json!([{
            "address": "bcrt1qbeacon",
            "txid": txid,
            "block_height": 660,
            "block_time": 1_774_015_945,
            "update_hash": hash,
        }]),
        serde_json::json!({
            "bcrt1qbeacon": [tx],
            "bcrt1qchange": change_history,
        }),
    )
}

/// The `signals.json` entry recording the announcement of
/// [`fixture_with_one_tx_at_two_addresses`].
fn entry_for_one_tx_at_two_addresses() -> SignalEntry {
    let mut json = signal_entry(Some(1), 660, None);
    json["address"] = serde_json::json!("bcrt1qbeacon");
    json["txid"] = serde_json::json!("d1".repeat(32));
    json["blockHash"] = serde_json::json!("00".repeat(32));
    json["signalBytes"] = serde_json::json!("7d".repeat(32));
    serde_json::from_value(json).expect("the synthetic entry deserializes")
}

#[test]
fn fixture_announcements_count_one_transaction_seen_at_two_addresses_once() {
    let fixture = fixture_with_one_tx_at_two_addresses(None);
    assert_signals_consistent(&fixture, "regtest/k1/synthetic");
    let announcements = fixture_announcements(&fixture);
    assert_eq!(
        announcements.len(),
        1,
        "one transaction is one announcement, however many histories list it: \
         {announcements:?}"
    );
    assert_eq!(
        signals_match(&[entry_for_one_tx_at_two_addresses()], &announcements),
        Ok(()),
        "the one signals.json entry the capture gate accepted must match the replay too"
    );
}

#[test]
fn signals_match_accepts_an_entry_naming_the_change_address() {
    let fixture = fixture_with_one_tx_at_two_addresses(None);
    let announcements = fixture_announcements(&fixture);
    assert_eq!(
        announcements[0].addresses,
        BTreeSet::from(["bcrt1qbeacon".to_string(), "bcrt1qchange".to_string()]),
        "both histories that list the transaction are carried"
    );
    let mut entry = entry_for_one_tx_at_two_addresses();
    entry.address = "bcrt1qchange".to_string();
    assert_eq!(signals_match(&[entry], &announcements), Ok(()));
}

#[test]
fn signals_match_rejects_an_entry_naming_an_address_that_does_not_carry_it() {
    let fixture = fixture_with_one_tx_at_two_addresses(None);
    let announcements = fixture_announcements(&fixture);
    let mut entry = entry_for_one_tx_at_two_addresses();
    entry.address = "bcrt1qelsewhere".to_string();
    let err = signals_match(&[entry], &announcements)
        .expect_err("the named address does not carry the transaction");
    for part in [
        "bcrt1qelsewhere",
        "bcrt1qbeacon",
        "bcrt1qchange",
        "d1".repeat(32).as_str(),
    ] {
        assert!(err.contains(part), "the message must carry {part}: {err}");
    }
}

#[test]
fn fixture_announcements_still_count_a_second_transaction_at_a_shared_address() {
    let second = chain_signal_tx_json(&"7e".repeat(32), &"d2".repeat(32), 661, 1_774_016_000);
    let fixture = fixture_with_one_tx_at_two_addresses(Some(second));
    let announcements = fixture_announcements(&fixture);
    assert_eq!(announcements.len(), 2, "{announcements:?}");
    let err = signals_match(&[entry_for_one_tx_at_two_addresses()], &announcements)
        .expect_err("the second transaction is unrecorded");
    assert!(
        err.contains(&"d2".repeat(32)) && err.contains("661"),
        "the message names the unrecorded announcement: {err}"
    );
}

#[test]
fn fixture_announcements_of_the_options_chain_equal_its_signals_json() {
    let corpus = Corpus::synthetic("options");
    let vectors = discover_in(&corpus);
    let vector = &vectors[0];
    let fixture = read_chain_fixture_in(&corpus.chain, &vector.id);
    let announcements = fixture_announcements(&fixture);
    assert_eq!(
        announcements.len(),
        3,
        "the minted chain announces three updates"
    );
    let entries = &vector.signals.as_ref().expect("signals.json").entries;
    assert_eq!(signals_match(entries, &announcements), Ok(()));
}
