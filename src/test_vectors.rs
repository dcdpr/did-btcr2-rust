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

/// `regtest/k1/qgppexmy` -> `<crate>/fixtures/chain/regtest/k1/qgppexmy.json`.
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
    "regtest/k1/qgppexmy",
    "regtest/k1/qgpy0hmm",
    "regtest/x1/q26jeds9",
    "regtest/x1/qfl7se8f",
    "mutinynet/k1/q5p6w9su",
    "mutinynet/k1/q5pgeu9z",
    "mutinynet/x1/q5ugrf3w",
    "minted/clean-rotating-beacons",
    "minted/late-publishing-fork",
];

/// Captures taken before the capture tool recorded the confirming blocks of
/// the announcements it found. A `versionTime` bound compares against the
/// block's `mediantime`, which only a `/block/{hash}` body carries, so the
/// replay tests' versionTime probe cannot run on these and skips, by name,
/// until they are re-captured. All seven are vendor vectors in
/// `STALE_UPDATE_CONTEXT`: a live capture rejects their pre-pin update
/// `@context`, so the re-capture waits on the upstream regeneration first.
/// Checked in BOTH directions: a listed fixture that now holds its blocks
/// fails saying the list is stale, and an unlisted fixture missing a block
/// fails as a new defect rather than being skipped.
pub(crate) const FIXTURES_WITHOUT_SIGNAL_BLOCKS: &[&str] = &[
    "regtest/k1/qgppexmy",
    "regtest/k1/qgpy0hmm",
    "regtest/x1/q26jeds9",
    "regtest/x1/qfl7se8f",
    "mutinynet/k1/q5p6w9su",
    "mutinynet/k1/q5pgeu9z",
    "mutinynet/x1/q5ugrf3w",
];

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
/// `recordedTip`. An entry's `update` N, when present, must name an update step
/// the set has — `update/{NN}` in a numbered layout, or N = 1 for a flat
/// `update/` — and an entry without `update` must name its `cohort`. The
/// `txid`, `blockHash` and `signalBytes` are 64 lowercase hex.
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

    let mut first_announcement: BTreeMap<u64, usize> = BTreeMap::new();
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
    let path = chain_fixture_path(vector_id);
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

/// Read and parse a JSON file that may legitimately be absent (`scenario.json`,
/// `signals.json`). Absent yields `None`; present but unreadable or malformed
/// panics, because a corrupt optional file is still a corrupt file.
fn read_json_opt(path: &Path, ctx: &str) -> Option<serde_json::Value> {
    path.is_file().then(|| read_json_at(path, ctx))
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

/// Read a `versionId`-shaped field through the encoding-tolerant coercion,
/// naming the vector and the JSON path on failure.
pub(crate) fn field_version_id(value: &serde_json::Value, path: &str, ctx: &str) -> u64 {
    version_id_u64(json_at(value, path), &format!("{ctx} {path}"))
}

/// Read a `versionId`-shaped field that the crate models as a `NonZeroU64`.
///
/// `version_id_u64` accepts `0`, which the crate's `NonZeroU64` cannot hold, so
/// a fixture stating `targetVersionId: 0` used to panic bare on
/// `NonZeroU64::new(..).unwrap()`.
pub(crate) fn field_nonzero_version_id(
    value: &serde_json::Value,
    path: &str,
    ctx: &str,
) -> NonZeroU64 {
    let raw = field_version_id(value, path, ctx);
    NonZeroU64::new(raw)
        .unwrap_or_else(|| panic!("{ctx}: {path} must be greater than zero, got {raw}"))
}

/// Read a fixture's `versionId` as a `u64`, accepting either a JSON number or
/// an ASCII-decimal string.
///
/// The regtest vectors encode it as `"2"` and the mutinynet vectors as `2`.
/// Both are read here; the crate's own emit-a-string / reject-a-number contract
/// is pinned by the `DocumentMetadata` round-trip test in `document.rs`, which
/// does not depend on fixtures. `ctx` is the vector id, so a bad fixture names
/// itself.
pub(crate) fn version_id_u64(value: &serde_json::Value, ctx: &str) -> u64 {
    match value {
        serde_json::Value::Number(n) => n
            .as_u64()
            .unwrap_or_else(|| panic!("{ctx}: versionId must be a non-negative integer, got {n}")),
        serde_json::Value::String(s) => {
            assert!(
                !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()),
                "{ctx}: versionId string must be ASCII decimal, got {s:?}"
            );
            s.parse()
                .unwrap_or_else(|e| panic!("{ctx}: versionId {s:?} does not fit u64: {e}"))
        }
        other => {
            panic!("{ctx}: versionId must be a JSON number or an ASCII-decimal string, got {other}")
        }
    }
}

/// One discovered operation-vector directory plus the raw facts later
/// classification rules consume.
#[derive(Clone, Debug)]
pub(crate) struct Vector {
    /// `"mutinynet/x1/q5m2fh36"` — the row key and the message prefix.
    pub(crate) id: String,
    /// `"mutinynet"` / `"regtest"`.
    pub(crate) network_dir: String,
    /// `"k1"` / `"x1"` — the directory segment, kept verbatim for messages.
    pub(crate) kind: String,
    /// `"q5m2fh36"`.
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
    /// At least one update step in this vector's own files —
    /// `update/**/output.json` `signedUpdate` and its `proof`, or
    /// `resolve/input.json` sidecar `updates[*]` and their proofs — carries an
    /// `@context` that is not the pinned BTCR2 Unsigned Update array. Such a
    /// vector predates the spec's pin and is being regenerated upstream; its
    /// Resolve row is skipped under `StaleContext` until the regenerated vector
    /// lands, at which point this flag clears itself.
    pub(crate) stale_update_context: bool,
    /// How the genesis document and the announcements reach a resolver,
    /// derived from the files present ([`derive_delivery`]) and cross-checked
    /// against `scenario.json.delivery` where that declares one.
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
    /// `pending.json` is present: the set's updates were never anchored.
    pub(crate) pending: bool,
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
/// update steps without a sidecar `updates` array are CAS announcements.
pub(crate) fn derive_delivery(
    id_type: VectorIdType,
    negative: bool,
    has_sidecar_genesis_document: bool,
    has_update_steps: bool,
    sidecar_has_updates: bool,
    pending: bool,
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
        pending,
    }
}

/// Cross-check a derived delivery against the `delivery` object a
/// `scenario.json` declares. `declared_genesis` / `declared_announcement` are
/// the object's members as strings; an absent member declares "not CAS".
///
/// A declared `"cas"` must match a derived CAS delivery and vice versa, for
/// the genesis document always and for the announcements only when the set is
/// not pending: a pending set never ran its anchoring step, so its files cannot
/// show which announcement mechanism was intended. A declared `"smt"` requires
/// an `SMTBeacon` in the genesis document.
pub(crate) fn cross_check_scenario(
    derived: &Delivery,
    declared_genesis: Option<&str>,
    declared_announcement: Option<&str>,
    genesis_service_types: &[String],
) -> Result<(), String> {
    let genesis_cas = derived.genesis == GenesisDelivery::Cas;
    if (declared_genesis == Some("cas")) != genesis_cas {
        return Err(format!(
            "scenario.json declares genesis delivery {declared_genesis:?} but the files show \
             {:?} — the files and scenario.json disagree",
            derived.genesis
        ));
    }
    if !derived.pending {
        let announcement_cas = derived.announcement == Some(AnnouncementDelivery::Cas);
        if (declared_announcement == Some("cas")) != announcement_cas {
            return Err(format!(
                "scenario.json declares announcement delivery {declared_announcement:?} but the \
                 files show {:?} — the files and scenario.json disagree",
                derived.announcement
            ));
        }
    }
    for declared in [declared_genesis, declared_announcement]
        .into_iter()
        .flatten()
    {
        if declared == "smt" && !genesis_service_types.iter().any(|t| t == "SMTBeacon") {
            return Err(format!(
                "scenario.json declares SMT delivery but the genesis document declares no \
                 SMTBeacon (services: {genesis_service_types:?}) — the files and scenario.json \
                 disagree"
            ));
        }
    }
    Ok(())
}

/// Cross-check a derived delivery against a whole `scenario.json`: a null or
/// absent `delivery` declares nothing and is not checked.
pub(crate) fn check_scenario_delivery(
    derived: &Delivery,
    scenario: &serde_json::Value,
    genesis_service_types: &[String],
) -> Result<(), String> {
    let declared = &scenario["delivery"];
    if declared.is_null() {
        return Ok(());
    }
    cross_check_scenario(
        derived,
        declared["genesis"].as_str(),
        declared["announcement"].as_str(),
        genesis_service_types,
    )
}

/// The outcome a resolve `output.json` expects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A resolved document, described by `didDocumentMetadata`.
    Positive {
        /// `didDocumentMetadata.versionId`, read from either encoding.
        version_id: u64,
        /// The same field verbatim when it is the ASCII string the
        /// specification requires; `None` when the fixture encodes it as a
        /// JSON number, a known upstream defect that the coverage summary
        /// reports.
        version_id_string: Option<String>,
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
/// `versionId` is read through [`version_id_u64`] (either encoding),
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
    Outcome::Positive {
        version_id: version_id_u64(
            version_id_node,
            &format!("{ctx} didDocumentMetadata.versionId"),
        ),
        version_id_string: version_id_node.as_str().map(str::to_string),
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

    /// The main resolve pair's `versionId` is a JSON number rather than the
    /// ASCII string the specification requires. Recorded so the coverage
    /// summary can report it: the coercion reads either encoding, but a
    /// silently-absorbed fixture defect is exactly the kind of gap this ledger
    /// exists to surface. Clears itself when the fixtures are corrected.
    pub(crate) fn version_id_is_number(&self) -> bool {
        matches!(
            self.outcome,
            Outcome::Positive {
                version_id_string: None,
                ..
            }
        )
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
/// Unknown *flat sibling files* are deliberately NOT policed — the vector
/// generator ships `scenario.json`, `funding.json` and `pending.json` as
/// metadata, and an unknown-file rule would go red on pure generator output.
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

                // Every update the vector carries — the signed output of each
                // update step, and the sidecar copies the resolve step feeds
                // back in — must carry the spec's pinned `@context` on the
                // update and on its proof. A vector with no update steps and
                // no sidecar updates has nothing to be stale about.
                let pinned = serde_json::json!(crate::update::UPDATE_CONTEXT);
                let mut stale_update_context = false;
                for step in update_layout.step_prefixes() {
                    let ctx = format!("{id}/{step}/output.json");
                    if let Some(output) =
                        read_json_opt(&vector_path.join(&step).join("output.json"), &ctx)
                    {
                        let signed_update = &output["signedUpdate"];
                        if signed_update["@context"] != pinned
                            || signed_update["proof"]["@context"] != pinned
                        {
                            stale_update_context = true;
                        }
                    }
                }
                if let Some(updates) =
                    resolve_input["resolutionOptions"]["sidecar"]["updates"].as_array()
                {
                    for update in updates {
                        if update["@context"] != pinned || update["proof"]["@context"] != pinned {
                            stale_update_context = true;
                        }
                    }
                }

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

                // Delivery comes from the files. Where a `scenario.json`
                // declares one (the regtest sets ship none, and `delivery` is
                // `null` on 9 mutinynet sets) the two must agree, so a silent
                // reclassification cannot shrink the ledger.
                let delivery = derive_delivery(
                    id_type,
                    matches!(outcome, Outcome::Error { .. }),
                    has_sidecar_genesis_document,
                    update_layout != UpdateLayout::None,
                    resolve_input["resolutionOptions"]["sidecar"]["updates"].is_array(),
                    vector_path.join("pending.json").is_file(),
                );
                if let Some(scenario) = read_json_opt(
                    &vector_path.join("scenario.json"),
                    &format!("{id}/scenario.json"),
                ) {
                    check_scenario_delivery(&delivery, &scenario, &genesis_service_types)
                        .unwrap_or_else(|msg| panic!("{id}: {msg}"));
                }

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
                    stale_update_context,
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

/// The five assertions the harness can make about an operation vector.
///
/// Accounting is per (vector x kind) row rather than per vector: a vector whose
/// derivation is asserted but whose resolve cannot be driven offline must show
/// up as one driven row and one skipped row, not as a single "covered" vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum AssertionKind {
    /// `create/input.json` -> the encoded DID equals `create/output.json.did`.
    Derivation,
    /// `other.json.genesisKeys.secret` derives `genesisKeys.public`, and every
    /// update step signs with that same secret.
    GenesisKey,
    /// The resolver FSM resolves the vector to `resolve/output.json`.
    Resolve,
    /// Each update step's content-bound triple and BIP340 proof re-derive from
    /// its own inputs and verify against its source document.
    UpdateCrypto,
    /// Applying every update step in order to the genesis document reproduces
    /// `resolve/output.json.didDocument`.
    EndState,
}

impl AssertionKind {
    /// Every kind, in report order.
    pub(crate) const ALL: [AssertionKind; 5] = [
        Self::Derivation,
        Self::GenesisKey,
        Self::Resolve,
        Self::UpdateCrypto,
        Self::EndState,
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
/// chain data cannot be captured" any more. If a new v2+ Singleton, non-pending
/// vector arrives whose beacon transactions are gone — a mutinynet reset, say —
/// it becomes a driven row with no fixture and `read_chain_fixture` panics. The
/// remedy is a `SKIP_OVERRIDES` entry with the reason stated, not resurrecting
/// a derived rule: an override is visible in the summary and
/// redundancy-checked, whereas a derived rule would silently re-skip every
/// future v2 vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum SkipReason {
    /// `pending.json`: the vector's updates are not fully anchored on chain.
    Unanchored,
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
    /// The vector's update `@context` predates the spec's pin; regenerated
    /// upstream and absorbed when the regenerated suite is bumped. Applies to
    /// the Resolve kind only: the UpdateCrypto and EndState drivers rebuild the
    /// update from `input.json` and compare document hashes, so those rows
    /// stay driven. Until the resolver rejects a non-pinned `@context`, the
    /// rows parked here would still pass; the skip lands before the reject so
    /// that no commit is ever red, and the label becomes literally true once
    /// the reject lands.
    StaleContext,
    /// A one-off no derived rule expresses; the payload is the stated reason.
    Override(&'static str),
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unanchored => f.write_str("unanchored (pending.json)"),
            Self::CasDelivery => f.write_str("CAS-aggregated delivery not implemented"),
            Self::SmtDelivery => f.write_str("SMT-aggregated delivery not implemented"),
            Self::UnsupportedBeaconType => f.write_str(
                "resolver cannot query this beacon type (CAS/SMT beacon requests unimplemented)",
            ),
            Self::StaleContext => f.write_str(
                "update @context predates the spec pin; regenerated upstream, absorbed at the \
                 test-suite bump",
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
    /// Row key, e.g. `"mutinynet/x1/qh66uy2s"`.
    pub(crate) vector: &'static str,
    /// The assertion this entry suppresses.
    pub(crate) kind: AssertionKind,
    /// Why, in plain domain language.
    pub(crate) reason: &'static str,
}

/// Empty by design: every skipped row on disk today is covered by a derived
/// rule. An entry added here must match a discovered (vector, kind) or the
/// suite fails — additions cannot hide, and neither can removals.
pub(crate) const SKIP_OVERRIDES: &[SkipOverride] = &[];

/// The vectors whose `resolve/output.json.didDocumentMetadata.versionId` is a
/// JSON number rather than the ASCII string the specification requires.
///
/// A known upstream fixture defect, pinned to an explicit id set and asserted in
/// BOTH directions:
/// - a number-encoded vector NOT listed here is a NEW defect and fails by name,
///   instead of being absorbed by the encoding-tolerant read;
/// - a listed vector that is now string-encoded also fails, telling the reader
///   to delete the entry.
///
/// The second direction is the point. Keying this on the network directory
/// instead would auto-forgive a newly added defective vector AND go red on a
/// partial upstream conformance fix with a message reading as though the
/// now-conformant fixture were at fault — blocking exactly the improvement the
/// check exists to encourage. Correcting a fixture (upstream's or ours) costs a
/// one-line edit here, which is the intended forcing function.
pub(crate) const NUMBER_ENCODED_VERSION_ID: &[&str] = &[
    "mutinynet/k1/q5p6w9su",
    "mutinynet/k1/q5pgeu9z",
    "mutinynet/k1/q5puld7y",
    "mutinynet/x1/q425c5wf",
    "mutinynet/x1/q4lqu6gr",
    "mutinynet/x1/q4rnhfhv",
    "mutinynet/x1/q4x4pxl2",
    "mutinynet/x1/q550pp4e",
    "mutinynet/x1/q59jnwfs",
    "mutinynet/x1/q5cfewep",
    "mutinynet/x1/q5g3smvu",
    "mutinynet/x1/q5m2fh36",
    "mutinynet/x1/q5ugrf3w",
    "mutinynet/x1/qh66uy2s",
    "mutinynet/x1/qkrrp544",
    "mutinynet/x1/qky9e7qz",
];

/// The vectors whose update files carry an `@context` that predates the spec's
/// pinned BTCR2 Unsigned Update array — every vector with an `update/`
/// directory in the vendor suite as checked out today.
///
/// The upstream suite is being regenerated with the pinned array. Until that
/// lands, these vectors' Resolve rows are skipped under
/// [`SkipReason::StaleContext`]; the population is pinned to an explicit id set
/// and asserted in BOTH directions:
/// - a stale vector NOT listed here is a NEW pre-pin vector and fails by name,
///   instead of being absorbed by the derived skip;
/// - a listed vector that is now clean also fails, telling the reader to delete
///   the entry and re-raise [`DRIVEN_FLOOR`]'s Resolve entry.
///
/// The second direction is the point. A derived skip with no pin would absorb
/// the regeneration silently — a regenerated vector clears the rule, its row
/// is driven, and nobody re-raises the floor. With the pin, the bump trips
/// this list (and the count check on it) until the regeneration is absorbed
/// deliberately; a regenerated vector that still carries the old array stays
/// honestly skipped rather than failing. At the bump this list should empty
/// and the guard flip to "none expected".
pub(crate) const STALE_UPDATE_CONTEXT: &[&str] = &[
    "mutinynet/k1/q5p6w9su",
    "mutinynet/k1/q5pgeu9z",
    "mutinynet/x1/q425c5wf",
    "mutinynet/x1/q4lqu6gr",
    "mutinynet/x1/q4rnhfhv",
    "mutinynet/x1/q4x4pxl2",
    "mutinynet/x1/q550pp4e",
    "mutinynet/x1/q59jnwfs",
    "mutinynet/x1/q5cfewep",
    "mutinynet/x1/q5m2fh36",
    "mutinynet/x1/q5ugrf3w",
    "mutinynet/x1/qkrrp544",
    "mutinynet/x1/qky9e7qz",
    "regtest/k1/qgppexmy",
    "regtest/k1/qgpy0hmm",
    "regtest/x1/q26jeds9",
    "regtest/x1/qfl7se8f",
];

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
/// Four Resolve rows are driven today: the genesis-era vectors
/// `mutinynet/k1/q5puld7y`, `mutinynet/x1/q5g3smvu`, `regtest/k1/qgpakaw4`
/// and `regtest/x1/q2fz9mz6`. The seven anchored past-genesis rows that were
/// driven from `fixtures/chain/` are parked under [`SkipReason::StaleContext`]
/// while the upstream suite is regenerated with the pinned update `@context`;
/// re-raise this entry to 11 or more when the regenerated suite is absorbed
/// and [`STALE_UPDATE_CONTEXT`] empties. UpdateCrypto and EndState are
/// unaffected: their drivers never read the vector's `@context`.
///
/// Compared with `>=`, so upstream ADDING vectors raises coverage without
/// failing; only silent coverage LOSS fails.
///
/// Evaluated against `expected_driven_with(kind, vectors, &[])` and never
/// against the live override table: a legitimate hand-written skip would
/// otherwise trip the ratchet, which is the very failure mode that makes the
/// escape hatch unusable.
pub(crate) const DRIVEN_FLOOR: &[(AssertionKind, usize)] = &[
    (AssertionKind::Derivation, 22),
    (AssertionKind::GenesisKey, 22),
    (AssertionKind::Resolve, 4),
    (AssertionKind::UpdateCrypto, 17),
    (AssertionKind::EndState, 17),
];

/// Derive the reasons a vector's `resolve` row cannot be driven, from the
/// vector's own files.
///
/// Three rules, all additive — a row keeps every reason that applies:
/// 1. `pending.json` present            -> `Unanchored`
/// 2. a `CASBeacon` / `SMTBeacon` service in the genesis document
///    -> `CasDelivery` / `SmtDelivery`, AND `UnsupportedBeaconType`
/// 3. the derived genesis or announcement delivery is CAS -> `CasDelivery`
///
/// Rule 3 reads the delivery [`derive_delivery`] reads off the files (an
/// external set with no sidecar genesis document; update steps with no sidecar
/// updates), which discovery has already cross-checked against any
/// `scenario.json` declaration. It is what accounts for the genesis-era vector
/// whose genesis document is CAS-delivered while it carries no beacon-type
/// signal at all (empty `service`, no `pending.json`, expected `versionId` 1).
///
/// Rule 2 applies to every set, negative sets included, and is what makes the
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
///
/// A fourth rule lives in [`Vector::skip_reasons_with`] rather than here,
/// because it reads a field this function's unit-tested signature does not
/// carry:
/// 4. any update step's `@context` (or its proof's) is not the pinned array
///    -> `StaleContext` (Resolve only) — from the vector's own update files
///    (`update/**/output.json`, `resolve/input.json` sidecar `updates`).
pub(crate) fn derived_resolve_skip_reasons(
    delivery: &Delivery,
    genesis_service_types: &[String],
) -> BTreeSet<SkipReason> {
    let mut reasons = BTreeSet::new();

    // Rule 1: the vector's own generator recorded undelivered update steps.
    if delivery.pending {
        reasons.insert(SkipReason::Unanchored);
    }

    // Rule 2: the genesis document's beacon services, by their wire strings.
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

    // Rule 3: a CAS delivery the files show.
    if delivery.genesis == GenesisDelivery::Cas
        || delivery.announcement == Some(AnnouncementDelivery::Cas)
    {
        reasons.insert(SkipReason::CasDelivery);
    }

    reasons
}

impl Vector {
    /// The kinds this vector has files for. `UpdateCrypto` and `EndState` exist
    /// only for update-bearing vectors; the other three exist for every vector.
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
            })
            .collect()
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
            // captured chain fixture to feed the beacon signals from.
            //
            // For an external vector the genesis source is
            // `resolve/input.json.resolutionOptions.sidecar.genesisDocument`;
            // reading `other.json.genesisDocument` instead would hand the
            // resolver a document the vector intends to be fetched from CAS,
            // asserting resolve logic while bypassing the delivery mechanism
            // and leaving no row marking the gap.
            //
            // The captured fixture is NOT a drivability condition. Every
            // anchored past-genesis vector on disk has one, and an absent
            // capture for a row this says is drivable is a bug that
            // `read_chain_fixture` raises by name — not a reason to quietly
            // drop the row.
            AssertionKind::Resolve => {
                self.id_type != VectorIdType::External || self.has_sidecar_genesis_document
            }
            AssertionKind::UpdateCrypto | AssertionKind::EndState => {
                self.update_layout != UpdateLayout::None
            }
        }
    }

    /// Every reason this row is skipped. Empty means the row is expected to be
    /// driven.
    ///
    /// The derived delivery/anchoring reasons scope to `Resolve` alone: they
    /// say nothing about whether a patch sequence reproduces a document, so an
    /// unanchored vector still drives derivation, genesis-key, update-crypto
    /// and end-state. Overrides apply to whatever kind they name.
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
        let mut reasons = if kind == AssertionKind::Resolve {
            derived_resolve_skip_reasons(&self.delivery, &self.genesis_service_types)
        } else {
            BTreeSet::new()
        };

        // Rule 4: a pre-pin update `@context`, from the vector's own update
        // files. Resolve only — the update-crypto and end-state drivers never
        // read the vector's `@context` (they rebuild the update and compare
        // document hashes), so those rows are genuinely driven.
        if kind == AssertionKind::Resolve && self.stale_update_context {
            reasons.insert(SkipReason::StaleContext);
        }

        for entry in overrides {
            if entry.vector == self.id && entry.kind == kind {
                reasons.insert(SkipReason::Override(entry.reason));
            }
        }

        reasons
    }

    /// Whether a driver for `kind` should assert against this vector.
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
    pub(crate) fn should_drive_with(
        &self,
        kind: AssertionKind,
        overrides: &[SkipOverride],
    ) -> bool {
        self.is_drivable(kind) && self.skip_reasons_with(kind, overrides).is_empty()
    }
}

/// The rows the ledger expects a driver for `kind` to have asserted against:
/// applicable, and `should_drive_with` the given override table.
pub(crate) fn expected_driven_with(
    kind: AssertionKind,
    vectors: &[Vector],
    overrides: &[SkipOverride],
) -> BTreeSet<String> {
    vectors
        .iter()
        .filter(|v| v.applicable_kinds().contains(&kind) && v.should_drive_with(kind, overrides))
        .map(|v| v.id.clone())
        .collect()
}

/// Assert that a driver's observed set equals the ledger's expected set for its
/// own kind.
///
/// "Driven" is observed, not declared: the caller passes the ids it actually
/// asserted against. A driver that skipped a row the ledger expects it to drive
/// fails here, as does a driver that asserted against a row the ledger has
/// classified as skipped.
///
/// Sharing `should_drive_with` with the driver loop gates does not make this
/// vacuous. The gate runs once per row at the top of the loop; `observed` is
/// filled at the bottom, after the assertions. Any early exit in between — a
/// `continue`, a `?`, a conditional that quietly walks past a step — leaves the
/// id out of `observed` and fails here.
///
/// The override table must match the one the driver gated on, or the two tell
/// different stories about the same run.
pub(crate) fn reconcile_driven_with(
    kind: AssertionKind,
    vectors: &[Vector],
    observed: &BTreeSet<String>,
    overrides: &[SkipOverride],
) {
    let expected = expected_driven_with(kind, vectors, overrides);
    let missing: Vec<&String> = expected.difference(observed).collect();
    let extra: Vec<&String> = observed.difference(&expected).collect();
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
/// Scope, so this is not over-trusted as a five-kind guard: `is_drivable` is
/// unconditionally `true` for `Derivation` and `GenesisKey`, and is exactly
/// "the vector has an `update/` directory" for `UpdateCrypto` and `EndState` —
/// which is also what makes those kinds applicable at all. So only a `Resolve`
/// row can currently reach this report, and only in the narrow shape "external
/// id type, expected versionId 1, no sidecar genesis document, and no delivery
/// declaration". That shape is real — it is one upstream vector away — but a
/// new *operation* arriving upstream is caught by `classify_operation_dirs`,
/// not here. Widen this report if a future kind gains a conditional
/// drivability rule.
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
            if !v.is_drivable(kind) && v.skip_reasons_with(kind, overrides).is_empty() {
                rows.push(format!(
                    "  {} :: {kind} — classify it: drive it, add a derived skip rule, \
                     or add a SKIP_OVERRIDES entry with a reason",
                    v.id
                ));
            }
        }
    }
    rows
}

/// Overrides that match no discovered (vector, kind) row.
///
/// The symmetric half of the set invariant: additions to the test suite cannot
/// hide behind an unexercised harness, and removals cannot hide behind a skip
/// entry nobody deleted.
pub(crate) fn stale_overrides(overrides: &[SkipOverride], vectors: &[Vector]) -> Vec<String> {
    overrides
        .iter()
        .filter(|o| {
            !vectors
                .iter()
                .any(|v| v.id == o.vector && v.applicable_kinds().contains(&o.kind))
        })
        .map(|o| {
            format!(
                "  {} :: {} — stale SKIP override: the vector or the assertion no longer \
                 exists; delete the entry",
                o.vector, o.kind
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
/// Scope, so this is not over-trusted as a five-kind guard: the derived reasons
/// are `Resolve`-scoped (`skip_reasons_with` returns an empty set for every
/// other kind), so `derived` is non-empty only for a `Resolve` row and the loop
/// `continue`s unconditionally for the other four kinds. Iterating
/// `applicable_kinds()` is deliberate — it costs nothing and needs no edit if a
/// future rule gains a wider scope — but today this reports on `Resolve` alone.
pub(crate) fn redundant_overrides(vectors: &[Vector], overrides: &[SkipOverride]) -> Vec<String> {
    let mut rows = Vec::new();
    for v in vectors {
        for kind in v.applicable_kinds() {
            let derived = v.skip_reasons_with(kind, &[]);
            if derived.is_empty() {
                continue;
            }
            let redundant: Vec<SkipReason> = v
                .skip_reasons_with(kind, overrides)
                .into_iter()
                .filter(|reason| matches!(reason, SkipReason::Override(_)))
                .collect();
            if !redundant.is_empty() {
                rows.push(format!(
                    "  {} :: {kind} — hand-written skip {redundant:?} is redundant: a derived \
                     rule already skips this row for {derived:?}; delete the entry",
                    v.id
                ));
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
        for v in vectors
            .iter()
            .filter(|v| v.applicable_kinds().contains(&kind))
        {
            total_rows += 1;
            if v.should_drive_with(kind, overrides) {
                driven += 1;
            } else {
                skipped += 1;
                for reason in v.skip_reasons_with(kind, overrides) {
                    *by_reason.entry(reason).or_default() += 1;
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

    // Known upstream fixture defect: the specification requires
    // didDocumentMetadata.versionId to be an ASCII string. Reported on every
    // green run so it cannot be absorbed silently, and self-clearing once the
    // fixtures are corrected.
    let defective: Vec<&Vector> = vectors
        .iter()
        .filter(|v| v.version_id_is_number())
        .collect();
    if defective.is_empty() {
        out.push_str("  fixture defects: none\n");
    } else {
        let networks: BTreeSet<&str> = defective.iter().map(|v| v.network_dir.as_str()).collect();
        out.push_str(&format!(
            "  fixture defects: {} vector(s) encode versionId as a JSON number \
             (the specification requires an ASCII string): {}\n",
            defective.len(),
            networks.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    // Vectors whose update @context predates the spec's pin. Their Resolve
    // rows are parked under `StaleContext` while the upstream suite is
    // regenerated; named on every run so the parked coverage is visible, and
    // self-clearing once the regenerated vectors land.
    let stale: Vec<&Vector> = vectors.iter().filter(|v| v.stale_update_context).collect();
    if stale.is_empty() {
        out.push_str("  stale update @context: none\n");
    } else {
        let networks: BTreeSet<&str> = stale.iter().map(|v| v.network_dir.as_str()).collect();
        out.push_str(&format!(
            "  stale update @context: {} vector(s) predate the spec's pinned update @context \
             (regenerated upstream; Resolve rows skipped under StaleContext until the bump): {}\n",
            stale.len(),
            networks.into_iter().collect::<Vec<_>>().join(", ")
        ));
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
        "signedUpdate": { "targetVersionId": "2", "zeroVersionId": 0 },
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

    // A wrong type, an absent path and a zero `versionId` each name themselves.
    let cases: [(&str, &dyn Fn()); 3] = [
        ("genesisKeys.public", &|| {
            field_str(&value, "genesisKeys.public", "regtest/k1/qgpakaw4");
        }),
        ("genesisKeys.absent", &|| {
            field_str(&value, "genesisKeys.absent", "regtest/k1/qgpakaw4");
        }),
        ("signedUpdate.zeroVersionId", &|| {
            field_nonzero_version_id(&value, "signedUpdate.zeroVersionId", "regtest/k1/qgpakaw4");
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

/// The regtest vectors encode `versionId` as a string and the mutinynet
/// vectors as a number; both are read.
#[test]
fn version_id_accepts_number_and_ascii_string() {
    assert_eq!(version_id_u64(&serde_json::json!(3), "ctx"), 3);
    assert_eq!(version_id_u64(&serde_json::json!("3"), "ctx"), 3);
}

/// The coercion is permissive about the ENCODING only — anything that is not a
/// non-negative integer in either encoding is a corrupt fixture and panics.
#[test]
fn version_id_rejects_non_integer_forms() {
    for bad in [
        serde_json::json!(1.5),
        serde_json::json!(""),
        serde_json::json!("v2"),
        serde_json::json!(true),
        serde_json::json!(null),
    ] {
        let result = std::panic::catch_unwind(|| version_id_u64(&bad, "ctx"));
        assert!(
            result.is_err(),
            "versionId {bad} must be rejected, not coerced"
        );
    }
}

/// The present/absent probe and the discovery walk agree, and discovery is
/// content-based: `signet/` ships only documentation and contributes nothing,
/// and no dot-prefixed entry (notably `.git`) is ever treated as a network.
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
    assert!(
        dirs.iter().any(|d| d == "regtest"),
        "regtest ships vector directories: {dirs:?}"
    );
    assert!(
        dirs.iter().any(|d| d == "mutinynet"),
        "mutinynet ships vector directories: {dirs:?}"
    );
    assert!(
        !dirs.iter().any(|d| d == "signet"),
        "signet ships only README + TODO and must contribute no vectors: {dirs:?}"
    );
    assert!(
        !dirs.iter().any(|d| d.starts_with('.')),
        "a dot-prefixed entry is repository metadata, not a network: {dirs:?}"
    );
}

/// The JSON wrapper reads and parses a real fixture.
#[test]
fn read_fixture_json_parses_a_known_fixture() {
    let Some(value) = read_fixture_json("regtest/k1/qgpakaw4/create/output.json") else {
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
            version_id_string: Some("3".into()),
            deactivated: false,
            confirmations: Some(7),
        }
    );
}

/// A number-encoded `versionId` is still read, with no string recorded, and an
/// absent `confirmations` is `None`.
#[test]
fn outcome_reads_a_number_encoded_version_id() {
    let output = serde_json::json!({
        "didDocumentMetadata": { "versionId": 2, "deactivated": true },
    });
    assert_eq!(
        parse_outcome(&output, "ctx"),
        Outcome::Positive {
            version_id: 2,
            version_id_string: None,
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

/// The accessors over the main outcome: a positive set has a version and says
/// whether it was number-encoded; a negative set has neither.
#[test]
fn outcome_accessors_track_the_main_pair() {
    let mut v = synthetic_vector("regtest/k1/qgpakaw4", "k1");
    assert_eq!(v.expected_version_id(), Some(1));
    assert!(!v.version_id_is_number());
    assert!(!v.is_negative());

    v.outcome = positive_outcome(4, false);
    assert_eq!(v.expected_version_id(), Some(4));
    assert!(v.version_id_is_number());

    v.outcome = Outcome::Error {
        code: "INVALID_DID".into(),
    };
    assert_eq!(v.expected_version_id(), None);
    assert!(!v.version_id_is_number());
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
    assert!(
        !vectors.iter().any(|v| v.network_dir == "signet"),
        "signet ships no vector directories"
    );
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
        by_id("mutinynet/x1/q5m2fh36").update_layout,
        UpdateLayout::Numbered(vec!["01".into(), "02".into()])
    );
    assert_eq!(
        by_id("mutinynet/x1/qky9e7qz").update_layout,
        UpdateLayout::Numbered(vec!["01".into(), "02".into(), "03".into()])
    );
    assert_eq!(
        by_id("regtest/k1/qgpakaw4").update_layout,
        UpdateLayout::None
    );
    assert_eq!(
        by_id("mutinynet/k1/q5p6w9su").update_layout,
        UpdateLayout::Flat
    );

    // Genesis-only CAS-delivered vector: no update, no pending, CAS genesis,
    // and no sidecar genesis document to resolve from.
    let qh66uy2s = by_id("mutinynet/x1/qh66uy2s");
    assert_eq!(qh66uy2s.expected_version_id(), Some(1));
    assert!(!qh66uy2s.delivery.pending);
    assert_eq!(qh66uy2s.delivery.genesis, GenesisDelivery::Cas);
    assert_eq!(qh66uy2s.delivery.announcement, None);
    assert!(!qh66uy2s.has_sidecar_genesis_document);

    // versionId is coerced from BOTH encodings: regtest ships a string, the
    // mutinynet vectors a number.
    assert_eq!(by_id("regtest/k1/qgpakaw4").expected_version_id(), Some(1));
    assert_eq!(
        by_id("mutinynet/x1/qky9e7qz").expected_version_id(),
        Some(4)
    );

    // Beacon service types are collected from other.json.genesisDocument.
    assert!(
        by_id("mutinynet/x1/q425c5wf")
            .genesis_service_types
            .iter()
            .any(|t| t == "SMTBeacon"),
        "q425c5wf declares an SMT beacon in its genesis document"
    );
    // Update steps with no sidecar updates are CAS-announced; with them, the
    // sidecar delivers them, and a key-based genesis is deterministic.
    assert_eq!(
        by_id("mutinynet/x1/q4x4pxl2").delivery.announcement,
        Some(AnnouncementDelivery::Cas)
    );
    let qgppexmy = by_id("regtest/k1/qgppexmy");
    assert_eq!(qgppexmy.delivery.genesis, GenesisDelivery::Deterministic);
    assert_eq!(
        qgppexmy.delivery.announcement,
        Some(AnnouncementDelivery::Sidecar)
    );
    // The mutinynet sets name their scenario; the checked-out suite ships no
    // signals.json.
    assert!(
        by_id("mutinynet/x1/qh66uy2s").scenario_id.is_some(),
        "mutinynet sets carry other.json.scenarioId"
    );
    assert!(vectors.iter().all(|v| v.signals.is_none()));
    // The directory name maps to a Network, and the id-type segment is kept.
    assert_eq!(by_id("mutinynet/x1/q5ugrf3w").network, Network::Mutinynet);
    assert_eq!(by_id("mutinynet/x1/q5ugrf3w").kind, "x1");
    // short_id is the leaf segment of the id.
    assert_eq!(by_id("regtest/k1/qgpakaw4").short_id, "qgpakaw4");
    // step_prefixes() is the shape every update-walking driver iterates.
    assert_eq!(
        by_id("mutinynet/x1/q5m2fh36").update_layout.step_prefixes(),
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
        outcome: positive_outcome(1, true),
        resolve_cases: Vec::new(),
        stale_update_context: false,
        delivery: Delivery {
            genesis: match id_type_from_kind(kind) {
                VectorIdType::Key => GenesisDelivery::Deterministic,
                VectorIdType::External => GenesisDelivery::Sidecar,
            },
            announcement: None,
            negative: false,
            pending: false,
        },
        signals: None,
        scenario_id: None,
        genesis_service_types: Vec::new(),
        has_sidecar_genesis_document: true,
    }
}

/// A resolved-document outcome at `version`, not deactivated, with no
/// confirmations; `as_string` chooses the specification's ASCII-string
/// `versionId` over the JSON-number encoding some fixtures carry.
fn positive_outcome(version: u64, as_string: bool) -> Outcome {
    Outcome::Positive {
        version_id: version,
        version_id_string: as_string.then(|| version.to_string()),
        deactivated: false,
        confirmations: None,
    }
}

/// A positive set's delivery, for the classification tests.
fn delivery_of(
    genesis: GenesisDelivery,
    announcement: Option<AnnouncementDelivery>,
    pending: bool,
) -> Delivery {
    Delivery {
        genesis,
        announcement,
        negative: false,
        pending,
    }
}

/// Each of the three derived rules fires on its own input, and they accumulate
/// rather than electing a first-match winner.
#[test]
fn derived_reasons_cover_the_three_rules() {
    use AnnouncementDelivery as A;
    use GenesisDelivery as G;

    // Nothing applies: an anchored, sidecar-delivered vector.
    assert_eq!(
        derived_resolve_skip_reasons(&delivery_of(G::Sidecar, Some(A::Sidecar), false), &[]),
        BTreeSet::new()
    );
    // Rule 1 alone.
    assert_eq!(
        derived_resolve_skip_reasons(&delivery_of(G::Deterministic, None, true), &[]),
        BTreeSet::from([SkipReason::Unanchored])
    );
    // Rule 3 alone — the `qh66uy2s` shape: genesis-era, but CAS-delivered.
    assert_eq!(
        derived_resolve_skip_reasons(&delivery_of(G::Cas, None, false), &[]),
        BTreeSet::from([SkipReason::CasDelivery])
    );
    // Rule 3 on the announcements alone.
    assert_eq!(
        derived_resolve_skip_reasons(&delivery_of(G::Deterministic, Some(A::Cas), false), &[]),
        BTreeSet::from([SkipReason::CasDelivery])
    );
    // Rules 1, 2 and 3 together, with the duplicate CAS signal collapsing.
    assert_eq!(
        derived_resolve_skip_reasons(
            &delivery_of(G::Cas, Some(A::Cas), true),
            &["SingletonBeacon".into(), "CASBeacon".into()]
        ),
        BTreeSet::from([
            SkipReason::Unanchored,
            SkipReason::CasDelivery,
            SkipReason::UnsupportedBeaconType,
        ])
    );
    // Rule 2 on the beacon type, with `SingletonBeacon` contributing nothing.
    // An SMT beacon in the genesis document blocks resolve twice over: the
    // delivery mechanism is unimplemented, AND the resolver will not issue a
    // request for that beacon type at all.
    assert_eq!(
        derived_resolve_skip_reasons(
            &delivery_of(G::Sidecar, None, false),
            &["SingletonBeacon".into(), "SMTBeacon".into()]
        ),
        BTreeSet::from([SkipReason::SmtDelivery, SkipReason::UnsupportedBeaconType,])
    );
    // Rule 2 applies to a negative set too: its beacons are what they are.
    let negative = Delivery {
        negative: true,
        ..delivery_of(G::Sidecar, Some(A::Sidecar), false)
    };
    assert_eq!(
        derived_resolve_skip_reasons(&negative, &["SMTBeacon".into()]),
        BTreeSet::from([SkipReason::SmtDelivery, SkipReason::UnsupportedBeaconType])
    );
}

/// The anchoring and delivery reasons say nothing about whether a patch
/// sequence reproduces a document, so they scope to `Resolve` alone — an
/// unanchored, CAS-delivered vector still drives its update assertions.
#[test]
fn delivery_reasons_scope_to_resolve_only() {
    let mut v = synthetic_vector("mutinynet/x1/q5m2fh36", "x1");
    v.delivery.pending = true;
    v.delivery.genesis = GenesisDelivery::Cas;
    v.outcome = positive_outcome(3, true);
    v.update_layout = UpdateLayout::Numbered(vec!["01".into(), "02".into()]);

    assert_eq!(
        v.skip_reasons_with(AssertionKind::Resolve, &[]),
        BTreeSet::from([SkipReason::Unanchored, SkipReason::CasDelivery])
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
        assert_eq!(v.applicable_kinds(), AssertionKind::ALL.to_vec());
    }
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
    key_based.outcome = positive_outcome(2, true);
    assert!(key_based.is_drivable(AssertionKind::Resolve));
    external.outcome = positive_outcome(2, true);
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
    let qh66uy2s = by_id("mutinynet/x1/qh66uy2s");
    assert_eq!(
        qh66uy2s.skip_reasons_with(AssertionKind::Resolve, &[]),
        BTreeSet::from([SkipReason::CasDelivery])
    );
    assert!(!qh66uy2s.should_drive_with(AssertionKind::Resolve, &[]));

    // A pending, multi-update vector still drives both update assertions.
    let q5m2fh36 = by_id("mutinynet/x1/q5m2fh36");
    assert!(q5m2fh36.should_drive_with(AssertionKind::UpdateCrypto, &[]));
    assert!(q5m2fh36.should_drive_with(AssertionKind::EndState, &[]));
    assert!(!q5m2fh36.should_drive_with(AssertionKind::Resolve, &[]));
}

/// The `versionId` encoding defect on disk is pinned to an explicit id set, in
/// both directions: an unlisted number-encoded vector is a NEW defect, and a
/// listed vector that is now string-encoded means the list is stale.
///
/// A number-encoded vector reaching this test unlisted would otherwise be
/// absorbed silently by the encoding-tolerant coercion, and an upstream (or our
/// own) conformance fix must not read as though the corrected fixture were at
/// fault.
#[test]
fn live_vectors_record_their_version_id_encoding() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    assert!(!vectors.is_empty());

    // Vacuity guard: the list describes vectors that exist.
    for listed in NUMBER_ENCODED_VERSION_ID {
        assert!(
            vectors.iter().any(|v| v.id == *listed),
            "{listed} is listed in NUMBER_ENCODED_VERSION_ID but was not discovered — \
             the vector was renamed or removed upstream; delete the entry"
        );
    }

    for v in &vectors {
        let known_bad = NUMBER_ENCODED_VERSION_ID.contains(&v.id.as_str());
        assert!(
            v.version_id_is_number() == known_bad,
            "{}: {}",
            v.id,
            if v.version_id_is_number() {
                "NEW versionId encoding defect — resolve/output.json encodes versionId as a \
                 JSON number, but the specification requires an ASCII string. Fix the fixture, \
                 or add this id to NUMBER_ENCODED_VERSION_ID to record it as known-bad."
            } else {
                "versionId is now correctly encoded as an ASCII string — delete this id from \
                 NUMBER_ENCODED_VERSION_ID."
            }
        );
    }
}

/// The stale update `@context` population is exactly `STALE_UPDATE_CONTEXT`,
/// in both directions: a stale vector not listed is a new pre-pin vector, and
/// a listed vector that is now clean means the list is stale. The count is
/// pinned too, so a partial regeneration trips this rather than being absorbed
/// by the derived skip while `DRIVEN_FLOOR`'s Resolve entry stays lowered.
#[test]
fn live_vectors_record_their_update_context() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    assert!(!vectors.is_empty());

    assert_eq!(
        STALE_UPDATE_CONTEXT.len(),
        17,
        "the stale update @context population is pinned at 17 vectors — every vector with \
         an update/ directory in the vendor suite as checked out; when the regenerated suite \
         is absorbed, empty the list, re-raise DRIVEN_FLOOR's Resolve entry, and drop this pin"
    );

    // Vacuity guard: the list describes vectors that exist.
    for listed in STALE_UPDATE_CONTEXT {
        assert!(
            vectors.iter().any(|v| v.id == *listed),
            "{listed} is listed in STALE_UPDATE_CONTEXT but was not discovered — \
             the vector was renamed or removed upstream; delete the entry"
        );
    }

    for v in &vectors {
        let listed = STALE_UPDATE_CONTEXT.contains(&v.id.as_str());
        assert!(
            v.stale_update_context == listed,
            "{}: {}",
            v.id,
            if v.stale_update_context {
                "NEW vector carrying the pre-pin update @context — add this id to \
                 STALE_UPDATE_CONTEXT, or fix the fixture"
            } else {
                "update @context is now the pinned array — delete this id from \
                 STALE_UPDATE_CONTEXT and re-raise DRIVEN_FLOOR's Resolve entry"
            }
        );
    }
}

/// Three synthetic vectors spanning the shapes the ledger has to tell apart: a
/// fully drivable genesis-era vector, an unanchored multi-update vector, and a
/// genesis-era vector classified solely by its delivery declaration.
fn synthetic_ledger() -> Vec<Vector> {
    let genesis_era = synthetic_vector("regtest/k1/qgpakaw4", "k1");

    let mut multi_update = synthetic_vector("mutinynet/x1/q5m2fh36", "x1");
    multi_update.update_layout = UpdateLayout::Numbered(vec!["01".into(), "02".into()]);
    multi_update.delivery.pending = true;
    multi_update.delivery.genesis = GenesisDelivery::Cas;
    // Both mutinynet members carry the number-encoded versionId the live
    // mutinynet fixtures carry, so the summary's defect line has a non-empty
    // case to report.
    multi_update.outcome = positive_outcome(3, false);

    let mut cas_genesis = synthetic_vector("mutinynet/x1/qh66uy2s", "x1");
    cas_genesis.has_sidecar_genesis_document = false;
    cas_genesis.delivery.genesis = GenesisDelivery::Cas;
    cas_genesis.outcome = positive_outcome(1, false);

    vec![genesis_era, multi_update, cas_genesis]
}

/// The panic message of a `reconcile_driven` call that is expected to fail.
fn reconcile_panic_message(
    kind: AssertionKind,
    vectors: &[Vector],
    observed: &BTreeSet<String>,
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
        let want: BTreeSet<String> = vectors
            .iter()
            .filter(|v| v.should_drive_with(kind, &[]))
            .map(|v| v.id.clone())
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
        BTreeSet::from(["regtest/k1/qgpakaw4".to_string()])
    );
    assert_eq!(
        expected_driven_with(AssertionKind::UpdateCrypto, &vectors, &[]),
        BTreeSet::from(["mutinynet/x1/q5m2fh36".to_string()])
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
    let dropped = "mutinynet/x1/qh66uy2s".to_string();
    assert!(
        observed.remove(&dropped),
        "the dropped row must have been expected in the first place"
    );

    let message = reconcile_panic_message(AssertionKind::Derivation, &vectors, &observed);
    assert!(
        message.contains(&dropped) && message.contains("expected but not driven"),
        "the message must name the missing row: {message}"
    );
}

/// The symmetric failure: a driver asserted against a row the ledger classified
/// as skipped, so one of the two is stale.
#[test]
fn reconcile_fails_on_an_unexpected_driven_row() {
    let vectors = synthetic_ledger();
    let mut observed = expected_driven_with(AssertionKind::Resolve, &vectors, &[]);
    let extra = "mutinynet/x1/qh66uy2s".to_string();
    observed.insert(extra.clone());

    let message = reconcile_panic_message(AssertionKind::Resolve, &vectors, &observed);
    assert!(
        message.contains(&extra) && message.contains("driven but not expected"),
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
    for reason in [SkipReason::Unanchored, SkipReason::CasDelivery] {
        assert!(
            summary.contains(&reason.to_string()),
            "{reason} applies to the synthetic ledger and must be broken out:\n{summary}"
        );
    }
}

/// The summary reports the fixture defect the coercion papers over, so a green
/// run says out loud that some vectors are non-conformant on this field.
#[test]
fn summary_reports_the_version_id_fixture_defect() {
    let ledger = synthetic_ledger();
    let defective = ledger.iter().filter(|v| v.version_id_is_number()).count();
    assert_eq!(defective, 2, "the fixture must exercise the non-empty case");

    let summary = render_summary_with(&ledger, &[]);
    assert!(summary.contains("fixture defects: 2"), "{summary}");
    assert!(
        summary.contains("versionId") && summary.contains("JSON number"),
        "{summary}"
    );
    assert!(summary.contains("mutinynet"), "{summary}");

    let clean: Vec<Vector> = ledger
        .into_iter()
        .map(|mut v| {
            let version = v
                .expected_version_id()
                .expect("the synthetic ledger is positive");
            v.outcome = positive_outcome(version, true);
            v
        })
        .collect();
    assert!(
        render_summary_with(&clean, &[]).contains("fixture defects: none"),
        "a clean ledger says so explicitly rather than omitting the line"
    );
}

/// The summary names the stale update `@context` population on every run, so
/// a green run says out loud how many Resolve rows are parked and why; and it
/// says "none" rather than omitting the line once the population empties.
#[test]
fn summary_reports_stale_context() {
    let ledger: Vec<Vector> = synthetic_ledger()
        .into_iter()
        .map(|mut v| {
            v.stale_update_context = true;
            v
        })
        .collect();
    let stale = ledger.iter().filter(|v| v.stale_update_context).count();
    assert_eq!(stale, 3, "the fixture must exercise the non-empty case");

    let summary = render_summary_with(&ledger, &[]);
    assert!(summary.contains("stale update @context: 3"), "{summary}");
    assert!(
        summary.contains("StaleContext") && summary.contains("regenerated upstream"),
        "{summary}"
    );
    assert!(
        summary.contains("mutinynet, regtest"),
        "both networks in the ledger are named:\n{summary}"
    );
    assert!(
        summary.contains(&SkipReason::StaleContext.to_string()),
        "the reason is broken out in the skipped-rows table:\n{summary}"
    );

    let clean: Vec<Vector> = ledger
        .into_iter()
        .map(|mut v| {
            v.stale_update_context = false;
            v
        })
        .collect();
    let summary = render_summary_with(&clean, &[]);
    assert!(
        summary.contains("stale update @context: none"),
        "a clean ledger says so explicitly rather than omitting the line:\n{summary}"
    );
    assert!(
        !summary.contains(&SkipReason::StaleContext.to_string()),
        "no row carries the reason once the population is empty:\n{summary}"
    );
}

/// `StaleContext` parks the Resolve row only. The update-crypto and end-state
/// drivers rebuild the update from `input.json` and compare document hashes,
/// never reading the vector's `@context`, so skipping them would hide rows
/// whose assertion passes.
#[test]
fn stale_context_applies_to_the_resolve_kind_only() {
    let mut v = synthetic_vector("regtest/k1/qgppexmy", "k1");
    v.update_layout = UpdateLayout::Flat;
    v.outcome = positive_outcome(2, true);
    v.stale_update_context = true;

    assert!(
        v.skip_reasons_with(AssertionKind::Resolve, &[])
            .contains(&SkipReason::StaleContext),
        "a stale vector's resolve row is parked"
    );
    assert!(
        !v.should_drive_with(AssertionKind::Resolve, &[]),
        "a parked row is not driven"
    );
    for kind in [
        AssertionKind::Derivation,
        AssertionKind::GenesisKey,
        AssertionKind::UpdateCrypto,
        AssertionKind::EndState,
    ] {
        assert!(
            !v.skip_reasons_with(kind, &[])
                .contains(&SkipReason::StaleContext),
            "{kind} must not inherit the resolve-scoped StaleContext reason"
        );
        assert!(
            v.should_drive_with(kind, &[]),
            "{kind} stays driven on a stale vector"
        );
    }

    v.stale_update_context = false;
    assert!(
        v.skip_reasons_with(AssertionKind::Resolve, &[]).is_empty(),
        "the rule clears itself with the flag"
    );
}

/// A hand-written skip on a row a derived rule already covers is reported: the
/// entry is redundant the day it is written and stale the day the rule changes.
#[test]
fn redundant_override_on_a_derived_skip_row_is_reported() {
    const OVERRIDES: &[SkipOverride] = &[SkipOverride {
        vector: "mutinynet/x1/qh66uy2s",
        kind: AssertionKind::Resolve,
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
            .contains("regtest/x1/q2fz9mz6"),
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
    let path = chain_fixture_path("regtest/k1/qgppexmy");
    assert!(
        path.ends_with("fixtures/chain/regtest/k1/qgppexmy.json"),
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
    let fixture = read_chain_fixture("regtest/k1/qgppexmy");

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
    let fixture = read_chain_fixture("regtest/k1/qgppexmy");

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
    let vendor = read_chain_fixture("regtest/k1/qgppexmy");
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

/// The signal-block ledger is exact in both directions: every committed
/// capture that lacks a `/block/{hash}` body for one of its announcements is
/// listed in `FIXTURES_WITHOUT_SIGNAL_BLOCKS`, and every listed capture still
/// lacks one. A re-capture that fills the blocks in fails here saying the
/// list is stale — which is the moment the versionTime probes start running
/// on that fixture — and a new capture missing blocks fails as a new defect.
#[test]
fn chain_fixture_signal_block_ledger_is_exact() {
    for id in ALL_CHAIN_FIXTURES {
        let fixture = read_chain_fixture(id);
        let listed = FIXTURES_WITHOUT_SIGNAL_BLOCKS.contains(id);
        match fixture.earliest_signal_mediantime() {
            Ok(_) => assert!(
                !listed,
                "{id}: the capture now holds every announcement's block — delete it from \
                 FIXTURES_WITHOUT_SIGNAL_BLOCKS so its versionTime probes run"
            ),
            Err(missing) => assert!(
                listed,
                "{id}: the capture holds no `/block/{missing}` body for one of its announcements; \
                 re-run capture, or add the id to FIXTURES_WITHOUT_SIGNAL_BLOCKS to record it as \
                 known-incomplete"
            ),
        }
    }
    for listed in FIXTURES_WITHOUT_SIGNAL_BLOCKS {
        assert!(
            ALL_CHAIN_FIXTURES.contains(listed),
            "{listed} is listed in FIXTURES_WITHOUT_SIGNAL_BLOCKS but is not a committed fixture"
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
            &delivery_of(GenesisDelivery::Sidecar, None, false),
            &["SingletonBeacon".into(), "SMTBeacon".into()]
        ),
        BTreeSet::from([SkipReason::SmtDelivery, SkipReason::UnsupportedBeaconType])
    );
    assert_eq!(
        derived_resolve_skip_reasons(
            &delivery_of(GenesisDelivery::Sidecar, None, false),
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
            &delivery_of(GenesisDelivery::Sidecar, None, false),
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
            &delivery_of(GenesisDelivery::Cas, Some(AnnouncementDelivery::Cas), false),
            &[]
        ),
        BTreeSet::from([SkipReason::CasDelivery])
    );
}

/// The reason fires on exactly the discovered vectors whose genesis document
/// declares a CAS or SMT beacon, and on no others. Pinned as an exact id set so
/// an upstream vector gaining or losing such a beacon fails by name rather than
/// quietly moving the aggregation milestone's target set.
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

    let observed: BTreeSet<String> = vectors
        .iter()
        .filter(|v| {
            v.skip_reasons_with(AssertionKind::Resolve, &[])
                .contains(&SkipReason::UnsupportedBeaconType)
        })
        .map(|v| v.id.clone())
        .collect();

    let expected: BTreeSet<String> = [
        "mutinynet/x1/q425c5wf",
        "mutinynet/x1/q4lqu6gr",
        "mutinynet/x1/q4rnhfhv",
        "mutinynet/x1/q4x4pxl2",
        "mutinynet/x1/q550pp4e",
        "mutinynet/x1/q59jnwfs",
        "mutinynet/x1/q5cfewep",
        "mutinynet/x1/qkrrp544",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    assert_eq!(
        observed, expected,
        "the vectors whose genesis document declares a CAS or SMT beacon"
    );

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

/// The rows the resolve driver is expected to drive, pinned BY ID.
///
/// [`DRIVEN_FLOOR`] alone would say only that the number moved. This says WHICH
/// row moved: the four genesis-era rows are driven; the seven anchored
/// past-genesis rows fed from `fixtures/chain/` (`mutinynet/k1/q5p6w9su`,
/// `mutinynet/k1/q5pgeu9z`, `mutinynet/x1/q5ugrf3w`, `regtest/k1/qgppexmy`,
/// `regtest/k1/qgpy0hmm`, `regtest/x1/q26jeds9`, `regtest/x1/qfl7se8f`) are
/// parked under [`SkipReason::StaleContext`] and return here when the
/// regenerated suite is absorbed. A vector losing its sidecar genesis
/// document, gaining a `pending.json`, clearing its stale `@context` early, or
/// an upstream vector arriving with a shape the rules classify differently
/// fails here naming the difference, instead of being absorbed by a `>=`
/// ratchet.
#[test]
fn resolve_driven_set_is_the_expected_four_ids() {
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

    let expected: BTreeSet<String> = [
        // Genesis-era, driven since the offline harness landed.
        "mutinynet/k1/q5puld7y",
        "mutinynet/x1/q5g3smvu",
        "regtest/k1/qgpakaw4",
        "regtest/x1/q2fz9mz6",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    let missing: Vec<&String> = expected.difference(&observed).collect();
    let extra: Vec<&String> = observed.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "the resolve driven set moved.\n  \
         expected but not driven ({}): {missing:?}\n  \
         driven but not expected ({}): {extra:?}\n  \
         Update this list together with DRIVEN_FLOOR, or restore the row.",
        missing.len(),
        extra.len(),
    );
    assert_eq!(observed.len(), 4, "the floor and this list must agree");
}

/// `Override` stays LAST in the derived ordering: `PartialOrd`/`Ord` are derived
/// and the summary keys a `BTreeMap` on this enum, so variant order is report
/// order and a hand-written skip belongs at the bottom of the table.
#[test]
fn override_still_sorts_after_every_derived_reason() {
    let ordered: Vec<SkipReason> = BTreeSet::from([
        SkipReason::Override("a one-off"),
        SkipReason::StaleContext,
        SkipReason::UnsupportedBeaconType,
        SkipReason::SmtDelivery,
        SkipReason::CasDelivery,
        SkipReason::Unanchored,
    ])
    .into_iter()
    .collect();

    assert_eq!(
        ordered,
        vec![
            SkipReason::Unanchored,
            SkipReason::CasDelivery,
            SkipReason::SmtDelivery,
            SkipReason::UnsupportedBeaconType,
            SkipReason::StaleContext,
            SkipReason::Override("a one-off"),
        ]
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
    let signals = signals_from(
        serde_json::json!([
            signal_entry(None, 300, Some(cohort_json())),
            signal_entry(None, 300, Some(cohort_json())),
        ]),
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
    let signals = signals_from(
        serde_json::json!([signal_entry(Some(1), 300, None), repeat]),
        &two_steps(),
    )
    .expect("a flagged later duplicate parses");
    assert!(signals.entries[1].duplicate);
}

/// The same repeat without the flag is rejected.
#[test]
fn signals_reject_an_unflagged_repeat() {
    let err = signals_from(
        serde_json::json!([
            signal_entry(Some(1), 300, None),
            signal_entry(Some(1), 326, None)
        ]),
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
    let mut entry = signal_entry(None, 1000, Some(cohort.clone()));
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
    let external = derive_delivery(VectorIdType::External, true, false, true, false, false);
    assert!(external.negative);
    assert_eq!(external.genesis, GenesisDelivery::Sidecar);
    assert_eq!(external.announcement, Some(AnnouncementDelivery::Sidecar));

    let key = derive_delivery(VectorIdType::Key, true, false, false, false, false);
    assert_eq!(key.genesis, GenesisDelivery::Deterministic);
    assert_eq!(key.announcement, None);
}

/// A positive external set with no sidecar genesis document has a CAS genesis;
/// with one, the sidecar delivers it.
#[test]
fn delivery_external_genesis_follows_the_sidecar() {
    let cas = derive_delivery(VectorIdType::External, false, false, false, false, false);
    assert_eq!(cas.genesis, GenesisDelivery::Cas);
    assert!(!cas.negative);

    let sidecar = derive_delivery(VectorIdType::External, false, true, false, false, false);
    assert_eq!(sidecar.genesis, GenesisDelivery::Sidecar);
}

/// Update steps with no sidecar `updates` are CAS-announced; with them, the
/// sidecar delivers them; with no update steps there is no announcement.
#[test]
fn delivery_announcement_follows_the_sidecar_updates() {
    let cas = derive_delivery(VectorIdType::Key, false, false, true, false, false);
    assert_eq!(cas.announcement, Some(AnnouncementDelivery::Cas));

    let sidecar = derive_delivery(VectorIdType::Key, false, false, true, true, false);
    assert_eq!(sidecar.announcement, Some(AnnouncementDelivery::Sidecar));

    let none = derive_delivery(VectorIdType::Key, false, false, false, true, false);
    assert_eq!(none.announcement, None);
}

/// A key-based genesis is deterministic whatever the sidecar says, and
/// `pending` is carried through.
#[test]
fn delivery_key_genesis_is_deterministic() {
    for has_sidecar_genesis in [false, true] {
        let d = derive_delivery(
            VectorIdType::Key,
            false,
            has_sidecar_genesis,
            false,
            false,
            true,
        );
        assert_eq!(d.genesis, GenesisDelivery::Deterministic);
        assert!(d.pending);
    }
}

/// A declared CAS genesis the files do not show, and a CAS genesis the files
/// show but the scenario does not declare, both disagree.
#[test]
fn delivery_cross_check_rejects_a_genesis_disagreement() {
    use GenesisDelivery as G;
    for derived in [G::Deterministic, G::Sidecar] {
        let err = cross_check_scenario(&delivery_of(derived, None, false), Some("cas"), None, &[])
            .expect_err("declared CAS genesis vs a non-CAS derivation");
        assert!(err.contains("disagree") && err.contains("cas"), "{err}");
    }
    cross_check_scenario(&delivery_of(G::Cas, None, false), None, None, &[])
        .expect_err("a derived CAS genesis the scenario does not declare");
    cross_check_scenario(&delivery_of(G::Cas, None, false), Some("cas"), None, &[])
        .expect("agreement passes");
}

/// On an anchored set a declared CAS announcement must be what the files show.
#[test]
fn delivery_cross_check_rejects_an_announcement_disagreement_when_anchored() {
    let derived = delivery_of(GenesisDelivery::Cas, None, false);
    let err = cross_check_scenario(&derived, Some("cas"), Some("cas"), &[])
        .expect_err("declared CAS announcement vs no announcement");
    assert!(
        err.contains("announcement") && err.contains("disagree"),
        "{err}"
    );
}

/// A pending set never anchored its updates, so only its genesis delivery is
/// cross-checked: the same disagreement passes, and a genesis disagreement
/// still fails.
#[test]
fn delivery_cross_check_checks_genesis_only_when_pending() {
    let derived = delivery_of(GenesisDelivery::Cas, None, true);
    cross_check_scenario(&derived, Some("cas"), Some("cas"), &[])
        .expect("the announcement of a pending set is not cross-checked");
    let derived = delivery_of(GenesisDelivery::Cas, Some(AnnouncementDelivery::Cas), true);
    cross_check_scenario(&derived, Some("cas"), None, &[]).expect("nor is an undeclared one");
    let derived = delivery_of(GenesisDelivery::Sidecar, None, true);
    cross_check_scenario(&derived, Some("cas"), None, &[])
        .expect_err("the genesis of a pending set still is");
}

/// A null or absent `delivery` declares nothing and is not checked, even where
/// the files show CAS delivery.
#[test]
fn delivery_cross_check_skips_a_null_declaration() {
    let derived = delivery_of(GenesisDelivery::Cas, Some(AnnouncementDelivery::Cas), false);
    for scenario in [
        serde_json::json!({ "delivery": null }),
        serde_json::json!({}),
    ] {
        check_scenario_delivery(&derived, &scenario, &[]).expect("nothing is declared");
    }
    check_scenario_delivery(
        &derived,
        &serde_json::json!({ "delivery": { "genesis": "cas", "announcement": "cas" } }),
        &[],
    )
    .expect("a matching declaration passes through the whole-file entry point");
    check_scenario_delivery(
        &delivery_of(GenesisDelivery::Sidecar, None, false),
        &serde_json::json!({ "delivery": { "genesis": "cas" } }),
        &[],
    )
    .expect_err("a disagreeing one fails through it");
}

/// A declared SMT delivery needs an SMT beacon in the genesis document.
#[test]
fn delivery_cross_check_smt_requires_an_smt_beacon() {
    let derived = delivery_of(
        GenesisDelivery::Sidecar,
        Some(AnnouncementDelivery::Sidecar),
        false,
    );
    let err = cross_check_scenario(&derived, None, Some("smt"), &["SingletonBeacon".into()])
        .expect_err("SMT declared with no SMT beacon");
    assert!(err.contains("SMTBeacon"), "{err}");
    cross_check_scenario(&derived, None, Some("smt"), &["SMTBeacon".into()])
        .expect("SMT declared with an SMT beacon");
}

/// The derived CAS delivery set on the checked-out suite, pinned by id: the
/// seven external sets whose files show a CAS genesis, plus the two whose
/// genesis document declares a `CASBeacon`. Every declaring `scenario.json` was
/// cross-checked against these at discovery, so this pin is the cross-check's
/// observable result.
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

    let observed: BTreeSet<String> = vectors
        .iter()
        .filter(|v| {
            v.skip_reasons_with(AssertionKind::Resolve, &[])
                .contains(&SkipReason::CasDelivery)
        })
        .map(|v| v.id.clone())
        .collect();
    let expected: BTreeSet<String> = [
        "mutinynet/x1/q4lqu6gr",
        "mutinynet/x1/q4rnhfhv",
        "mutinynet/x1/q4x4pxl2",
        "mutinynet/x1/q550pp4e",
        "mutinynet/x1/q59jnwfs",
        "mutinynet/x1/q5m2fh36",
        "mutinynet/x1/qh66uy2s",
        "mutinynet/x1/qkrrp544",
        "mutinynet/x1/qky9e7qz",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(
        observed, expected,
        "the sets whose files (or genesis beacons) show CAS delivery"
    );
}

/// No set of the checked-out suite expects an error, so a negative set leaking
/// in fails here by name rather than as a driver failure.
#[test]
fn no_live_vector_is_negative() {
    if !test_suite_checked_out() {
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        return;
    }
    let vectors = discover_in(&Corpus::test_suite());
    assert!(!vectors.is_empty());
    let negative: Vec<&str> = vectors
        .iter()
        .filter(|v| v.is_negative())
        .map(|v| v.id.as_str())
        .collect();
    assert!(
        negative.is_empty(),
        "the checked-out suite ships no negative set, but these expect an error: {negative:?}"
    );
}
