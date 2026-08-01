//! The chain-fixture envelope: what one capture session persists, where it goes
//! on disk, and how it is written.
//!
//! One file per vector or minted scenario, mirroring the test-suite tree, so a
//! vector maps to its fixture mechanically from ids the reader already has and
//! the provenance travels with the data.

use onlyerror::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// One captured chain snapshot for one vector or minted scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainFixture {
    /// RFC-3339 UTC instant the capture ran.
    pub captured_at: String,
    /// Esplora base URL the bodies came from. The base URL ONLY: no credential
    /// ever belongs in a committed fixture.
    ///
    /// Enforced rather than asserted: `targets::endpoint` refuses a userinfo
    /// component or a query string before a session issues its first request, so
    /// a credential-bearing endpoint cannot reach this field.
    pub endpoint: String,
    /// `"regtest"` / `"mutinynet"` / `"testnet4"` / `"signet"`. Recorded, never
    /// assumed: the minted scenarios are re-minted on successively more durable
    /// chains, and each move regenerates these fixtures — so the chain is
    /// fixture DATA, not a constant baked into any reader.
    pub network: String,
    /// `"regtest/k1/qgppexmy"` or `"minted/clean-rotating-beacons"`.
    pub vector: String,
    /// The DID this snapshot resolves.
    pub did: String,
    /// `/blocks/tip/height` at capture time. Replay pins this as the resolution
    /// options' chain tip height, so `confirmations` is reproducible.
    pub tip_height: u32,
    /// Every beacon signal found in the captured bodies, in capture order.
    pub signals: Vec<CapturedSignal>,
    /// Per-address `GET /address/{a}/txs` bodies, verbatim and parsed.
    ///
    /// A key present with `[]` means captured-and-empty; a key ABSENT means
    /// never captured, and only the latter is a replay failure.
    pub addresses: BTreeMap<String, Vec<Value>>,
    /// Minted scenarios only: the sidecar the replay test must resolve with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar: Option<Value>,
    /// Minted scenarios only: `{"didDocument": .., "didDocumentMetadata": ..}`
    /// for a scenario that resolves, or `{"error": "LATE_PUBLISHING"}` for one
    /// that must abort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<Value>,
}

/// A beacon signal observed in a captured body: the provenance that makes the
/// confirmations and `versionTime` assertions derivable without re-parsing
/// scripts.
///
/// Derived data. It is re-derivable from [`ChainFixture::addresses`] at read
/// time, and the replay reader checks exactly that on every load, so a hand edit
/// or a partial re-capture cannot desynchronize the two.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedSignal {
    /// Beacon address whose body carried this transaction.
    pub address: String,
    /// Transaction id of the beacon announcement.
    pub txid: String,
    /// Height of the block confirming it.
    pub block_height: u32,
    /// Unix timestamp of that block.
    pub block_time: i64,
    /// Lowercase hex of the 32 `OP_RETURN` push bytes (the update hash).
    pub update_hash: String,
}

/// Fixture-layer failures: an unusable vector id, a serialization fault, or an
/// I/O fault. None of them panics; a bad operator argument is a typed error.
#[derive(Debug, Error)]
pub enum FixtureError {
    /// The vector id would escape the fixture root (empty, absolute, or
    /// carrying a `..` segment), so no path is derived from it.
    #[error(
        "unusable vector id `{0}`: it must be a relative path of plain segments (e.g. `regtest/k1/qgppexmy` or `minted/clean-rotating-beacons`)"
    )]
    UnsafeVectorId(String),

    /// JSON serialization of the fixture body failed.
    Json(#[from] serde_json::Error),

    /// I/O error creating the directory, writing the temporary file, or
    /// renaming it over the target.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// The directory every chain fixture lives under.
///
/// Derived from `CARGO_MANIFEST_DIR`, which is fixed at compile time, so the
/// tool writes into the right tree no matter which directory it is invoked from.
pub fn fixture_root() -> PathBuf {
    PathBuf::from(format!(
        "{}/../../fixtures/chain",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Map a vector id to its fixture file.
///
/// `regtest/k1/qgppexmy` becomes `<root>/regtest/k1/qgppexmy.json`;
/// `minted/clean-rotating-beacons` becomes
/// `<root>/minted/clean-rotating-beacons.json`.
///
/// An id that is empty, absolute, or contains a `..` (or `.`) segment is
/// rejected before anything is joined, so a hostile or fat-fingered
/// `--vector ../../../etc/x` cannot reach outside the root. The check lives
/// only here, so no caller can join an unchecked id onto any root.
///
/// Every caller passes a root — the repository's own comes from
/// [`fixture_root`] — so no destination is ever derived from an ambient
/// default, and a caller whose write semantics need testing can be pointed at a
/// scratch tree.
pub fn fixture_path_in(root: &Path, vector: &str) -> Result<PathBuf, FixtureError> {
    let relative = Path::new(vector);
    let mut segments = 0usize;
    for component in relative.components() {
        match component {
            Component::Normal(_) => segments += 1,
            // RootDir/Prefix (absolute), ParentDir (`..`) and CurDir (`.`) all
            // mean the id is not a plain relative location under the root.
            _ => return Err(FixtureError::UnsafeVectorId(vector.to_string())),
        }
    }
    if segments == 0 {
        return Err(FixtureError::UnsafeVectorId(vector.to_string()));
    }
    Ok(root.join(format!("{vector}.json")))
}

/// Serialize `fixture` and write it under `root` atomically.
///
/// The filename comes from the fixture's own `vector` field — the caller passes
/// a root but never a path, so the id in the data and the id in the filename
/// cannot disagree. The id check lives in [`fixture_path_in`], so no root
/// shortens it, and a caller whose write semantics need testing can be pointed
/// at a scratch tree instead of this repository's fixture directory.
///
/// The full JSON body is built in memory, written to `<path>.tmp`, then renamed
/// over the target. Rename is atomic on the same filesystem, so an interrupted
/// or failed write never leaves the target truncated or holding invalid JSON:
/// the previous contents survive intact.
///
/// Bodies are stored pretty-printed and parsed — never trimmed. A re-capture
/// then produces a reviewable line-oriented diff, and whatever the endpoint
/// returned is what is stored.
pub fn write_atomic_in(root: &Path, fixture: &ChainFixture) -> Result<PathBuf, FixtureError> {
    let path = fixture_path_in(root, &fixture.vector)?;
    write_atomic_to(&path, fixture)?;
    Ok(path)
}

/// [`write_atomic_in`]'s body against a fully resolved destination, so the
/// rename semantics can be exercised on a path no vector id maps to.
fn write_atomic_to(path: &Path, fixture: &ChainFixture) -> Result<(), FixtureError> {
    let body = serde_json::to_string_pretty(fixture)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.to_path_buf().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A scratch directory unique to one test, removed by the test itself.
    fn scratch_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chain-capture-fixture-{}-{tag}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");
        dir
    }

    /// A fixture with one populated address and one captured-but-empty address.
    fn sample_fixture() -> ChainFixture {
        let mut addresses = BTreeMap::new();
        addresses.insert(
            "bcrt1qpopulated".to_string(),
            vec![json!({
                "txid": "aa".repeat(32),
                "version": 2,
                "locktime": 0,
                "vin": [],
                "vout": [{ "scriptpubkey": "6a2011".to_string() + &"22".repeat(31), "value": 0 }],
                "size": 0,
                "weight": 0,
                "fee": 0,
                "status": {
                    "confirmed": true,
                    "block_height": 120,
                    "block_hash": "00".repeat(32),
                    "block_time": 1_700_000_000i64,
                },
            })],
        );
        addresses.insert("bcrt1qempty".to_string(), Vec::new());

        ChainFixture {
            captured_at: "2026-07-30T01:00:00Z".to_string(),
            endpoint: "http://localhost:3000".to_string(),
            network: "regtest".to_string(),
            vector: "regtest/k1/qgppexmy".to_string(),
            did: "did:btcr2:k1qgppexmy".to_string(),
            tip_height: 212,
            signals: vec![CapturedSignal {
                address: "bcrt1qpopulated".to_string(),
                txid: "aa".repeat(32),
                block_height: 120,
                block_time: 1_700_000_000,
                update_hash: "11".to_string() + &"22".repeat(31),
            }],
            addresses,
            sidecar: None,
            expected: None,
        }
    }

    #[test]
    fn fixture_round_trips_including_a_captured_but_empty_address() {
        let fixture = sample_fixture();
        let body = serde_json::to_string(&fixture).expect("the envelope serializes");
        let parsed: ChainFixture = serde_json::from_str(&body).expect("the envelope deserializes");

        assert_eq!(parsed.captured_at, fixture.captured_at);
        assert_eq!(parsed.endpoint, fixture.endpoint);
        assert_eq!(parsed.network, fixture.network);
        assert_eq!(parsed.vector, fixture.vector);
        assert_eq!(parsed.did, fixture.did);
        assert_eq!(parsed.tip_height, fixture.tip_height);
        assert_eq!(parsed.addresses, fixture.addresses);
        assert_eq!(parsed.signals.len(), 1);
        assert_eq!(parsed.signals[0].block_time, 1_700_000_000);
        assert_eq!(
            parsed.signals[0].update_hash,
            fixture.signals[0].update_hash
        );
        assert_eq!(
            parsed.addresses.get("bcrt1qempty").map(Vec::len),
            Some(0),
            "an address captured as empty must survive as an empty list, not vanish"
        );
        assert!(
            parsed.addresses.contains_key("bcrt1qempty"),
            "captured-and-empty must stay distinguishable from never-captured"
        );
        assert!(parsed.sidecar.is_none());
        assert!(parsed.expected.is_none());
    }

    #[test]
    fn minted_scenario_fields_round_trip() {
        let mut fixture = sample_fixture();
        fixture.vector = "minted/clean-rotating-beacons".to_string();
        fixture.sidecar = Some(json!({ "updates": [] }));
        fixture.expected = Some(json!({ "error": "LATE_PUBLISHING" }));

        let body = serde_json::to_string(&fixture).expect("the envelope serializes");
        let parsed: ChainFixture = serde_json::from_str(&body).expect("the envelope deserializes");

        assert_eq!(parsed.sidecar, fixture.sidecar);
        assert_eq!(parsed.expected, fixture.expected);
    }

    #[test]
    fn fixture_path_mirrors_the_test_suite_tree() {
        let path = fixture_path_in(&fixture_root(), "regtest/k1/qgppexmy")
            .expect("a plain vector id is accepted");
        assert_eq!(path, fixture_root().join("regtest/k1/qgppexmy.json"));
    }

    #[test]
    fn fixture_path_maps_a_minted_scenario_name() {
        let path = fixture_path_in(&fixture_root(), "minted/clean-rotating-beacons")
            .expect("a minted scenario name is accepted");
        assert_eq!(
            path,
            fixture_root().join("minted/clean-rotating-beacons.json")
        );
    }

    #[test]
    fn fixture_path_rejects_traversal_and_absolute_ids() {
        for bad in [
            "",
            "/etc/passwd",
            "../../../etc/x",
            "regtest/../../../etc/x",
            "./regtest/k1/qgppexmy",
        ] {
            let error = fixture_path_in(&fixture_root(), bad)
                .err()
                .unwrap_or_else(|| panic!("`{bad}` must be rejected, not joined onto the root"));
            assert!(
                matches!(error, FixtureError::UnsafeVectorId(ref id) if id == bad),
                "`{bad}` must be rejected as an unsafe vector id, got: {error}"
            );
        }
    }

    #[test]
    fn write_is_pretty_printed_and_leaves_no_temporary_behind() {
        let dir = scratch_dir("pretty");
        let path = dir.join("nested/regtest.json");
        let fixture = sample_fixture();

        write_atomic_to(&path, &fixture).expect("the write succeeds");

        let body = std::fs::read_to_string(&path).expect("the fixture was written");
        assert!(
            body.lines().count() > 5,
            "a pretty-printed body is multi-line, got: {body}"
        );
        assert!(
            !dir.join("nested/regtest.json.tmp").exists(),
            "the temporary file must be renamed away, not left behind"
        );

        let parsed: ChainFixture = serde_json::from_str(&body).expect("the written body reparses");
        assert_eq!(parsed.addresses, fixture.addresses);
        assert!(parsed.addresses.contains_key("bcrt1qempty"));

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn a_failed_write_never_truncates_the_previous_fixture() {
        let dir = scratch_dir("atomic");
        let path = dir.join("regtest.json");
        std::fs::write(&path, b"{\"previous\": true}").expect("the previous fixture is written");

        // Occupy the temporary path with a directory so the write half fails
        // after the body has been built but before the target is touched.
        std::fs::create_dir(dir.join("regtest.json.tmp")).expect("the blocker is creatable");

        let error =
            write_atomic_to(&path, &sample_fixture()).expect_err("the temporary write must fail");
        assert!(
            matches!(error, FixtureError::Io(_)),
            "a blocked temporary path is an I/O error, got: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("the previous fixture survives"),
            "{\"previous\": true}",
            "a failed write must leave the previous fixture byte-identical"
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn write_atomic_derives_its_destination_from_the_fixture() {
        // Named for `write_atomic_in`, so it calls it: the caller passes a root
        // and never a path, and the filename has to come from the fixture's own
        // vector id. Asserting the derivation alone would leave the function the
        // test is named after unexercised, and the id in the data could drift
        // from the id in the filename without this failing.
        let root = scratch_dir("derived-destination");
        let fixture = sample_fixture();

        let written = write_atomic_in(&root, &fixture).expect("the sample fixture is written");
        assert_eq!(
            written,
            root.join("regtest/k1/qgppexmy.json"),
            "the write targets the path derived from the fixture's own vector id"
        );
        let body: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&written).expect("the fixture is there"))
                .expect("the fixture is JSON");
        assert_eq!(
            body["vector"],
            json!(fixture.vector),
            "the id in the filename and the id in the data cannot disagree"
        );

        std::fs::remove_dir_all(&root).expect("scratch directory is removable");
    }

    #[test]
    fn write_atomic_rejects_an_unsafe_vector_id_without_writing() {
        let root = scratch_dir("unsafe-id");
        let mut fixture = sample_fixture();
        fixture.vector = "../escape".to_string();
        let error = write_atomic_in(&root, &fixture).expect_err("an unsafe id must not be written");
        assert!(
            matches!(error, FixtureError::UnsafeVectorId(_)),
            "got: {error}"
        );
        assert!(
            !root.join("../escape.json").exists(),
            "the id is refused before anything is joined onto the root"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
