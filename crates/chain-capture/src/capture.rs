//! The capture drive: resolve a vector against a real chain, prove the recording
//! reproduces what the vector states, and only then write its fixture.
//!
//! Capturing a vector is not "download some transactions". It is "resolve this
//! DID for real and keep exactly what the resolver asked for". The resolve runs
//! through the recording transport, so beacon-signal discovery is evidence in the
//! fixture rather than an assumption in a test, and the recording is refused
//! unless it reproduces the vector's own `resolve/output.json`.
//!
//! That is also why no live-network test ships: contacting a real chain happens
//! here, every time an operator runs a capture, and the tool says out loud
//! whether the result is drivable.

use chrono::Utc;
use did_btcr2::document::{ResolutionOptions, SidecarData};
use did_btcr2_client::{Client, UreqTransport};
use error_iter::ErrorIter as _;
use onlyerror::Error;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::fixture::{self, ChainFixture};
use crate::record::RecordingTransport;
use crate::targets::{self, VectorTarget};
use crate::validate;

/// Capture-layer failures. Every message names the vector it is about, because a
/// session captures several vectors and a failure that cannot be attributed to a
/// row is a failure the operator has to go looking for.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// The vector, or the endpoint to capture it from, could not be prepared.
    Target(#[from] targets::TargetError),

    /// The gate refused the recording, so nothing was written.
    Validation(#[from] validate::ValidateError),

    /// The fixture could not be written.
    Fixture(#[from] fixture::FixtureError),

    /// The vector's sidecar object is not resolution sidecar data.
    #[error(
        "the vector's `resolutionOptions.sidecar` is not sidecar data the resolver accepts: {0}"
    )]
    Sidecar(#[from] serde_json::Error),

    /// `--vector` names a vector filed under a different chain than `--network`.
    #[error(
        "{vector}: this session captures `{network_dir}`, but that vector is filed under `{filed_under}` — re-run with --network naming its own chain. Every chain produces different txids, block heights and block times, so a vector is only capturable from the chain it was minted on"
    )]
    NetworkMismatch {
        /// The requested vector id.
        vector: String,
        /// The chain the session was pointed at.
        network_dir: String,
        /// The chain the vector is filed under.
        filed_under: String,
    },

    /// A vector's DID names a different chain than the directory it lives in.
    #[error(
        "{vector}: the DID names the {did_network:?} chain but the vector is filed under `{network_dir}` — one of the two is wrong, and capturing would record the wrong chain's transactions under this vector's name"
    )]
    MisfiledVector {
        /// The vector whose DID and directory disagree.
        vector: String,
        /// The directory it lives in.
        network_dir: String,
        /// The chain its DID names.
        did_network: did_btcr2::identifier::Network,
    },

    /// The resolve against the chain failed outright.
    #[error(
        "{vector}: resolving against the chain failed, so nothing was captured for it — check that the endpoint serves this chain and is reachable"
    )]
    ResolveFailed {
        /// The vector being captured.
        vector: String,
        /// The client's own failure.
        #[source]
        source: did_btcr2_client::Error,
    },

    /// The resolve succeeded but did not reproduce what the vector states.
    #[error(
        "{vector}: the resolve does not reproduce the vector's {field} — expected {expected}, got {got}. The capture is refused: either the chain no longer carries what the vector was minted against, or the resolver disagrees with the vector, and writing a fixture would hide which"
    )]
    ResolutionMismatch {
        /// The vector being captured.
        vector: String,
        /// The field that disagrees (`didDocument`, `versionId`, ...).
        field: String,
        /// What the vector states.
        expected: String,
        /// What the resolve produced.
        got: String,
    },

    /// The recording holds no chain tip.
    #[error(
        "{vector}: the capture recorded no chain tip, so the confirmations the fixture pins could not be reproduced — the endpoint answered no `/blocks/tip/height`"
    )]
    NoTip {
        /// The vector being captured.
        vector: String,
    },

    /// The chain has no vector this tool captures.
    #[error(
        "no vector this tool captures is filed under `{network_dir}` — the drivable set is: {drivable}"
    )]
    NoTargets {
        /// The chain the session was pointed at.
        network_dir: String,
        /// The drivable ids, comma-separated.
        drivable: String,
    },

    /// At least one target in the session failed.
    #[error(
        "{failed} of {total} vector(s) failed to capture; nothing was written for those rows. See the session table above for each failure"
    )]
    SessionIncomplete {
        /// How many rows failed.
        failed: usize,
        /// How many rows were attempted.
        total: usize,
    },
}

/// Build the resolution options for a vector from its `resolutionOptions.sidecar`
/// object, verbatim.
///
/// One assembly, used by capture here and mirrored line-for-line by the replay
/// driver in the core crate's resolve tests. `SidecarData::from_json_value` is
/// necessary AND sufficient for every vector shape: its manual `Deserialize`
/// always builds the update lookup table, and it sets `genesisDocument` from the
/// wire field, which the external-resolve path bridges into the initial document
/// itself (`resolve_external`; the core crate's
/// `resolve_external_bridges_genesis_document_from_serde_path` proves it, and the
/// in-memory `initial_document` field is documented there as the legacy shortcut).
///
/// Do NOT parse `genesisDocument` into an intermediate document and set the
/// in-memory initial document by hand. If capture and replay assembled options
/// differently, capture would validate a path replay never takes, and the
/// refuse-to-write gate could bless a fixture the suite then fails on.
pub fn resolution_options_for(
    sidecar: &Value,
    chain_tip_height: Option<u32>,
) -> Result<ResolutionOptions, CaptureError> {
    Ok(ResolutionOptions {
        sidecar_data: Some(SidecarData::from_json_value(sidecar.clone())?),
        chain_tip_height,
        ..Default::default()
    })
}

/// How a captured row's `confirmations` came out.
///
/// Two independently derived numbers: `expected` is what the vector states, and
/// `observed` is what the resolver reported while resolving against the real
/// chain. The refuse-to-write gate re-derives the same value a third way, from
/// the recorded tip and the announcement's block height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationsCheck {
    /// The vector's stated confirmations, `None` when it states none.
    pub expected: Option<u64>,
    /// What the resolver reported for this resolve.
    pub observed: Option<u32>,
}

impl std::fmt::Display for ConfirmationsCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.expected, self.observed) {
            (Some(expected), Some(observed)) if expected == u64::from(observed) => {
                write!(f, "{expected} == {observed} ok")
            }
            (Some(expected), Some(observed)) => write!(f, "{expected} != {observed} MISMATCH"),
            (Some(expected), None) => write!(f, "{expected} expected, none reported MISMATCH"),
            (None, Some(observed)) => {
                write!(f, "n/a (vector states none; resolver reported {observed})")
            }
            (None, None) => write!(f, "n/a (vector states none)"),
        }
    }
}

/// What one captured vector produced, in the terms the operator's summary needs.
#[derive(Debug, Clone)]
pub struct CaptureOutcome {
    /// How many beacon addresses were captured.
    pub addresses: usize,
    /// How many of those returned no transactions. A CAPTURED state, not a
    /// failure: the resolver asked, the chain answered "nothing here", and the
    /// replay must serve that same empty answer.
    pub empty_addresses: usize,
    /// How many beacon signals the capture proved.
    pub signals: usize,
    /// The chain tip the fixture pins.
    pub tip_height: u32,
    /// The confirmations check for this row.
    pub confirmations: ConfirmationsCheck,
    /// Where the fixture was written.
    pub path: PathBuf,
}

/// Validate a recording and, only if it passes, write the fixture.
///
/// The gate and the write are ONE function so no caller can reorder them. A
/// failure returns before the write, so an existing fixture is left
/// byte-identical — `emit_writes_nothing_when_validation_fails` asserts exactly
/// that.
///
/// `endpoint` records the base URL only and must never carry a credential;
/// neither endpoint this tool contacts uses authentication, and no header, token
/// or query string is recorded.
pub fn emit(
    target: &VectorTarget,
    endpoint: &str,
    tip_height: u32,
    addresses: &BTreeMap<String, Vec<Value>>,
    observed_confirmations: Option<u32>,
) -> Result<CaptureOutcome, CaptureError> {
    let signals = validate::validate(target, tip_height, addresses)?;
    let fixture = ChainFixture {
        captured_at: Utc::now().to_rfc3339(),
        endpoint: endpoint.to_string(),
        network: target.network_dir.clone(),
        vector: target.id.clone(),
        did: target.did.encode().to_string(),
        tip_height,
        signals,
        addresses: addresses.clone(),
        // A vendor vector reads its sidecar and its expectations from the
        // test-suite tree; only a minted scenario carries its own.
        sidecar: None,
        expected: None,
    };
    let path = fixture::write_atomic(&fixture)?;
    // The derived path runs through the crate manifest directory, so it carries
    // `../..` segments; the file exists by now, so report the resolved one. A
    // filesystem that cannot resolve it is not a reason to fail a written
    // capture — fall back to the path as derived.
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    Ok(CaptureOutcome {
        addresses: addresses.len(),
        empty_addresses: addresses.values().filter(|txs| txs.is_empty()).count(),
        signals: fixture.signals.len(),
        tip_height,
        confirmations: ConfirmationsCheck {
            expected: target.expected_confirmations,
            observed: observed_confirmations,
        },
        path,
    })
}

/// Capture one vector: resolve it against the chain through the recorder, prove
/// the result, then emit.
fn capture_one(target: &VectorTarget, base_url: &str) -> Result<CaptureOutcome, CaptureError> {
    // The vector's directory and its DID must name the same chain before a single
    // request goes out: capturing a mutinynet DID's transactions into a regtest
    // row would record the wrong chain under this vector's name.
    let did_network = target.did.components().network();
    if did_network != target.network {
        return Err(CaptureError::MisfiledVector {
            vector: target.id.clone(),
            network_dir: target.network_dir.clone(),
            did_network,
        });
    }

    // Clone the recording handle BEFORE the transport is moved into the client:
    // the client consumes the transport by value and never gives it back.
    let transport = RecordingTransport::new(UreqTransport::new());
    let recording = transport.recording();
    let client = Client::new(base_url.to_string(), transport);

    // `chain_tip_height` is None on purpose: the client fetches
    // `/blocks/tip/height` and defaults it, and the recorder captures that value
    // as the tip the fixture will pin.
    let options = resolution_options_for(&target.sidecar, None)?;
    let resolved = client.resolve(&target.did, options);
    let result = resolved.map_err(|source| CaptureError::ResolveFailed {
        vector: target.id.clone(),
        source,
    })?;

    // The expected-output check. This is where a real chain is contacted on every
    // run, which is why no live-network test ships: a capture is accepted only
    // when it reproduces the vector's own stated resolution, so a substituted or
    // partial body set cannot pass.
    let mismatch = |field: &str, expected: String, got: String| CaptureError::ResolutionMismatch {
        vector: target.id.clone(),
        field: field.to_string(),
        expected,
        got,
    };
    let resolved_document: &Value = result.document.as_ref();
    if *resolved_document != target.expected_document {
        return Err(mismatch(
            "didDocument",
            pretty(&target.expected_document),
            pretty(resolved_document),
        ));
    }
    let resolved_version_id = result.document_metadata.version_id.get();
    if resolved_version_id != target.expected_version_id {
        return Err(mismatch(
            "versionId",
            target.expected_version_id.to_string(),
            resolved_version_id.to_string(),
        ));
    }
    if result.document_metadata.deactivated != target.expected_deactivated {
        return Err(mismatch(
            "deactivated",
            target.expected_deactivated.to_string(),
            result.document_metadata.deactivated.to_string(),
        ));
    }
    // A vector that states confirmations states them against a frozen tip, so the
    // resolver's own report is checked too. A vector that states none is not
    // checked here — the tip moves on a live chain and the vector never claimed
    // otherwise.
    if let Some(expected) = target.expected_confirmations {
        let observed = result.document_metadata.confirmations;
        if observed.map(u64::from) != Some(expected) {
            return Err(mismatch(
                "confirmations",
                expected.to_string(),
                observed.map_or_else(|| "none".to_string(), |n| n.to_string()),
            ));
        }
    }

    let recorded = recording.borrow();
    let tip = recorded.tip.ok_or_else(|| CaptureError::NoTip {
        vector: target.id.clone(),
    })?;
    emit(
        target,
        base_url,
        tip,
        &recorded.addresses,
        result.document_metadata.confirmations,
    )
}

/// A JSON value as pretty text, for an error an operator has to read.
fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// Run a capture session: every drivable vector on `network_dir`, or the single
/// one named by `vector`.
///
/// The endpoint is resolved first, so an operator who forgot `--esplora-url` on a
/// chain with no hosted endpoint is told so before anything else happens.
pub fn run(
    network_dir: &str,
    esplora_url: Option<String>,
    vector: Option<String>,
) -> Result<(), CaptureError> {
    let base_url = targets::endpoint(network_dir, esplora_url)?;

    let selected = match vector {
        Some(id) => {
            let filed_under = id.split('/').next().unwrap_or_default();
            if filed_under != network_dir {
                return Err(CaptureError::NetworkMismatch {
                    vector: id.clone(),
                    network_dir: network_dir.to_string(),
                    filed_under: filed_under.to_string(),
                });
            }
            vec![targets::load(&id)?]
        }
        None => targets::load_all(network_dir)?,
    };
    if selected.is_empty() {
        return Err(CaptureError::NoTargets {
            network_dir: network_dir.to_string(),
            drivable: targets::DRIVABLE_VECTORS.join(", "),
        });
    }

    let rows: Vec<(String, Result<CaptureOutcome, CaptureError>)> = selected
        .iter()
        .map(|target| (target.id.clone(), capture_one(target, &base_url)))
        .collect();

    // The session's own report goes to stderr, so a shell pipeline reading
    // stdout is unaffected by it.
    eprint!("{}", render_summary(network_dir, &base_url, &rows));

    let failed = rows.iter().filter(|(_, row)| row.is_err()).count();
    if failed > 0 {
        return Err(CaptureError::SessionIncomplete {
            failed,
            total: rows.len(),
        });
    }
    Ok(())
}

/// One row of the operator's session table.
///
/// An address captured with no transactions is reported in the `empty` column as
/// a CAPTURED state — the resolver asked and the chain answered "nothing here".
/// Only an address that was never captured is a failure, and only at replay.
fn render_row(id: &str, row: &Result<CaptureOutcome, CaptureError>) -> String {
    match row {
        Ok(outcome) => format!(
            "  {:<24}{:>6}{:>7}{:>9}  {:<52}  {}\n",
            id,
            outcome.addresses,
            outcome.empty_addresses,
            outcome.signals,
            outcome.confirmations.to_string(),
            outcome.path.display(),
        ),
        Err(error) => format!("  {id:<24}FAILED, nothing written: {}\n", error_line(error)),
    }
}

/// An error and its whole cause chain on one line.
///
/// A `#[from]` variant's own `Display` is its doc sentence and the detail lives
/// one level down, so a row that printed only the top line would tell the
/// operator that something failed without saying what.
fn error_line(error: &CaptureError) -> String {
    let mut out = error.to_string();
    for source in error.sources().skip(1) {
        out.push_str(" | caused by: ");
        out.push_str(&source.to_string());
    }
    out
}

/// The operator-facing session summary: which vectors are now drivable, which
/// failed and why, and — on a chain whose vectors pin a frozen tip — what that
/// tip is and why it must not move.
///
/// Capture-time validation is this tool's operator-facing artifact. A session
/// must end with the operator knowing exactly what is now drivable, without
/// reading any code.
fn render_summary(
    network_dir: &str,
    endpoint: &str,
    rows: &[(String, Result<CaptureOutcome, CaptureError>)],
) -> String {
    let mut out = format!("capture session: {network_dir} via {endpoint}\n");
    out.push_str(&format!(
        "  {:<24}{:>6}{:>7}{:>9}  {:<52}  {}\n",
        "vector", "addrs", "empty", "signals", "confirmations", "fixture"
    ));
    for (id, row) in rows {
        out.push_str(&render_row(id, row));
    }

    let drivable: Vec<&str> = rows
        .iter()
        .filter(|(_, row)| row.is_ok())
        .map(|(id, _)| id.as_str())
        .collect();
    if drivable.is_empty() {
        out.push_str("  drivable now: none — no fixture was written this session\n");
    } else {
        out.push_str(&format!("  drivable now: {}\n", drivable.join(", ")));
    }
    for (id, row) in rows {
        if let Err(error) = row {
            out.push_str(&format!("  failed: {id} — {}\n", error_line(error)));
        }
    }

    // A chain whose vectors state `confirmations` measures every one of them
    // against a single tip, so that tip is session state the operator has to
    // know about before doing anything else with the chain.
    let frozen_tip = rows
        .iter()
        .filter_map(|(_, row)| row.as_ref().ok())
        .find(|outcome| outcome.confirmations.expected.is_some())
        .map(|outcome| outcome.tip_height);
    if let Some(tip) = frozen_tip {
        out.push_str(&format!(
            "  frozen tip {tip}: every confirmations expectation captured above is measured \
             against this tip. DO NOT MINE on this chain until every vector filed under \
             `{network_dir}` has been captured — one new block invalidates all of them at \
             once, and they cannot be re-derived.\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::{ValidateError, update_hashes};
    use did_btcr2::identifier::{Did, Network, Sha256Hash};
    use serde_json::json;
    use std::str::FromStr as _;

    /// A DID from the vendor vectors, so the synthetic targets below carry a real
    /// identifier rather than one this test invented.
    const REGTEST_DID: &str =
        "did:btcr2:k1qgppexmyqqlce9netky3h4ur2j9dur83j7m7vva497kfhdgsq2t9nxgqj3x0s";

    /// The vector tree is a git submodule; a non-recursive clone leaves it empty.
    /// Every test that reads it calls this first and skips green when it is
    /// absent, matching the core crate's absent-submodule contract.
    fn test_suite_present() -> bool {
        if targets::test_suite_root()
            .join("regtest/k1/qgppexmy/resolve/input.json")
            .exists()
        {
            return true;
        }
        eprintln!(
            "SKIP: test-suite submodule absent; \
             run `git submodule update --init --recursive` to enable"
        );
        false
    }

    /// A vector's `resolutionOptions.sidecar`, read from the tree.
    ///
    /// Read directly rather than through `targets::load`, because three of the
    /// four sidecar shapes this exercises belong to vectors outside the drivable
    /// set — the shapes are what matter here, not the rows.
    fn vendor_sidecar(id: &str) -> Value {
        let path = targets::test_suite_root()
            .join(id)
            .join("resolve/input.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: must be readable ({e})", path.display()));
        let input: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("{}: must be JSON ({e})", path.display()));
        let sidecar = input["resolutionOptions"]["sidecar"].clone();
        assert!(
            sidecar.is_object(),
            "{id}: this test is about a sidecar OBJECT; the tree no longer has one"
        );
        sidecar
    }

    /// The sidecar data inside a set of options, rendered two ways.
    ///
    /// The wire view is `SidecarData`'s own `Serialize` (the four spec fields).
    /// The debug view is the only public window onto the two NON-wire fields —
    /// the update lookup table the resolver's hot path reads, and the legacy
    /// in-memory initial document this assembly must leave alone — both of which
    /// are crate-private in the core with no accessor.
    fn sidecar_views(options: &ResolutionOptions) -> (Value, String) {
        let data = options
            .sidecar_data
            .as_ref()
            .expect("the assembly always sets sidecar data");
        (
            serde_json::to_value(data).expect("sidecar data serializes to its wire form"),
            format!("{data:?}"),
        )
    }

    /// A minimal signed update the core crate accepts, targeting `version`.
    fn update(version: u64, salt: &str) -> Value {
        json!({
            "targetVersionId": version,
            "sourceHash": "AHcGbJ3OGSIrjVTIHFbIc2OEA25EDtMOM1uXBlw2qDQ",
            "targetHash": "hduKs2Pj2VpUueLkvWLSR5MeSjTYgKPO02H9zrqjUKw",
            "patch": [{ "op": "replace", "path": "/service/0/serviceEndpoint", "value": salt }],
            "proof": {
                "@context": [
                    "https://w3id.org/security/v2",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/json-ld-patch/v1",
                    "https://btcr2.dev/context/v1",
                ],
                "type": "DataIntegrityProof",
                "cryptosuite": "bip340-jcs-2025",
                "verificationMethod": format!("{REGTEST_DID}#initialKey"),
                "proofPurpose": "capabilityInvocation",
                "capability": format!("urn:zcap:root:did%3Abtcr2%3A{REGTEST_DID}"),
                "capabilityAction": "Write",
                "proofValue": "z4uLUfMjfUufPGgeXa9ZgJ1DR7bnH7FAkHVf83ebT1C4iwFtiJPPNgStUrT9cpV2h8PKdN6RH4TFJgrRd7APPBqWA",
            },
        })
    }

    /// A target that does not need the test-suite submodule to exist, filed under
    /// `vector` so a test can write to a throwaway fixture path.
    fn synthetic_target(vector: &str, sidecar: Value, confirmations: Option<u64>) -> VectorTarget {
        VectorTarget {
            id: vector.to_string(),
            network_dir: "regtest".to_string(),
            network: Network::Regtest,
            did: Did::from_str(REGTEST_DID).expect("a vendor DID parses"),
            sidecar,
            expected_document: json!({ "id": REGTEST_DID }),
            expected_version_id: 2,
            expected_deactivated: false,
            expected_confirmations: confirmations,
        }
    }

    /// An Esplora transaction body announcing `hash` in its last output.
    fn announcement(hash: [u8; 32], height: u32) -> Value {
        json!({
            "txid": "a1".repeat(32),
            "version": 2,
            "locktime": 0,
            "vin": [],
            "vout": [
                { "scriptpubkey": "0014abababababababababababababababababababab", "value": 0 },
                { "scriptpubkey": format!("6a20{}", hex::encode(hash)), "value": 0 },
            ],
            "size": 0,
            "weight": 0,
            "fee": 0,
            "status": {
                "confirmed": true,
                "block_height": height,
                "block_hash": "00".repeat(32),
                "block_time": 1_700_000_000i64,
            },
        })
    }

    fn bodies(entries: Vec<(&str, Vec<Value>)>) -> BTreeMap<String, Vec<Value>> {
        entries
            .into_iter()
            .map(|(address, txs)| (address.to_string(), txs))
            .collect()
    }

    /// Remove a fixture written by a test, and the directory holding it when that
    /// leaves it empty.
    fn remove_fixture(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[test]
    fn an_empty_sidecar_yields_no_updates_and_no_genesis_document() {
        if !test_suite_present() {
            return;
        }
        let options = resolution_options_for(&vendor_sidecar("regtest/k1/qgpakaw4"), None)
            .expect("an empty sidecar object is valid sidecar data");
        let (wire, debug) = sidecar_views(&options);

        assert_eq!(
            wire,
            json!({ "updates": [] }),
            "an empty sidecar carries no updates and no genesis document: {wire}"
        );
        assert!(
            debug.contains("update_lookup_table: {}"),
            "the lookup table is empty: {debug}"
        );
        assert_eq!(options.chain_tip_height, None);
    }

    #[test]
    fn a_genesis_document_sidecar_sets_the_wire_field_and_not_the_legacy_one() {
        if !test_suite_present() {
            return;
        }
        let sidecar = vendor_sidecar("regtest/x1/q2fz9mz6");
        let options =
            resolution_options_for(&sidecar, None).expect("a genesis-document sidecar is valid");
        let (wire, debug) = sidecar_views(&options);

        assert_eq!(
            wire["genesisDocument"], sidecar["genesisDocument"],
            "the genesis document is carried through verbatim"
        );
        assert!(
            debug.contains("genesis_document: Some("),
            "the wire genesis document is set: {debug}"
        );
        assert!(
            debug.contains("initial_document: None"),
            "the legacy in-memory initial document is left untouched — the external \
             resolve path bridges the genesis document itself, and building an \
             intermediate document here would be an assembly the replay never takes: \
             {debug}"
        );
    }

    #[test]
    fn an_updates_sidecar_yields_one_entry_in_the_update_lookup_table() {
        if !test_suite_present() {
            return;
        }
        let id = "regtest/k1/qgppexmy";
        let sidecar = vendor_sidecar(id);
        let options = resolution_options_for(&sidecar, Some(212)).expect("an updates sidecar");
        let (wire, debug) = sidecar_views(&options);

        assert_eq!(
            wire["updates"].as_array().map(Vec::len),
            Some(1),
            "this vector announces exactly one update: {wire}"
        );
        assert_eq!(options.chain_tip_height, Some(212));

        // The table the resolver's hot path reads is keyed by the announcement
        // hash, so the key is derived independently and looked for by name.
        let hashes = update_hashes(id, &sidecar).expect("its sidecar hashes");
        let key = format!("{:?}", Sha256Hash::from(hashes[0]));
        assert!(
            debug.contains(&key),
            "the update lookup table must be keyed by the announced hash {}: {debug}",
            hex::encode(hashes[0])
        );
    }

    #[test]
    fn a_sidecar_carrying_both_keys_yields_both() {
        if !test_suite_present() {
            return;
        }
        let id = "regtest/x1/q26jeds9";
        let sidecar = vendor_sidecar(id);
        let options = resolution_options_for(&sidecar, None).expect("a full sidecar is valid");
        let (wire, debug) = sidecar_views(&options);

        assert_eq!(wire["genesisDocument"], sidecar["genesisDocument"]);
        assert_eq!(
            wire["updates"].as_array().map(Vec::len),
            sidecar["updates"].as_array().map(Vec::len),
            "every update survives the assembly"
        );
        let hashes = update_hashes(id, &sidecar).expect("its sidecar hashes");
        for hash in &hashes {
            let key = format!("{:?}", Sha256Hash::from(*hash));
            assert!(
                debug.contains(&key),
                "every update is in the lookup table, missing {}",
                hex::encode(hash)
            );
        }
        assert!(debug.contains("initial_document: None"), "{debug}");
    }

    #[test]
    fn emit_writes_a_fixture_when_validation_passes() {
        let vector = "minted/__test_emit_pass";
        let one = update(2, "bitcoin:mmBCLTLMZqUFhiG4vhhaM7EbLRN6h7sCfG");
        let sidecar = json!({ "updates": [one] });
        let hashes = update_hashes(vector, &sidecar).expect("the synthetic sidecar hashes");
        let target = synthetic_target(vector, sidecar, Some(93));
        let addresses = bodies(vec![
            ("bcrt1qbeacon", vec![announcement(hashes[0], 120)]),
            ("bcrt1qquiet", Vec::new()),
        ]);

        let outcome = emit(&target, "http://localhost:3000", 212, &addresses, Some(93))
            .expect("a validated capture is written");

        let body = std::fs::read_to_string(&outcome.path).expect("the fixture was written");
        let written: Value = serde_json::from_str(&body).expect("the fixture is JSON");
        assert_eq!(written["endpoint"], json!("http://localhost:3000"));
        assert_eq!(written["network"], json!("regtest"));
        assert_eq!(written["vector"], json!(vector));
        assert_eq!(written["tip_height"], json!(212));
        assert_eq!(written["did"], json!(REGTEST_DID));
        assert_eq!(
            written["signals"].as_array().map(Vec::len),
            Some(1),
            "the proved announcement travels with the fixture"
        );
        assert!(
            written.get("sidecar").is_none() && written.get("expected").is_none(),
            "a vendor vector reads its sidecar and expectations from the test-suite: {body}"
        );
        assert_eq!(
            written["addresses"]["bcrt1qquiet"],
            json!([]),
            "an address that returned nothing is captured-and-empty, not dropped"
        );

        assert_eq!(outcome.addresses, 2);
        assert_eq!(outcome.empty_addresses, 1);
        assert_eq!(outcome.signals, 1);
        assert_eq!(outcome.tip_height, 212);
        assert_eq!(outcome.confirmations.expected, Some(93));
        assert_eq!(outcome.confirmations.observed, Some(93));

        remove_fixture(&outcome.path);
    }

    #[test]
    fn emit_writes_nothing_when_validation_fails() {
        let vector = "minted/__test_emit_refuse";
        let path = fixture::fixture_path(vector).expect("the throwaway id is safe");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("the fixture directory is creatable");
        }
        let sentinel = "{\"previous\": true}";
        std::fs::write(&path, sentinel).expect("the sentinel fixture is written");

        let sidecar = json!({ "updates": [update(2, "salt")] });
        let target = synthetic_target(vector, sidecar, Some(93));
        // Bodies that carry no announcement at all: the gate must refuse.
        let addresses = bodies(vec![("bcrt1qbeacon", Vec::new())]);

        let error = emit(&target, "http://localhost:3000", 212, &addresses, Some(93))
            .expect_err("an unannounced update must not be written");
        assert!(
            matches!(
                error,
                CaptureError::Validation(ValidateError::MissingSignal { .. })
            ),
            "got: {error}"
        );

        assert_eq!(
            std::fs::read_to_string(&path).expect("the sentinel survives"),
            sentinel,
            "a refused capture must leave an existing fixture byte-identical"
        );
        let mut tmp = path.clone().into_os_string();
        tmp.push(".tmp");
        assert!(
            !PathBuf::from(tmp).exists(),
            "a refused capture must not leave a temporary file behind"
        );

        remove_fixture(&path);
    }

    #[test]
    fn run_rejects_a_vector_filed_under_another_network_before_any_request() {
        // mutinynet resolves its own endpoint, so this gets past the endpoint rule
        // and is refused on the mismatch — with no socket opened either way.
        let error = run("mutinynet", None, Some("regtest/k1/qgppexmy".to_string()))
            .expect_err("a vector may only be captured from its own chain");
        assert!(
            matches!(
                error,
                CaptureError::NetworkMismatch { ref vector, .. } if vector == "regtest/k1/qgppexmy"
            ),
            "got: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("regtest/k1/qgppexmy")
                && message.contains("`regtest`")
                && message.contains("--network"),
            "the message names the vector, the chain it belongs to and the next action: \
             {message}"
        );
    }

    #[test]
    fn run_refuses_a_chain_with_no_endpoint_before_anything_else() {
        let error = run("regtest", None, None).expect_err("regtest has no hosted Esplora endpoint");
        assert!(matches!(error, CaptureError::Target(_)), "got: {error}");
        let message = error_line(&error);
        assert!(
            message.contains("--esplora-url") && message.contains("regtest"),
            "the failure names the chain and the missing endpoint flag: {message}"
        );
    }

    #[test]
    fn run_refuses_a_chain_this_tool_captures_nothing_on() {
        let error = run("signet", None, None).expect_err("no vector is filed under signet");
        assert!(
            matches!(error, CaptureError::NoTargets { .. }),
            "got: {error}"
        );
        for id in targets::DRIVABLE_VECTORS {
            assert!(
                error.to_string().contains(id),
                "the message lists what IS drivable, missing {id}: {error}"
            );
        }
    }

    /// An outcome as a captured row produces it, filed at the fixture path that
    /// vector id derives.
    fn sample_outcome(id: &str, confirmations: ConfirmationsCheck) -> CaptureOutcome {
        CaptureOutcome {
            addresses: 2,
            empty_addresses: 1,
            signals: 1,
            tip_height: 212,
            confirmations,
            path: PathBuf::from("/fixtures/chain").join(format!("{id}.json")),
        }
    }

    #[test]
    fn a_captured_row_names_the_vector_the_fixture_and_the_confirmations_check() {
        let row = render_row(
            "regtest/k1/qgppexmy",
            &Ok(sample_outcome(
                "regtest/k1/qgppexmy",
                ConfirmationsCheck {
                    expected: Some(93),
                    observed: Some(93),
                },
            )),
        );
        assert!(row.contains("regtest/k1/qgppexmy"), "{row}");
        assert!(
            row.contains("/fixtures/chain/regtest/k1/qgppexmy.json"),
            "the row names the file that was written: {row}"
        );
        assert!(
            row.contains("93 == 93"),
            "the row shows the vector's expectation against the resolver's report: {row}"
        );

        let mutinynet = render_row(
            "mutinynet/k1/q5p6w9su",
            &Ok(sample_outcome(
                "mutinynet/k1/q5p6w9su",
                ConfirmationsCheck {
                    expected: None,
                    observed: Some(1_045),
                },
            )),
        );
        assert!(
            mutinynet.contains("n/a"),
            "a vector stating no confirmations reports n/a rather than a bare number: \
             {mutinynet}"
        );
    }

    #[test]
    fn a_failed_row_names_the_error_and_says_nothing_was_written() {
        let row = render_row(
            "regtest/k1/qgpy0hmm",
            &Err(CaptureError::NoTip {
                vector: "regtest/k1/qgpy0hmm".to_string(),
            }),
        );
        assert!(row.contains("regtest/k1/qgpy0hmm"), "{row}");
        assert!(row.contains("FAILED"), "{row}");
        assert!(
            row.contains("nothing was written") || row.contains("nothing written"),
            "{row}"
        );
        assert!(
            row.contains("no chain tip"),
            "the row carries the reason, not just the fact: {row}"
        );
    }

    #[test]
    fn a_regtest_session_footer_carries_the_frozen_tip_and_the_do_not_mine_reminder() {
        let rows = vec![
            (
                "regtest/k1/qgppexmy".to_string(),
                Ok(sample_outcome(
                    "regtest/k1/qgppexmy",
                    ConfirmationsCheck {
                        expected: Some(93),
                        observed: Some(93),
                    },
                )),
            ),
            (
                "regtest/k1/qgpy0hmm".to_string(),
                Err(CaptureError::NoTip {
                    vector: "regtest/k1/qgpy0hmm".to_string(),
                }),
            ),
        ];
        let summary = render_summary("regtest", "http://localhost:3000", &rows);

        assert!(
            summary.contains("drivable now: regtest/k1/qgppexmy"),
            "the session says what is drivable now: {summary}"
        );
        assert!(
            summary.contains("failed: regtest/k1/qgpy0hmm"),
            "the session names each failure: {summary}"
        );
        assert!(
            summary.contains("frozen tip 212"),
            "a regtest session states the tip its confirmations are measured against: \
             {summary}"
        );
        assert!(
            summary.to_lowercase().contains("do not mine"),
            "a regtest session warns that mining invalidates the captures: {summary}"
        );
    }

    #[test]
    fn a_session_with_no_frozen_tip_omits_the_mining_reminder() {
        let rows = vec![(
            "mutinynet/k1/q5p6w9su".to_string(),
            Ok(sample_outcome(
                "mutinynet/k1/q5p6w9su",
                ConfirmationsCheck {
                    expected: None,
                    observed: Some(1_045),
                },
            )),
        )];
        let summary = render_summary("mutinynet", "https://mutinynet.com/api", &rows);

        assert!(summary.contains("drivable now: mutinynet/k1/q5p6w9su"));
        assert!(
            !summary.to_lowercase().contains("do not mine"),
            "a chain whose vectors pin no confirmations has no frozen tip to protect: \
             {summary}"
        );
    }

    #[test]
    fn the_confirmations_check_reports_a_disagreement_as_a_mismatch() {
        let check = ConfirmationsCheck {
            expected: Some(93),
            observed: Some(91),
        };
        assert_eq!(check.to_string(), "93 != 91 MISMATCH");
        let missing = ConfirmationsCheck {
            expected: Some(93),
            observed: None,
        };
        assert!(missing.to_string().contains("MISMATCH"), "{missing}");
    }
}
