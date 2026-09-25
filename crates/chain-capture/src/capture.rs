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
use did_btcr2::document::{ResolutionOptions, ResolutionResult, SidecarData};
use did_btcr2::identifier::Network;
use did_btcr2_client::{BtcTransport, Client, TransportError, UreqTransport};
use error_iter::ErrorIter as _;
use onlyerror::Error;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::fixture::{self, ChainFixture};
use crate::pace::{Clock, PacePolicy, PaceState, PacedTransport, SystemClock};
use crate::record::{self, Recording, RecordingTransport};
use crate::targets::{self, CaptureSignals, ExpectedOutcome, VectorTarget};
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

    /// The indexer's tip is below the tip the set was recorded against.
    #[error(
        "{vector}: the indexer's tip is {live_tip}, below the recordedTip {recorded_tip} the set was recorded against — the indexer is behind the chain the set was recorded on, so wait for it to catch up or use another endpoint; nothing was written"
    )]
    TipBelowRecorded {
        /// The set being captured.
        vector: String,
        /// The tip the indexer reported.
        live_tip: u32,
        /// The set's `recordedTip`.
        recorded_tip: u32,
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
/// One assembly, used by capture here; the replay driver in the core crate's
/// resolve tests builds the same options for every main pair this tool
/// captures. Two input rules keep the two in step. The target loader refuses a
/// main input carrying `versionId`, `versionTime` or `minConf`, which replay
/// would honour and this function does not read. And an absent sidecar reads
/// as `{}` on both sides for a set with `signals.json`, and is refused on both
/// sides otherwise. `SidecarData::from_json_value` is
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
    /// Whether the capture was pinned to the set's `recordedTip` rather than
    /// the live tip.
    pub recorded_tip: bool,
    /// The confirmations check for this row.
    pub confirmations: ConfirmationsCheck,
    /// Where the fixture was written.
    pub path: PathBuf,
}

/// Validate a recording and, only if it passes, write the fixture under `root`.
///
/// The gate and the write are ONE function so no caller can reorder them. A
/// failure returns before the write, so an existing fixture is left
/// byte-identical — `emit_writes_nothing_when_validation_fails` asserts exactly
/// that.
///
/// `endpoint` records the base URL only and must never carry a credential;
/// neither endpoint this tool contacts uses authentication, and no header, token
/// or query string is recorded.
///
/// The destination is a parameter. Without it, testing the write semantics
/// meant writing into this repository's committed fixture tree and deleting the
/// file afterwards — which a failing assertion in between would skip, leaving a
/// stray file no committed-fixture check would catch, because that ledger is an
/// explicit list rather than a directory scan.
pub fn emit_to(
    root: &Path,
    target: &VectorTarget,
    endpoint: &str,
    tip_height: u32,
    addresses: &BTreeMap<String, Vec<Value>>,
    blocks: &BTreeMap<String, Value>,
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
        blocks: blocks.clone(),
        // A vendor vector reads its sidecar and its expectations from the
        // test-suite tree; only a minted scenario carries its own.
        sidecar: None,
        expected: None,
    };
    let path = fixture::write_atomic_in(root, &fixture)?;
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
        recorded_tip: false,
        confirmations: ConfirmationsCheck {
            expected: target.expected.confirmations(),
            observed: observed_confirmations,
        },
        path,
    })
}

/// [`emit_to`] for a set that carries `signals.json`: the gate is the exact
/// match with that record, and the fixture pins the set's `recordedTip`.
///
/// The ordering checks of [`validate::validate`] are not run: the record is
/// the oracle for such a set, and a legitimate duplicate above a later update,
/// or an announcement deliberately below the current height, would fail them.
pub fn emit_signals_to(
    root: &Path,
    target: &VectorTarget,
    signals: &CaptureSignals,
    endpoint: &str,
    addresses: &BTreeMap<String, Vec<Value>>,
    blocks: &BTreeMap<String, Value>,
    observed_confirmations: Option<u32>,
) -> Result<CaptureOutcome, CaptureError> {
    let proved = validate::validate_signals(target, signals, addresses)?;
    let tip_height = signals.recorded_tip;
    let fixture = ChainFixture {
        captured_at: Utc::now().to_rfc3339(),
        endpoint: endpoint.to_string(),
        network: target.network_dir.clone(),
        vector: target.id.clone(),
        did: target.did.encode().to_string(),
        tip_height,
        signals: proved,
        addresses: addresses.clone(),
        blocks: blocks.clone(),
        // The set's sidecar and expectations stay in the set's own tree.
        sidecar: None,
        expected: None,
    };
    let path = fixture::write_atomic_in(root, &fixture)?;
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    Ok(CaptureOutcome {
        addresses: addresses.len(),
        empty_addresses: addresses.values().filter(|txs| txs.is_empty()).count(),
        signals: fixture.signals.len(),
        tip_height,
        recorded_tip: true,
        confirmations: ConfirmationsCheck {
            expected: target.expected.confirmations(),
            observed: observed_confirmations,
        },
        path,
    })
}

/// Ask the indexer for its current tip, outside the recording.
///
/// Built by hand because the client's own tip request is not reachable from
/// here. The answer decides whether the capture may proceed; it is not fixture
/// data, since a set carrying `signals.json` replays against its `recordedTip`.
fn live_tip<T: BtcTransport>(
    transport: &T,
    base_url: &str,
    vector: &str,
) -> Result<u32, CaptureError> {
    let no_tip = || CaptureError::NoTip {
        vector: vector.to_string(),
    };
    let failed = |source: TransportError| CaptureError::ResolveFailed {
        vector: vector.to_string(),
        source: source.into(),
    };
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("{base_url}/blocks/tip/height"))
        .body(Vec::new())
        .map_err(|e| failed(TransportError::Io(std::io::Error::other(e.to_string()))))?;
    let response = transport.execute(request).map_err(failed)?;
    if !response.status().is_success() {
        return Err(no_tip());
    }
    std::str::from_utf8(response.body())
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .ok_or_else(no_tip)
}

/// Capture one vector: resolve it against the chain through the recorder, prove
/// the result, then emit into `out_root`.
///
/// The transport and the clock are parameters so a whole session — pacing,
/// rate-limit retries, the tip check and the write — runs against a scripted
/// indexer in tests exactly as it runs against a hosted one.
pub fn capture_one_with<T: BtcTransport + Clone, C: Clock + Clone>(
    target: &VectorTarget,
    base_url: &str,
    transport: T,
    clock: C,
    out_root: &Path,
) -> Result<CaptureOutcome, CaptureError> {
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

    // One recording, one pace state, and handles over both: the client consumes
    // its transport by value and never gives it back, so the tip check before
    // the resolve and the block fetches after it go through handles of their
    // own. The pace state is shared by every handle so the whole session is
    // spaced as one stream against a hosted indexer. The pacer sits below the
    // recorder because the recorder refuses a non-2xx answer: a rate-limited
    // reply is retried here and never reaches the fixture.
    let recording = Rc::new(RefCell::new(Recording::default()));
    let pace = Rc::new(RefCell::new(PaceState::default()));
    let policy = if target.network == Network::Regtest {
        PacePolicy::unpaced()
    } else {
        PacePolicy::public_indexer()
    };
    let paced =
        || PacedTransport::sharing(transport.clone(), clock.clone(), policy, Rc::clone(&pace));

    // A set carrying `signals.json` states its expected confirmations against
    // its `recordedTip`, so the capture resolves at that tip and the replay
    // reads it back from the fixture. A live tip below it means the indexer is
    // behind the chain the set was recorded on, and nothing it serves can
    // reproduce the set.
    let pinned_tip = match &target.signals {
        Some(signals) => {
            let live = live_tip(&paced(), base_url, &target.id)?;
            if live < signals.recorded_tip {
                return Err(CaptureError::TipBelowRecorded {
                    vector: target.id.clone(),
                    live_tip: live,
                    recorded_tip: signals.recorded_tip,
                });
            }
            Some(signals.recorded_tip)
        }
        // Without a record, the client fetches `/blocks/tip/height` itself and
        // the recorder captures that value as the tip the fixture will pin.
        None => None,
    };

    let client = Client::new(
        base_url.to_string(),
        RecordingTransport::sharing(paced(), Rc::clone(&recording)),
    );
    let options = resolution_options_for(&target.sidecar, pinned_tip)?;
    let resolved = client.resolve(&target.did, options);

    // The expected-output check. This is where a real chain is contacted on every
    // run, which is why no live-network test ships: a capture is accepted only
    // when it reproduces the vector's own stated resolution, so a substituted or
    // partial body set cannot pass. `None` means the set expects an error and
    // the resolve failed with one; its recording is still the fixture.
    let result = check_outcome(target, resolved)?;
    let observed_confirmations = result.and_then(|r| r.document_metadata.confirmations);

    // The confirming block of every announcement, whether or not the resolve
    // asked for it: a replay under a `versionTime` bound reads its
    // `mediantime`, and a capture without it cannot host that probe.
    let addresses = recording.borrow().addresses.clone();
    let blocks_transport = RecordingTransport::sharing(paced(), Rc::clone(&recording));
    record::capture_announcement_blocks(&blocks_transport, base_url, &addresses).map_err(
        |source| CaptureError::ResolveFailed {
            vector: target.id.clone(),
            source: source.into(),
        },
    )?;

    let recorded = recording.borrow();
    if let Some(signals) = &target.signals {
        // The pinned resolve never fetches the tip, so the recorder holds none;
        // the fixture pins the set's own.
        return emit_signals_to(
            out_root,
            target,
            signals,
            base_url,
            &recorded.addresses,
            &recorded.blocks,
            observed_confirmations,
        );
    }
    let tip = recorded.tip.ok_or_else(|| CaptureError::NoTip {
        vector: target.id.clone(),
    })?;
    emit_to(
        out_root,
        target,
        base_url,
        tip,
        &recorded.addresses,
        &recorded.blocks,
        observed_confirmations,
    )
}

/// The specification error code a client error carries, or `None` for a
/// failure that is not a resolution outcome (transport, endpoint selection,
/// JSON, funding).
///
/// The same mapping the HTTP resolver uses for its problem details: the core's
/// own errors report their problem details, an identifier error is an invalid
/// DID, and the code is the fragment after `#` in the problem `type`.
fn client_error_code(err: &did_btcr2_client::Error) -> Option<String> {
    use did_btcr2::error::{Btcr2Error, ProblemDetails as _};
    use did_btcr2_client::Error;

    let details = match err {
        Error::Btcr2(e) => e.details(),
        Error::Core(e) => e.details(),
        Error::Resolver(e) => e.details(),
        // `Btcr2Error`'s conversion takes the parse error by value and the
        // parse error is not `Clone`, so its two arms are restated here;
        // `outcome_identifier_codes_follow_the_core_conversion` fails if they
        // drift apart.
        Error::Identifier(did_btcr2::identifier::Error::MethodNotSupported(method)) => {
            Btcr2Error::MethodNotSupported(method.clone()).details()
        }
        Error::Identifier(e) => Btcr2Error::InvalidDid(e.to_string()).details(),
        _ => None,
    }?;
    let (_, code) = details["type"].as_str()?.rsplit_once('#')?;
    (!code.is_empty()).then(|| code.to_string())
}

/// Judge a resolve against what the set says it produces.
///
/// A resolved expectation is compared on `didDocument`, `versionId`,
/// `deactivated` and — when the set states them — exact `confirmations`: a
/// capture measures against one tip, so the count must reproduce exactly. A
/// resolve that fails is refused with the client's own error.
///
/// An expected error is satisfied by any failure that carries a specification
/// error code, whatever the code: the capture only proves the chain makes the
/// resolve fail with a specification error. Which code is right is the test
/// harness's judgement, made through its single pinned divergence table on the
/// run that follows the capture — a second table here would have to gain the
/// same entries, and nothing could check that the two agree. A success, or a
/// failure with no specification code (a transport or endpoint fault), is
/// refused.
///
/// Returns the resolution for a resolved expectation and `None` for a
/// reproduced error.
fn check_outcome(
    target: &VectorTarget,
    resolved: Result<ResolutionResult, did_btcr2_client::Error>,
) -> Result<Option<ResolutionResult>, CaptureError> {
    let mismatch = |field: &str, expected: String, got: String| CaptureError::ResolutionMismatch {
        vector: target.id.clone(),
        field: field.to_string(),
        expected,
        got,
    };
    let failed = |source| CaptureError::ResolveFailed {
        vector: target.id.clone(),
        source,
    };

    match &target.expected {
        ExpectedOutcome::Error { code } => match resolved {
            Err(e) if client_error_code(&e).is_some() => Ok(None),
            Err(e) => Err(failed(e)),
            Ok(result) => Err(mismatch(
                "error",
                format!("an error (the set records {code})"),
                format!("resolved versionId {}", result.document_metadata.version_id),
            )),
        },
        ExpectedOutcome::Resolved {
            document,
            version_id,
            deactivated,
            confirmations,
        } => {
            let result = resolved.map_err(failed)?;
            let resolved_document: &Value = result.document.as_ref();
            if resolved_document != document {
                return Err(mismatch(
                    "didDocument",
                    pretty(document),
                    pretty(resolved_document),
                ));
            }
            let resolved_version_id = result.document_metadata.version_id.get();
            if resolved_version_id != *version_id {
                return Err(mismatch(
                    "versionId",
                    version_id.to_string(),
                    resolved_version_id.to_string(),
                ));
            }
            if result.document_metadata.deactivated != *deactivated {
                return Err(mismatch(
                    "deactivated",
                    deactivated.to_string(),
                    result.document_metadata.deactivated.to_string(),
                ));
            }
            // A set that states confirmations states them against one tip, so
            // the resolver's own report is checked too. A set that states none
            // is not checked here — the tip moves on a live chain and the set
            // never claimed otherwise.
            if let Some(expected) = confirmations {
                let observed = result.document_metadata.confirmations;
                if observed.map(u64::from) != Some(*expected) {
                    return Err(mismatch(
                        "confirmations",
                        expected.to_string(),
                        observed.map_or_else(|| "none".to_string(), |n| n.to_string()),
                    ));
                }
            }
            Ok(Some(result))
        }
    }
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
///
/// With `suite_root`, the one set `vector` names is read from that root rather
/// than from the allow-listed test-suite tree, and it must carry
/// `signals.json`. `out` redirects every fixture of the session; without it they
/// land in the repository's own fixture tree.
pub fn run(
    network_dir: &str,
    esplora_url: Option<String>,
    vector: Option<String>,
    suite_root: Option<PathBuf>,
    out: Option<PathBuf>,
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
            match &suite_root {
                Some(root) => vec![targets::load_in(root, &id)?],
                None => vec![targets::load(&id)?],
            }
        }
        None => targets::load_all(network_dir)?,
    };
    if selected.is_empty() {
        return Err(CaptureError::NoTargets {
            network_dir: network_dir.to_string(),
            drivable: targets::DRIVABLE_VECTORS.join(", "),
        });
    }

    let out_root = out.unwrap_or_else(fixture::fixture_root);
    let rows: Vec<(String, Result<CaptureOutcome, CaptureError>)> = selected
        .iter()
        .map(|target| {
            (
                target.id.clone(),
                capture_one_with(
                    target,
                    &base_url,
                    UreqTransport::new(),
                    SystemClock,
                    &out_root,
                ),
            )
        })
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
/// failed and why, and — on a chain whose vectors state `confirmations` — the
/// tip those counts were measured against.
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
    // against a single tip. The fixtures written above replay from their files
    // whatever the chain does next; the tip is stated so the operator knows
    // what a later re-capture has to be taken against. A capture pinned to a
    // set's `recordedTip` can be repeated for as long as the live tip is at or
    // above it and the beacon has announced nothing above it, since the tool
    // pins the same tip again and refuses either; an unpinned capture measures against the live tip, so once the
    // chain has been mined on only a fresh unpack of the export reproduces it.
    let shared_tip = rows
        .iter()
        .filter_map(|(_, row)| row.as_ref().ok())
        .find(|outcome| outcome.confirmations.expected.is_some())
        .map(|outcome| (outcome.tip_height, outcome.recorded_tip));
    match shared_tip {
        Some((tip, true)) => out.push_str(&format!(
            "  tip {tip}: every confirmations expectation captured above is measured \
             against the set's recordedTip, {tip}. The fixtures replay from their files \
             regardless; a re-capture works as long as the live tip is at or above the \
             recordedTip and no announcement has been confirmed above it — the tool \
             refuses either.\n"
        )),
        Some((tip, false)) => out.push_str(&format!(
            "  tip {tip}: every confirmations expectation captured above is measured \
             against this tip. The fixtures replay from their files regardless; to \
             re-capture a `{network_dir}` vector after this chain has been mined on, \
             start from a fresh unpack of the export.\n"
        )),
        None => {}
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
            "@context": did_btcr2::UPDATE_CONTEXT,
            "targetVersionId": version,
            "sourceHash": "AHcGbJ3OGSIrjVTIHFbIc2OEA25EDtMOM1uXBlw2qDQ",
            "targetHash": "hduKs2Pj2VpUueLkvWLSR5MeSjTYgKPO02H9zrqjUKw",
            "patch": [{ "op": "replace", "path": "/service/0/serviceEndpoint", "value": salt }],
            "proof": {
                "@context": did_btcr2::UPDATE_CONTEXT,
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
            expected: ExpectedOutcome::Resolved {
                document: json!({ "id": REGTEST_DID }),
                version_id: 2,
                deactivated: false,
                confirmations,
            },
            signals: None,
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

    /// A scratch fixture root unique to one test, removed by the test itself.
    ///
    /// Every emission test writes HERE. Writing into the repository's own
    /// `fixtures/chain/` and deleting afterwards left a stray file whenever an
    /// assertion in between failed, and `ALL_CHAIN_FIXTURES` is an explicit list
    /// rather than a directory scan, so nothing would have caught it before a
    /// `git add .` did.
    fn scratch_root(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chain-capture-emit-{}-{tag}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch fixture root is creatable");
        dir
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
        let root = scratch_root("pass");
        let vector = "minted/__test_emit_pass";
        let one = update(2, "bitcoin:mmBCLTLMZqUFhiG4vhhaM7EbLRN6h7sCfG");
        let sidecar = json!({ "updates": [one] });
        let hashes = update_hashes(vector, &sidecar).expect("the synthetic sidecar hashes");
        let target = synthetic_target(vector, sidecar, Some(93));
        let addresses = bodies(vec![
            ("bcrt1qbeacon", vec![announcement(hashes[0], 120)]),
            ("bcrt1qquiet", Vec::new()),
        ]);

        let outcome = emit_to(
            &root,
            &target,
            "http://localhost:3000",
            212,
            &addresses,
            &BTreeMap::new(),
            Some(93),
        )
        .expect("a validated capture is written");
        assert!(
            !outcome.recorded_tip,
            "a capture without signals.json measures against the live tip"
        );
        assert!(
            outcome
                .path
                .starts_with(std::fs::canonicalize(&root).expect("the scratch root resolves")),
            "the fixture lands under the destination it was given, not the \
             repository's own tree: {}",
            outcome.path.display()
        );

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

        std::fs::remove_dir_all(&root).expect("scratch fixture root is removable");
    }

    #[test]
    fn emit_writes_nothing_when_validation_fails() {
        let root = scratch_root("refuse");
        let vector = "minted/__test_emit_refuse";
        let path = fixture::fixture_path_in(&root, vector).expect("the throwaway id is safe");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("the fixture directory is creatable");
        }
        let sentinel = "{\"previous\": true}";
        std::fs::write(&path, sentinel).expect("the sentinel fixture is written");

        let sidecar = json!({ "updates": [update(2, "salt")] });
        let target = synthetic_target(vector, sidecar, Some(93));
        // Bodies that carry no announcement at all: the gate must refuse.
        let addresses = bodies(vec![("bcrt1qbeacon", Vec::new())]);

        let error = emit_to(
            &root,
            &target,
            "http://localhost:3000",
            212,
            &addresses,
            &BTreeMap::new(),
            Some(93),
        )
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

        std::fs::remove_dir_all(&root).expect("scratch fixture root is removable");
    }

    #[test]
    fn emit_defaults_to_the_repositorys_fixture_tree() {
        // `emit_to` takes the destination so the write is testable, and
        // `emit_writes_a_fixture_when_validation_passes` proves that root is a
        // real parameter. What is left unguarded by that is the DEFAULT: the
        // root a capture session writes into when no output root is given must
        // still be the repository's own tree, and nothing else.
        //
        // Compared against an independently built literal, never against a
        // second call to the same function. Two identical calls agree for ANY
        // definition of `fixture_root` — including one repointed at /tmp — so
        // such an assertion cannot fail and buys nothing.
        let vector = "minted/__test_emit_pass";
        assert_eq!(
            fixture::fixture_path_in(&fixture::fixture_root(), vector)
                .expect("the throwaway id is safe"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/chain")
                .join(format!("{vector}.json")),
            "emit's default root is the repository's own fixtures/chain, never a \
             scratch tree"
        );
        assert!(
            fixture::fixture_root().starts_with(env!("CARGO_MANIFEST_DIR")),
            "and it is derived from this crate's location rather than from the \
             working directory a session happens to run in: {}",
            fixture::fixture_root().display()
        );
    }

    #[test]
    fn run_rejects_a_vector_filed_under_another_network_before_any_request() {
        // mutinynet resolves its own endpoint, so this gets past the endpoint rule
        // and is refused on the mismatch — with no socket opened either way.
        let error = run(
            "mutinynet",
            None,
            Some("regtest/k1/qgppexmy".to_string()),
            None,
            None,
        )
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
        let error = run("regtest", None, None, None, None)
            .expect_err("regtest has no hosted Esplora endpoint");
        assert!(matches!(error, CaptureError::Target(_)), "got: {error}");
        let message = error_line(&error);
        assert!(
            message.contains("--esplora-url") && message.contains("regtest"),
            "the failure names the chain and the missing endpoint flag: {message}"
        );
    }

    #[test]
    fn run_refuses_a_chain_this_tool_captures_nothing_on() {
        let error =
            run("signet", None, None, None, None).expect_err("no vector is filed under signet");
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

    #[test]
    fn run_with_a_suite_root_loads_the_set_from_it() {
        // An empty root: the set is looked for there, not in the test-suite
        // tree, and a set without signals.json is refused before any request.
        let root = scratch_root("run-suite-root");
        let out = scratch_root("run-suite-out");
        let error = run(
            "signet",
            None,
            Some("signet/k1/qabc".to_string()),
            Some(root.clone()),
            Some(out.clone()),
        )
        .expect_err("a set without signals.json is not captured from a suite root");
        assert!(
            matches!(
                error,
                CaptureError::Target(targets::TargetError::NoSignals { ref vector })
                    if vector == "signet/k1/qabc"
            ),
            "got: {error}"
        );
        assert_eq!(
            std::fs::read_dir(&out)
                .expect("the output root exists")
                .count(),
            0,
            "nothing is written"
        );
        std::fs::remove_dir_all(&root).expect("scratch root is removable");
        std::fs::remove_dir_all(&out).expect("scratch root is removable");
    }

    #[test]
    fn run_with_a_suite_root_still_refuses_a_set_filed_under_another_network() {
        let root = scratch_root("run-suite-mismatch");
        let error = run(
            "signet",
            None,
            Some("testnet4/k1/qabc".to_string()),
            Some(root.clone()),
            None,
        )
        .expect_err("a set may only be captured from its own chain");
        assert!(
            matches!(error, CaptureError::NetworkMismatch { ref filed_under, .. } if filed_under == "testnet4"),
            "got: {error}"
        );
        std::fs::remove_dir_all(&root).expect("scratch root is removable");
    }

    #[test]
    fn run_with_a_suite_root_refuses_a_malformed_set_id() {
        let root = scratch_root("run-suite-bad-id");
        let error = run(
            "signet",
            None,
            Some("signet/../../etc".to_string()),
            Some(root.clone()),
            None,
        )
        .expect_err("a set id is shape-checked before any path is built");
        assert!(
            matches!(
                error,
                CaptureError::Target(targets::TargetError::InvalidVectorId { .. })
            ),
            "got: {error}"
        );
        std::fs::remove_dir_all(&root).expect("scratch root is removable");
    }

    /// An outcome as a captured row produces it, filed at the fixture path that
    /// vector id derives.
    fn sample_outcome(id: &str, confirmations: ConfirmationsCheck) -> CaptureOutcome {
        CaptureOutcome {
            addresses: 2,
            empty_addresses: 1,
            signals: 1,
            tip_height: 212,
            recorded_tip: false,
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
    fn a_regtest_session_footer_states_the_tip_the_confirmations_were_measured_against() {
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
            summary.contains("tip 212"),
            "a regtest session states the tip its confirmations are measured against: \
             {summary}"
        );
        assert!(
            summary.contains("fresh unpack"),
            "a regtest session says how to re-capture once the chain has moved: {summary}"
        );
        assert!(
            !summary.to_lowercase().contains("do not mine"),
            "mining is not forbidden: the fixtures replay from their files: {summary}"
        );
    }

    #[test]
    fn a_recorded_tip_session_footer_states_the_recorded_tip_rule() {
        let mut pinned = sample_outcome(
            "signet/k1/qyp5h7kz",
            ConfirmationsCheck {
                expected: Some(4),
                observed: Some(4),
            },
        );
        pinned.recorded_tip = true;
        let rows = vec![("signet/k1/qyp5h7kz".to_string(), Ok(pinned))];
        let summary = render_summary("signet", "https://mempool.space/signet/api", &rows);

        assert!(summary.contains("tip 212"), "{summary}");
        assert!(
            summary.contains("recordedTip"),
            "a pinned session names the tip it was pinned to: {summary}"
        );
        assert!(
            summary.contains("at or above"),
            "a pinned session states when a re-capture works: {summary}"
        );
        assert!(
            !summary.contains("fresh unpack"),
            "a public chain has no export to unpack: {summary}"
        );
    }

    #[test]
    fn a_session_with_no_stated_confirmations_omits_the_tip_footer() {
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
            !summary.contains("measured against this tip"),
            "a chain whose vectors state no confirmations has no shared tip to report: \
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

    /// An offline resolution of the vendor DID: its generated
    /// genesis document with the given metadata.
    fn resolution(version: u64, deactivated: bool, confirmations: Option<u32>) -> ResolutionResult {
        use did_btcr2::document::{
            Document, DocumentMetadata, InitialDocument, ResolutionMetadata,
        };
        let did = Did::from_str(REGTEST_DID).expect("a vendor DID parses");
        let genesis = InitialDocument::from_did(&did, &ResolutionOptions::default())
            .expect("a key DID's genesis document generates offline");
        ResolutionResult {
            resolution_metadata: ResolutionMetadata::default(),
            document: Document::from(genesis),
            document_metadata: DocumentMetadata {
                version_id: std::num::NonZeroU64::new(version).expect("versions start at 1"),
                confirmations,
                deactivated,
                updated: None,
            },
        }
    }

    /// A target expecting [`resolution`]'s document.
    fn expecting(expected: ExpectedOutcome) -> VectorTarget {
        let mut target = synthetic_target("signet/k1/qoutcome", json!({}), None);
        target.expected = expected;
        target
    }

    fn resolved_outcome(version_id: u64, confirmations: Option<u64>) -> ExpectedOutcome {
        ExpectedOutcome::Resolved {
            document: resolution(1, false, None).document.as_ref().clone(),
            version_id,
            deactivated: false,
            confirmations,
        }
    }

    fn expected_error(code: &str) -> ExpectedOutcome {
        ExpectedOutcome::Error {
            code: code.to_string(),
        }
    }

    fn missing_update_data() -> did_btcr2_client::Error {
        did_btcr2_client::Error::Btcr2(did_btcr2::error::Btcr2Error::MissingUpdateData {
            update_hash: Sha256Hash::from([0x11; 32]),
        })
    }

    #[test]
    fn outcome_resolved_accepts_a_matching_resolution() {
        let target = expecting(resolved_outcome(2, Some(5)));
        let result = check_outcome(&target, Ok(resolution(2, false, Some(5))))
            .expect("a matching resolution passes")
            .expect("a resolved expectation returns the resolution");
        assert_eq!(result.document_metadata.confirmations, Some(5));
    }

    #[test]
    fn outcome_resolved_refuses_a_different_confirmation_count() {
        let target = expecting(resolved_outcome(2, Some(5)));
        let error = check_outcome(&target, Ok(resolution(2, false, Some(6))))
            .expect_err("confirmations are exact at capture: the tip is pinned");
        assert!(
            matches!(
                error,
                CaptureError::ResolutionMismatch { ref field, ref expected, ref got, .. }
                    if field == "confirmations" && expected == "5" && got == "6"
            ),
            "got: {error}"
        );
        let error = check_outcome(&target, Ok(resolution(2, false, None)))
            .expect_err("a stated count needs a reported one");
        assert!(
            matches!(error, CaptureError::ResolutionMismatch { ref got, .. } if got == "none"),
            "got: {error}"
        );
    }

    #[test]
    fn outcome_resolved_without_stated_confirmations_does_not_compare_them() {
        let target = expecting(resolved_outcome(2, None));
        check_outcome(&target, Ok(resolution(2, false, Some(1_045))))
            .expect("a set stating no confirmations is not checked on them");
    }

    #[test]
    fn outcome_resolved_refuses_a_different_document_version_or_flag() {
        let target = expecting(resolved_outcome(2, None));
        for (result, field) in [
            (resolution(3, false, None), "versionId"),
            (resolution(2, true, None), "deactivated"),
        ] {
            let error = check_outcome(&target, Ok(result)).expect_err("a mismatch is refused");
            assert!(
                matches!(error, CaptureError::ResolutionMismatch { field: ref f, .. } if f == field),
                "{field}: got {error}"
            );
        }
        let other_document = expecting(ExpectedOutcome::Resolved {
            document: json!({ "id": "did:btcr2:someone-else" }),
            version_id: 2,
            deactivated: false,
            confirmations: None,
        });
        let error = check_outcome(&other_document, Ok(resolution(2, false, None)))
            .expect_err("a different document is refused");
        assert!(
            matches!(error, CaptureError::ResolutionMismatch { ref field, .. } if field == "didDocument"),
            "got: {error}"
        );
    }

    #[test]
    fn outcome_resolved_refuses_a_failed_resolve_with_its_error() {
        let target = expecting(resolved_outcome(2, None));
        let error = check_outcome(&target, Err(missing_update_data()))
            .expect_err("a failed resolve is not a resolution");
        assert!(
            matches!(
                error,
                CaptureError::ResolveFailed {
                    source: did_btcr2_client::Error::Btcr2(
                        did_btcr2::error::Btcr2Error::MissingUpdateData { .. }
                    ),
                    ..
                }
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn outcome_expected_error_accepts_the_same_code() {
        let target = expecting(expected_error("MISSING_UPDATE_DATA"));
        assert!(
            check_outcome(&target, Err(missing_update_data()))
                .expect("the recorded error is reproduced")
                .is_none()
        );
    }

    #[test]
    fn outcome_expected_error_accepts_a_different_code() {
        // The code is not compared at capture: the harness judges it.
        let target = expecting(expected_error("NOT_FOUND"));
        assert!(
            check_outcome(&target, Err(missing_update_data()))
                .expect("any specification error satisfies an expected error")
                .is_none()
        );
    }

    #[test]
    fn outcome_expected_error_accepts_a_code_the_set_spells_differently() {
        // The set spells LATE_PUBLISHING_ERROR; the specification, and this
        // resolver, say LATE_PUBLISHING.
        let target = expecting(expected_error("LATE_PUBLISHING_ERROR"));
        let late = did_btcr2_client::Error::Resolver(did_btcr2::resolver::Error::Btcr2Error(
            did_btcr2::error::Btcr2Error::LatePublishingError("late".to_string()),
        ));
        assert_eq!(client_error_code(&late).as_deref(), Some("LATE_PUBLISHING"));
        assert!(
            check_outcome(&target, Err(late))
                .expect("a coded failure satisfies an expected error")
                .is_none()
        );
    }

    #[test]
    fn outcome_expected_error_refuses_a_success() {
        let target = expecting(expected_error("MISSING_UPDATE_DATA"));
        let error = check_outcome(&target, Ok(resolution(2, false, Some(5))))
            .expect_err("a resolve that succeeds does not reproduce an expected error");
        assert!(
            matches!(
                error,
                CaptureError::ResolutionMismatch { ref field, ref expected, ref got, .. }
                    if field == "error"
                        && expected.contains("MISSING_UPDATE_DATA")
                        && got == "resolved versionId 2"
            ),
            "got: {error}"
        );
    }

    #[test]
    fn outcome_expected_error_refuses_an_uncoded_error() {
        let target = expecting(expected_error("MISSING_UPDATE_DATA"));
        let transport =
            did_btcr2_client::Error::Transport(did_btcr2_client::TransportError::Status {
                status: 503,
                body: "unavailable".to_string(),
            });
        let error = check_outcome(&target, Err(transport))
            .expect_err("a transport fault is not a reproduced error");
        assert!(
            matches!(
                error,
                CaptureError::ResolveFailed {
                    source: did_btcr2_client::Error::Transport(_),
                    ..
                }
            ),
            "got: {error:?}"
        );

        let no_endpoint = did_btcr2_client::Error::NoDefaultEndpoint("regtest");
        let error = check_outcome(&target, Err(no_endpoint))
            .expect_err("an endpoint fault is not a reproduced error");
        assert!(
            matches!(
                error,
                CaptureError::ResolveFailed {
                    source: did_btcr2_client::Error::NoDefaultEndpoint(_),
                    ..
                }
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn outcome_client_error_code_maps_identifier_and_transport() {
        let identifier = Did::from_str("did:btcr2:notbech32").expect_err("not a DID");
        assert_eq!(
            client_error_code(&did_btcr2_client::Error::Identifier(identifier)).as_deref(),
            Some("INVALID_DID")
        );
        let transport = did_btcr2_client::Error::Transport(
            did_btcr2_client::TransportError::Malformed("x".to_string()),
        );
        assert_eq!(client_error_code(&transport), None);
        assert_eq!(
            client_error_code(&did_btcr2_client::Error::UnknownNetwork("x".to_string())),
            None
        );
    }

    #[test]
    fn outcome_identifier_codes_follow_the_core_conversion() {
        use did_btcr2::error::{Btcr2Error, ProblemDetails as _};
        // Each identifier error, parsed twice: one copy goes through the core's
        // own conversion, the other through this crate's restatement of it.
        for did in ["did:btcr2:notbech32", "did:example:123", "not-a-did"] {
            let owned = Did::from_str(did).expect_err("not a did:btcr2 identifier");
            let borrowed = Did::from_str(did).expect_err("not a did:btcr2 identifier");
            let core = Btcr2Error::from(owned).details().expect("details")["type"]
                .as_str()
                .and_then(|t| t.rsplit_once('#'))
                .map(|(_, code)| code.to_string());
            assert_eq!(
                client_error_code(&did_btcr2_client::Error::Identifier(borrowed)),
                core,
                "{did}"
            );
        }
        let method = Did::from_str("did:example:123").expect_err("another method");
        assert_eq!(
            client_error_code(&did_btcr2_client::Error::Identifier(method)).as_deref(),
            Some("METHOD_NOT_SUPPORTED")
        );
    }

    /// End-to-end captures of sets carrying `signals.json`, driven through a
    /// scripted indexer and a fake clock: real key, real signed update, real
    /// resolver, and the written fixture replayed offline.
    mod signals_sets {
        use super::*;
        use crate::targets::TargetError;
        use std::collections::VecDeque;
        use std::num::NonZeroU64;
        use std::time::{Duration, Instant};

        const BASE: &str = "https://indexer.test";

        /// A fixed test key, used only to build scratch sets in memory.
        const TEST_KEY_HEX: &str =
            "3a8e5c1f9b20d47e6f13c95a0b7d28e4f16a3c9d05b8e7f21c4d6a9b30e5f718";

        /// Where the one update of every scratch set is announced.
        const ANNOUNCED_AT: u32 = 300;
        /// The tip every scratch set records its expectations against.
        const RECORDED_TIP: u32 = 310;
        /// The tip the scripted indexer reports unless a test says otherwise.
        const LIVE_TIP: u32 = 320;

        /// A clock that never waits: `sleep` advances `now`.
        #[derive(Clone)]
        struct FakeClock(Rc<RefCell<(Instant, Duration)>>);

        impl FakeClock {
            fn new() -> Self {
                Self(Rc::new(RefCell::new((Instant::now(), Duration::ZERO))))
            }
        }

        impl Clock for FakeClock {
            fn now(&self) -> Instant {
                let (base, offset) = *self.0.borrow();
                base + offset
            }

            fn sleep(&self, duration: Duration) {
                self.0.borrow_mut().1 += duration;
            }
        }

        /// Queued `(status, body)` replies per request path.
        type Replies = Rc<RefCell<BTreeMap<String, VecDeque<(u16, String)>>>>;

        /// An in-memory Esplora. Scripted paths answer from their queue (the
        /// last reply repeats); a continuation page answers `[]`; a block
        /// header is generated from its hash unless the indexer is strict.
        /// Every request is logged with the fake clock's time.
        #[derive(Clone)]
        struct FakeIndexer {
            replies: Replies,
            log: Rc<RefCell<Vec<(Instant, String)>>>,
            clock: FakeClock,
            strict: bool,
        }

        impl FakeIndexer {
            fn new(clock: &FakeClock, strict: bool) -> Self {
                Self {
                    replies: Rc::default(),
                    log: Rc::default(),
                    clock: clock.clone(),
                    strict,
                }
            }

            /// Replace `path`'s queue with `replies`.
            fn script(&self, path: &str, replies: Vec<(u16, String)>) {
                self.replies
                    .borrow_mut()
                    .insert(path.to_string(), replies.into_iter().collect());
            }

            fn history(&self, address: &str, txs: Vec<Value>) {
                self.script(
                    &format!("/address/{address}/txs"),
                    vec![(200, Value::Array(txs).to_string())],
                );
            }

            fn tip(&self, height: u32) {
                self.script("/blocks/tip/height", vec![(200, format!("{height}\n"))]);
            }

            fn log(&self) -> Vec<(Instant, String)> {
                self.log.borrow().clone()
            }
        }

        impl BtcTransport for FakeIndexer {
            fn execute(
                &self,
                req: http::Request<Vec<u8>>,
            ) -> Result<http::Response<Vec<u8>>, TransportError> {
                let path = req.uri().path().to_string();
                self.log.borrow_mut().push((self.clock.now(), path.clone()));
                let scripted = self.replies.borrow_mut().get_mut(&path).map(|queue| {
                    if queue.len() > 1 {
                        queue.pop_front().expect("a non-empty queue")
                    } else {
                        queue.front().cloned().expect("a non-empty queue")
                    }
                });
                let (status, body) = match scripted {
                    Some(reply) => reply,
                    None if path.contains("/txs/chain/") => (200, "[]".to_string()),
                    None if !self.strict && path.starts_with("/block/") => {
                        let hash = &path["/block/".len()..];
                        let height = u32::from_str_radix(hash, 16).unwrap_or_default();
                        (200, block_header(hash, height).to_string())
                    }
                    None => (404, format!("nothing at `{path}`")),
                };
                Ok(http::Response::builder()
                    .status(status)
                    .body(body.into_bytes())
                    .expect("a valid status and body build a response"))
            }
        }

        /// The hash of the block at `height` on the scripted chain.
        fn block_hash(height: u32) -> String {
            format!("{height:064x}")
        }

        fn block_header(hash: &str, height: u32) -> Value {
            json!({
                "id": hash,
                "height": height,
                "timestamp": 1_700_000_000i64 + i64::from(height),
                "mediantime": 1_699_996_400i64 + i64::from(height),
            })
        }

        /// An Esplora body for a transaction confirmed at `height` whose last
        /// output is `last_script`.
        fn tx(txid: &str, last_script: String, height: u32) -> Value {
            json!({
                "txid": txid,
                "version": 2,
                "locktime": 0,
                "vin": [],
                "vout": [
                    { "scriptpubkey": "0014abababababababababababababababababababab", "value": 1_000 },
                    { "scriptpubkey": last_script, "value": 0 },
                ],
                "size": 0,
                "weight": 0,
                "fee": 0,
                "status": {
                    "confirmed": true,
                    "block_height": height,
                    "block_hash": block_hash(height),
                    "block_time": 1_700_000_000i64 + i64::from(height),
                },
            })
        }

        fn op_return(bytes: [u8; 32]) -> String {
            format!("6a20{}", hex::encode(bytes))
        }

        /// A txid for the `n`th scripted transaction.
        fn txid(n: u8) -> String {
            format!("{n:02x}").repeat(32)
        }

        /// A scratch set in the regenerated layout, with the indexer that
        /// serves its chain.
        struct ScratchSet {
            suite_root: PathBuf,
            out_root: PathBuf,
            id: String,
            did: Did,
            beacon: String,
            update_hash: [u8; 32],
            sidecar: Value,
            genesis_document: Value,
            expected_document: Value,
            clock: FakeClock,
            indexer: FakeIndexer,
        }

        impl ScratchSet {
            /// A k1 DID on `network` with one signed update announced at
            /// [`ANNOUNCED_AT`] on its P2WPKH genesis beacon, recorded against
            /// [`RECORDED_TIP`]; the indexer reports [`LIVE_TIP`].
            fn new(network: Network, network_dir: &str, tag: &str) -> Self {
                let clock = FakeClock::new();
                let indexer = FakeIndexer::new(&clock, false);

                let mut key = [0u8; 32];
                hex::decode_to_slice(TEST_KEY_HEX, &mut key).expect("the test key is hex");
                let secret = secp256k1::SecretKey::from_slice(&key).expect("a valid scalar");
                let public_key = secret.public_key(&secp256k1::Secp256k1::new());
                let genesis = Client::new(BASE.to_string(), indexer.clone())
                    .create(&public_key, network)
                    .expect("a key DID is created offline");
                let did_str = genesis.as_ref()["id"]
                    .as_str()
                    .expect("the created document names its DID")
                    .to_string();
                let did = Did::from_str(&did_str).expect("the created DID parses");

                let patch_json = json!([{
                    "op": "add",
                    "path": "/service/-",
                    "value": {
                        "id": format!("{did_str}#dwn"),
                        "type": "DecentralizedWebNode",
                        "serviceEndpoint": "http://example.com/dwn",
                    },
                }]);
                let patch: did_btcr2_client::Patch =
                    serde_json::from_value(patch_json).expect("a static RFC-6902 patch");
                let mut expected_document = genesis.as_ref().clone();
                json_patch::patch(&mut expected_document, &patch).expect("the patch applies");
                let update = genesis
                    .construct_signed_update(
                        patch,
                        NonZeroU64::new(2).expect("version 2 is above zero"),
                        &format!("{did_str}#initialKey"),
                        did_btcr2::key::SecretKey::try_from(key).expect("a valid scalar"),
                    )
                    .expect("the update signs offline");
                let update_json = update.as_ref().clone();
                let sidecar = json!({ "updates": [update_json] });
                let update_hash = update_hashes(&did_str, &sidecar).expect("the sidecar hashes")[0];

                let beacons: Vec<(String, String)> = genesis
                    .beacons()
                    .map(|b| (b.id().to_string(), b.address().to_string()))
                    .collect();
                let beacon = beacons
                    .iter()
                    .find(|(id, _)| id.ends_with("#initialP2WPKH"))
                    .map(|(_, address)| address.clone())
                    .expect("a k1 DID has a P2WPKH genesis beacon");
                for (_, address) in &beacons {
                    indexer.history(address, Vec::new());
                }
                indexer.history(
                    &beacon,
                    vec![tx(&txid(1), op_return(update_hash), ANNOUNCED_AT)],
                );
                indexer.tip(LIVE_TIP);

                let short: String = did_str
                    .trim_start_matches("did:btcr2:k1")
                    .chars()
                    .take(8)
                    .collect();
                let id = format!("{network_dir}/k1/{short}");
                let suite_root = scratch_root(&format!("{tag}-suite"));
                let set_dir = suite_root.join(&id);
                let write = |relative: &str, value: &Value| {
                    let path = set_dir.join(relative);
                    std::fs::create_dir_all(path.parent().expect("a file has a parent"))
                        .expect("the set tree is creatable");
                    std::fs::write(&path, serde_json::to_string_pretty(value).expect("JSON"))
                        .expect("the set file is writable");
                };
                write(
                    "create/input.json",
                    &json!({ "idType": "KEY", "network": network_dir }),
                );
                write(
                    "create/output.json",
                    &json!({ "did": did_str, "genesisDocument": genesis.as_ref() }),
                );
                write(
                    "update/01/input.json",
                    &json!({ "sourceDocument": genesis.as_ref(), "patch": patch_json_of(&update_json) }),
                );
                write(
                    "update/01/output.json",
                    &json!({ "signedUpdate": update_json }),
                );
                write(
                    "resolve/input.json",
                    &json!({ "did": did_str, "resolutionOptions": { "sidecar": sidecar } }),
                );
                write(
                    "resolve/output.json",
                    &json!({
                        "didDocument": expected_document,
                        "didDocumentMetadata": {
                            "versionId": "2",
                            "deactivated": false,
                            "confirmations": RECORDED_TIP - ANNOUNCED_AT + 1,
                        },
                        "didResolutionMetadata": { "contentType": "application/did" },
                    }),
                );
                write(
                    "other.json",
                    &json!({ "scenarioId": format!("{tag}-scenario") }),
                );

                let set = Self {
                    suite_root,
                    out_root: scratch_root(&format!("{tag}-out")),
                    id,
                    did,
                    beacon,
                    update_hash,
                    sidecar,
                    genesis_document: genesis.as_ref().clone(),
                    expected_document,
                    clock,
                    indexer,
                };
                set.write_signals(vec![set.entry(Some(1), false, &txid(1), ANNOUNCED_AT)]);
                set
            }

            /// One `signals.json` entry announcing this set's update.
            fn entry(
                &self,
                update: Option<u64>,
                duplicate: bool,
                txid: &str,
                height: u32,
            ) -> Value {
                let mut entry = json!({
                    "beaconId": format!("{}#initialP2WPKH", self.did.encode()),
                    "address": self.beacon,
                    "txid": txid,
                    "blockHeight": height,
                    "blockHash": block_hash(height),
                    "signalBytes": hex::encode(self.update_hash),
                    "recordedTip": RECORDED_TIP,
                });
                if let Some(update) = update {
                    entry["update"] = json!(update);
                }
                if duplicate {
                    entry["duplicate"] = json!(true);
                }
                entry
            }

            fn write_signals(&self, entries: Vec<Value>) {
                std::fs::write(
                    self.suite_root.join(&self.id).join("signals.json"),
                    Value::Array(entries).to_string(),
                )
                .expect("signals.json is writable");
            }

            /// Rewrite `resolve/` as a negative set: no sidecar updates, and an
            /// expected MISSING_UPDATE_DATA.
            fn make_negative(&self) {
                let resolve = self.suite_root.join(&self.id).join("resolve");
                std::fs::write(
                    resolve.join("input.json"),
                    json!({ "did": self.did.encode().to_string(), "resolutionOptions": { "sidecar": {} } })
                        .to_string(),
                )
                .expect("input.json is writable");
                std::fs::write(
                    resolve.join("output.json"),
                    json!({
                        "didDocument": null,
                        "didResolutionMetadata": {
                            "error": "MISSING_UPDATE_DATA",
                            "errorMessage": "the update was withheld",
                        },
                    })
                    .to_string(),
                )
                .expect("output.json is writable");
            }

            fn target(&self) -> VectorTarget {
                targets::load_in(&self.suite_root, &self.id).expect("the scratch set loads")
            }

            fn capture(&self) -> Result<CaptureOutcome, CaptureError> {
                capture_one_with(
                    &self.target(),
                    BASE,
                    self.indexer.clone(),
                    self.clock.clone(),
                    &self.out_root,
                )
            }

            /// The fixture the capture wrote, parsed.
            fn written(&self) -> Value {
                let path = fixture::fixture_path_in(&self.out_root, &self.id)
                    .expect("the set id is a safe fixture path");
                serde_json::from_str(
                    &std::fs::read_to_string(&path)
                        .unwrap_or_else(|e| panic!("{}: not written ({e})", path.display())),
                )
                .expect("the fixture is JSON")
            }

            /// Every file under the output root.
            fn files_written(&self) -> Vec<PathBuf> {
                fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
                    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            walk(&path, into);
                        } else {
                            into.push(path);
                        }
                    }
                }
                let mut files = Vec::new();
                walk(&self.out_root, &mut files);
                files
            }

            /// Resolve the set again from nothing but the written fixture: a
            /// strict indexer serving only its bodies, at its pinned tip.
            fn replay(&self) -> ResolutionResult {
                let fixture = self.written();
                let clock = FakeClock::new();
                let replay = FakeIndexer::new(&clock, true);
                for (address, txs) in fixture["addresses"]
                    .as_object()
                    .expect("the fixture records addresses")
                {
                    replay.history(address, txs.as_array().expect("a body is a list").clone());
                }
                for (hash, body) in fixture["blocks"].as_object().expect("blocks") {
                    replay.script(&format!("/block/{hash}"), vec![(200, body.to_string())]);
                }
                let tip = u32::try_from(fixture["tip_height"].as_u64().expect("a pinned tip"))
                    .expect("a block height");
                Client::new(BASE.to_string(), replay)
                    .resolve(
                        &self.did,
                        resolution_options_for(&self.sidecar, Some(tip))
                            .expect("the sidecar is valid"),
                    )
                    .expect("the fixture replays offline")
            }

            fn cleanup(self) {
                std::fs::remove_dir_all(&self.suite_root).expect("scratch suite is removable");
                std::fs::remove_dir_all(&self.out_root).expect("scratch output is removable");
            }
        }

        /// The patch an update carries, for the set's `update/01/input.json`.
        fn patch_json_of(update: &Value) -> Value {
            update["patch"].clone()
        }

        /// Capture `network` end to end and check what was written.
        fn captures_and_replays(network: Network, network_dir: &str) {
            let set = ScratchSet::new(network, network_dir, network_dir);
            assert_eq!(set.did.components().network(), network);

            let outcome = set.capture().expect("the set captures");
            assert_eq!(outcome.tip_height, RECORDED_TIP);
            assert!(outcome.recorded_tip, "the capture is pinned to recordedTip");
            assert_eq!(outcome.signals, 1);
            assert_eq!(
                outcome.confirmations,
                ConfirmationsCheck {
                    expected: Some(11),
                    observed: Some(11),
                }
            );
            let expected_path = std::fs::canonicalize(&set.out_root)
                .expect("the output root resolves")
                .join(format!("{}.json", set.id));
            assert_eq!(
                outcome.path, expected_path,
                "filed by set id under the output root"
            );
            assert!(
                set.id.starts_with(&format!("{network_dir}/k1/")),
                "{}",
                set.id
            );

            let written = set.written();
            assert_eq!(written["network"], json!(network_dir));
            assert_eq!(written["vector"], json!(set.id));
            assert_eq!(written["did"], json!(set.did.encode().to_string()));
            assert_eq!(
                written["tip_height"],
                json!(RECORDED_TIP),
                "the fixture pins the recorded tip, not the live one"
            );
            assert_eq!(written["signals"].as_array().map(Vec::len), Some(1));
            assert_eq!(written["signals"][0]["txid"], json!(txid(1)));
            assert_eq!(written["signals"][0]["block_height"], json!(ANNOUNCED_AT));
            assert_eq!(
                written["addresses"][&set.beacon].as_array().map(Vec::len),
                Some(1),
                "the beacon's body is recorded"
            );
            assert_eq!(
                written["addresses"].as_object().map(|a| a.len()),
                Some(3),
                "every genesis beacon the resolver asked about is recorded"
            );
            assert!(
                written["blocks"].get(block_hash(ANNOUNCED_AT)).is_some(),
                "the announcement's block is recorded: {}",
                written["blocks"]
            );

            let replayed = set.replay();
            assert_eq!(replayed.document.as_ref(), &set.expected_document);
            assert_eq!(replayed.document_metadata.version_id.get(), 2);
            assert_eq!(replayed.document_metadata.confirmations, Some(11));
            assert!(!replayed.document_metadata.deactivated);
            set.cleanup();
        }

        #[test]
        fn captures_a_signet_set_against_its_recorded_tip_and_replays_it() {
            captures_and_replays(Network::Signet, "signet");
        }

        #[test]
        fn captures_a_testnet4_set_against_its_recorded_tip_and_replays_it() {
            captures_and_replays(Network::TestnetV4, "testnet4");
        }

        #[test]
        fn paced_capture_spaces_every_request_across_both_handles() {
            let set = ScratchSet::new(Network::Signet, "signet", "paced");
            set.capture().expect("the set captures");

            let log = set.indexer.log();
            assert_eq!(
                log.first().map(|(_, path)| path.as_str()),
                Some("/blocks/tip/height"),
                "the live tip is asked for first: {log:?}"
            );
            assert!(
                log.iter().any(|(_, path)| path.starts_with("/block/")),
                "the block fetch after the resolve is part of the session: {log:?}"
            );
            for pair in log.windows(2) {
                let gap = pair[1].0 - pair[0].0;
                assert!(
                    gap >= Duration::from_millis(500),
                    "{} started {gap:?} after {}",
                    pair[1].1,
                    pair[0].1
                );
            }
            set.cleanup();
        }

        #[test]
        fn paced_capture_retries_a_rate_limited_answer_and_records_the_success() {
            let set = ScratchSet::new(Network::Signet, "signet", "retry");
            let body = vec![tx(&txid(1), op_return(set.update_hash), ANNOUNCED_AT)];
            set.indexer.script(
                &format!("/address/{}/txs", set.beacon),
                vec![
                    (429, "slow down".to_string()),
                    (200, Value::Array(body.clone()).to_string()),
                ],
            );

            set.capture().expect("a 429 is retried, not fatal");
            assert_eq!(
                set.written()["addresses"][&set.beacon],
                Value::Array(body),
                "the fixture holds the 2xx body"
            );
            let asked = set
                .indexer
                .log()
                .iter()
                .filter(|(_, path)| *path == format!("/address/{}/txs", set.beacon))
                .count();
            assert!(
                asked >= 2,
                "the rate-limited request was sent again: {asked}"
            );
            set.cleanup();
        }

        #[test]
        fn refuses_a_live_tip_below_the_recorded_tip() {
            let set = ScratchSet::new(Network::Signet, "signet", "behind");
            set.indexer.tip(305);

            let error = set
                .capture()
                .expect_err("an indexer behind the set cannot capture it");
            assert!(
                matches!(
                    error,
                    CaptureError::TipBelowRecorded {
                        live_tip: 305,
                        recorded_tip: RECORDED_TIP,
                        ..
                    }
                ),
                "got: {error}"
            );
            let message = error.to_string();
            assert!(
                message.contains("305") && message.contains("310"),
                "{message}"
            );
            assert!(set.files_written().is_empty(), "nothing is written");
            assert_eq!(
                set.indexer.log().len(),
                1,
                "the refusal comes before the resolve: {:?}",
                set.indexer.log()
            );
            set.cleanup();
        }

        #[test]
        fn refuses_an_unreadable_live_tip() {
            let set = ScratchSet::new(Network::Signet, "signet", "no-tip");
            set.indexer.script(
                "/blocks/tip/height",
                vec![(200, "not a height".to_string())],
            );
            let error = set
                .capture()
                .expect_err("an unreadable tip refuses the capture");
            assert!(matches!(error, CaptureError::NoTip { .. }), "got: {error}");

            set.indexer
                .script("/blocks/tip/height", vec![(503, "unavailable".to_string())]);
            let error = set
                .capture()
                .expect_err("a failed tip request refuses the capture");
            assert!(matches!(error, CaptureError::NoTip { .. }), "got: {error}");
            assert!(set.files_written().is_empty(), "nothing is written");
            set.cleanup();
        }

        /// The set's history with the same update announced again at 308.
        fn with_repeat(set: &ScratchSet) {
            set.indexer.history(
                &set.beacon,
                vec![
                    tx(&txid(1), op_return(set.update_hash), ANNOUNCED_AT),
                    tx(&txid(2), op_return(set.update_hash), 308),
                ],
            );
        }

        #[test]
        fn captures_a_repeated_signal_recorded_as_a_duplicate() {
            let set = ScratchSet::new(Network::Signet, "signet", "dup-ok");
            with_repeat(&set);
            set.write_signals(vec![
                set.entry(Some(1), false, &txid(1), ANNOUNCED_AT),
                set.entry(Some(1), true, &txid(2), 308),
            ]);

            let outcome = set.capture().expect("a recorded duplicate captures");
            assert_eq!(outcome.signals, 2);
            let heights: Vec<Value> = set.written()["signals"]
                .as_array()
                .expect("signals")
                .iter()
                .map(|s| s["block_height"].clone())
                .collect();
            assert_eq!(heights, vec![json!(ANNOUNCED_AT), json!(308)]);
            let replayed = set.replay();
            assert_eq!(replayed.document_metadata.version_id.get(), 2);
            assert_eq!(replayed.document_metadata.confirmations, Some(11));
            set.cleanup();
        }

        #[test]
        fn refuses_a_repeated_signal_recorded_without_the_duplicate_flag() {
            let set = ScratchSet::new(Network::Signet, "signet", "dup-unflagged");
            with_repeat(&set);
            set.write_signals(vec![
                set.entry(Some(1), false, &txid(1), ANNOUNCED_AT),
                set.entry(Some(1), false, &txid(2), 308),
            ]);

            let error = targets::load_in(&set.suite_root, &set.id)
                .expect_err("a repeat without the flag is a malformed record");
            assert!(
                matches!(error, TargetError::MalformedFixture { ref detail, .. } if detail.contains("duplicate")),
                "got: {error}"
            );
            assert!(set.files_written().is_empty(), "nothing is written");
            set.cleanup();
        }

        #[test]
        fn refuses_a_repeated_signal_the_record_omits() {
            let set = ScratchSet::new(Network::Signet, "signet", "dup-unrecorded");
            with_repeat(&set);

            let error = set.capture().expect_err("an unrecorded repeat is refused");
            assert!(
                matches!(
                    error,
                    CaptureError::Validation(ValidateError::UnrecordedSignal { txid: ref found, height: 308, .. })
                        if *found == txid(2)
                ),
                "got: {error}"
            );
            assert!(set.files_written().is_empty(), "nothing is written");
            set.cleanup();
        }

        #[test]
        fn refuses_an_announcement_above_the_recorded_tip() {
            let set = ScratchSet::new(Network::Signet, "signet", "above");
            set.indexer.history(
                &set.beacon,
                vec![
                    tx(&txid(1), op_return(set.update_hash), ANNOUNCED_AT),
                    tx(&txid(3), op_return([0x77; 32]), 315),
                ],
            );

            let error = set
                .capture()
                .expect_err("an announcement past the recorded tip is refused");
            assert!(
                matches!(
                    error,
                    CaptureError::Validation(ValidateError::AnnouncementAboveRecordedTip {
                        height: 315,
                        recorded_tip: RECORDED_TIP,
                        ..
                    })
                ),
                "got: {error}"
            );
            assert!(set.files_written().is_empty(), "nothing is written");
            set.cleanup();
        }

        #[test]
        fn captures_a_signet_set_with_dust_above_the_recorded_tip() {
            let set = ScratchSet::new(Network::Signet, "signet", "dust");
            let mut dust = tx(
                &txid(4),
                "0014cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_string(),
                315,
            );
            dust["vout"] = json!([{
                "scriptpubkey": "0014cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "value": 546,
            }]);
            set.indexer.history(
                &set.beacon,
                vec![
                    tx(&txid(1), op_return(set.update_hash), ANNOUNCED_AT),
                    dust.clone(),
                ],
            );

            let outcome = set
                .capture()
                .expect("dust above the tip does not block a capture");
            assert_eq!(outcome.tip_height, RECORDED_TIP);
            assert_eq!(outcome.signals, 1);
            let written = set.written();
            assert_eq!(written["tip_height"], json!(RECORDED_TIP));
            assert!(
                written["addresses"][&set.beacon]
                    .as_array()
                    .expect("the beacon body")
                    .contains(&dust),
                "the dust transaction is recorded as the chain served it"
            );
            let replayed = set.replay();
            assert_eq!(replayed.document_metadata.version_id.get(), 2);
            assert_eq!(replayed.document_metadata.confirmations, Some(11));
            set.cleanup();
        }

        #[test]
        fn captures_a_negative_set_whose_resolve_fails_with_a_coded_error() {
            let set = ScratchSet::new(Network::Signet, "signet", "negative");
            set.make_negative();
            assert!(matches!(
                set.target().expected,
                ExpectedOutcome::Error { .. }
            ));

            let outcome = set
                .capture()
                .expect("a coded failure captures a negative set");
            assert_eq!(outcome.tip_height, RECORDED_TIP);
            assert_eq!(outcome.signals, 1);
            assert_eq!(outcome.confirmations.observed, None);
            let written = set.written();
            assert_eq!(written["tip_height"], json!(RECORDED_TIP));
            assert!(written.get("expected").is_none() && written.get("sidecar").is_none());
            set.cleanup();
        }

        #[test]
        fn captures_a_set_without_signals_through_the_sidecar_gate_at_the_live_tip() {
            let set = ScratchSet::new(Network::Signet, "signet", "no-signals");
            let mut target = set.target();
            target.signals = None;
            target.expected = ExpectedOutcome::Resolved {
                document: set.expected_document.clone(),
                version_id: 2,
                deactivated: false,
                confirmations: Some(u64::from(LIVE_TIP - ANNOUNCED_AT + 1)),
            };

            let outcome = capture_one_with(
                &target,
                BASE,
                set.indexer.clone(),
                set.clock.clone(),
                &set.out_root,
            )
            .expect("a set without a record captures through the sidecar gate");
            assert_eq!(outcome.tip_height, LIVE_TIP, "the recorder's tip is pinned");
            assert_eq!(set.written()["tip_height"], json!(LIVE_TIP));

            // The sidecar gate, not the record, judges this row: a sidecar
            // update the chain never announced is refused as a missing signal.
            set.indexer.history(&set.beacon, Vec::new());
            target.expected = ExpectedOutcome::Resolved {
                document: set.genesis_document.clone(),
                version_id: 1,
                deactivated: false,
                confirmations: None,
            };
            let error = capture_one_with(
                &target,
                BASE,
                set.indexer.clone(),
                set.clock.clone(),
                &set.out_root,
            )
            .expect_err("an unannounced sidecar update is refused");
            assert!(
                matches!(
                    error,
                    CaptureError::Validation(ValidateError::MissingSignal { .. })
                ),
                "got: {error}"
            );
            set.cleanup();
        }
    }
}
