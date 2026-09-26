//! Which vendor vectors this tool captures chain data for, and what each one
//! expects.
//!
//! Four things live here: the target set (with the derivation that produced it,
//! plus a test that re-derives it from the tree), the per-vector loader that
//! reads a vector's DID, sidecar and expected resolve output from its own files,
//! the explicit-root loader for sets that carry a `signals.json` record
//! ([`load_in`]), and the endpoint rule that maps a chain name onto an Esplora
//! base URL.

use did_btcr2::identifier::{Did, Network};
use did_btcr2_client::resolve_base_url;
use onlyerror::Error;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

/// The seven vendor vectors this tool drives on-chain.
///
/// Derived, not chosen: eleven vectors resolve to version 2 or later and ship no
/// `pending.json`, and four of them declare a CAS or Sparse Merkle Tree beacon in
/// their genesis document, which the resolver rejects as unsupported before it
/// reads a single transaction. Capturing their chain data would put bytes in the
/// tree that no test reads.
///
/// Written out as an allow-list rather than re-derived at runtime because the
/// core crate's vector-classification machinery is test-only and unreachable from
/// here: a runtime re-derivation would be a SECOND independent implementation of
/// the same rules, able to drift in two directions instead of one. The derivation
/// instead lives in `drivable_set_matches_the_tree` below, which recomputes both
/// lists from the vector files and fails if they disagree — the drift check
/// without the duplicate control flow.
pub const DRIVABLE_VECTORS: &[&str] = &[
    "mutinynet/k1/q5p6w9su",
    "mutinynet/k1/q5pgeu9z",
    "mutinynet/x1/q5ugrf3w",
    "regtest/k1/qgppexmy",
    "regtest/k1/qgpy0hmm",
    "regtest/x1/q26jeds9",
    "regtest/x1/qfl7se8f",
];

/// The four vectors foreclosed by a non-Singleton beacon, with the blocker named
/// so asking for one of them says why instead of failing on a missing file.
pub const UNSUPPORTED_BEACON_VECTORS: &[&str] = &[
    "mutinynet/x1/q425c5wf",
    "mutinynet/x1/q550pp4e",
    "mutinynet/x1/q5cfewep",
    "mutinynet/x1/qkrrp544",
];

/// Genesis beacon service types the resolver cannot query, so a set declaring
/// one of them is out of scope for capture.
///
/// Read at runtime only by [`load_in`], which has no allow-list to consult; the
/// allow-list path uses the same list in `drivable_set_matches_the_tree` to
/// re-derive its constants from the tree.
const UNSUPPORTED_BEACON_TYPES: &[&str] = &["CASBeacon", "SMTBeacon"];

/// Target-layer failures. Every message names the vector it is about, including
/// the network segment, so an operator reading a capture log knows which row
/// failed without cross-referencing.
#[derive(Debug, Error)]
pub enum TargetError {
    /// The vector declares a CAS or SMT beacon in its genesis document.
    #[error(
        "{0}: declares a CAS or SMT beacon, which the resolver cannot query yet — capturing its transactions would put bytes in the tree no test reads"
    )]
    UnsupportedBeacon(String),

    /// The id is not one this tool captures. Checked before any path is built,
    /// so an operator-supplied `--vector` is never a free-form path.
    #[error(
        "{vector}: not a vector this tool captures. The drivable set is: {drivable}. Capture is scoped to what the resolver can replay"
    )]
    NotDrivable {
        /// The rejected id, verbatim.
        vector: String,
        /// The drivable ids, comma-separated.
        drivable: String,
    },

    /// An id handed to [`load_in`] is not shaped like a set id. Checked before
    /// any path is built, so the id is never a free-form path under the root.
    #[error(
        "{vector}: is not a set id of the form `<network>/<k1|x1>/<id>` (lowercase letters and digits in the last segment); pass the id as it appears under the suite root"
    )]
    InvalidVectorId {
        /// The rejected id, verbatim.
        vector: String,
    },

    /// A set loaded from an explicit suite root ships no `signals.json`.
    #[error(
        "{vector}: ships no signals.json, and an explicit suite root captures only sets that carry signals.json — capture a set without one through the default test-suite tree"
    )]
    NoSignals {
        /// The set that ships no `signals.json`.
        vector: String,
    },

    /// A fixture the vector must ship could not be read.
    #[error(
        "{vector}: could not read {path} — run `git submodule update --init --recursive` if the test-suite submodule is absent, or check whether the vector was renamed upstream"
    )]
    MissingFixture {
        /// The vector whose fixture is missing.
        vector: String,
        /// The path that was attempted.
        path: String,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// A fixture is present but is not valid JSON.
    #[error("{vector}: {path} is not valid JSON")]
    UnparseableFixture {
        /// The vector whose fixture is malformed.
        vector: String,
        /// The path that failed to parse.
        path: String,
        /// The underlying parse failure.
        #[source]
        source: serde_json::Error,
    },

    /// A fixture parses as JSON but does not carry a field this tool needs, or
    /// carries it in a shape that cannot be read.
    #[error("{vector}: {path} is unusable: {detail}")]
    MalformedFixture {
        /// The vector whose fixture is unusable.
        vector: String,
        /// The path that is unusable.
        path: String,
        /// What is wrong, and what was expected instead.
        detail: String,
    },

    /// The vector's `did` field is not a valid `did:btcr2` identifier.
    #[error("{vector}: `{did}` is not a valid did:btcr2 identifier")]
    Identifier {
        /// The vector carrying the bad identifier.
        vector: String,
        /// The identifier, verbatim.
        did: String,
        /// The underlying parse failure.
        #[source]
        source: did_btcr2::identifier::Error,
    },

    /// A network name this crate does not model.
    #[error(
        "unknown network `{0}`: expected mainnet, signet, regtest, mutinynet, testnet, testnet3 or testnet4"
    )]
    UnknownNetwork(String),

    /// No Esplora base URL could be resolved for a network.
    ///
    /// Carries the underlying rule's own error as its source, so the distinction
    /// between "recognized chain with no hosted endpoint" and "name the endpoint
    /// table does not know" survives to the operator.
    #[error(
        "{network}: no Esplora endpoint could be resolved — pass --esplora-url with the base URL of an endpoint serving this chain"
    )]
    Endpoint {
        /// The network that could not be resolved.
        network: String,
        /// The endpoint rule's own error.
        #[source]
        source: did_btcr2_client::Error,
    },

    /// The Esplora base URL carries something that must not be recorded.
    ///
    /// Names the FLAG and the part that is unusable, never the URL: the whole
    /// point is that the value may be a credential.
    #[error(
        "--esplora-url carries {part}, and every capture and minting session records its base URL verbatim into a fixture this repository commits and into the state file beside it — so a credential in the endpoint would be published. Pass the base URL alone (scheme, host, port and path) and supply the credential another way, such as a local proxy that adds it"
    )]
    CredentialInEndpoint {
        /// Which part is unusable: `a userinfo component` or `a query string`.
        part: &'static str,
    },
}

/// Absolute path of the nested `test-suite/` submodule.
///
/// Derived from the crate manifest directory, which is fixed at compile time, so
/// this is stable regardless of the directory the tool is invoked from.
pub fn test_suite_root() -> PathBuf {
    PathBuf::from(format!("{}/../../test-suite", env!("CARGO_MANIFEST_DIR")))
}

/// The network directories a vector tree may hold.
#[cfg(test)]
const SUITE_NETWORK_DIRS: [&str; 4] = ["regtest", "mutinynet", "signet", "testnet4"];

/// True iff `root` holds at least one set directory: some network directory
/// with a `k1` or `x1` directory that has a subdirectory of its own.
///
/// Content-based on purpose. A probe on one named set would turn every
/// corpus-reading test into a silent skip the moment that set is renamed or
/// dropped; this one only answers "is a corpus checked out", so a present
/// corpus that lacks the set a test reads makes that test fail.
#[cfg(test)]
pub(crate) fn test_suite_present_in(root: &Path) -> bool {
    SUITE_NETWORK_DIRS.iter().any(|network| {
        ["k1", "x1"].iter().any(|kind| {
            std::fs::read_dir(root.join(network).join(kind)).is_ok_and(|entries| {
                entries
                    .filter_map(Result::ok)
                    .any(|entry| entry.path().is_dir())
            })
        })
    })
}

/// [`test_suite_present_in`] over the real submodule, printing the skip line
/// when it is absent. A non-recursive clone leaves the submodule empty; every
/// test that reads it calls this first and skips green in that case only.
#[cfg(test)]
pub(crate) fn test_suite_present() -> bool {
    if test_suite_present_in(&test_suite_root()) {
        return true;
    }
    eprintln!(
        "SKIP: test-suite submodule absent; \
         run `git submodule update --init --recursive` to enable"
    );
    false
}

/// Map a `test-suite/` network directory name onto a [`Network`].
///
/// Nothing is defaulted: an unrecognized name is a typed error naming the value,
/// because this is operator-facing tooling where a mistyped chain must stop the
/// run rather than quietly capture a different one.
pub fn network_from_dir(name: &str) -> Result<Network, TargetError> {
    match name {
        "mainnet" => Ok(Network::Mainnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        "mutinynet" => Ok(Network::Mutinynet),
        "testnet" | "testnet3" => Ok(Network::TestnetV3),
        "testnet4" => Ok(Network::TestnetV4),
        other => Err(TargetError::UnknownNetwork(other.to_string())),
    }
}

/// Require `id` to be a set id: exactly `{network}/{k1|x1}/{short}`, where
/// `network` is a name [`network_from_dir`] knows and `short` is non-empty
/// lowercase letters and digits.
///
/// A whitelist of the shape, not a blacklist of dangerous characters: nothing
/// that passes can be absolute, climb out of the root with `..`, or reach a
/// deeper directory than a set's own.
fn check_vector_id(id: &str) -> Result<(), TargetError> {
    let invalid = || TargetError::InvalidVectorId {
        vector: id.to_string(),
    };
    let segments: Vec<&str> = id.split('/').collect();
    let [network, kind, short] = segments[..] else {
        return Err(invalid());
    };
    network_from_dir(network).map_err(|_| invalid())?;
    if kind != "k1" && kind != "x1" {
        return Err(invalid());
    }
    if short.is_empty()
        || !short
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(invalid());
    }
    Ok(())
}

/// Resolve the Esplora base URL for a network, honouring an operator override.
///
/// A thin wrapper over the client's own endpoint rule so every chain this tool
/// runs against goes through ONE rule set: `mutinynet`, `signet` and `testnet4`
/// resolve their hosted endpoints, while `regtest` has none and requires
/// `--esplora-url`. There is deliberately no fallback — a fallback would
/// silently capture a different chain than the operator named.
/// The resolved URL is then checked for anything that must not be recorded (see
/// [`reject_credential_in_endpoint`]).
pub fn endpoint(network: &str, override_url: Option<String>) -> Result<String, TargetError> {
    let url =
        resolve_base_url(Some(network), override_url).map_err(|source| TargetError::Endpoint {
            network: network.to_string(),
            source,
        })?;
    reject_credential_in_endpoint(&url)?;
    Ok(url)
}

/// Refuse a base URL that carries a credential.
///
/// `resolve_base_url` returns an operator's `--esplora-url` verbatim — only a
/// trailing slash is trimmed — and both sessions RECORD that value: a capture
/// writes it into `endpoint` in a fixture this repository commits, and a minting
/// session writes it there and into the state file. The fixture field's own
/// documentation says no credential ever belongs in a committed fixture, and
/// nothing enforced it. An endpoint of the form `https://user:token@host/api` or
/// `https://host/api?apikey=…` would publish that credential into git.
///
/// Refused rather than quietly stripped, so an operator who passed a credential
/// learns it was in scope instead of watching the endpoint answer 401. Refused
/// here, before a single request goes out, rather than at the write: a capture
/// taken against an endpoint whose URL could not be recorded anyway is a session
/// spent for nothing.
fn reject_credential_in_endpoint(url: &str) -> Result<(), TargetError> {
    // Hand-parsed rather than through a URI type: only two components matter,
    // and the check must not depend on a parser accepting the whole URL — an
    // endpoint this rejected for being unparseable would be one an operator
    // could not diagnose from the message, which names no part of the value.
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    if after_scheme[..authority_end].contains('@') {
        return Err(TargetError::CredentialInEndpoint {
            part: "a userinfo component",
        });
    }
    if after_scheme[authority_end..].contains('?') {
        return Err(TargetError::CredentialInEndpoint {
            part: "a query string",
        });
    }
    Ok(())
}

/// One vector's capture target: what to resolve, what to resolve it with, and
/// what the result must be.
#[derive(Debug, Clone)]
pub struct VectorTarget {
    /// The vector id, e.g. `regtest/k1/qgppexmy`.
    pub id: String,
    /// The leading path segment, e.g. `regtest`.
    pub network_dir: String,
    /// The chain that segment names.
    pub network: Network,
    /// The DID the vector resolves.
    pub did: Did,
    /// `resolve/input.json`'s `resolutionOptions.sidecar`, verbatim.
    pub sidecar: Value,
    /// What `resolve/output.json` says the resolve produces.
    pub expected: ExpectedOutcome,
    /// The set's `signals.json`, when it ships one.
    pub signals: Option<CaptureSignals>,
}

/// What a set's `resolve/output.json` says resolving its DID produces.
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedOutcome {
    /// The resolve succeeds with this document and metadata.
    Resolved {
        /// `didDocument`.
        document: Value,
        /// `didDocumentMetadata.versionId`, read tolerantly (see [`version_id`]).
        version_id: u64,
        /// `didDocumentMetadata.deactivated`.
        deactivated: bool,
        /// `didDocumentMetadata.confirmations`, `None` when the set states none.
        confirmations: Option<u64>,
    },
    /// The resolve fails; `didResolutionMetadata.error` names the code.
    Error {
        /// The error code the set records, verbatim.
        code: String,
    },
}

impl ExpectedOutcome {
    /// The confirmations the set states, `None` for a set that states none or
    /// expects an error.
    pub fn confirmations(&self) -> Option<u64> {
        match self {
            Self::Resolved { confirmations, .. } => *confirmations,
            Self::Error { .. } => None,
        }
    }
}

/// One entry of a set's `signals.json`: a Beacon Signal the set records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalRecord {
    /// The 1-based update step the signal announces, `None` for a cohort
    /// member whose share of an aggregated signal carries no update of its own.
    pub update: Option<u64>,
    /// A later announcement of an update an earlier entry already announced.
    pub duplicate: bool,
    /// The beacon address the signal belongs to.
    pub address: String,
    /// The signalling transaction, lowercase hex.
    pub txid: String,
    /// The height of the block confirming it.
    pub block_height: u32,
    /// The hash of that block, lowercase hex.
    pub block_hash: String,
    /// The 32 bytes the transaction's last output pushes.
    pub signal_bytes: [u8; 32],
    /// The chain tip the set's expected outputs were recorded against.
    pub recorded_tip: u32,
    /// The cohort's `id`, when the signal is aggregated.
    pub cohort: Option<String>,
}

/// A set's `signals.json`: the upstream record of every Beacon Signal of the
/// set, and the tip its expected outputs were recorded against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSignals {
    /// The `recordedTip` every entry agrees on.
    pub recorded_tip: u32,
    /// The entries, in file order.
    pub entries: Vec<SignalRecord>,
}

/// The wire shape of one `signals.json` entry, before its rules are checked.
///
/// Only the members this tool reads; members upstream adds later are ignored
/// rather than rejected, because the file is extended additively.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSignalEntry {
    #[serde(default)]
    update: Option<u64>,
    #[serde(default)]
    duplicate: bool,
    address: String,
    txid: String,
    block_height: u32,
    block_hash: String,
    signal_bytes: String,
    recorded_tip: u32,
    #[serde(default)]
    cohort: Option<RawCohort>,
}

/// The part of a `cohort` member this tool reads.
#[derive(serde::Deserialize)]
struct RawCohort {
    id: String,
}

/// Load one vector's capture target from its own files.
///
/// The id is matched against the allow-lists BEFORE any path is built, so an
/// operator-supplied id is never joined onto the fixture root as a free-form
/// path.
pub fn load(id: &str) -> Result<VectorTarget, TargetError> {
    load_from(&test_suite_root(), id)
}

/// [`load`]'s body against an explicit root, so the missing-fixture path is
/// testable without mutating the repository's vector tree.
fn load_from(root: &Path, id: &str) -> Result<VectorTarget, TargetError> {
    if UNSUPPORTED_BEACON_VECTORS.contains(&id) {
        return Err(TargetError::UnsupportedBeacon(id.to_string()));
    }
    if !DRIVABLE_VECTORS.contains(&id) {
        return Err(TargetError::NotDrivable {
            vector: id.to_string(),
            drivable: DRIVABLE_VECTORS.join(", "),
        });
    }

    let network_dir = id
        .split('/')
        .next()
        .expect("`str::split` always yields at least one segment")
        .to_string();
    let network = network_from_dir(&network_dir)?;

    let input_path = root.join(id).join("resolve/input.json");
    let output_path = root.join(id).join("resolve/output.json");
    let input = read_json(id, &input_path)?;
    let output = read_json(id, &output_path)?;

    let did_str = input["did"].as_str().ok_or_else(|| {
        malformed(
            id,
            &input_path,
            "no `did` string at the top level; a resolve vector must name the DID it resolves",
        )
    })?;
    let did = Did::from_str(did_str).map_err(|source| TargetError::Identifier {
        vector: id.to_string(),
        did: did_str.to_string(),
        source,
    })?;

    refuse_target_options(id, &input_path, &input)?;

    // Every drivable vector ships a sidecar object (several non-drivable ones do
    // not — they omit `resolutionOptions.sidecar` entirely). Treating an absent
    // sidecar as an empty one would let a capture validate against zero updates
    // and pass vacuously, which is exactly the failure the capture gate exists to
    // prevent, so an absent sidecar is an error here.
    let sidecar = input["resolutionOptions"]["sidecar"].clone();
    if !sidecar.is_object() {
        return Err(malformed(
            id,
            &input_path,
            "no `resolutionOptions.sidecar` object; every vector this tool captures \
             supplies its updates out of band",
        ));
    }

    let expected = resolved_outcome(id, &output_path, &output)?;

    // An allow-listed vector that later ships a signals.json is captured
    // through the signals gate like any other set that carries one.
    let signals_path = root.join(id).join("signals.json");
    let signals = if signals_path.exists() {
        Some(parse_signals(
            id,
            &signals_path,
            &read_json(id, &signals_path)?,
        )?)
    } else {
        None
    };

    Ok(VectorTarget {
        id: id.to_string(),
        network_dir,
        network,
        did,
        sidecar,
        expected,
        signals,
    })
}

/// Load one set from an explicit suite root.
///
/// The path for regenerated-layout sets, which the allow-list does not name:
/// the id is shape-checked instead ([`check_vector_id`]) before any path is
/// built, and only a set that ships `signals.json` is accepted, because that
/// record is what the capture gate compares the chain with.
///
/// Refusals, in order: a malformed id; no `signals.json`; a `signals.json` that
/// breaks its shape rules; a set that is out of scope because it aggregates its
/// signals in a cohort or declares a CAS or SMT genesis beacon. The cohort
/// refusal comes before the duplicate rule and before anything looks for an
/// `update/` directory, so a cohort-only set — no `update/`, no `update` member
/// on any entry — is reported as unsupported rather than malformed.
///
/// Unlike [`load`], a set may carry no sidecar (read as `{}`), a sidecar
/// without `updates`, and an expected error rather than a resolved document.
/// The core crate's replay reads an absent sidecar on a set with
/// `signals.json` as `{}` too. Like [`load`], a main input carrying
/// `versionId`, `versionTime` or `minConf` is refused.
pub fn load_in(suite_root: &Path, id: &str) -> Result<VectorTarget, TargetError> {
    check_vector_id(id)?;
    let network_dir = id
        .split('/')
        .next()
        .expect("`check_vector_id` accepted exactly three segments")
        .to_string();
    let network = network_from_dir(&network_dir)?;
    let set_dir = suite_root.join(id);

    let signals_path = set_dir.join("signals.json");
    if !signals_path.is_file() {
        return Err(TargetError::NoSignals {
            vector: id.to_string(),
        });
    }
    let signals = parse_signals(id, &signals_path, &read_json(id, &signals_path)?)?;

    let input_path = set_dir.join("resolve/input.json");
    let output_path = set_dir.join("resolve/output.json");
    let input = read_json(id, &input_path)?;
    let output = read_json(id, &output_path)?;
    let other_path = set_dir.join("other.json");
    let other = if other_path.exists() {
        read_json(id, &other_path)?
    } else {
        Value::Null
    };

    let did_str = input["did"].as_str().ok_or_else(|| {
        malformed(
            id,
            &input_path,
            "no `did` string at the top level; a resolve vector must name the DID it resolves",
        )
    })?;
    let did = Did::from_str(did_str).map_err(|source| TargetError::Identifier {
        vector: id.to_string(),
        did: did_str.to_string(),
        source,
    })?;

    refuse_target_options(id, &input_path, &input)?;

    // A set whose update is delivered some other way, or withheld on purpose,
    // carries no sidecar or one without `updates`; the gate for these sets is
    // the signals record, not the sidecar, so an empty sidecar is not vacuous.
    let sidecar = match &input["resolutionOptions"]["sidecar"] {
        Value::Null => Value::Object(serde_json::Map::new()),
        object @ Value::Object(_) => object.clone(),
        other => {
            return Err(malformed(
                id,
                &input_path,
                &format!("`resolutionOptions.sidecar` is `{other}`, expected an object"),
            ));
        }
    };

    // The genesis document of an x1 set lives in other.json or in the sidecar;
    // a k1 set's is generated from its key and carries Singleton beacons only.
    for genesis in [&other["genesisDocument"], &sidecar["genesisDocument"]] {
        let declares_unsupported = genesis["service"].as_array().is_some_and(|services| {
            services.iter().any(|service| {
                service["type"]
                    .as_str()
                    .is_some_and(|t| UNSUPPORTED_BEACON_TYPES.contains(&t))
            })
        });
        if declares_unsupported {
            return Err(TargetError::UnsupportedBeacon(id.to_string()));
        }
    }

    let expected = match &output["didResolutionMetadata"]["error"] {
        Value::Null => resolved_outcome(id, &output_path, &output)?,
        Value::String(code) => ExpectedOutcome::Error { code: code.clone() },
        other => {
            return Err(malformed(
                id,
                &output_path,
                &format!("`didResolutionMetadata.error` is `{other}`, expected an error code"),
            ));
        }
    };

    Ok(VectorTarget {
        id: id.to_string(),
        network_dir,
        network,
        did,
        sidecar,
        expected,
        signals: Some(signals),
    })
}

/// Read a positive `resolve/output.json`: its document, versionId, deactivated
/// flag and confirmations.
fn resolved_outcome(
    vector: &str,
    path: &Path,
    output: &Value,
) -> Result<ExpectedOutcome, TargetError> {
    let document = output["didDocument"].clone();
    if !document.is_object() {
        return Err(malformed(
            vector,
            path,
            "no `didDocument` object; a resolve vector must state the document it expects",
        ));
    }

    let metadata = &output["didDocumentMetadata"];
    let version_id = version_id(vector, path, &metadata["versionId"])?;
    let deactivated = metadata["deactivated"]
        .as_bool()
        .ok_or_else(|| malformed(vector, path, "no `didDocumentMetadata.deactivated` boolean"))?;
    let confirmations = confirmations(vector, path, &metadata["confirmations"])?;
    Ok(ExpectedOutcome::Resolved {
        document,
        version_id,
        deactivated,
        confirmations,
    })
}

/// True for 64 lowercase hex characters: a txid, a block hash, 32 signal bytes.
fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse and check a set's `signals.json`.
///
/// A second reader of the file the core crate's test harness parses — by
/// necessity, since that parser is test-only and unreachable from here — so the
/// two apply the same rules and both follow the upstream shape; unknown members
/// are ignored, not rejected. The rules:
///
/// - the file is a bare array of at least one entry, all agreeing on
///   `recordedTip`;
/// - `txid`, `blockHash` and `signalBytes` are 64 lowercase hex, and no two
///   entries share a `txid` (the gate would otherwise report the second as a
///   signal not on chain, pointing at the chain instead of the file);
/// - `update` is optional, but an entry without it must carry `cohort`, and
///   `duplicate` on an entry without `update` is malformed;
/// - an entry carrying a cohort is refused as unsupported (an aggregated signal
///   is a CAS or SMT beacon's), before the duplicate rule can fire;
/// - duplicates are keyed on `update`, never on `signalBytes`: an entry repeating
///   an earlier entry's `update` needs `duplicate: true`, the same
///   `signalBytes` and a strictly higher `blockHeight`, and `duplicate: true` on
///   a first announcement is malformed.
fn parse_signals(vector: &str, path: &Path, raw: &Value) -> Result<CaptureSignals, TargetError> {
    let bad = |detail: String| malformed(vector, path, &detail);

    let array = raw.as_array().ok_or_else(|| {
        bad("signals.json must be a bare array of signal entries, not an object or a scalar".into())
    })?;
    if array.is_empty() {
        return Err(bad(
            "signals.json holds no entry, so it records no recordedTip — a set with no Beacon \
             Signal ships no signals.json"
                .into(),
        ));
    }

    let mut entries = Vec::with_capacity(array.len());
    let mut first_txid: BTreeMap<String, usize> = BTreeMap::new();
    for (index, raw_entry) in array.iter().enumerate() {
        let entry: RawSignalEntry = serde_json::from_value(raw_entry.clone())
            .map_err(|e| bad(format!("entry {index} is not a signal entry ({e})")))?;
        for (member, value) in [
            ("txid", &entry.txid),
            ("blockHash", &entry.block_hash),
            ("signalBytes", &entry.signal_bytes),
        ] {
            if !is_hex64(value) {
                return Err(bad(format!(
                    "entry {index} {member} must be 64 lowercase hex characters, got {value:?}"
                )));
            }
        }
        if let Some(first) = first_txid.insert(entry.txid.clone(), index) {
            return Err(bad(format!(
                "entries {first} and {index} both record transaction {} — one transaction \
                 carries one Beacon Signal, so it has one entry; a repeated announcement is a \
                 later transaction",
                entry.txid
            )));
        }
        if entry.update.is_none() {
            if entry.cohort.is_none() {
                return Err(bad(format!(
                    "entry {index} carries neither `update` nor `cohort` — an entry announcing \
                     no update step of this set must name the cohort it shares a signal with"
                )));
            }
            if entry.duplicate {
                return Err(bad(format!(
                    "entry {index} sets `duplicate` but carries no `update` — only a repeated \
                     announcement of an update step can be a duplicate"
                )));
            }
        }
        let mut signal_bytes = [0u8; 32];
        hex::decode_to_slice(&entry.signal_bytes, &mut signal_bytes)
            .expect("64 lowercase hex characters decode to 32 bytes");
        entries.push(SignalRecord {
            update: entry.update,
            duplicate: entry.duplicate,
            address: entry.address,
            txid: entry.txid,
            block_height: entry.block_height,
            block_hash: entry.block_hash,
            signal_bytes,
            recorded_tip: entry.recorded_tip,
            cohort: entry.cohort.map(|c| c.id),
        });
    }

    let recorded_tip = entries[0].recorded_tip;
    if let Some((index, entry)) = entries
        .iter()
        .enumerate()
        .find(|(_, e)| e.recorded_tip != recorded_tip)
    {
        return Err(bad(format!(
            "entry {index} records recordedTip {} but entry 0 records {recorded_tip} — every \
             entry of one file is recorded against the same tip",
            entry.recorded_tip
        )));
    }

    if entries.iter().any(|e| e.cohort.is_some()) {
        return Err(TargetError::UnsupportedBeacon(vector.to_string()));
    }

    let mut first_announcement: BTreeMap<u64, usize> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(update) = entry.update else {
            continue;
        };
        match first_announcement.get(&update) {
            None => {
                if entry.duplicate {
                    return Err(bad(format!(
                        "entry {index} sets `duplicate` on the first announcement of update \
                         {update}"
                    )));
                }
                first_announcement.insert(update, index);
            }
            Some(&first) => {
                let original = &entries[first];
                if !entry.duplicate {
                    return Err(bad(format!(
                        "entry {index} announces update {update} again (entry {first} announced \
                         it first) without `duplicate: true`"
                    )));
                }
                if entry.signal_bytes != original.signal_bytes {
                    return Err(bad(format!(
                        "entry {index} is a duplicate of entry {first} but pushes signalBytes \
                         {} instead of {}",
                        hex::encode(entry.signal_bytes),
                        hex::encode(original.signal_bytes)
                    )));
                }
                if entry.block_height <= original.block_height {
                    return Err(bad(format!(
                        "entry {index} is a duplicate of entry {first} at blockHeight {}, not \
                         above the first announcement's {}",
                        entry.block_height, original.block_height
                    )));
                }
            }
        }
    }

    Ok(CaptureSignals {
        recorded_tip,
        entries,
    })
}

/// Every drivable target filed under `network_dir`, in [`DRIVABLE_VECTORS`]
/// order.
pub fn load_all(network_dir: &str) -> Result<Vec<VectorTarget>, TargetError> {
    DRIVABLE_VECTORS
        .iter()
        .filter(|id| id.split('/').next() == Some(network_dir))
        .map(|id| load(id))
        .collect()
}

/// Read a vector fixture as JSON, distinguishing "not there" from "there and
/// unusable".
fn read_json(vector: &str, path: &Path) -> Result<Value, TargetError> {
    let raw = std::fs::read_to_string(path).map_err(|source| TargetError::MissingFixture {
        vector: vector.to_string(),
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| TargetError::UnparseableFixture {
        vector: vector.to_string(),
        path: path.display().to_string(),
        source,
    })
}

/// A [`TargetError::MalformedFixture`] naming the vector, the file and the fault.
fn malformed(vector: &str, path: &Path, detail: &str) -> TargetError {
    TargetError::MalformedFixture {
        vector: vector.to_string(),
        path: path.display().to_string(),
        detail: detail.to_string(),
    }
}

/// The resolution options a main resolve input may not carry here: a target
/// condition and a confirmation depth.
const TARGET_OPTIONS: [&str; 3] = ["versionId", "versionTime", "minConf"];

/// Refuse a main resolve input that asks for a target condition or a
/// confirmation depth, because this tool cannot yet capture such a resolve.
///
/// Capture resolves the main pair with its sidecar and the pinned tip and
/// nothing else ([`crate::capture::resolution_options_for`]). The core crate's
/// replay honours `versionId`, `versionTime` and `minConf` wherever an input
/// carries them, so a main input carrying one would have capture validate a
/// different resolve from the one replay runs, and the refuse-to-write gate
/// could refuse a valid set or bless a recording of another walk. This is a
/// limitation of the capture, not a defect in the set: capturing it needs
/// this tool extended to resolve with the input's options.
fn refuse_target_options(vector: &str, path: &Path, input: &Value) -> Result<(), TargetError> {
    match TARGET_OPTIONS
        .into_iter()
        .find(|option| !input["resolutionOptions"][*option].is_null())
    {
        None => Ok(()),
        Some(option) => Err(malformed(
            vector,
            path,
            &format!(
                "the main resolve input sets `resolutionOptions.{option}`; this tool does not \
                 yet capture a main resolve with a target option — it resolves the main pair \
                 with only its sidecar and the recorded tip, so a capture would validate a \
                 different resolve from the one the suite replays. Capturing such a set needs \
                 this tool extended to resolve with the input's options."
            ),
        )),
    }
}

/// Read a `versionId` tolerantly.
///
/// The spec's wire shape is a string, and the regtest vectors encode it that way;
/// the mutinynet vectors encode it as a JSON number. This tool reads both and
/// normalizes NEITHER file: a fixture is evidence of what a chain was told, and
/// rewriting it here would hide an encoding disagreement that belongs upstream.
fn version_id(vector: &str, path: &Path, value: &Value) -> Result<u64, TargetError> {
    match value {
        Value::String(s) => s.parse::<u64>().map_err(|e| {
            malformed(
                vector,
                path,
                &format!("`didDocumentMetadata.versionId` is `{s}`, not a number ({e})"),
            )
        }),
        Value::Number(n) => n.as_u64().ok_or_else(|| {
            malformed(
                vector,
                path,
                &format!("`didDocumentMetadata.versionId` is `{n}`, not a non-negative integer"),
            )
        }),
        other => Err(malformed(
            vector,
            path,
            &format!("`didDocumentMetadata.versionId` is `{other}`, expected a string or a number"),
        )),
    }
}

/// Read a `confirmations` value: absent or null means the vector states none.
///
/// A present-but-unreadable value is an error rather than a silent `None`, which
/// would turn a malformed expectation into a skipped check.
fn confirmations(vector: &str, path: &Path, value: &Value) -> Result<Option<u64>, TargetError> {
    match value {
        Value::Null => Ok(None),
        Value::Number(n) => n.as_u64().map(Some).ok_or_else(|| {
            malformed(
                vector,
                path,
                &format!(
                    "`didDocumentMetadata.confirmations` is `{n}`, not a non-negative integer"
                ),
            )
        }),
        other => Err(malformed(
            vector,
            path,
            &format!("`didDocumentMetadata.confirmations` is `{other}`, expected a number or null"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_btcr2::document::{InitialDocument, ResolutionOptions};
    use std::collections::BTreeSet;

    /// The resolved expectation's fields, for the assertions written before the
    /// outcome could be an expected error.
    impl VectorTarget {
        fn resolved(&self) -> (&Value, u64, bool, Option<u64>) {
            match &self.expected {
                ExpectedOutcome::Resolved {
                    document,
                    version_id,
                    deactivated,
                    confirmations,
                } => (document, *version_id, *deactivated, *confirmations),
                ExpectedOutcome::Error { code } => {
                    panic!("{}: expects the error {code}, not a resolution", self.id)
                }
            }
        }
        fn expected_document(&self) -> &Value {
            self.resolved().0
        }
        fn expected_version_id(&self) -> u64 {
            self.resolved().1
        }
        fn expected_deactivated(&self) -> bool {
            self.resolved().2
        }
        fn expected_confirmations(&self) -> Option<u64> {
            self.resolved().3
        }
    }

    /// Sorted names of `dir`'s child directories, dot entries excluded. An absent
    /// directory yields nothing; an unreadable one panics, because a directory
    /// that silently disappears would shrink the recomputed set and let the drift
    /// check pass on a tree it never saw.
    fn child_dirs(dir: &Path) -> Vec<String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => panic!("{}: could not be read ({e})", dir.display()),
        };
        let mut names: Vec<String> = entries
            .map(|entry| entry.unwrap_or_else(|e| panic!("{}: {e}", dir.display())))
            .filter(|entry| entry.path().is_dir())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    /// The beacon service types declared in a vector's GENESIS document — the
    /// document as it stood at version 1, which is what the resolver reads before
    /// it asks for any transaction.
    ///
    /// The two id types keep their genesis document in different places, so this
    /// is two branches on purpose:
    ///
    /// - `k1`: nothing on disk holds it. The genesis document is generated
    ///   deterministically from the key in the identifier, so it is generated
    ///   here the same way, through the core crate. A generated document that
    ///   ever grew a non-Singleton beacon would show up here rather than being
    ///   assumed away.
    /// - `x1`: the genesis document is supplied out of band, so it is read from
    ///   the vector's sidecar (or from `other.json`, where some vectors keep it).
    fn genesis_beacon_types(root: &Path, id: &str, kind: &str) -> Vec<String> {
        let types = |doc: &Value| -> Vec<String> {
            let found: Vec<String> = doc["service"]
                .as_array()
                .map(|services| {
                    services
                        .iter()
                        .filter_map(|s| s["type"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            // A genesis document with no readable beacon service would classify
            // every vector as drivable for want of a disqualifying type — the
            // check would pass without ever having looked at anything. Every
            // btcr2 genesis document declares at least one beacon, so an empty
            // list here means the document was not found where it was looked for.
            assert!(
                !found.is_empty(),
                "{id}: no beacon service types read from the genesis document — \
                 the classification would then be vacuous"
            );
            found
        };

        let input: Value = serde_json::from_str(
            &std::fs::read_to_string(root.join(id).join("resolve/input.json"))
                .unwrap_or_else(|e| panic!("{id}: resolve/input.json must be readable ({e})")),
        )
        .unwrap_or_else(|e| panic!("{id}: resolve/input.json must be valid JSON ({e})"));

        if kind == "k1" {
            let did_str = input["did"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: resolve/input.json must name a DID"));
            let did = Did::from_str(did_str)
                .unwrap_or_else(|e| panic!("{id}: `{did_str}` must parse as a DID ({e})"));
            let genesis = InitialDocument::from_did(&did, &ResolutionOptions::default())
                .unwrap_or_else(|e| panic!("{id}: genesis document must generate ({e})"));
            return types(genesis.as_ref());
        }

        let sidecar_genesis = &input["resolutionOptions"]["sidecar"]["genesisDocument"];
        if sidecar_genesis.is_object() {
            return types(sidecar_genesis);
        }
        let other: Value = serde_json::from_str(
            &std::fs::read_to_string(root.join(id).join("other.json"))
                .unwrap_or_else(|e| panic!("{id}: other.json must be readable ({e})")),
        )
        .unwrap_or_else(|e| panic!("{id}: other.json must be valid JSON ({e})"));
        let other_genesis = &other["genesisDocument"];
        assert!(
            other_genesis.is_object(),
            "{id}: no genesis document in resolve/input.json's sidecar or in other.json — \
             its beacon types cannot be classified, and guessing would silently widen or \
             narrow the capture set"
        );
        types(other_genesis)
    }

    /// Recompute both target lists from the vector tree and require them to match
    /// the constants above.
    ///
    /// This is the whole classification rule, stated in one place: a vector is in
    /// scope when its `resolve/output.json` versionId is greater than 1, it ships
    /// no `pending.json`, and no service in its genesis document declares a CAS or
    /// SMT beacon type; it is foreclosed when it meets the first two conditions
    /// and fails the third. Same versionId encoding tolerance as `load`. If this
    /// test fails, the tree gained or lost a vector and the constants need
    /// re-checking.
    #[test]
    fn drivable_set_matches_the_tree() {
        if !test_suite_present() {
            return;
        }
        let root = test_suite_root();
        let mut drivable = BTreeSet::new();
        let mut unsupported = BTreeSet::new();

        for network_dir in child_dirs(&root) {
            for kind in child_dirs(&root.join(&network_dir)) {
                for short_id in child_dirs(&root.join(&network_dir).join(&kind)) {
                    let id = format!("{network_dir}/{kind}/{short_id}");
                    let vector_dir = root.join(&id);
                    let output_path = vector_dir.join("resolve/output.json");
                    if !output_path.exists() {
                        continue;
                    }
                    let output: Value = serde_json::from_str(
                        &std::fs::read_to_string(&output_path)
                            .unwrap_or_else(|e| panic!("{id}: resolve/output.json ({e})")),
                    )
                    .unwrap_or_else(|e| panic!("{id}: resolve/output.json is not JSON ({e})"));

                    let version = version_id(
                        &id,
                        &output_path,
                        &output["didDocumentMetadata"]["versionId"],
                    )
                    .unwrap_or_else(|e| panic!("{e}"));
                    if version < 2 {
                        continue;
                    }
                    if vector_dir.join("pending.json").exists() {
                        continue;
                    }

                    let beacons = genesis_beacon_types(&root, &id, &kind);
                    if beacons
                        .iter()
                        .any(|t| UNSUPPORTED_BEACON_TYPES.contains(&t.as_str()))
                    {
                        unsupported.insert(id);
                    } else {
                        drivable.insert(id);
                    }
                }
            }
        }

        let expected_drivable: BTreeSet<String> =
            DRIVABLE_VECTORS.iter().map(|s| s.to_string()).collect();
        let expected_unsupported: BTreeSet<String> = UNSUPPORTED_BEACON_VECTORS
            .iter()
            .map(|s| s.to_string())
            .collect();

        assert_eq!(
            drivable, expected_drivable,
            "the drivable set re-derived from the tree does not match DRIVABLE_VECTORS.\n\
             re-derived: {drivable:?}\n  declared: {expected_drivable:?}"
        );
        assert_eq!(
            unsupported, expected_unsupported,
            "the foreclosed set re-derived from the tree does not match \
             UNSUPPORTED_BEACON_VECTORS.\nre-derived: {unsupported:?}\n  declared: \
             {expected_unsupported:?}"
        );
    }

    #[test]
    fn drivable_vectors_are_the_seven_ids_in_order() {
        assert_eq!(
            DRIVABLE_VECTORS,
            &[
                "mutinynet/k1/q5p6w9su",
                "mutinynet/k1/q5pgeu9z",
                "mutinynet/x1/q5ugrf3w",
                "regtest/k1/qgppexmy",
                "regtest/k1/qgpy0hmm",
                "regtest/x1/q26jeds9",
                "regtest/x1/qfl7se8f",
            ],
            "the target set is the seven vectors this phase drives, in tree order"
        );
        assert_eq!(UNSUPPORTED_BEACON_VECTORS.len(), 4);
        for id in UNSUPPORTED_BEACON_VECTORS {
            assert!(
                !DRIVABLE_VECTORS.contains(id),
                "{id} cannot be both drivable and foreclosed"
            );
        }
    }

    #[test]
    fn load_reads_a_regtest_target_from_its_own_files() {
        if !test_suite_present() {
            return;
        }
        let target = load("regtest/k1/qgppexmy").expect("a drivable regtest vector loads");

        assert_eq!(target.id, "regtest/k1/qgppexmy");
        assert_eq!(target.network_dir, "regtest");
        assert_eq!(target.network, Network::Regtest);
        assert!(
            target.did.encode().starts_with("did:btcr2:k1qgppexmy"),
            "the DID comes from the vector's own input.json, got {}",
            target.did.encode()
        );
        assert_eq!(
            target.sidecar["updates"]
                .as_array()
                .expect("the sidecar carries an updates array")
                .len(),
            1,
            "this vector announces exactly one update"
        );
        assert_eq!(target.expected_version_id(), 2);
        assert_eq!(target.expected_confirmations(), Some(93));
        assert!(!target.expected_deactivated());
        assert_eq!(
            target.expected_document()["id"],
            *target.did.encode(),
            "the expected document is the one the vector states"
        );
    }

    #[test]
    fn load_tolerates_a_number_encoded_version_id() {
        if !test_suite_present() {
            return;
        }
        let target = load("mutinynet/k1/q5p6w9su").expect("a drivable mutinynet vector loads");

        // This vector encodes `versionId` as a JSON number where the regtest
        // vectors encode it as a string; both must read as 2 without either file
        // being rewritten.
        let raw: Value = serde_json::from_str(
            &std::fs::read_to_string(
                test_suite_root().join("mutinynet/k1/q5p6w9su/resolve/output.json"),
            )
            .expect("the vector's output is readable"),
        )
        .expect("the vector's output is JSON");
        assert!(
            raw["didDocumentMetadata"]["versionId"].is_number(),
            "this test is only meaningful while the fixture encodes versionId as a number"
        );

        assert_eq!(target.expected_version_id(), 2);
        assert_eq!(
            target.expected_confirmations(),
            None,
            "the mutinynet vectors state no confirmations"
        );
        assert!(
            target.expected_deactivated(),
            "this vector's final update deactivates the DID"
        );
        assert_eq!(target.network, Network::Mutinynet);
    }

    #[test]
    fn load_refuses_a_cas_or_smt_beacon_vector_with_the_reason() {
        let id = UNSUPPORTED_BEACON_VECTORS[0];
        let error = load(id).expect_err("a foreclosed vector must not load");
        let message = error.to_string();
        assert!(
            matches!(error, TargetError::UnsupportedBeacon(ref got) if got == id),
            "got: {error}"
        );
        assert!(
            message.contains(id),
            "the message names the vector: {message}"
        );
        assert!(
            message.contains("CAS or SMT beacon"),
            "the message names the blocker, not a missing file: {message}"
        );
    }

    #[test]
    fn load_refuses_an_id_outside_the_drivable_set() {
        let error = load("regtest/nope/nope").expect_err("an unknown id must not load");
        let message = error.to_string();
        assert!(
            matches!(error, TargetError::NotDrivable { ref vector, .. } if vector == "regtest/nope/nope"),
            "got: {error}"
        );
        assert!(
            message.contains("regtest/nope/nope"),
            "the message names the rejected id: {message}"
        );
        for id in DRIVABLE_VECTORS {
            assert!(
                message.contains(id),
                "the message lists the drivable set, missing {id}: {message}"
            );
        }
    }

    #[test]
    fn load_refuses_a_traversal_id_before_touching_the_filesystem() {
        // The allow-list check runs before any path join, so an operator-supplied
        // id can never be used as a free-form path.
        for bad in [
            "../../../etc/passwd",
            "/etc/passwd",
            "regtest/../../etc/x",
            "",
        ] {
            let error = load(bad).expect_err("an id outside the allow-list must not load");
            assert!(
                matches!(error, TargetError::NotDrivable { .. }),
                "`{bad}` must be rejected by the allow-list, got: {error}"
            );
        }
    }

    #[test]
    fn a_missing_fixture_names_the_path() {
        let empty_root = std::env::temp_dir().join(format!(
            "chain-capture-targets-empty-{}",
            std::process::id()
        ));
        let error = load_from(&empty_root, "regtest/k1/qgppexmy")
            .expect_err("an absent fixture must be an error, not an empty target");
        let message = error.to_string();
        assert!(
            matches!(error, TargetError::MissingFixture { .. }),
            "got: {error}"
        );
        assert!(
            message.contains("resolve/input.json"),
            "the message names the missing path: {message}"
        );
        assert!(
            message.contains("regtest/k1/qgppexmy"),
            "the message names the vector: {message}"
        );
    }

    #[test]
    fn load_all_returns_only_the_named_network() {
        if !test_suite_present() {
            return;
        }
        let regtest = load_all("regtest").expect("every regtest target loads");
        assert_eq!(regtest.len(), 4);
        assert!(regtest.iter().all(|t| t.network_dir == "regtest"));
        assert!(
            regtest.iter().all(|t| t.expected_confirmations().is_some()),
            "every regtest vector pins a confirmations count"
        );

        let mutinynet = load_all("mutinynet").expect("every mutinynet target loads");
        assert_eq!(mutinynet.len(), 3);
        assert!(mutinynet.iter().all(|t| t.network_dir == "mutinynet"));

        assert!(
            load_all("signet")
                .expect("an unrepresented network loads nothing")
                .is_empty()
        );
    }

    #[test]
    fn endpoint_selection_covers_every_chain_this_tool_runs_against() {
        // A chain with a confirmed hosted endpoint resolves on its own.
        assert_eq!(
            endpoint("mutinynet", None).expect("mutinynet has a hosted endpoint"),
            "https://mutinynet.com/api"
        );
        assert_eq!(
            endpoint("signet", None).expect("signet has a hosted endpoint"),
            "https://mempool.space/signet/api"
        );
        assert_eq!(
            endpoint("testnet4", None).expect("testnet4 has a hosted endpoint"),
            "https://mempool.space/testnet4/api"
        );

        // regtest is a recognized chain with no hosted endpoint: it must fail,
        // and the failure must point at the override rather than fall back.
        let error = endpoint("regtest", None).expect_err("regtest has no default endpoint");
        assert!(
            error.to_string().contains("--esplora-url"),
            "the message names the next action: {error}"
        );
        assert!(
            error.to_string().contains("regtest"),
            "the message names the chain: {error}"
        );
        assert!(matches!(
            error,
            TargetError::Endpoint {
                source: did_btcr2_client::Error::NoDefaultEndpoint("regtest"),
                ..
            }
        ));

        // An explicit override wins for every chain, trailing slash trimmed.
        assert_eq!(
            endpoint("regtest", Some("http://localhost:3000".to_string()))
                .expect("an override resolves"),
            "http://localhost:3000"
        );
        assert_eq!(
            endpoint("testnet4", Some("http://localhost:3002/".to_string()))
                .expect("an override resolves"),
            "http://localhost:3002"
        );
    }

    #[test]
    fn an_endpoint_carrying_a_credential_is_refused_before_any_request() {
        // Every session records its base URL verbatim into a fixture this
        // repository commits and into the state file beside it, so an
        // authenticated endpoint would publish the credential. Nothing enforced
        // the fixture field's own "no credential ever belongs in a committed
        // fixture", and both committed endpoints being clean made it latent.
        for (url, part) in [
            ("https://user:token@esplora.example/api", "userinfo"),
            ("https://token@esplora.example/api", "userinfo"),
            ("https://esplora.example/api?apikey=abc123", "query"),
            ("http://u:p@localhost:3000", "userinfo"),
        ] {
            let error = endpoint("regtest", Some(url.to_string()))
                .expect_err("an endpoint carrying a credential must not be recorded");
            assert!(
                matches!(error, TargetError::CredentialInEndpoint { .. }),
                "`{url}` must be refused as a credential-bearing endpoint, got {error:?}"
            );
            let message = error.to_string();
            assert!(
                message.contains(part) && message.contains("--esplora-url"),
                "the refusal names the part and the flag: {message}"
            );
            assert!(
                !message.contains("token")
                    && !message.contains("abc123")
                    && !message.contains("esplora.example"),
                "the refusal must not echo the value it is refusing: {message}"
            );
        }

        // The shapes this project actually uses stay accepted, including a port,
        // a path and a trailing slash.
        for url in [
            "http://localhost:3000",
            "https://mutinynet.com/api",
            "http://127.0.0.1:3002/api/",
        ] {
            endpoint("regtest", Some(url.to_string()))
                .unwrap_or_else(|e| panic!("`{url}` is a plain base URL and must resolve: {e}"));
        }
    }

    #[test]
    fn network_from_dir_maps_the_tree_names_and_refuses_anything_else() {
        assert_eq!(
            network_from_dir("regtest").expect("regtest"),
            Network::Regtest
        );
        assert_eq!(
            network_from_dir("mutinynet").expect("mutinynet"),
            Network::Mutinynet
        );
        assert_eq!(network_from_dir("signet").expect("signet"), Network::Signet);
        assert_eq!(
            network_from_dir("mainnet").expect("mainnet"),
            Network::Mainnet
        );
        assert_eq!(
            network_from_dir("testnet").expect("testnet"),
            Network::TestnetV3
        );
        assert_eq!(
            network_from_dir("testnet3").expect("testnet3"),
            Network::TestnetV3
        );
        assert_eq!(
            network_from_dir("testnet4").expect("testnet4"),
            Network::TestnetV4
        );

        let error = network_from_dir("mutiny").expect_err("no defaulting");
        assert!(
            matches!(error, TargetError::UnknownNetwork(ref n) if n == "mutiny"),
            "got: {error}"
        );
        assert!(
            error.to_string().contains("mutiny"),
            "the message names the value: {error}"
        );
    }

    /// A DID from the vendor vectors. `load_in` does not compare a set's DID
    /// with its directory (the capture does, before any request), so the scratch
    /// sets below reuse it under every network.
    const REGTEST_DID: &str =
        "did:btcr2:k1qgppexmyqqlce9netky3h4ur2j9dur83j7m7vva497kfhdgsq2t9nxgqj3x0s";

    /// A scratch suite root unique to one test, removed by the test itself.
    fn scratch_suite(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chain-capture-suite-{}-{tag}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch suite root is creatable");
        dir
    }

    /// One `signals.json` entry in the upstream shape. `seed` fills the txid,
    /// `bytes` the signal bytes.
    fn entry(update: Option<u64>, seed: u8, height: u32, bytes: u8, tip: u32) -> Value {
        let mut entry = serde_json::json!({
            "beaconId": format!("{REGTEST_DID}#initialP2WPKH"),
            "address": "bcrt1qbeacon",
            "txid": format!("{seed:02x}").repeat(32),
            "blockHeight": height,
            "blockHash": format!("{:064x}", height),
            "blockTime": 1_700_000_000,
            "mediantime": 1_699_999_900,
            "signalBytes": format!("{bytes:02x}").repeat(32),
            "recordedTip": tip,
            "someLaterMember": "ignored",
        });
        if let Some(update) = update {
            entry["update"] = serde_json::json!(update);
        }
        entry
    }

    /// A cohort member entry: no `update`, a `cohort`.
    fn cohort_entry(seed: u8) -> Value {
        let mut entry = entry(None, seed, 1000, 0x7c, 1010);
        entry["cohort"] = serde_json::json!({ "id": "cas-09", "members": ["a", "b"] });
        entry
    }

    fn positive_output() -> Value {
        serde_json::json!({
            "didDocument": { "id": REGTEST_DID },
            "didDocumentMetadata": {
                "versionId": "2",
                "deactivated": false,
                "confirmations": 11,
            },
            "didResolutionMetadata": { "contentType": "application/did" },
        })
    }

    fn error_output(code: &str) -> Value {
        serde_json::json!({
            "didDocumentMetadata": {},
            "didResolutionMetadata": { "error": code, "errorMessage": "JS text" },
        })
    }

    /// Write a set's files under `root/id`. `None` leaves a file out.
    fn write_set(
        root: &Path,
        id: &str,
        signals: Option<Value>,
        sidecar: Option<Value>,
        output: Value,
        other: Option<Value>,
    ) {
        let dir = root.join(id);
        std::fs::create_dir_all(dir.join("resolve")).expect("the set directory is creatable");
        let write = |name: &str, value: &Value| {
            std::fs::write(
                dir.join(name),
                serde_json::to_string_pretty(value).expect("JSON serializes"),
            )
            .expect("the set file is writable");
        };
        let mut input = serde_json::json!({ "did": REGTEST_DID, "resolutionOptions": {} });
        if let Some(sidecar) = sidecar {
            input["resolutionOptions"]["sidecar"] = sidecar;
        }
        write("resolve/input.json", &input);
        write("resolve/output.json", &output);
        if let Some(signals) = signals {
            write("signals.json", &signals);
        }
        if let Some(other) = other {
            write("other.json", &other);
        }
    }

    #[test]
    fn the_probe_finds_no_corpus_in_an_empty_root() {
        let root = scratch_suite("probe-empty");
        assert!(!test_suite_present_in(&root));
        assert!(!test_suite_present_in(&root.join("absent")));
        std::fs::remove_dir_all(&root).expect("the scratch root is removable");
    }

    #[test]
    fn the_probe_finds_a_corpus_holding_one_set_directory() {
        let root = scratch_suite("probe-set");
        std::fs::create_dir_all(root.join("regtest/k1/qanyset"))
            .expect("the set directory is creatable");
        assert!(test_suite_present_in(&root));
        std::fs::remove_dir_all(&root).expect("the scratch root is removable");

        let root = scratch_suite("probe-x1");
        std::fs::create_dir_all(root.join("testnet4/x1/qanyset"))
            .expect("the set directory is creatable");
        assert!(test_suite_present_in(&root));
        std::fs::remove_dir_all(&root).expect("the scratch root is removable");
    }

    #[test]
    fn the_probe_ignores_network_directories_without_set_directories() {
        let root = scratch_suite("probe-hollow");
        std::fs::create_dir_all(root.join("regtest")).expect("the network dir is creatable");
        std::fs::create_dir_all(root.join("signet/k1")).expect("the kind dir is creatable");
        std::fs::write(root.join("signet/k1/README.md"), "not a set")
            .expect("a stray file is writable");
        std::fs::create_dir_all(root.join("elsewhere/k1/qnotanetwork"))
            .expect("an unrelated dir is creatable");
        assert!(!test_suite_present_in(&root));
        std::fs::remove_dir_all(&root).expect("the scratch root is removable");
    }

    /// `parse_signals` on an in-memory file.
    fn parse(raw: Value) -> Result<CaptureSignals, TargetError> {
        parse_signals("regtest/k1/qsignals", Path::new("signals.json"), &raw)
    }

    /// The detail of a malformed-fixture refusal, or a panic naming what came
    /// back instead.
    fn malformed_detail(result: Result<CaptureSignals, TargetError>) -> String {
        match result {
            Err(TargetError::MalformedFixture { detail, .. }) => detail,
            other => panic!("expected a malformed-fixture refusal, got {other:?}"),
        }
    }

    #[test]
    fn load_in_reads_a_set_with_its_signals_and_expected_resolution() {
        let root = scratch_suite("happy");
        let id = "signet/k1/qyp5h7kz";
        write_set(
            &root,
            id,
            Some(serde_json::json!([
                entry(Some(1), 0xa1, 300, 0x11, 310),
                entry(Some(2), 0xa2, 305, 0x22, 310),
            ])),
            Some(serde_json::json!({ "updates": [] })),
            positive_output(),
            Some(serde_json::json!({ "scenarioId": "k1-two-updates" })),
        );

        let target = load_in(&root, id).expect("a set carrying signals.json loads");
        assert_eq!(target.id, id);
        assert_eq!(target.network_dir, "signet");
        assert_eq!(target.network, Network::Signet);
        let signals = target
            .signals
            .as_ref()
            .expect("the record travels with the target");
        assert_eq!(signals.recorded_tip, 310);
        assert_eq!(signals.entries.len(), 2);
        assert_eq!(signals.entries[0].update, Some(1));
        assert_eq!(signals.entries[0].txid, "a1".repeat(32));
        assert_eq!(signals.entries[0].block_height, 300);
        assert_eq!(signals.entries[0].block_hash, format!("{:064x}", 300));
        assert_eq!(signals.entries[1].signal_bytes, [0x22; 32]);
        assert!(!signals.entries[1].duplicate);
        assert_eq!(signals.entries[1].cohort, None);
        assert_eq!(
            target.expected,
            ExpectedOutcome::Resolved {
                document: serde_json::json!({ "id": REGTEST_DID }),
                version_id: 2,
                deactivated: false,
                confirmations: Some(11),
            }
        );

        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    #[test]
    fn load_in_accepts_every_network_the_tree_names() {
        let root = scratch_suite("networks");
        for (id, network) in [
            ("testnet4/x1/q9pspvd9", Network::TestnetV4),
            ("regtest/k1/qgpepnx0", Network::Regtest),
            ("mutinynet/k1/q5p6w9su", Network::Mutinynet),
        ] {
            write_set(
                &root,
                id,
                Some(serde_json::json!([entry(Some(1), 0xa1, 300, 0x11, 310)])),
                None,
                positive_output(),
                None,
            );
            let target = load_in(&root, id).unwrap_or_else(|e| panic!("{id} loads: {e}"));
            assert_eq!(target.network, network);
        }
        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    #[test]
    fn load_in_refuses_a_malformed_id_before_reading_anything() {
        // A root that does not exist: any file read would surface as NoSignals
        // or MissingFixture, so InvalidVectorId proves the id was refused first.
        let root = std::env::temp_dir().join("chain-capture-suite-that-does-not-exist");
        for bad in [
            "../x/k1/a",
            "/abs/k1/a",
            "signet/k1/a/b",
            "signet/z1/a",
            "signet/k1/",
            "Signet/k1/a",
            "signet/k1/A",
            "signet/k1/a.b",
            "signet/k1/..",
            "nowhere/k1/a",
            "signet/k1",
            "",
        ] {
            let error = load_in(&root, bad).expect_err("a malformed id must not load");
            assert!(
                matches!(error, TargetError::InvalidVectorId { ref vector } if vector == bad),
                "`{bad}` must be refused as an id, got: {error}"
            );
            let message = error.to_string();
            assert!(
                message.contains("<network>/<k1|x1>/<id>"),
                "the message states the shape: {message}"
            );
        }
    }

    #[test]
    fn load_in_refuses_a_set_without_signals() {
        let root = scratch_suite("no-signals");
        let id = "regtest/k1/qgppexmy";
        write_set(&root, id, None, None, positive_output(), None);

        let error = load_in(&root, id).expect_err("a set without signals.json must not load");
        assert!(
            matches!(error, TargetError::NoSignals { ref vector } if vector == id),
            "got: {error}"
        );
        assert!(error.to_string().contains(id), "names the set: {error}");
        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    #[test]
    fn signals_record_must_be_a_bare_array() {
        let detail = malformed_detail(parse(serde_json::json!({})));
        assert!(detail.contains("bare array"), "{detail}");
        let detail = malformed_detail(parse(serde_json::json!({ "signals": [] })));
        assert!(detail.contains("bare array"), "{detail}");
        let detail = malformed_detail(parse(serde_json::json!([])));
        assert!(detail.contains("no entry"), "{detail}");
    }

    #[test]
    fn signals_record_refuses_disagreeing_recorded_tips() {
        let detail = malformed_detail(parse(serde_json::json!([
            entry(Some(1), 0xa1, 300, 0x11, 310),
            entry(Some(2), 0xa2, 305, 0x22, 312),
        ])));
        assert!(
            detail.contains("310") && detail.contains("312"),
            "names both tips: {detail}"
        );
    }

    #[test]
    fn signals_record_refuses_non_hex_members() {
        for member in ["signalBytes", "txid", "blockHash"] {
            let mut bad = entry(Some(1), 0xa1, 300, 0x11, 310);
            bad[member] = serde_json::json!("zz".repeat(32));
            let detail = malformed_detail(parse(serde_json::json!([bad])));
            assert!(detail.contains(member), "names {member}: {detail}");
        }
        let mut upper = entry(Some(1), 0xa1, 300, 0x11, 310);
        upper["signalBytes"] = serde_json::json!("AB".repeat(32));
        let detail = malformed_detail(parse(serde_json::json!([upper])));
        assert!(detail.contains("lowercase hex"), "{detail}");
    }

    #[test]
    fn signals_record_refuses_an_entry_missing_a_required_member() {
        let mut bad = entry(Some(1), 0xa1, 300, 0x11, 310);
        bad.as_object_mut()
            .expect("an entry is an object")
            .remove("recordedTip");
        let detail = malformed_detail(parse(serde_json::json!([bad])));
        assert!(detail.contains("recordedTip"), "{detail}");
    }

    #[test]
    fn signals_record_refuses_an_unflagged_repeat() {
        let detail = malformed_detail(parse(serde_json::json!([
            entry(Some(1), 0xa1, 300, 0x11, 330),
            entry(Some(1), 0xa2, 326, 0x11, 330),
        ])));
        assert!(detail.contains("duplicate"), "{detail}");
    }

    #[test]
    fn signals_record_refuses_a_repeated_txid() {
        // A flagged duplicate at a higher block is otherwise well-formed; it is
        // the shared txid that the record refuses, naming both entries.
        let mut repeat = entry(Some(1), 0xa1, 326, 0x11, 330);
        repeat["duplicate"] = serde_json::json!(true);
        let detail = malformed_detail(parse(serde_json::json!([
            entry(Some(1), 0xa1, 300, 0x11, 330),
            repeat
        ])));
        assert!(
            detail.contains("entries 0 and 1") && detail.contains(&"a1".repeat(32)),
            "the refusal names both entries and the transaction: {detail}"
        );

        // Refused as malformed before a cohort is refused as unsupported.
        let detail = malformed_detail(parse(serde_json::json!([
            cohort_entry(0xc1),
            cohort_entry(0xc1)
        ])));
        assert!(detail.contains("entries 0 and 1"), "{detail}");
    }

    #[test]
    fn signals_record_accepts_a_flagged_repeat() {
        let mut repeat = entry(Some(1), 0xa2, 326, 0x11, 330);
        repeat["duplicate"] = serde_json::json!(true);
        let signals = parse(serde_json::json!([
            entry(Some(1), 0xa1, 300, 0x11, 330),
            repeat
        ]))
        .expect("a flagged repeat at a higher block is a duplicate");
        assert!(signals.entries[1].duplicate);
        assert_eq!(signals.entries[1].update, Some(1));
    }

    #[test]
    fn signals_record_refuses_a_flagged_repeat_that_differs_or_is_not_higher() {
        let mut other_bytes = entry(Some(1), 0xa2, 326, 0x12, 330);
        other_bytes["duplicate"] = serde_json::json!(true);
        let detail = malformed_detail(parse(serde_json::json!([
            entry(Some(1), 0xa1, 300, 0x11, 330),
            other_bytes
        ])));
        assert!(detail.contains("signalBytes"), "{detail}");

        let mut same_block = entry(Some(1), 0xa2, 300, 0x11, 330);
        same_block["duplicate"] = serde_json::json!(true);
        let detail = malformed_detail(parse(serde_json::json!([
            entry(Some(1), 0xa1, 300, 0x11, 330),
            same_block
        ])));
        assert!(detail.contains("blockHeight 300"), "{detail}");
    }

    #[test]
    fn signals_record_refuses_duplicate_on_a_first_occurrence() {
        let mut first = entry(Some(1), 0xa1, 300, 0x11, 330);
        first["duplicate"] = serde_json::json!(true);
        let detail = malformed_detail(parse(serde_json::json!([first])));
        assert!(detail.contains("first announcement"), "{detail}");
    }

    #[test]
    fn signals_record_refuses_duplicate_without_update() {
        let mut orphan = entry(None, 0xa1, 300, 0x11, 330);
        orphan["duplicate"] = serde_json::json!(true);
        orphan["cohort"] = serde_json::json!({ "id": "cas-09", "members": [] });
        let detail = malformed_detail(parse(serde_json::json!([orphan])));
        assert!(
            detail.contains("duplicate") && detail.contains("no `update`"),
            "{detail}"
        );
    }

    #[test]
    fn signals_record_keys_duplicates_on_update_not_on_bytes() {
        // Two different updates whose entries carry the same signal bytes are
        // two first announcements, not a repeat: the rule keys on `update`.
        let signals = parse(serde_json::json!([
            entry(Some(1), 0xa1, 300, 0x11, 330),
            entry(Some(2), 0xa2, 305, 0x11, 330),
        ]))
        .expect("equal bytes under different updates are not duplicates");
        assert!(signals.entries.iter().all(|e| !e.duplicate));
    }

    #[test]
    fn signals_record_refuses_an_entry_with_neither_update_nor_cohort() {
        let detail = malformed_detail(parse(serde_json::json!([entry(
            None, 0xa1, 300, 0x11, 330
        )])));
        assert!(
            detail.contains("`update`") && detail.contains("`cohort`"),
            "names both members: {detail}"
        );
    }

    #[test]
    fn load_in_refuses_a_cohort_entry_as_unsupported() {
        let root = scratch_suite("cohort");
        let id = "mutinynet/x1/q5cfewep";
        let mut member = entry(Some(1), 0xa1, 300, 0x11, 310);
        member["cohort"] = serde_json::json!({ "id": "cas-09", "members": ["a", "b"] });
        write_set(
            &root,
            id,
            Some(serde_json::json!([member])),
            None,
            positive_output(),
            None,
        );

        let error = load_in(&root, id).expect_err("a cohort set is out of scope");
        assert!(
            matches!(error, TargetError::UnsupportedBeacon(ref v) if v == id),
            "got: {error}"
        );
        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    #[test]
    fn load_in_refuses_the_cohort_only_shape_as_unsupported() {
        // The regenerated corpus's cohort-only sets: no update/ directory, and
        // every signals.json entry carries `cohort` but no `update`. Out of
        // scope, never malformed.
        let root = scratch_suite("cohort-only");
        let id = "regtest/x1/qh2etls9";
        write_set(
            &root,
            id,
            Some(serde_json::json!([cohort_entry(0xa1)])),
            Some(serde_json::json!({})),
            positive_output(),
            Some(serde_json::json!({ "scenarioId": "cohort-member-b" })),
        );
        assert!(!root.join(id).join("update").exists());

        let error = load_in(&root, id).expect_err("a cohort-only set is out of scope");
        assert!(
            matches!(error, TargetError::UnsupportedBeacon(ref v) if v == id),
            "the cohort-only shape is unsupported, not malformed; got: {error}"
        );
        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    #[test]
    fn load_in_refuses_a_cas_or_smt_genesis_beacon() {
        let root = scratch_suite("genesis-beacon");
        let genesis = |kind: &str| {
            serde_json::json!({
                "id": REGTEST_DID,
                "service": [
                    { "id": "#a", "type": "SingletonBeacon", "serviceEndpoint": "bitcoin:x" },
                    { "id": "#b", "type": kind, "serviceEndpoint": "bitcoin:y" },
                ],
            })
        };
        for (n, kind) in ["SMTBeacon", "CASBeacon"].into_iter().enumerate() {
            // Once in other.json, once in the sidecar.
            let in_other = format!("regtest/x1/qother{n}");
            write_set(
                &root,
                &in_other,
                Some(serde_json::json!([entry(Some(1), 0xa1, 300, 0x11, 310)])),
                None,
                positive_output(),
                Some(serde_json::json!({ "genesisDocument": genesis(kind) })),
            );
            let in_sidecar = format!("regtest/x1/qsidecar{n}");
            write_set(
                &root,
                &in_sidecar,
                Some(serde_json::json!([entry(Some(1), 0xa1, 300, 0x11, 310)])),
                Some(serde_json::json!({ "genesisDocument": genesis(kind) })),
                error_output("INVALID_DID_UPDATE"),
                None,
            );
            for id in [&in_other, &in_sidecar] {
                let error = load_in(&root, id).expect_err("a CAS or SMT genesis is out of scope");
                assert!(
                    matches!(error, TargetError::UnsupportedBeacon(ref v) if v == id),
                    "{id} ({kind}): got {error}"
                );
            }
        }
        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    #[test]
    fn load_in_reads_an_expected_error() {
        // The withheld-update shape: update present, a sidecar carrying only
        // the genesis document, and an expected error.
        let root = scratch_suite("negative");
        let id = "regtest/x1/qn05miss";
        write_set(
            &root,
            id,
            Some(serde_json::json!([entry(Some(1), 0xa1, 300, 0x11, 310)])),
            Some(serde_json::json!({ "genesisDocument": { "id": REGTEST_DID, "service": [] } })),
            error_output("MISSING_UPDATE_DATA"),
            None,
        );

        let target = load_in(&root, id).expect("a negative set loads");
        assert_eq!(
            target.expected,
            ExpectedOutcome::Error {
                code: "MISSING_UPDATE_DATA".to_string()
            }
        );
        assert_eq!(target.expected.confirmations(), None);
        assert!(target.sidecar.get("updates").is_none());
        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    #[test]
    fn load_in_accepts_an_absent_sidecar_and_one_without_updates() {
        let root = scratch_suite("sidecars");
        let absent = "regtest/k1/qabsent";
        write_set(
            &root,
            absent,
            Some(serde_json::json!([entry(Some(1), 0xa1, 300, 0x11, 310)])),
            None,
            positive_output(),
            None,
        );
        assert_eq!(
            load_in(&root, absent)
                .expect("an absent sidecar loads")
                .sidecar,
            serde_json::json!({})
        );

        let empty = "regtest/k1/qempty";
        write_set(
            &root,
            empty,
            Some(serde_json::json!([entry(Some(1), 0xa1, 300, 0x11, 310)])),
            Some(serde_json::json!({})),
            positive_output(),
            None,
        );
        assert_eq!(
            load_in(&root, empty)
                .expect("a sidecar without updates loads")
                .sidecar,
            serde_json::json!({})
        );

        let scalar = "regtest/k1/qscalar";
        write_set(
            &root,
            scalar,
            Some(serde_json::json!([entry(Some(1), 0xa1, 300, 0x11, 310)])),
            Some(serde_json::json!("nope")),
            positive_output(),
            None,
        );
        assert!(matches!(
            load_in(&root, scalar),
            Err(TargetError::MalformedFixture { .. })
        ));
        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    #[test]
    fn load_from_reads_signals_when_an_allow_listed_vector_ships_them() {
        let root = scratch_suite("allow-listed");
        let id = "regtest/k1/qgppexmy";
        write_set(
            &root,
            id,
            None,
            Some(serde_json::json!({ "updates": [] })),
            positive_output(),
            None,
        );
        let target = load_from(&root, id).expect("the allow-listed vector loads");
        assert_eq!(target.signals, None, "no signals.json, no record");
        assert_eq!(target.expected.confirmations(), Some(11));

        std::fs::write(
            root.join(id).join("signals.json"),
            serde_json::json!([entry(Some(1), 0xa1, 300, 0x11, 310)]).to_string(),
        )
        .expect("signals.json is writable");
        let target = load_from(&root, id).expect("the allow-listed vector loads");
        assert_eq!(
            target.signals.map(|s| s.recorded_tip),
            Some(310),
            "a vector that ships signals.json carries its record"
        );
        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    /// Add `resolutionOptions.{option}` to the main input of `root/id`.
    fn set_main_option(root: &Path, id: &str, option: &str, value: Value) {
        let path = root.join(id).join("resolve/input.json");
        let mut input: Value = serde_json::from_str(
            &std::fs::read_to_string(&path).expect("the main input was written"),
        )
        .expect("the main input is JSON");
        input["resolutionOptions"][option] = value;
        std::fs::write(&path, input.to_string()).expect("the main input is writable");
    }

    #[test]
    fn both_loaders_refuse_a_target_condition_or_depth_on_the_main_input() {
        let root = scratch_suite("target-options");
        for (n, (option, value)) in [
            ("versionId", serde_json::json!("2")),
            ("versionTime", serde_json::json!("2026-09-21T07:07:00Z")),
            ("minConf", serde_json::json!(1)),
        ]
        .into_iter()
        .enumerate()
        {
            let set = format!("regtest/k1/qoption{n}");
            write_set(
                &root,
                &set,
                Some(serde_json::json!([entry(Some(1), 0xa1, 300, 0x11, 310)])),
                Some(serde_json::json!({})),
                positive_output(),
                None,
            );
            load_in(&root, &set).expect("the set loads before the option is added");
            set_main_option(&root, &set, option, value.clone());
            match load_in(&root, &set) {
                Err(TargetError::MalformedFixture { detail, .. }) => {
                    assert!(
                        detail.contains(&format!("resolutionOptions.{option}"))
                            && detail.contains("does not yet capture")
                            && detail.contains("extended"),
                        "the refusal names the option as a capture limitation: {detail}"
                    );
                    assert!(
                        !detail.contains("resolve/NN/"),
                        "the refusal does not blame the set's layout: {detail}"
                    );
                }
                other => panic!("{option}: expected a refusal, got {other:?}"),
            }

            let allow_listed = "regtest/k1/qgppexmy";
            write_set(
                &root,
                allow_listed,
                None,
                Some(serde_json::json!({ "updates": [] })),
                positive_output(),
                None,
            );
            set_main_option(&root, allow_listed, option, value);
            assert!(
                matches!(
                    load_from(&root, allow_listed),
                    Err(TargetError::MalformedFixture { ref detail, .. })
                        if detail.contains(&format!("resolutionOptions.{option}"))
                ),
                "{option}: the allow-listed loader refuses it too"
            );
        }
        std::fs::remove_dir_all(&root).expect("scratch suite root is removable");
    }

    #[test]
    fn load_leaves_the_vendor_vectors_without_a_signals_record() {
        if !test_suite_present() {
            return;
        }
        for id in DRIVABLE_VECTORS {
            let target = load(id).unwrap_or_else(|e| panic!("{id} loads: {e}"));
            assert!(target.signals.is_none(), "{id} ships no signals.json");
            assert!(matches!(target.expected, ExpectedOutcome::Resolved { .. }));
        }
    }
}
