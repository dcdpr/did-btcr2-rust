//! Which vendor vectors this tool captures chain data for, and what each one
//! expects.
//!
//! Three things live here: the target set (with the derivation that produced it,
//! plus a test that re-derives it from the tree), the per-vector loader that
//! reads a vector's DID, sidecar and expected resolve output from its own files,
//! and the endpoint rule that maps a chain name onto an Esplora base URL.

use did_btcr2::identifier::{Did, Network};
use did_btcr2_client::resolve_base_url;
use onlyerror::Error;
use serde_json::Value;
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

/// Resolve the Esplora base URL for a network, honouring an operator override.
///
/// A thin wrapper over the client's own endpoint rule so every chain this tool
/// runs against goes through ONE rule set: `mutinynet` and `signet` resolve their
/// own endpoints, while `regtest` and `testnet4` have none and require
/// `--esplora-url`. Neither has a hosted public Esplora this project has
/// confirmed, so there is deliberately no fallback — a fallback would silently
/// capture a different chain than the operator named.
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
    /// `resolve/output.json`'s `didDocument`.
    pub expected_document: Value,
    /// `didDocumentMetadata.versionId`, read tolerantly (see [`version_id`]).
    pub expected_version_id: u64,
    /// `didDocumentMetadata.deactivated`.
    pub expected_deactivated: bool,
    /// `didDocumentMetadata.confirmations`, `None` when the vector states none.
    pub expected_confirmations: Option<u64>,
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

    let expected_document = output["didDocument"].clone();
    if !expected_document.is_object() {
        return Err(malformed(
            id,
            &output_path,
            "no `didDocument` object; a resolve vector must state the document it expects",
        ));
    }

    let metadata = &output["didDocumentMetadata"];
    let expected_version_id = version_id(id, &output_path, &metadata["versionId"])?;
    let expected_deactivated = metadata["deactivated"].as_bool().ok_or_else(|| {
        malformed(
            id,
            &output_path,
            "no `didDocumentMetadata.deactivated` boolean",
        )
    })?;
    let expected_confirmations = confirmations(id, &output_path, &metadata["confirmations"])?;

    Ok(VectorTarget {
        id: id.to_string(),
        network_dir,
        network,
        did,
        sidecar,
        expected_document,
        expected_version_id,
        expected_deactivated,
        expected_confirmations,
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

    /// Genesis beacon service types the resolver cannot query, so a vector
    /// declaring one of them is out of scope for capture.
    ///
    /// Lives with the check that applies it: the allow-lists above are what the
    /// tool reads at runtime, and this is the rule that re-derives them from the
    /// tree.
    const UNSUPPORTED_BEACON_TYPES: &[&str] = &["CASBeacon", "SMTBeacon"];

    /// The vector tree is a git submodule; a non-recursive clone leaves it empty.
    /// Every test that reads it calls this first and skips green when it is
    /// absent, matching the core crate's absent-submodule contract.
    fn test_suite_present() -> bool {
        if test_suite_root()
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
        assert_eq!(target.expected_version_id, 2);
        assert_eq!(target.expected_confirmations, Some(93));
        assert!(!target.expected_deactivated);
        assert_eq!(
            target.expected_document["id"],
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

        assert_eq!(target.expected_version_id, 2);
        assert_eq!(
            target.expected_confirmations, None,
            "the mutinynet vectors state no confirmations"
        );
        assert!(
            target.expected_deactivated,
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
            regtest.iter().all(|t| t.expected_confirmations.is_some()),
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
            "https://blockstream.info/signet/api"
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

        // testnet4 is modeled by the crate but absent from the endpoint table, so
        // it is likewise override-only.
        let error = endpoint("testnet4", None).expect_err("testnet4 has no default endpoint");
        assert!(matches!(
            error,
            TargetError::Endpoint {
                source: did_btcr2_client::Error::UnknownNetwork(_),
                ..
            }
        ));
        assert!(
            error.to_string().contains("--esplora-url"),
            "the message names the next action: {error}"
        );

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
}
