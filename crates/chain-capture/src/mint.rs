//! The minting session: its progress file, its key loading, the prompt guarding
//! each broadcast, and the scenarios it publishes.
//!
//! Two scenarios live here, and neither exists upstream. The clean one announces
//! three updates from three DIFFERENT derived beacons and ends the DID
//! deactivated on chain, so cross-beacon signal discovery, multi-update
//! sequencing and the deactivation short-circuit all get real-transaction
//! coverage. The fork publishes two conflicting version 2 announcements on a DID
//! of its own, which makes the late-publishing anomaly a historical fact rather
//! than an arrangement assembled at replay time: composing it at replay from a
//! chosen subset of captured transactions would prove only that the harness can
//! select two transactions, whereas a real fork proves the resolver rejects a
//! history that actually exists.
//!
//! A minting session spans several steps, each of which must confirm before the
//! next can be built, and it WILL be interrupted — a container restarts, a faucet
//! is slow, a terminal closes. Re-running without state would mint a SECOND DID
//! and orphan the first, leaving a half-finished history whose fixture cannot be
//! emitted. The state file turns a re-run into a resume, and its scenario /
//! network / DID guard stops a resume aimed at one chain from silently continuing
//! against another.
//!
//! The secret key is not part of that state. It is supplied on every invocation,
//! lives only in memory, and never reaches the state file, stdout, stderr, or an
//! error message — `mint_errors_never_echo_key_bytes` is what proves that rather
//! than a reviewer reading print statements.

use chrono::Utc;
use did_btcr2::Update;
use did_btcr2::document::{Document, ResolutionOptions, ResolutionResult, SidecarData};
use did_btcr2::error::Btcr2Error;
use did_btcr2::identifier::{Did, Network};
use did_btcr2::key::PublicKey;
use did_btcr2_client::{BtcTransport, Client, Fee, Patch, UreqTransport};
use esploda::bitcoin::Address;
use onlyerror::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use crate::chain::{self, ChainError, ChainOps};
use crate::fixture::{self, ChainFixture};
use crate::record::RecordingTransport;
use crate::targets;
use crate::validate;

/// The only three reasons a key file is rejected.
///
/// Fixed strings, and the field that carries them is `&'static str`, so the
/// contents of the file are not merely absent from these messages — they cannot
/// be put there.
const REASON_LENGTH: &str = "expected 64 hex characters";
/// The file is the right length but is not hexadecimal.
const REASON_HEX: &str = "not valid hex";
/// The bytes decode but are not a usable secp256k1 scalar.
const REASON_SCALAR: &str = "not a valid secp256k1 secret key";

/// The `block_height` a step carries between its broadcast and its confirmation.
///
/// Written before the wait so an interrupted session resumes instead of
/// re-broadcasting; a step still holding it has a real txid on the chain and an
/// unknown block.
const UNCONFIRMED_HEIGHT: u32 = 0;

/// The scenario that announces three updates from three different beacons and
/// ends the DID deactivated on chain.
pub const CLEAN_SCENARIO: &str = "clean-rotating-beacons";

/// The scenario that publishes two conflicting version 2 announcements, so the
/// resolver's refusal to resolve them is a fact about a real chain.
pub const FORK_SCENARIO: &str = "late-publishing-fork";

/// How much each announcing beacon is funded above the announcement fee.
///
/// The announcement spends one confirmed output and pays the fee out of it; the
/// remainder returns as change. The headroom keeps that change above the dust
/// threshold, so a beacon that announces twice still has a spendable output the
/// second time.
const FUNDING_HEADROOM_SATS: u64 = 5_000;

/// How many times the extra beacon key derivation re-hashes before giving up.
///
/// A SHA-256 digest is outside the secp256k1 scalar range with probability
/// around 2^-128, so one attempt is effectively always enough — but "effectively
/// always" is not a code path, and the retry makes the unlucky case
/// deterministic instead of a panic nobody will ever see.
const KEY_DERIVATION_ATTEMPTS: u32 = 8;

/// Minting-layer failures.
///
/// No variant can carry key material: the one that talks about a key file
/// carries the PATH plus a `&'static str` reason, and there is no variant with a
/// field the loaded bytes could be placed in.
#[derive(Debug, Error)]
pub enum MintError {
    /// The secret key file could not be used.
    #[error("{path}: unusable secret key file: {reason}")]
    KeyFile {
        /// The file that was read. The path, never its contents.
        path: String,
        /// One of the three fixed reasons above.
        reason: &'static str,
    },

    /// The state file was written for a different session than this invocation.
    #[error(
        "the minting state file was written for {field} `{in_file}`, but this run asked for `{requested}` — a session cannot continue against a different scenario, chain or DID. Point --state-file at that session's own file, or start a new session with a new one"
    )]
    StateMismatch {
        /// Which field disagrees: `scenario`, `network` or `did`.
        field: String,
        /// What the state file records.
        in_file: String,
        /// What this invocation asked for.
        requested: String,
    },

    /// The operator declined at the confirmation prompt.
    #[error("declined at the confirmation prompt — nothing was broadcast")]
    Declined,

    /// The created document carries no readable identifier.
    #[error(
        "the created document has no string `id` field, so the DID could not be read back out of it"
    )]
    NoDid,

    /// The scenario named on the command line is not one this tool mints.
    #[error("unknown scenario `{scenario}` — this tool mints: {known}")]
    UnknownScenario {
        /// The rejected name, verbatim.
        scenario: String,
        /// The names that are accepted, comma-separated.
        known: String,
    },

    /// The bounded re-hash produced no usable secp256k1 scalar.
    #[error(
        "the clean-rotating-beacons scenario could not derive its extra beacon key: {attempts} successive hashes of the minting key were all outside the secp256k1 scalar range"
    )]
    KeyDerivation {
        /// How many hashes were tried.
        attempts: u32,
    },

    /// A derived key produced no address on the target chain.
    #[error(
        "the clean-rotating-beacons scenario could not derive its extra beacon address on {network}: {reason}"
    )]
    ExtraBeaconAddress {
        /// The chain the address was being derived for.
        network: String,
        /// What the address constructor said.
        reason: String,
    },

    /// A step announces from a beacon index the document does not have.
    #[error(
        "{name}: the document declares no beacon at index {index}, so the step has nothing to announce from"
    )]
    NoBeacon {
        /// The step that could not be announced.
        name: String,
        /// The index that was asked for.
        index: usize,
    },

    /// A step's announcement did not take effect on chain.
    #[error(
        "{name}: the DID resolves to version {got}, not {expected} — the step did not land, so the session stops here rather than signing the next update against a state the chain does not have"
    )]
    StepDidNotLand {
        /// The step that did not land.
        name: String,
        /// The version the step targets.
        expected: u64,
        /// The version the chain actually reports.
        got: u64,
    },

    /// The clean scenario finished without deactivating the DID.
    #[error(
        "{name}: the DID resolves to version {version} but reports deactivated=false — the clean-rotating-beacons scenario exists to end deactivated on chain, and a replay of it would cover the deactivation short-circuit vacuously"
    )]
    NotDeactivated {
        /// The step that should have deactivated the DID.
        name: String,
        /// The version the chain reports.
        version: u64,
    },

    /// The two conflicting announcements confirmed in the same block.
    #[error(
        "{name_a} and {name_b} both confirmed in block {height}, so the two version 2 announcements are indistinguishable by height and the resolver's (targetVersionId, block height) ordering is non-deterministic.\n\nThe second announcement is ALREADY on chain — re-running this scenario would add a THIRD version 2 announcement rather than recover. To recover: delete the state file, generate a fresh key, and restart this scenario from genesis. On a chain this tool mines, also check why no block was produced between the two confirmations."
    )]
    SameBlock {
        /// The branch that confirmed first.
        name_a: String,
        /// The branch that confirmed second.
        name_b: String,
        /// The block they share.
        height: u32,
    },

    /// The finished fork did not raise the late-publishing error.
    #[error(
        "the late-publishing-fork scenario finished, but resolving the DID with both announcements did not raise the late-publishing error: {got}. A fork that resolves is worse than no fork at all, because a replay test built on it would assert nothing"
    )]
    AnomalyNotReached {
        /// What resolving produced instead.
        got: String,
    },

    /// The fork scenario was aimed at a DID another session is minting a clean
    /// history for.
    #[error(
        "{did} is already being minted as a clean history by {state_file} — publishing a conflicting announcement on it would abort that DID's resolution and destroy the coverage permanently. The late-publishing-fork scenario needs its own --key-file, which mints its own DID"
    )]
    SharedDid {
        /// The DID both sessions would share.
        did: String,
        /// The state file that already claims it.
        state_file: String,
    },

    /// A minted update is not announced anywhere in the captured bodies.
    #[error(
        "{scenario}: the capture taken for this scenario's fixture announces nothing for update hash {update_hash_hex} — the fixture is refused rather than written, because a replay of it would resolve a shorter history than the one that was minted. Check that the announcement confirmed and re-run the emission"
    )]
    MissingSignal {
        /// The scenario whose fixture was being emitted.
        scenario: String,
        /// Lowercase hex of the update hash that no captured transaction carries.
        update_hash_hex: String,
    },

    /// The emission recorded no chain tip.
    #[error(
        "{scenario}: the capture taken for this scenario's fixture recorded no chain tip, so the replay would have nothing to measure confirmations against — the endpoint answered no `/blocks/tip/height`"
    )]
    NoTip {
        /// The scenario whose fixture was being emitted.
        scenario: String,
    },

    /// The fixture could not be written.
    Fixture(#[from] fixture::FixtureError),

    /// The minted sidecar could not be hashed into the announcements to look for.
    Validate(#[from] validate::ValidateError),

    /// A DID string could not be read back as an identifier.
    Identifier(#[from] did_btcr2::identifier::Error),

    /// A funding, mining or confirmation step failed.
    Chain(#[from] ChainError),

    /// A facade call failed.
    Client(#[from] did_btcr2_client::Error),

    /// A core `did:btcr2` operation failed.
    Btcr2(#[from] did_btcr2::error::Btcr2Error),

    /// The chain named on the command line is not one this crate models.
    Target(#[from] targets::TargetError),

    /// The state file could not be built or read.
    Json(#[from] serde_json::Error),

    /// I/O error reading the key file or writing the state file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A minting session's progress, on disk.
///
/// Never holds the secret key or the node credentials: the key is supplied by
/// `--key-file` on every invocation, and the credentials belong in an
/// `Authorization` header.
#[derive(Debug, Serialize, Deserialize)]
pub struct MintState {
    /// The scenario being minted, e.g. `clean-rotating-beacons`.
    pub scenario: String,
    /// The chain this session is minting on. Compared against `--network` on
    /// every resume, so a session cannot silently continue on another chain.
    pub network: String,
    /// The Esplora base URL the session ran against.
    pub endpoint: String,
    /// The DID being minted.
    pub did: String,
    /// The derived beacon addresses, in document order.
    pub beacons: Vec<String>,
    /// Completed steps, in order.
    pub steps: Vec<MintStep>,
}

/// One announced update in a minting session.
#[derive(Debug, Serialize, Deserialize)]
pub struct MintStep {
    /// What this step did, e.g. `v2-add-beacon-service`.
    pub name: String,
    /// Which of the document's beacons announced it.
    pub beacon_index: usize,
    /// The version this update produces.
    pub target_version_id: u64,
    /// The announcement transaction.
    pub txid: String,
    /// [`UNCONFIRMED_HEIGHT`] until the step's confirmation lands. Written BEFORE
    /// the wait, so an interrupted session resumes rather than re-broadcasting.
    pub block_height: u32,
    /// The confirming block's time, `0` until the confirmation lands.
    pub block_time: i64,
    /// The signed update, verbatim — this is the sidecar element.
    pub update: Value,
}

impl MintStep {
    /// A step that has been broadcast but not yet confirmed.
    pub fn broadcast(
        name: String,
        beacon_index: usize,
        target_version_id: u64,
        txid: String,
        update: Value,
    ) -> Self {
        Self {
            name,
            beacon_index,
            target_version_id,
            txid,
            block_height: UNCONFIRMED_HEIGHT,
            block_time: 0,
            update,
        }
    }

    /// Whether this step's confirmation has landed.
    pub fn is_confirmed(&self) -> bool {
        self.block_height != UNCONFIRMED_HEIGHT
    }
}

/// Load the secret key controlling the minted DIDs.
///
/// Returns the raw secp key (which signs the Bitcoin announcement) and the
/// derived public key (which the DID is generated from). The key that signs a DID
/// update is a separate, scrubbing newtype built one step at a time by
/// [`update_secret`], because signing consumes it.
///
/// A malformed file is rejected with the path and one of three fixed reasons —
/// never the file's contents, and never a parse library's echo of the input.
pub fn keys(key_file: &Path) -> Result<(secp256k1::SecretKey, PublicKey), MintError> {
    let text = std::fs::read_to_string(key_file)?;
    let text = text.trim();
    let bad = |reason: &'static str| MintError::KeyFile {
        path: key_file.display().to_string(),
        reason,
    };

    if text.len() != 64 {
        return Err(bad(REASON_LENGTH));
    }
    // Decode into a fixed array rather than through a `Vec<u8>`: an owned heap
    // buffer of secret bytes is dropped without being scrubbed, leaving a copy of
    // the key in freed memory.
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| bad(REASON_HEX))?;

    let secret = secp256k1::SecretKey::from_slice(&bytes).map_err(|_| bad(REASON_SCALAR))?;
    let public_key = secret.public_key(&secp256k1::Secp256k1::new());
    Ok((secret, public_key))
}

/// Build the update-signing key for ONE signing operation.
///
/// The core crate's [`did_btcr2::key::SecretKey`] scrubs its bytes on drop and is
/// deliberately not `Clone`, and every construct-signed-update call consumes one.
/// A session that signs three updates therefore builds three, each of which is
/// scrubbed as soon as its signature exists, rather than keeping one alive for
/// the whole session.
fn update_secret(seed: &secp256k1::SecretKey) -> Result<did_btcr2::key::SecretKey, MintError> {
    did_btcr2::key::SecretKey::try_from(seed.secret_bytes()).map_err(|_| MintError::KeyFile {
        // Unreachable in practice: the bytes came out of a secp key, so they are
        // already a valid scalar. Typed rather than unwrapped so the impossible
        // case still cannot panic in an operator's session.
        path: "<the key supplied on the command line>".to_string(),
        reason: REASON_SCALAR,
    })
}

/// The verification method a minted update is signed with — the same default the
/// CLI applies when none is given.
pub fn vm_id(did: &str) -> String {
    format!("{did}#initialKey")
}

/// Load a minting session's state, or start one.
///
/// The document is generated on both paths because generating it makes no
/// network call: it is what produces the DID and the beacon addresses this
/// session works from, and on a resume it is what the recorded DID is checked
/// against. A resume with a different key file therefore fails here rather than
/// announcing one DID's update from another DID's beacon.
///
/// The beacon addresses come out of the core crate's own derivation for the
/// requested network. This module composes no address and contains no
/// human-readable-part literal, which is what lets the same code serve every
/// chain the scenarios are re-minted on.
pub fn load_or_init_state<T: BtcTransport>(
    path: &Path,
    scenario: &str,
    network: &str,
    endpoint: &str,
    client: &Client<T>,
    public_key: &PublicKey,
) -> Result<MintState, MintError> {
    let document = client.create(public_key, targets::network_from_dir(network)?)?;
    let did = document.as_ref()["id"]
        .as_str()
        .ok_or(MintError::NoDid)?
        .to_string();
    let beacons: Vec<String> = document
        .beacons()
        .map(|beacon| beacon.address().to_string())
        .collect();

    if path.exists() {
        let state: MintState = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        for (field, in_file, requested) in [
            ("scenario", &state.scenario, scenario),
            ("network", &state.network, network),
            ("did", &state.did, did.as_str()),
        ] {
            if in_file != requested {
                return Err(MintError::StateMismatch {
                    field: field.to_string(),
                    in_file: in_file.clone(),
                    requested: requested.to_string(),
                });
            }
        }
        eprintln!(
            "resuming {scenario} on {network}: {did} ({} step(s) already recorded)",
            state.steps.len()
        );
        return Ok(state);
    }

    let state = MintState {
        scenario: scenario.to_string(),
        network: network.to_string(),
        endpoint: endpoint.to_string(),
        did,
        beacons,
        steps: Vec::new(),
    };
    write_state_atomic(path, &state)?;
    eprintln!("minting {scenario} on {network}: {}", state.did);
    for (index, address) in state.beacons.iter().enumerate() {
        eprintln!("  beacon {index}: {address}");
    }
    Ok(state)
}

/// Serialize `state` and write it to `path` atomically.
///
/// The body is built in memory, written to `<path>.tmp`, then renamed over the
/// target. Rename is atomic on the same filesystem, so an interrupted or failed
/// write never leaves the previous state truncated or holding invalid JSON — and
/// a session whose state file is unreadable is a session that cannot resume.
pub fn write_state_atomic(path: &Path, state: &MintState) -> Result<(), MintError> {
    let body = serde_json::to_string_pretty(state)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.to_path_buf().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Record a step and persist it BEFORE any confirmation wait.
///
/// A crash between a broadcast and its confirmation is then recoverable. Without
/// it, a resume would re-broadcast the same version from a different output and
/// fork the DID it was minting.
pub fn ensure_step_recorded(
    state: &mut MintState,
    path: &Path,
    step: MintStep,
) -> Result<(), MintError> {
    state.steps.push(step);
    write_state_atomic(path, state)
}

/// The prompt shown before a broadcast, stating what it will do and whether it
/// can be undone.
pub fn broadcast_prompt(network: &str, what: &str) -> String {
    // Local-versus-public is derived from the network name, not from a list of
    // known chain names: a chain the tool mines itself is local and disposable,
    // and every other chain is a real one whose history outlives the session. So
    // `regtest` is local and ANY other name — including one this project has not
    // used yet — is described as permanent, which is the safe direction to be
    // wrong in.
    let consequence = if network == "regtest" {
        "this chain is local and disposable: its history can be thrown away and the scenario re-minted"
    } else {
        "this broadcast is real and permanent: once it is relayed it cannot be recalled"
    };
    format!("about to broadcast {what} on {network}. {consequence}.")
}

/// Require an explicit `yes` before proceeding, unless `--yes` was passed.
pub fn require_confirmation(prompt: &str, yes: bool) -> Result<(), MintError> {
    if yes {
        return Ok(());
    }
    let mut stderr = std::io::stderr();
    write!(stderr, "{prompt}\ntype `yes` to continue: ")?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim() == "yes" {
        Ok(())
    } else {
        Err(MintError::Declined)
    }
}

/// One step of a minted scenario: what it is called, which version it produces,
/// and which of the document's beacons announces it.
///
/// A table rather than a sequence of calls, so the shape of a scenario — three
/// versions across three beacons, or two announcements of the same version from
/// one — is a value a test can assert against instead of control flow it has to
/// re-derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioStep {
    /// What this step does, and the key it is recorded under in the state file.
    pub name: &'static str,
    /// The version this step's update produces.
    pub target_version_id: u64,
    /// Which beacon announces it, in document order.
    pub beacon_index: usize,
}

/// The clean scenario's three steps.
///
/// Every vendor vector announces from a single beacon, so this rotation is the
/// only real-transaction coverage of cross-beacon signal discovery, of merging
/// several addresses' responses into one singleton-beacon result, and of the
/// resolver's request de-duplication. Document order is P2PKH, P2WPKH, P2TR, so
/// the indices below name three different address types as well as three
/// different addresses.
pub const CLEAN_STEPS: [ScenarioStep; 3] = [
    ScenarioStep {
        name: "v2-add-beacon-service",
        target_version_id: 2,
        beacon_index: 1,
    },
    ScenarioStep {
        name: "v3-add-non-beacon-service",
        target_version_id: 3,
        beacon_index: 2,
    },
    ScenarioStep {
        name: "v4-deactivate",
        target_version_id: 4,
        beacon_index: 0,
    },
];

/// The fork scenario's two steps.
///
/// Both target version 2 and both announce from the SAME beacon: the anomaly is
/// two conflicting histories, not two beacons.
pub const FORK_STEPS: [ScenarioStep; 2] = [
    ScenarioStep {
        name: "v2-branch-a",
        target_version_id: 2,
        beacon_index: 1,
    },
    ScenarioStep {
        name: "v2-branch-b",
        target_version_id: 2,
        beacon_index: 1,
    },
];

/// Derive the extra beacon address the clean scenario's version 2 update adds.
///
/// Deterministic, so the runbook can reproduce it, and derived from the minting
/// key rather than written out as a literal so it is correct on every chain the
/// scenario is re-minted on — a hardcoded address would hardcode a
/// human-readable part and therefore a chain. Nothing ever publishes from it;
/// its only job is to give a replayed resolve a second round of requests naming
/// an address the first round did not.
fn extra_beacon_address(
    seed: &secp256k1::SecretKey,
    network: Network,
) -> Result<Address, MintError> {
    let bytes: [u8; 32] = Sha256::digest(seed.secret_bytes()).into();
    address_from_hash_seed(bytes, network)
}

/// The bounded re-hash [`extra_beacon_address`] runs, factored out so a test can
/// hand it a first value that is NOT a valid scalar and prove the retry works.
///
/// A digest outside the secp256k1 scalar range is astronomically unlikely rather
/// than impossible, and "astronomically unlikely" written as a comment is an
/// untested branch. Written as a bounded loop it is a code path with a
/// deterministic answer and a named error at the end of it.
fn address_from_hash_seed(mut bytes: [u8; 32], network: Network) -> Result<Address, MintError> {
    let btc_network = esploda::bitcoin::Network::try_from(network)?;
    for _ in 0..KEY_DERIVATION_ATTEMPTS {
        if let Ok(secret) = secp256k1::SecretKey::from_slice(&bytes) {
            let public_key =
                esploda::bitcoin::PublicKey::new(secret.public_key(&secp256k1::Secp256k1::new()));
            // The only failure is an uncompressed public key, and `PublicKey::new`
            // produces a compressed one — reported rather than unwrapped so an
            // upstream change cannot turn it into a panic in an operator session.
            return Address::p2wpkh(&public_key, btc_network).map_err(|e| {
                MintError::ExtraBeaconAddress {
                    network: btc_network.to_string(),
                    reason: e.to_string(),
                }
            });
        }
        bytes = Sha256::digest(bytes).into();
    }
    Err(MintError::KeyDerivation {
        attempts: KEY_DERIVATION_ATTEMPTS,
    })
}

/// The patch the clean scenario's version 2 update applies: a FOURTH singleton
/// beacon, at an address nothing ever publishes from.
fn add_beacon_service_patch(did: &str, extra_address: &Address) -> Patch {
    serde_json::from_value(json!([{
        "op": "add",
        "path": "/service/3",
        "value": {
            "id": format!("{did}#rotatedP2WPKH"),
            "type": "SingletonBeacon",
            "serviceEndpoint": format!("bitcoin:{extra_address}"),
        },
    }]))
    .expect("the beacon-service patch is a static RFC-6902 shape")
}

/// The patch the clean scenario's version 3 update applies: a service that is
/// NOT a beacon, which document parsing retains and the beacon list skips.
fn add_non_beacon_service_patch(did: &str) -> Patch {
    serde_json::from_value(json!([{
        "op": "add",
        "path": "/service/4",
        "value": {
            "id": format!("{did}#dwn"),
            "type": "DecentralizedWebNode",
            "serviceEndpoint": "http://example.com/dwn",
        },
    }]))
    .expect("the non-beacon-service patch is a static RFC-6902 shape")
}

/// The patch one fork branch applies.
///
/// The two branches differ only in the service they add, which is enough to give
/// their updates different hashes and therefore make them a genuine conflict
/// rather than two announcements of the same thing.
fn fork_branch_patch(did: &str, branch: &str) -> Patch {
    serde_json::from_value(json!([{
        "op": "add",
        "path": "/service/3",
        "value": {
            "id": format!("{did}#{branch}"),
            "type": "DecentralizedWebNode",
            "serviceEndpoint": format!("http://example.com/{branch}"),
        },
    }]))
    .expect("the fork-branch patch is a static RFC-6902 shape")
}

/// Which document a step's update is signed against.
///
/// Every step but one signs against the CONTEMPORARY document — the state the
/// chain reports after the previous step landed. The fork's second branch signs
/// against the RETAINED genesis document instead, which is the whole anomaly: an
/// update built from the contemporary state after branch A confirmed would be a
/// legitimate version 3, not a conflicting version 2. It is also exactly what the
/// four-operation facade cannot express — it resolves the current state before
/// signing — which is why the fork is minted by a library-driven tool rather than
/// from the command line.
fn source_document_for<'a>(
    step: &str,
    genesis: &'a Document,
    contemporary: &'a Document,
) -> &'a Document {
    if step == FORK_STEPS[1].name {
        genesis
    } else {
        contemporary
    }
}

/// What a resume must do with a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepAction {
    /// Already confirmed on chain: do nothing.
    Done,
    /// Broadcast but not confirmed. Wait for THIS txid rather than
    /// re-broadcasting: a second announcement of the same version from a
    /// different output would fork the DID being minted.
    AwaitConfirmation(String),
    /// Not on chain at all.
    Announce,
}

/// Decide what a resume owes a step, from the state file alone.
pub fn resume_action(state: &MintState, name: &str) -> StepAction {
    match state.steps.iter().find(|step| step.name == name) {
        Some(step) if step.is_confirmed() => StepAction::Done,
        Some(step) => StepAction::AwaitConfirmation(step.txid.clone()),
        None => StepAction::Announce,
    }
}

/// Fill in a step's confirmation and rewrite the state file.
///
/// Separate from [`ensure_step_recorded`] on purpose: the txid is persisted
/// before the wait, and this is the second write that closes it out.
fn confirm_step(
    state: &mut MintState,
    path: &Path,
    name: &str,
    height: u32,
    time: i64,
) -> Result<(), MintError> {
    if let Some(step) = state.steps.iter_mut().find(|step| step.name == name) {
        step.block_height = height;
        step.block_time = time;
    }
    write_state_atomic(path, state)
}

/// Assemble resolution options from the updates recorded so far.
///
/// Built from each step's RETAINED wire JSON rather than from typed values,
/// because a resumed session has only the state file: the typed updates from the
/// interrupted run are gone. It is also the same assembly the capture path and
/// the replay driver use, so a scenario is proved against the code path its
/// fixture will later be replayed through.
fn options_for(updates: &[Value]) -> Result<ResolutionOptions, MintError> {
    Ok(ResolutionOptions {
        sidecar_data: Some(SidecarData::from_json_value(json!({ "updates": updates }))?),
        ..Default::default()
    })
}

/// Every update the session has recorded, in order.
fn recorded_updates(state: &MintState) -> Vec<Value> {
    state.steps.iter().map(|step| step.update.clone()).collect()
}

/// Everything a scenario step needs that does not change between steps.
pub struct MintSession<'a, T: BtcTransport> {
    /// The four-operation facade, pointed at this chain's Esplora endpoint.
    pub client: &'a Client<T>,
    /// Funding and confirmation, whichever chain family this session is on.
    pub ops: &'a dyn ChainOps,
    /// Where progress is persisted.
    pub state_path: &'a Path,
    /// The key that signs the announcement transaction's inputs.
    pub beacon_sk: secp256k1::SecretKey,
    /// Absolute fee per announcement, in satoshis.
    pub fee: u64,
    /// Whether the broadcast prompt is skipped.
    pub yes: bool,
}

impl<T: BtcTransport> MintSession<'_, T> {
    /// Fund the announcing beacon, broadcast the update, and record the txid
    /// BEFORE waiting for its confirmation.
    ///
    /// The ordering is the point: a broadcast that is not recorded is
    /// unrecoverable, because a resume would re-announce the same version from a
    /// different output and fork the DID it is minting.
    fn announce(
        &self,
        state: &mut MintState,
        step: &ScenarioStep,
        doc: &Document,
        update: Update,
    ) -> Result<(), MintError> {
        let address = doc
            .beacons()
            .nth(step.beacon_index)
            .ok_or_else(|| MintError::NoBeacon {
                name: step.name.to_string(),
                index: step.beacon_index,
            })?
            .address()
            .clone();

        // Announcements select CONFIRMED outputs only, so each rotated beacon
        // needs its own already-mined funding. On a chain this tool mines that is
        // a wallet transfer plus a block; on a public chain it is a faucet visit
        // and a poll. The scenario does not branch on which.
        let needed_sats = self.fee + FUNDING_HEADROOM_SATS;
        self.ops.ensure_funded(&address, needed_sats)?;

        // The signed update's wire JSON IS the sidecar element, and the typed
        // value is about to be consumed by the announcement build. Retain it
        // first or it is gone.
        let retained = update.as_ref().clone();

        require_confirmation(
            &broadcast_prompt(
                self.ops.network(),
                &format!(
                    "{} from beacon {} ({address})",
                    step.name, step.beacon_index
                ),
            ),
            self.yes,
        )?;

        let tx = self.client.build_update_tx(
            doc,
            update,
            step.beacon_index,
            Fee::Absolute(self.fee),
            None,
            self.beacon_sk,
        )?;
        let txid = self.client.broadcast(&tx)?.to_string();
        ensure_step_recorded(
            state,
            self.state_path,
            MintStep::broadcast(
                step.name.to_string(),
                step.beacon_index,
                step.target_version_id,
                txid.clone(),
                retained,
            ),
        )?;
        eprintln!("  {}: broadcast {txid}, waiting for its block", step.name);

        self.await_step(state, step.name, &txid)
    }

    /// Wait for a broadcast step's confirmation and write it into the state file.
    fn await_step(&self, state: &mut MintState, name: &str, txid: &str) -> Result<(), MintError> {
        let (height, time) = self.ops.await_confirmation(txid)?;
        confirm_step(state, self.state_path, name, height, time)?;
        eprintln!("  {name}: confirmed in block {height}");
        Ok(())
    }

    /// Re-resolve the DID with every update recorded so far, and require it to
    /// report the version the step targets.
    ///
    /// There is no public way to step a document forward locally, so this is the
    /// only way to advance the contemporary document between steps — and that is
    /// a feature here: it proves each step actually landed on chain before the
    /// next is built on it.
    fn advance(
        &self,
        state: &MintState,
        did: &Did,
        step: &ScenarioStep,
    ) -> Result<ResolutionResult, MintError> {
        let result = self
            .client
            .resolve(did, options_for(&recorded_updates(state))?)?;
        let got = result.document_metadata.version_id.get();
        if got != step.target_version_id {
            return Err(MintError::StepDidNotLand {
                name: step.name.to_string(),
                expected: step.target_version_id,
                got,
            });
        }
        Ok(result)
    }
}

/// Tell the operator what each announcing beacon must hold, before anything is
/// broadcast.
///
/// On a public chain that means one faucet visit covering every address instead
/// of one visit per step; on a chain this tool mines it is a statement of what it
/// is about to do with the node's wallet.
fn print_funding_plan(ops: &dyn ChainOps, addresses: &[(usize, String)], needed_sats: u64) {
    if ops.mines_on_demand() {
        eprintln!(
            "funding {} announcing beacon(s) from the node wallet on {} with {needed_sats} sats each:",
            addresses.len(),
            ops.network(),
        );
    } else {
        eprintln!(
            "fund these {} announcing beacon(s) with {needed_sats} sats each on {} before the session can proceed{}:",
            addresses.len(),
            ops.network(),
            chain::faucet_url(ops.network())
                .map(|url| format!(" (faucet: {url})"))
                .unwrap_or_default(),
        );
    }
    for (index, address) in addresses {
        eprintln!("  beacon {index}: {address}");
    }
}

/// The announcing beacons of a scenario, in the order its steps use them.
fn announcing_beacons(
    doc: &Document,
    steps: &[ScenarioStep],
) -> Result<Vec<(usize, String)>, MintError> {
    let mut seen = Vec::new();
    for step in steps {
        if seen.iter().any(|(index, _)| *index == step.beacon_index) {
            continue;
        }
        let address = doc
            .beacons()
            .nth(step.beacon_index)
            .ok_or_else(|| MintError::NoBeacon {
                name: step.name.to_string(),
                index: step.beacon_index,
            })?
            .address()
            .to_string();
        seen.push((step.beacon_index, address));
    }
    Ok(seen)
}

/// Mint the clean scenario: three updates, three different beacons, three
/// distinct blocks, ending deactivated on chain.
///
/// Each step waits for its own confirmation before the next is built, so the
/// three announcements land at three distinct heights. On a chain this tool mines
/// that is chosen rather than hoped for — exactly one block is produced per
/// confirmation — and the two height gaps are what give a replay something to
/// sequence.
pub fn mint_clean<T: BtcTransport>(
    session: &MintSession<'_, T>,
    state: &mut MintState,
    genesis: &Document,
    network: Network,
) -> Result<(), MintError> {
    let did = Did::from_str(&state.did)?;
    let vm = vm_id(&state.did);
    let extra_address = extra_beacon_address(&session.beacon_sk, network)?;

    print_funding_plan(
        session.ops,
        &announcing_beacons(genesis, &CLEAN_STEPS)?,
        session.fee + FUNDING_HEADROOM_SATS,
    );
    eprintln!(
        "  the version 2 update adds a fourth beacon at {extra_address}, which is never funded and never announces"
    );

    let mut contemporary = genesis.clone();
    let mut latest = None;
    for step in &CLEAN_STEPS {
        let target = NonZeroU64::new(step.target_version_id)
            .expect("every scenario step targets a version above zero");
        match resume_action(state, step.name) {
            StepAction::Done => eprintln!("  {}: already confirmed, skipping", step.name),
            StepAction::AwaitConfirmation(txid) => {
                eprintln!("  {}: already broadcast as {txid}, waiting", step.name);
                session.await_step(state, step.name, &txid)?;
            }
            StepAction::Announce => {
                let source = source_document_for(step.name, genesis, &contemporary);
                let update = if step.name == CLEAN_STEPS[2].name {
                    source.deactivate(&vm, update_secret(&session.beacon_sk)?, target)?
                } else {
                    let patch = if step.name == CLEAN_STEPS[0].name {
                        add_beacon_service_patch(&state.did, &extra_address)
                    } else {
                        add_non_beacon_service_patch(&state.did)
                    };
                    source.construct_signed_update(
                        patch,
                        target,
                        &vm,
                        update_secret(&session.beacon_sk)?,
                    )?
                };
                session.announce(state, step, source, update)?;
            }
        }
        let result = session.advance(state, &did, step)?;
        contemporary = result.document.clone();
        latest = Some(result);
    }

    // The on-chain deactivation is a coverage goal of this scenario, not a
    // side-effect of its last patch: a scenario that ended active would let a
    // replay cover the resolver's deactivation short-circuit vacuously.
    let last = CLEAN_STEPS[CLEAN_STEPS.len() - 1];
    let result = latest.expect("the step table is never empty");
    if !result.document_metadata.deactivated {
        return Err(MintError::NotDeactivated {
            name: last.name.to_string(),
            version: result.document_metadata.version_id.get(),
        });
    }
    eprintln!(
        "{CLEAN_SCENARIO} complete: {} resolves to version {} and is deactivated on chain",
        state.did,
        result.document_metadata.version_id.get(),
    );
    emit_minted(state)?;
    Ok(())
}

/// Refuse the fork scenario on a DID another session is minting a clean history
/// for.
///
/// A real on-chain fork ABORTS resolution, so one DID cannot carry both a clean
/// multi-update history and the anomaly. The two scenarios therefore take
/// separate key files, and this reads the state files sitting beside this
/// session's own to catch the case where they were handed the same one.
fn refuse_shared_did(did: &str, own_state_path: &Path) -> Result<(), MintError> {
    let dir = own_state_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty());
    let Some(entries) = dir.and_then(|dir| std::fs::read_dir(dir).ok()) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path == own_state_path {
            continue;
        }
        // A file that is not a minting state file is not evidence either way;
        // this guard reads what it recognizes and ignores the rest.
        let recognized = std::fs::read_to_string(&path)
            .ok()
            .and_then(|body| serde_json::from_str::<MintState>(&body).ok());
        let Some(other) = recognized else {
            continue;
        };
        if other.scenario == CLEAN_SCENARIO && other.did == did {
            return Err(MintError::SharedDid {
                did: did.to_string(),
                state_file: path.display().to_string(),
            });
        }
    }
    Ok(())
}

/// Require the two conflicting announcements to sit in different blocks.
///
/// The resolver orders signals by `(targetVersionId, block height)`, so two
/// version 2 announcements in one block have no defined order and the anomaly
/// they demonstrate becomes a coin flip. On a chain this tool mines this cannot
/// fail by construction — branch A's confirmation produces a block before branch
/// B is even funded — so this is a defensive assertion, not a race handler.
fn require_distinct_heights(state: &MintState) -> Result<(), MintError> {
    let height_of = |name: &str| {
        state
            .steps
            .iter()
            .find(|step| step.name == name)
            .map(|step| step.block_height)
    };
    let (Some(height_a), Some(height_b)) =
        (height_of(FORK_STEPS[0].name), height_of(FORK_STEPS[1].name))
    else {
        return Ok(());
    };
    if height_b > height_a {
        return Ok(());
    }
    Err(MintError::SameBlock {
        name_a: FORK_STEPS[0].name.to_string(),
        name_b: FORK_STEPS[1].name.to_string(),
        height: height_b,
    })
}

/// Whether a facade failure is the spec's late-publishing error.
///
/// Matched on the concrete variant path rather than on a formatted string: a
/// message-substring check would pass on an unrelated failure that happened to
/// mention the words, which is precisely the mistake a scenario existing to prove
/// an anomaly must not make.
fn is_late_publishing(error: &did_btcr2_client::Error) -> bool {
    matches!(
        error,
        did_btcr2_client::Error::Resolver(did_btcr2::resolver::Error::Btcr2Error(
            Btcr2Error::LatePublishingError(_)
        )) | did_btcr2_client::Error::Btcr2(Btcr2Error::LatePublishingError(_))
    )
}

/// Resolve the finished fork and require the late-publishing error.
///
/// A scenario minted to carry an anomaly that then resolves cleanly is worse than
/// no scenario at all: a replay test built on it would assert nothing.
fn prove_late_publishing<T: BtcTransport>(
    client: &Client<T>,
    did: &Did,
    state: &MintState,
) -> Result<(), MintError> {
    match client.resolve(did, options_for(&recorded_updates(state))?) {
        Ok(result) => Err(MintError::AnomalyNotReached {
            got: format!(
                "the DID resolved cleanly to version {}",
                result.document_metadata.version_id.get()
            ),
        }),
        Err(error) if is_late_publishing(&error) => {
            eprintln!("  the fork is on chain: resolving it raises {error}");
            Ok(())
        }
        Err(error) => Err(MintError::AnomalyNotReached {
            got: error.to_string(),
        }),
    }
}

/// Mint the fork scenario: two conflicting version 2 announcements, both signed
/// against the retained genesis document, at two distinct heights.
///
/// The contemporary document is deliberately never advanced. Re-resolving between
/// the two steps would report version 2 once branch A confirmed, and an update
/// built from that document would be a legitimate version 3 rather than a
/// conflict.
pub fn mint_fork<T: BtcTransport>(
    session: &MintSession<'_, T>,
    state: &mut MintState,
    genesis: &Document,
) -> Result<(), MintError> {
    let did = Did::from_str(&state.did)?;
    let vm = vm_id(&state.did);

    print_funding_plan(
        session.ops,
        &announcing_beacons(genesis, &FORK_STEPS)?,
        session.fee + FUNDING_HEADROOM_SATS,
    );

    // Never advanced: see this function's own note. It is named for what it would
    // be in any other scenario, because it is the value the shared
    // source-document choice consults.
    let contemporary = genesis.clone();
    for step in &FORK_STEPS {
        let target = NonZeroU64::new(step.target_version_id)
            .expect("every scenario step targets a version above zero");
        match resume_action(state, step.name) {
            StepAction::Done => eprintln!("  {}: already confirmed, skipping", step.name),
            StepAction::AwaitConfirmation(txid) => {
                eprintln!("  {}: already broadcast as {txid}, waiting", step.name);
                session.await_step(state, step.name, &txid)?;
            }
            StepAction::Announce => {
                let source = source_document_for(step.name, genesis, &contemporary);
                let update = source.construct_signed_update(
                    fork_branch_patch(&state.did, step.name),
                    target,
                    &vm,
                    update_secret(&session.beacon_sk)?,
                )?;
                session.announce(state, step, source, update)?;
            }
        }
    }

    require_distinct_heights(state)?;
    prove_late_publishing(session.client, &did, state)?;
    eprintln!(
        "{FORK_SCENARIO} complete: {} carries two conflicting version 2 announcements and no longer resolves",
        state.did,
    );
    emit_minted(state)?;
    Ok(())
}

/// The vector id a minted scenario's fixture is filed under, which is also what
/// derives its path: `minted/clean-rotating-beacons` becomes
/// `fixtures/chain/minted/clean-rotating-beacons.json`.
fn minted_vector(state: &MintState) -> String {
    format!("minted/{}", state.scenario)
}

/// The sidecar a replay of a minted scenario must resolve with: every update the
/// session announced, in the order it announced them.
///
/// A vendor vector reads its sidecar out of the test-suite tree. A minted
/// scenario has no upstream source at all, so its fixture has to carry its own —
/// the fixture is the only artifact of the session that outlives the chain it ran
/// against.
fn minted_sidecar(state: &MintState) -> Value {
    json!({ "updates": recorded_updates(state) })
}

/// The expectation a replay of the clean scenario asserts.
///
/// `versionId` is the ASCII STRING the specification requires and this crate
/// emits, never a JSON number.
///
/// Nothing here records a block height, a chain tip or a `confirmations` count,
/// and that omission is the point. Every chain this scenario is re-minted on
/// regenerates its txids, heights and block times, so a number baked in here
/// would be wrong the moment the scenario moved to another chain — and on a chain
/// that is still mining it goes stale within a block. The replay derives
/// `confirmations` from the fixture's own recorded tip and the height of the
/// most-recently-applied signal instead, which asserts the resolver's real
/// behaviour rather than restating `tip - height + 1` back at it.
fn clean_expected(document: &Value, version_id: u64) -> Value {
    json!({
        "didDocument": document,
        "didDocumentMetadata": {
            "versionId": version_id.to_string(),
            "deactivated": true,
        },
    })
}

/// The expectation a replay of the fork asserts: the resolve ABORTS.
///
/// `LATE_PUBLISHING` is the problem-details code this crate reports for the
/// spec's late-publishing error, so a replay matches the code rather than a
/// message — the same reason [`is_late_publishing`] matches a variant.
fn fork_expected() -> Value {
    json!({ "error": "LATE_PUBLISHING" })
}

/// What a minted scenario contributes that no upstream vector does.
///
/// Printed when its fixture is written, because the reason a scenario exists is
/// the thing an operator most needs to see confirmed at the end of a session.
fn minted_contributions(scenario: &str) -> &'static [&'static str] {
    if scenario == CLEAN_SCENARIO {
        &[
            "multi-update sequencing across rotating beacons",
            "on-chain deactivation short-circuit",
        ]
    } else {
        &["late publishing detected against a real on-chain fork"]
    }
}

/// Assemble the self-contained fixture for a minted scenario.
///
/// Self-contained is the whole difference from a vendor capture: the sidecar, the
/// expectation, the signal provenance, the chain and the captured bodies all
/// travel in one file, because nothing upstream holds any of them.
///
/// Every minted update must be matched by an announcement in the captured bodies
/// or nothing is built — the same refuse-to-write posture the vendor path takes,
/// for the same reason: a fixture missing an announcement replays a shorter
/// history than the one that was minted, and the resulting test failure points at
/// the resolver instead of at the capture.
fn build_minted_fixture(
    state: &MintState,
    tip_height: u32,
    addresses: &BTreeMap<String, Vec<Value>>,
    expected: Value,
) -> Result<ChainFixture, MintError> {
    let vector = minted_vector(state);
    let sidecar = minted_sidecar(state);
    let hashes = validate::update_hashes(&vector, &sidecar)?;
    let signals = validate::scan_signals(addresses, &hashes);
    for hash in &hashes {
        let update_hash_hex = hex::encode(hash);
        if !signals
            .iter()
            .any(|signal| signal.update_hash == update_hash_hex)
        {
            return Err(MintError::MissingSignal {
                scenario: state.scenario.clone(),
                update_hash_hex,
            });
        }
    }

    Ok(ChainFixture {
        captured_at: Utc::now().to_rfc3339(),
        endpoint: state.endpoint.clone(),
        // Recorded, never assumed: a scenario re-minted on another chain writes
        // that chain's name here, and every reader takes the chain from the
        // fixture rather than from a constant.
        network: state.network.clone(),
        vector,
        did: state.did.clone(),
        tip_height,
        signals,
        addresses: addresses.clone(),
        sidecar: Some(sidecar),
        expected: Some(expected),
    })
}

/// Resolve the finished DID and require the scenario's own expectation before any
/// fixture is built from it.
///
/// A scenario that does not reach its expectation writes nothing: a fixture whose
/// `expected` was produced by a resolve that did something else would make a
/// replay assert whatever happened rather than what the scenario exists to prove.
fn expectation_of<T: BtcTransport>(
    client: &Client<T>,
    did: &Did,
    state: &MintState,
    options: ResolutionOptions,
) -> Result<Value, MintError> {
    if state.scenario == FORK_SCENARIO {
        return match client.resolve(did, options) {
            Ok(result) => Err(MintError::AnomalyNotReached {
                got: format!(
                    "the DID resolved cleanly to version {}",
                    result.document_metadata.version_id.get()
                ),
            }),
            Err(error) if is_late_publishing(&error) => Ok(fork_expected()),
            Err(error) => Err(MintError::AnomalyNotReached {
                got: error.to_string(),
            }),
        };
    }

    let result = client.resolve(did, options)?;
    let version = result.document_metadata.version_id.get();
    let final_step = CLEAN_STEPS[CLEAN_STEPS.len() - 1];
    if version != final_step.target_version_id {
        return Err(MintError::StepDidNotLand {
            name: format!("{}: fixture emission", state.scenario),
            expected: final_step.target_version_id,
            got: version,
        });
    }
    if !result.document_metadata.deactivated {
        return Err(MintError::NotDeactivated {
            name: format!("{}: fixture emission", state.scenario),
            version,
        });
    }
    Ok(clean_expected(result.document.as_ref(), version))
}

/// Write a minted scenario's fixture.
///
/// Reads NOTHING but the state file: the DID, the endpoint, the chain and every
/// signed update are already recorded there, so this runs on a completed session
/// without re-minting anything — which is what makes a lost or hand-deleted
/// fixture recoverable without touching the chain again.
///
/// The resolve runs through the recording transport, so the captured bodies are
/// exactly what a production resolve of this DID asked for, and the fixture's
/// signal provenance is evidence rather than an assumption.
pub fn emit_minted(state: &MintState) -> Result<PathBuf, MintError> {
    let did = Did::from_str(&state.did)?;

    // Clone the recording handle BEFORE the transport is moved into the client:
    // the client consumes the transport by value and never gives it back.
    let transport = RecordingTransport::new(UreqTransport::new());
    let recording = transport.recording();
    let client = Client::new(state.endpoint.clone(), transport);

    // No `chain_tip_height` is supplied: the client fetches `/blocks/tip/height`
    // itself and the recorder captures whatever the chain reported, so the tip in
    // the fixture is the chain's own number and never one this tool chose.
    let options = options_for(&recorded_updates(state))?;
    let expected = expectation_of(&client, &did, state, options)?;

    let recorded = recording.borrow();
    let tip_height = recorded.tip.ok_or_else(|| MintError::NoTip {
        scenario: state.scenario.clone(),
    })?;
    let fixture = build_minted_fixture(state, tip_height, &recorded.addresses, expected)?;
    let path = fixture::write_atomic(&fixture)?;
    // The derived path runs through the crate manifest directory, so it carries
    // `../..` segments; the file exists by now, so report the resolved one.
    let path = std::fs::canonicalize(&path).unwrap_or(path);

    eprintln!("wrote {}", path.display());
    for contribution in minted_contributions(&state.scenario) {
        eprintln!("  covers: {contribution}");
    }
    Ok(path)
}

/// Map a `--scenario` value onto the name its state file records.
fn scenario_name(scenario: &str) -> Result<&'static str, MintError> {
    match scenario {
        "clean" => Ok(CLEAN_SCENARIO),
        "poisoned" => Ok(FORK_SCENARIO),
        other => Err(MintError::UnknownScenario {
            scenario: other.to_string(),
            known: "clean, poisoned".to_string(),
        }),
    }
}

/// Run a minting session: resolve the endpoint, load the key and the progress
/// file, then drive the requested scenario.
#[allow(clippy::too_many_arguments)]
pub fn run(
    scenario: &str,
    network: &str,
    esplora_url: Option<String>,
    bitcoind_url: Option<String>,
    bitcoind_auth: Option<String>,
    key_file: &Path,
    state_file: &Path,
    fee: u64,
    yes: bool,
) -> Result<(), MintError> {
    // The scenario name is checked before the endpoint, the key or the node, so a
    // typo costs nothing and touches nothing.
    let name = scenario_name(scenario)?;
    let base_url = targets::endpoint(network, esplora_url)?;
    let (beacon_sk, public_key) = keys(key_file)?;
    let client = Client::new(base_url.clone(), UreqTransport::new());
    let ops = chain::ops_for(network, base_url.clone(), bitcoind_url, bitcoind_auth)?;

    let mut state = load_or_init_state(state_file, name, network, &base_url, &client, &public_key)?;
    let genesis = client.create(&public_key, targets::network_from_dir(network)?)?;
    let session = MintSession {
        client: &client,
        ops: ops.as_ref(),
        state_path: state_file,
        beacon_sk,
        fee,
        yes,
    };

    if name == CLEAN_SCENARIO {
        mint_clean(
            &session,
            &mut state,
            &genesis,
            targets::network_from_dir(network)?,
        )
    } else {
        refuse_shared_did(&state.did, state_file)?;
        mint_fork(&session, &mut state, &genesis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_btcr2_client::TransportError;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A well-formed secret key, deliberately non-repetitive so the
    /// substring scan in `mint_errors_never_echo_key_bytes` is a real check.
    const KEY_HEX: &str = "4c9f3a71b2e85d06f13a7c58e29b4d70a6512f8c3d9e0b47a85c621f3e70d9ab";

    /// A transport that refuses every request.
    ///
    /// Everything this module does is offline, and `create` is pure composition
    /// over the sans-I/O core. A test that passes with this injected has proved
    /// the scaffolding touches no network.
    struct NoNetwork;

    impl BtcTransport for NoNetwork {
        fn execute(
            &self,
            _req: http::Request<Vec<u8>>,
        ) -> Result<http::Response<Vec<u8>>, TransportError> {
            Err(TransportError::Io(std::io::Error::other(
                "the minting scaffolding must not touch the network",
            )))
        }
    }

    /// A scratch directory unique to one test, removed by the test itself.
    fn scratch_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chain-capture-mint-{}-{tag}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");
        dir
    }

    fn offline_client() -> Client<NoNetwork> {
        Client::new("http://localhost:3000".to_string(), NoNetwork)
    }

    fn key_file(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("key.hex");
        std::fs::write(&path, contents).expect("the key file is writable");
        path
    }

    fn public_key() -> PublicKey {
        let (_, public_key) = sample_keys();
        public_key
    }

    /// The sample key, loaded through the real loader so the tests use the same
    /// path an operator does.
    fn sample_keys() -> (secp256k1::SecretKey, PublicKey) {
        let dir = scratch_dir("sample-keys");
        let path = key_file(&dir, KEY_HEX);
        let loaded = keys(&path).expect("the sample key loads");
        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
        loaded
    }

    /// The genesis document the sample key mints on `network`, with no network
    /// call: `create` is pure composition over the sans-I/O core.
    fn genesis_document(network: Network) -> Document {
        offline_client()
            .create(&public_key(), network)
            .expect("a key DID is created offline")
    }

    fn sample_state() -> MintState {
        MintState {
            scenario: "clean-rotating-beacons".to_string(),
            network: "regtest".to_string(),
            endpoint: "http://localhost:3000".to_string(),
            did: "did:btcr2:k1qsample".to_string(),
            beacons: vec!["addr-0".to_string(), "addr-1".to_string()],
            steps: vec![MintStep::broadcast(
                "v2-add-beacon-service".to_string(),
                1,
                2,
                "aa".repeat(32),
                json!({ "targetVersionId": 2 }),
            )],
        }
    }

    #[test]
    fn mint_state_round_trips_including_an_unconfirmed_step() {
        let state = sample_state();
        assert!(
            !state.steps[0].is_confirmed(),
            "a broadcast step starts unconfirmed"
        );

        let body = serde_json::to_string(&state).expect("the state serializes");
        let parsed: MintState = serde_json::from_str(&body).expect("the state deserializes");

        assert_eq!(parsed.scenario, state.scenario);
        assert_eq!(parsed.network, state.network);
        assert_eq!(parsed.endpoint, state.endpoint);
        assert_eq!(parsed.did, state.did);
        assert_eq!(parsed.beacons, state.beacons);
        assert_eq!(parsed.steps.len(), 1);
        assert_eq!(parsed.steps[0].name, state.steps[0].name);
        assert_eq!(parsed.steps[0].beacon_index, 1);
        assert_eq!(parsed.steps[0].target_version_id, 2);
        assert_eq!(parsed.steps[0].txid, state.steps[0].txid);
        assert_eq!(
            parsed.steps[0].block_height, UNCONFIRMED_HEIGHT,
            "the pre-confirmation sentinel survives a round trip"
        );
        assert!(!parsed.steps[0].is_confirmed());
        assert_eq!(parsed.steps[0].update, state.steps[0].update);
        assert!(
            !body.contains(KEY_HEX),
            "the state file holds no key material"
        );
    }

    #[test]
    fn load_or_init_state_creates_the_did_and_records_three_beacons() {
        let dir = scratch_dir("init");
        let path = dir.join("state.json");

        let state = load_or_init_state(
            &path,
            "clean-rotating-beacons",
            "regtest",
            "http://localhost:3000",
            &offline_client(),
            &public_key(),
        )
        .expect("a fresh session initializes with no network");

        assert!(state.did.starts_with("did:btcr2:k1"), "{}", state.did);
        assert_eq!(state.beacons.len(), 3, "three derived beacons, in order");
        assert!(state.steps.is_empty());
        assert!(path.exists(), "the state file is written on the fresh path");

        // A second call with the same arguments resumes rather than re-minting.
        let resumed = load_or_init_state(
            &path,
            "clean-rotating-beacons",
            "regtest",
            "http://localhost:3000",
            &offline_client(),
            &public_key(),
        )
        .expect("the same session resumes");
        assert_eq!(resumed.did, state.did);
        assert_eq!(resumed.beacons, state.beacons);

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn load_or_init_state_rejects_a_mismatched_scenario_network_or_did() {
        let dir = scratch_dir("mismatch");
        let path = dir.join("state.json");
        load_or_init_state(
            &path,
            "clean-rotating-beacons",
            "regtest",
            "http://localhost:3000",
            &offline_client(),
            &public_key(),
        )
        .expect("a fresh session initializes");

        // A different scenario against the same file.
        let error = load_or_init_state(
            &path,
            "late-publishing-fork",
            "regtest",
            "http://localhost:3000",
            &offline_client(),
            &public_key(),
        )
        .expect_err("a different scenario cannot reuse this state");
        assert!(
            matches!(error, MintError::StateMismatch { ref field, .. } if field == "scenario"),
            "got {error:?}"
        );

        // A different chain: the same key mints a different DID there, so the
        // network guard is what has to fire first.
        let error = load_or_init_state(
            &path,
            "clean-rotating-beacons",
            "signet",
            "http://localhost:3000",
            &offline_client(),
            &public_key(),
        )
        .expect_err("a session cannot continue on another chain");
        assert!(
            matches!(error, MintError::StateMismatch { ref field, .. } if field == "network"),
            "got {error:?}"
        );

        // A different DID, with everything else matching.
        let mut state = sample_state();
        state.scenario = "clean-rotating-beacons".to_string();
        state.network = "regtest".to_string();
        write_state_atomic(&path, &state).expect("the substituted state is writable");
        let error = load_or_init_state(
            &path,
            "clean-rotating-beacons",
            "regtest",
            "http://localhost:3000",
            &offline_client(),
            &public_key(),
        )
        .expect_err("a state file for another DID is refused");
        match &error {
            MintError::StateMismatch {
                field,
                in_file,
                requested,
            } => {
                assert_eq!(field, "did");
                assert_eq!(in_file, "did:btcr2:k1qsample");
                assert!(requested.starts_with("did:btcr2:k1"), "{requested}");
            }
            other => panic!("expected StateMismatch, got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn beacon_addresses_come_from_the_requested_chain() {
        let dir = scratch_dir("hrps");

        let regtest = load_or_init_state(
            &dir.join("regtest.json"),
            "clean-rotating-beacons",
            "regtest",
            "http://localhost:3000",
            &offline_client(),
            &public_key(),
        )
        .expect("a regtest session initializes");
        // Document order is P2PKH, P2WPKH, P2TR; the core crate derives each one
        // for the requested network, so the encodings differ per chain without
        // this module knowing any of them.
        assert!(
            regtest.beacons[0].starts_with('m') || regtest.beacons[0].starts_with('n'),
            "regtest P2PKH: {}",
            regtest.beacons[0]
        );
        assert!(
            regtest.beacons[1].starts_with("bcrt1q"),
            "regtest P2WPKH: {}",
            regtest.beacons[1]
        );
        assert!(
            regtest.beacons[2].starts_with("bcrt1p"),
            "regtest P2TR: {}",
            regtest.beacons[2]
        );

        let signet = load_or_init_state(
            &dir.join("signet.json"),
            "clean-rotating-beacons",
            "signet",
            "http://localhost:3000",
            &offline_client(),
            &public_key(),
        )
        .expect("a signet session initializes");
        assert!(
            signet.beacons[1].starts_with("tb1q"),
            "signet P2WPKH: {}",
            signet.beacons[1]
        );
        assert!(
            signet.beacons[2].starts_with("tb1p"),
            "signet P2TR: {}",
            signet.beacons[2]
        );
        assert_ne!(
            regtest.did, signet.did,
            "the same key mints a different DID per chain"
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn vm_id_names_the_documents_initial_key() {
        let did = "did:btcr2:k1abc";
        // Built rather than written out, so the format string in the tool stays
        // the only place that fragment appears.
        assert_eq!(vm_id(did), format!("{did}{}initialKey", '#'));
    }

    #[test]
    fn the_key_loader_rejects_a_short_a_long_and_a_non_hex_file() {
        let dir = scratch_dir("bad-keys");

        for (contents, expected) in [
            (KEY_HEX[..63].to_string(), REASON_LENGTH),
            (format!("{KEY_HEX}00"), REASON_LENGTH),
            (format!("{}zz", &KEY_HEX[..62]), REASON_HEX),
            ("0".repeat(64), REASON_SCALAR),
        ] {
            let path = key_file(&dir, &contents);
            let error = keys(&path).expect_err("a malformed key file is rejected");
            match &error {
                MintError::KeyFile { reason, .. } => assert_eq!(
                    *reason, expected,
                    "the reason names the fault for `{contents}`"
                ),
                other => panic!("expected KeyFile, got {other:?}"),
            }
        }

        // Surrounding whitespace is tolerated, so a file written with a trailing
        // newline is not a fault the operator has to discover.
        let path = key_file(&dir, &format!("  {KEY_HEX}\n"));
        keys(&path).expect("a trimmed key file loads");

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn mint_errors_never_echo_key_bytes() {
        let dir = scratch_dir("no-echo");
        let good = key_file(&dir, KEY_HEX);
        keys(&good).expect("the sample key file loads");

        // Every error a key-handling path can produce, from the loader itself and
        // from the variants around it.
        let mut errors = Vec::new();
        for contents in [
            KEY_HEX[..63].to_string(),
            format!("{KEY_HEX}00"),
            format!("{}zz", &KEY_HEX[..62]),
            "0".repeat(64),
        ] {
            let path = key_file(&dir, &contents);
            errors.push(keys(&path).expect_err("a corrupted key file is rejected"));
        }
        errors.push(keys(&dir.join("absent.hex")).expect_err("an absent key file is rejected"));
        for reason in [REASON_LENGTH, REASON_HEX, REASON_SCALAR] {
            errors.push(MintError::KeyFile {
                path: good.display().to_string(),
                reason,
            });
        }
        errors.push(MintError::Declined);
        errors.push(MintError::NoDid);
        errors.push(MintError::StateMismatch {
            field: "did".to_string(),
            in_file: "did:btcr2:k1one".to_string(),
            requested: "did:btcr2:k1two".to_string(),
        });

        for error in &errors {
            let rendered = format!("{error} {error:?}");
            assert!(
                !rendered.contains(KEY_HEX),
                "an error rendered the whole key: {rendered}"
            );
            for start in 0..=KEY_HEX.len() - 16 {
                let window = &KEY_HEX[start..start + 16];
                assert!(
                    !rendered.contains(window),
                    "an error rendered `{window}`, 16 characters of the key: {rendered}"
                );
            }
        }

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn require_confirmation_is_satisfied_by_an_explicit_yes_flag() {
        require_confirmation(
            &broadcast_prompt("regtest", "the version 2 announcement"),
            true,
        )
        .expect("--yes skips the prompt");
    }

    #[test]
    fn the_prompt_names_the_chain_and_whether_the_broadcast_is_reversible() {
        let local = broadcast_prompt("regtest", "the version 2 announcement");
        assert!(local.contains("regtest"), "{local}");
        assert!(local.contains("disposable"), "{local}");

        for public in [
            "mutinynet",
            "testnet4",
            "signet",
            "a-chain-we-have-not-used",
        ] {
            let prompt = broadcast_prompt(public, "the version 2 announcement");
            assert!(prompt.contains(public), "{prompt}");
            assert!(
                prompt.contains("permanent"),
                "an unrecognized chain is described as permanent: {prompt}"
            );
        }
    }

    #[test]
    fn write_state_atomic_leaves_no_temporary_behind() {
        let dir = scratch_dir("atomic-ok");
        let path = dir.join("nested/state.json");
        let state = sample_state();

        write_state_atomic(&path, &state).expect("the write succeeds");

        let body = std::fs::read_to_string(&path).expect("the state was written");
        assert!(
            body.lines().count() > 5,
            "a pretty-printed body is multi-line: {body}"
        );
        assert!(
            !dir.join("nested/state.json.tmp").exists(),
            "the temporary file must be renamed away, not left behind"
        );
        let parsed: MintState = serde_json::from_str(&body).expect("the written body reparses");
        assert_eq!(parsed.did, state.did);

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn a_failed_state_write_never_truncates_the_previous_file() {
        let dir = scratch_dir("atomic-fail");
        let path = dir.join("state.json");
        std::fs::write(&path, b"{\"previous\": true}").expect("the previous state is written");

        // Occupy the temporary path with a directory so the write half fails
        // after the body has been built and before the target is touched.
        std::fs::create_dir(dir.join("state.json.tmp")).expect("the blocker is creatable");

        let error =
            write_state_atomic(&path, &sample_state()).expect_err("the temporary write must fail");
        assert!(matches!(error, MintError::Io(_)), "got {error}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("the previous state survives"),
            "{\"previous\": true}",
            "a failed write must leave the previous state byte-identical"
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn a_step_is_recorded_before_its_confirmation_can_land() {
        let dir = scratch_dir("record-step");
        let path = dir.join("state.json");
        let mut state = sample_state();
        state.steps.clear();
        write_state_atomic(&path, &state).expect("the initial state is writable");

        ensure_step_recorded(
            &mut state,
            &path,
            MintStep::broadcast(
                "v2-add-beacon-service".to_string(),
                1,
                2,
                "bb".repeat(32),
                json!({ "targetVersionId": 2 }),
            ),
        )
        .expect("the step is recorded");

        let persisted: MintState =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the state is readable"))
                .expect("the state reparses");
        assert_eq!(persisted.steps.len(), 1);
        assert_eq!(persisted.steps[0].txid, "bb".repeat(32));
        assert!(
            !persisted.steps[0].is_confirmed(),
            "the txid is on disk before the wait, with no block yet"
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn the_clean_step_table_is_three_versions_across_three_beacons() {
        // Asserted by VALUE, not re-derived: the whole point of the scenario is
        // that consecutive versions are announced from DIFFERENT beacons, and a
        // test that recomputed the table from the table would not notice a
        // rotation collapsing back onto one address.
        let table: Vec<(&str, u64, usize)> = CLEAN_STEPS
            .iter()
            .map(|step| (step.name, step.target_version_id, step.beacon_index))
            .collect();
        assert_eq!(
            table,
            vec![
                ("v2-add-beacon-service", 2, 1),
                ("v3-add-non-beacon-service", 3, 2),
                ("v4-deactivate", 4, 0),
            ]
        );

        let versions: Vec<u64> = CLEAN_STEPS.iter().map(|s| s.target_version_id).collect();
        assert_eq!(versions, vec![2, 3, 4], "consecutive versions");
        let mut beacons: Vec<usize> = CLEAN_STEPS.iter().map(|s| s.beacon_index).collect();
        beacons.sort_unstable();
        beacons.dedup();
        assert_eq!(
            beacons.len(),
            CLEAN_STEPS.len(),
            "every step announces from a beacon no other step uses"
        );
    }

    #[test]
    fn the_clean_patches_are_well_formed_rfc_6902_against_the_documents_they_extend() {
        let genesis = genesis_document(Network::Regtest);
        let did = genesis.as_ref()["id"]
            .as_str()
            .expect("the created document names its DID")
            .to_string();
        let extra = extra_beacon_address(&sample_keys().0, Network::Regtest)
            .expect("the extra beacon address derives");

        // Building the patch at all proves it parses as `json_patch::Patch`; the
        // assertions below pin what it says.
        let beacon_patch = serde_json::to_value(add_beacon_service_patch(&did, &extra))
            .expect("a patch serializes back to JSON");
        assert_eq!(beacon_patch[0]["op"], json!("add"));
        assert_eq!(
            beacon_patch[0]["path"],
            json!("/service/3"),
            "the genesis document declares three services, so this appends a fourth"
        );
        assert_eq!(beacon_patch[0]["value"]["type"], json!("SingletonBeacon"));
        assert_eq!(
            beacon_patch[0]["value"]["serviceEndpoint"],
            json!(format!("bitcoin:{extra}")),
            "the endpoint carries the derived address, never a literal"
        );

        let service_patch = serde_json::to_value(add_non_beacon_service_patch(&did))
            .expect("a patch serializes back to JSON");
        assert_eq!(
            service_patch[0]["path"],
            json!("/service/4"),
            "the version 3 update appends after the beacon the version 2 update added"
        );
        assert_eq!(
            service_patch[0]["value"]["type"],
            json!("DecentralizedWebNode"),
            "a service the beacon list skips and the document retains"
        );

        // The patches are RFC-6902 documents the core accepts against the state
        // they are built for: applying them proves the paths exist.
        let mut doc = genesis.as_ref().clone();
        json_patch::patch(&mut doc, &add_beacon_service_patch(&did, &extra))
            .expect("the version 2 patch applies to the genesis document");
        json_patch::patch(&mut doc, &add_non_beacon_service_patch(&did))
            .expect("the version 3 patch applies to the version 2 document");
        assert_eq!(
            doc["service"].as_array().map(Vec::len),
            Some(5),
            "three derived beacons, the rotated beacon, and the non-beacon service"
        );
    }

    #[test]
    fn the_extra_beacon_address_is_deterministic_and_chain_specific() {
        let (secret, _) = sample_keys();

        let once = extra_beacon_address(&secret, Network::Regtest).expect("it derives");
        let twice = extra_beacon_address(&secret, Network::Regtest).expect("it derives again");
        assert_eq!(
            once, twice,
            "the same key in must yield the same address out, or the runbook cannot \
             reproduce it"
        );

        // No human-readable part is written anywhere in this module: the address
        // constructor is given the chain and produces the right encoding for it.
        assert!(once.to_string().starts_with("bcrt1q"), "{once}");
        let signet = extra_beacon_address(&secret, Network::Signet).expect("it derives on signet");
        assert!(signet.to_string().starts_with("tb1q"), "{signet}");
        assert_ne!(
            once, signet,
            "the same key yields a different encoding per chain"
        );
    }

    #[test]
    fn the_extra_beacon_address_is_none_of_the_documents_own_beacons() {
        let (secret, _) = sample_keys();
        let extra = extra_beacon_address(&secret, Network::Regtest).expect("it derives");
        let genesis = genesis_document(Network::Regtest);

        for (index, beacon) in genesis.beacons().enumerate() {
            assert_ne!(
                beacon.address(),
                &extra,
                "beacon {index} must differ from the extra beacon, or the version 2 \
                 update would add an address the resolver already queries and the \
                 rotation would prove nothing"
            );
        }
    }

    #[test]
    fn the_extra_beacon_key_derivation_survives_an_out_of_range_first_hash() {
        // All-ones is above the secp256k1 group order, so the first candidate is
        // rejected and the loop must re-hash rather than fail.
        let refused = [0xffu8; 32];
        assert!(
            secp256k1::SecretKey::from_slice(&refused).is_err(),
            "this test is only meaningful while all-ones is not a valid scalar"
        );

        let derived = address_from_hash_seed(refused, Network::Regtest)
            .expect("an out-of-range first hash is retried, not fatal");
        let next: [u8; 32] = Sha256::digest(refused).into();
        assert_eq!(
            derived,
            address_from_hash_seed(next, Network::Regtest).expect("the retried seed derives"),
            "the retry advanced to the next hash rather than returning something else"
        );
    }

    #[test]
    fn a_confirmed_step_is_skipped_and_a_broadcast_one_is_waited_for() {
        let mut state = sample_state();
        // `sample_state` carries `v2-add-beacon-service` broadcast but not yet
        // confirmed: a resume owes it a wait on the txid it already has, never a
        // second broadcast.
        assert_eq!(
            resume_action(&state, "v2-add-beacon-service"),
            StepAction::AwaitConfirmation("aa".repeat(32))
        );
        assert_eq!(
            resume_action(&state, "v3-add-non-beacon-service"),
            StepAction::Announce,
            "a step with no record at all is announced"
        );

        state.steps[0].block_height = 212;
        assert_eq!(
            resume_action(&state, "v2-add-beacon-service"),
            StepAction::Done,
            "a confirmed step is skipped entirely on resume"
        );
    }

    #[test]
    fn a_step_recorded_before_the_wait_is_confirmed_in_place() {
        let dir = scratch_dir("confirm-step");
        let path = dir.join("state.json");
        let mut state = sample_state();
        state.steps.clear();
        write_state_atomic(&path, &state).expect("the initial state is writable");

        ensure_step_recorded(
            &mut state,
            &path,
            MintStep::broadcast(
                CLEAN_STEPS[0].name.to_string(),
                CLEAN_STEPS[0].beacon_index,
                CLEAN_STEPS[0].target_version_id,
                "cc".repeat(32),
                json!({ "targetVersionId": 2 }),
            ),
        )
        .expect("the step is recorded before any wait");

        let before: MintState =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("readable"))
                .expect("reparses");
        assert_eq!(before.steps[0].block_height, UNCONFIRMED_HEIGHT);
        assert_eq!(before.steps[0].block_time, 0);

        confirm_step(&mut state, &path, CLEAN_STEPS[0].name, 213, 1_700_000_500)
            .expect("the confirmation is written in place");

        let after: MintState =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("readable"))
                .expect("reparses");
        assert_eq!(
            after.steps.len(),
            1,
            "the confirmation updates the step, it does not append a second one"
        );
        assert_eq!(after.steps[0].txid, "cc".repeat(32), "same announcement");
        assert_eq!(after.steps[0].block_height, 213);
        assert_eq!(after.steps[0].block_time, 1_700_000_500);
        assert!(after.steps[0].is_confirmed());

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn an_unknown_scenario_is_refused_by_name_before_anything_is_contacted() {
        assert_eq!(
            scenario_name("clean").expect("the clean scenario is mapped"),
            CLEAN_SCENARIO
        );

        let error = scenario_name("cleanup").expect_err("a near miss is not accepted");
        match &error {
            MintError::UnknownScenario { scenario, known } => {
                assert_eq!(scenario, "cleanup");
                assert!(
                    known.contains("clean"),
                    "the message lists what exists: {known}"
                );
            }
            other => panic!("expected UnknownScenario, got {other:?}"),
        }
    }

    #[test]
    fn the_announcing_beacons_of_the_clean_scenario_are_three_distinct_addresses() {
        let genesis = genesis_document(Network::Regtest);
        let beacons = announcing_beacons(&genesis, &CLEAN_STEPS).expect("all three resolve");

        assert_eq!(
            beacons.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            vec![1, 2, 0],
            "reported in the order the steps use them, so one faucet visit covers them"
        );
        let mut addresses: Vec<&str> = beacons.iter().map(|(_, a)| a.as_str()).collect();
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(addresses.len(), 3, "three different addresses");

        // A document with no beacon at the requested index names the step rather
        // than panicking on the index.
        let stripped = {
            let mut json = genesis.as_ref().clone();
            json["service"] = json!([json["service"][0].clone()]);
            Document::from_json_value(json).expect("a one-beacon document is conformant")
        };
        let error = announcing_beacons(&stripped, &CLEAN_STEPS)
            .expect_err("a missing beacon is an error, not a panic");
        assert!(
            matches!(error, MintError::NoBeacon { ref name, index: 1 } if name == "v2-add-beacon-service"),
            "got {error:?}"
        );
    }
    #[test]
    fn the_fork_step_table_is_two_version_2_announcements_from_one_beacon() {
        let table: Vec<(&str, u64, usize)> = FORK_STEPS
            .iter()
            .map(|step| (step.name, step.target_version_id, step.beacon_index))
            .collect();
        assert_eq!(
            table,
            vec![("v2-branch-a", 2, 1), ("v2-branch-b", 2, 1)],
            "both branches target version 2 from the same beacon: the anomaly is two \
             conflicting histories, not two addresses"
        );
    }

    #[test]
    fn the_two_fork_patches_are_well_formed_rfc_6902_and_differ() {
        let genesis = genesis_document(Network::Regtest);
        let did = genesis.as_ref()["id"]
            .as_str()
            .expect("the created document names its DID")
            .to_string();

        let branch_a = fork_branch_patch(&did, FORK_STEPS[0].name);
        let branch_b = fork_branch_patch(&did, FORK_STEPS[1].name);
        let json_a = serde_json::to_value(&branch_a).expect("a patch serializes back");
        let json_b = serde_json::to_value(&branch_b).expect("a patch serializes back");

        assert_eq!(json_a[0]["path"], json!("/service/3"));
        assert_eq!(json_b[0]["path"], json!("/service/3"));
        assert_ne!(
            json_a, json_b,
            "identical patches would produce identical update hashes, and two \
             announcements of the SAME update are a duplicate, not a fork"
        );

        // Both apply to the SAME genesis document: that is what makes them a fork.
        for patch in [&branch_a, &branch_b] {
            let mut doc = genesis.as_ref().clone();
            json_patch::patch(&mut doc, patch)
                .expect("each branch's patch applies to the genesis document");
            assert_eq!(doc["service"].as_array().map(Vec::len), Some(4));
        }
    }

    #[test]
    fn the_second_fork_branch_is_signed_against_the_retained_genesis_document() {
        // Two documents that are trivially distinguishable, standing in for
        // "genesis" and "whatever a re-resolve would have reported".
        let genesis = genesis_document(Network::Regtest);
        let contemporary = genesis_document(Network::Signet);
        assert_ne!(
            genesis.as_ref()["id"],
            contemporary.as_ref()["id"],
            "the two stand-ins must differ or this test proves nothing"
        );

        assert_eq!(
            source_document_for(FORK_STEPS[1].name, &genesis, &contemporary).as_ref()["id"],
            genesis.as_ref()["id"],
            "branch B signs against the RETAINED genesis: an update built from the \
             contemporary state after branch A confirmed would be a legitimate \
             version 3, not a conflicting version 2"
        );
        for step in [FORK_STEPS[0].name, CLEAN_STEPS[0].name, CLEAN_STEPS[2].name] {
            assert_eq!(
                source_document_for(step, &genesis, &contemporary).as_ref()["id"],
                contemporary.as_ref()["id"],
                "{step} signs against the state the chain reports"
            );
        }
    }

    /// A fork state whose two branches confirmed at the given heights.
    fn fork_state(height_a: u32, height_b: u32) -> MintState {
        let branch = |step: &ScenarioStep, txid: &str, height: u32| {
            let mut recorded = MintStep::broadcast(
                step.name.to_string(),
                step.beacon_index,
                step.target_version_id,
                txid.repeat(32),
                json!({ "targetVersionId": step.target_version_id }),
            );
            recorded.block_height = height;
            recorded
        };
        MintState {
            scenario: FORK_SCENARIO.to_string(),
            network: "regtest".to_string(),
            endpoint: "http://localhost:3000".to_string(),
            did: "did:btcr2:k1qsample".to_string(),
            beacons: vec!["addr-0".to_string(), "addr-1".to_string()],
            steps: vec![
                branch(&FORK_STEPS[0], "aa", height_a),
                branch(&FORK_STEPS[1], "bb", height_b),
            ],
        }
    }

    #[test]
    fn two_branches_in_one_block_are_rejected() {
        require_distinct_heights(&fork_state(213, 214))
            .expect("a later second branch is what the scenario is for");

        for (height_a, height_b) in [(213, 213), (214, 213)] {
            let error = require_distinct_heights(&fork_state(height_a, height_b))
                .expect_err("two indistinguishable announcements must not pass");
            match &error {
                MintError::SameBlock {
                    name_a,
                    name_b,
                    height,
                } => {
                    assert_eq!(name_a, "v2-branch-a");
                    assert_eq!(name_b, "v2-branch-b");
                    assert_eq!(*height, height_b);
                }
                other => panic!("expected SameBlock, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_same_block_advice_is_the_one_that_actually_recovers() {
        let message = MintError::SameBlock {
            name_a: FORK_STEPS[0].name.to_string(),
            name_b: FORK_STEPS[1].name.to_string(),
            height: 213,
        }
        .to_string();

        assert!(
            message.contains("v2-branch-a") && message.contains("v2-branch-b"),
            "{message}"
        );
        assert!(
            message.contains("213"),
            "the message names the block: {message}"
        );

        // The two needles are spelled in pieces so the advice itself has exactly
        // one home in this module — the error's own message.
        let recover = format!("delete the state {}", "file");
        assert!(
            message.contains(&recover) && message.contains("fresh key"),
            "the advice must be delete-state-and-restart-from-genesis: {message}"
        );
        let futile = format!("mint branch {} again", "b");
        assert!(
            !message.to_lowercase().contains(&futile),
            "telling the operator to re-mint the second branch cannot work — it is \
             already confirmed by the time the heights are compared, so a retry adds \
             a THIRD version 2 announcement: {message}"
        );
        assert!(
            message.contains("THIRD"),
            "the message says what a retry would actually do: {message}"
        );
    }

    #[test]
    fn the_fork_scenario_refuses_a_did_a_clean_session_already_claims() {
        let dir = scratch_dir("shared-did");
        let own = dir.join("poisoned.json");
        let did = "did:btcr2:k1qsample";

        // Nothing beside it yet: the guard has no evidence and permits the run.
        refuse_shared_did(did, &own).expect("an empty directory is not evidence");

        // A file that is not a minting state file is ignored rather than fatal.
        std::fs::write(dir.join("notes.txt"), b"not a state file").expect("writable");
        refuse_shared_did(did, &own).expect("an unrelated file is not evidence either");

        let mut clean = sample_state();
        clean.did = did.to_string();
        write_state_atomic(&dir.join("clean.json"), &clean).expect("writable");

        let error = refuse_shared_did(did, &own)
            .expect_err("a fork on a DID being minted clean must be refused");
        match &error {
            MintError::SharedDid {
                did: named,
                state_file,
            } => {
                assert_eq!(named, did);
                assert!(state_file.ends_with("clean.json"), "{state_file}");
            }
            other => panic!("expected SharedDid, got {other:?}"),
        }
        assert!(
            error.to_string().contains("--key-file"),
            "the message names the next action: {error}"
        );

        // A different DID under the same roof is fine: two scenarios are expected
        // to sit side by side, on separate keys.
        refuse_shared_did("did:btcr2:k1qother", &own)
            .expect("another DID's clean session is not this one's problem");

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn the_anomaly_is_recognized_by_variant_and_not_by_wording() {
        use did_btcr2::error::Btcr2Error;
        use did_btcr2::resolver::Error as ResolverError;

        assert!(is_late_publishing(&did_btcr2_client::Error::Resolver(
            ResolverError::Btcr2Error(Btcr2Error::LatePublishingError(
                "Found hash `aa`, expected `bb`".to_string()
            ))
        )));
        assert!(is_late_publishing(&did_btcr2_client::Error::Btcr2(
            Btcr2Error::LatePublishingError("Found hash `aa`, expected `bb`".to_string())
        )));

        // A different failure that merely MENTIONS the anomaly is not the anomaly:
        // a substring check on the rendered message would accept this and let a
        // scenario be declared poisoned when it is only broken.
        assert!(!is_late_publishing(&did_btcr2_client::Error::Btcr2(
            Btcr2Error::InvalidDidUpdate("late publishing was suspected".to_string())
        )));
        assert!(!is_late_publishing(&did_btcr2_client::Error::Resolver(
            ResolverError::UpdateHashMismatch
        )));
        assert!(!is_late_publishing(&did_btcr2_client::Error::NoBeacon));
    }

    /// A DID from the vendor regtest vectors, so the emission tests carry a real
    /// identifier rather than one this test invented.
    const MINTED_DID: &str =
        "did:btcr2:k1qgppexmyqqlce9netky3h4ur2j9dur83j7m7vva497kfhdgsq2t9nxgqj3x0s";

    /// A signed update the core crate parses, targeting `version`.
    ///
    /// Field order is deliberately NOT alphabetical, so an announcement hash
    /// computed without JCS canonicalization would differ from the one the
    /// emission looks for.
    fn signed_update(version: u64, salt: &str) -> Value {
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
                "verificationMethod": format!("{MINTED_DID}#initialKey"),
                "proofPurpose": "capabilityInvocation",
                "capability": format!("urn:zcap:root:did%3Abtcr2%3A{MINTED_DID}"),
                "capabilityAction": "Write",
                "proofValue": "z4uLUfMjfUufPGgeXa9ZgJ1DR7bnH7FAkHVf83ebT1C4iwFtiJPPNgStUrT9cpV2h8PKdN6RH4TFJgrRd7APPBqWA",
            },
        })
    }

    /// A finished session's state file, with one confirmed step per update.
    fn minted_state(scenario: &str, network: &str, updates: Vec<Value>) -> MintState {
        let steps = updates
            .into_iter()
            .enumerate()
            .map(|(index, update)| MintStep {
                name: format!("v{}-step", index + 2),
                beacon_index: index,
                target_version_id: index as u64 + 2,
                txid: format!("{:02x}", 0xd0 + index).repeat(32),
                block_height: 100 + index as u32,
                block_time: 1_700_000_000 + index as i64,
                update,
            })
            .collect();
        MintState {
            scenario: scenario.to_string(),
            network: network.to_string(),
            endpoint: "http://localhost:3000".to_string(),
            did: MINTED_DID.to_string(),
            beacons: vec!["addr-0".to_string(), "addr-1".to_string()],
            steps,
        }
    }

    /// An Esplora transaction whose LAST output announces `hash`.
    fn announcement(hash: [u8; 32], txid_seed: u8, height: u32) -> Value {
        json!({
            "txid": format!("{txid_seed:02x}").repeat(32),
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

    /// Captured bodies announcing every update in `state`, all from one address.
    fn bodies_announcing(state: &MintState) -> BTreeMap<String, Vec<Value>> {
        let hashes = validate::update_hashes(&minted_vector(state), &minted_sidecar(state))
            .expect("the minted sidecar hashes");
        let txs = hashes
            .iter()
            .enumerate()
            .map(|(index, hash)| announcement(*hash, 0xd0 + index as u8, 100 + index as u32))
            .collect();
        BTreeMap::from([("bcrt1qbeacon".to_string(), txs)])
    }

    #[test]
    fn minted_expected_records_no_confirmations() {
        let document = json!({ "id": MINTED_DID });
        let expected = clean_expected(&document, 4);

        assert!(
            expected["didDocumentMetadata"]
                .get("confirmations")
                .is_none(),
            "the expectation must not bake a confirmations count: {expected}"
        );
        assert!(
            expected.get("confirmations").is_none(),
            "not at the top level either: {expected}"
        );
        // Nor the two numbers a confirmations count would be derived from: every
        // rung of the chain ladder regenerates both.
        for baked in ["blockHeight", "block_height", "tipHeight", "tip_height"] {
            assert!(
                expected["didDocumentMetadata"].get(baked).is_none()
                    && expected.get(baked).is_none(),
                "the expectation must not bake `{baked}`: {expected}"
            );
        }

        let fork = fork_expected();
        assert!(
            fork.get("confirmations").is_none(),
            "the fork aborts before any confirmations are reported: {fork}"
        );
    }

    #[test]
    fn the_clean_expectation_states_version_four_as_an_ascii_string() {
        let document = json!({ "id": MINTED_DID, "service": [] });
        let expected = clean_expected(&document, 4);

        assert_eq!(expected["didDocument"], document);
        assert_eq!(
            expected["didDocumentMetadata"],
            json!({ "versionId": "4", "deactivated": true }),
        );
        assert!(
            expected["didDocumentMetadata"]["versionId"].is_string(),
            "the specification carries versionId as a string, and a JSON number \
             here would make the replay assert the wrong encoding: {expected}"
        );
    }

    #[test]
    fn the_fork_expectation_is_the_late_publishing_problem_code() {
        assert_eq!(fork_expected(), json!({ "error": "LATE_PUBLISHING" }));
        assert!(
            fork_expected().get("didDocument").is_none(),
            "a resolve that aborts produces no document to assert"
        );
    }

    #[test]
    fn the_minted_sidecar_carries_every_update_in_step_order() {
        let updates = vec![
            signed_update(2, "first"),
            signed_update(3, "second"),
            signed_update(4, "third"),
        ];
        let state = minted_state(CLEAN_SCENARIO, "regtest", updates.clone());
        let sidecar = minted_sidecar(&state);

        assert_eq!(
            sidecar["updates"],
            Value::Array(updates),
            "the sidecar is every announced update, in the order it was announced"
        );
    }

    #[test]
    fn a_minted_fixture_is_filed_under_its_scenario_name() {
        let state = minted_state(CLEAN_SCENARIO, "regtest", vec![signed_update(2, "a")]);
        let fixture = build_minted_fixture(
            &state,
            212,
            &bodies_announcing(&state),
            clean_expected(&json!({ "id": MINTED_DID }), 4),
        )
        .expect("a capture that announces every update builds a fixture");

        assert_eq!(fixture.vector, "minted/clean-rotating-beacons");
        let path = fixture::fixture_path(&fixture.vector).expect("the minted id is safe");
        assert!(
            path.to_string_lossy()
                .ends_with("fixtures/chain/minted/clean-rotating-beacons.json"),
            "the minted fixture lands under fixtures/chain/minted/: {}",
            path.display()
        );

        let fork = minted_state(FORK_SCENARIO, "regtest", vec![signed_update(2, "a")]);
        assert_eq!(minted_vector(&fork), "minted/late-publishing-fork");
    }

    #[test]
    fn a_minted_fixture_records_the_chain_the_session_ran_on() {
        // The same scenario on a different chain: the fixture takes the chain from
        // the session rather than from a constant, which is what lets the scenario
        // be re-minted on a public chain with no code change.
        for network in ["regtest", "mutinynet"] {
            let state = minted_state(CLEAN_SCENARIO, network, vec![signed_update(2, "a")]);
            let fixture = build_minted_fixture(
                &state,
                212,
                &bodies_announcing(&state),
                clean_expected(&json!({ "id": MINTED_DID }), 4),
            )
            .expect("a sound capture builds a fixture");

            assert_eq!(fixture.network, network);
            assert_eq!(fixture.did, MINTED_DID);
            assert_eq!(fixture.endpoint, state.endpoint);
            assert_eq!(fixture.tip_height, 212);
            assert!(fixture.sidecar.is_some() && fixture.expected.is_some());
        }
    }

    #[test]
    fn an_emission_whose_capture_misses_an_announcement_is_refused() {
        let state = minted_state(
            CLEAN_SCENARIO,
            "regtest",
            vec![signed_update(2, "announced"), signed_update(3, "silent")],
        );
        let hashes = validate::update_hashes(&minted_vector(&state), &minted_sidecar(&state))
            .expect("the minted sidecar hashes");
        // Only the FIRST update is announced.
        let addresses = BTreeMap::from([(
            "bcrt1qbeacon".to_string(),
            vec![announcement(hashes[0], 0xd0, 100)],
        )]);

        let error = build_minted_fixture(
            &state,
            212,
            &addresses,
            clean_expected(&json!({ "id": MINTED_DID }), 4),
        )
        .expect_err("a half-announced history must not be written");

        let message = error.to_string();
        assert!(
            matches!(error, MintError::MissingSignal { ref scenario, .. } if scenario == CLEAN_SCENARIO),
            "got: {error}"
        );
        assert!(
            message.contains(CLEAN_SCENARIO) && message.contains(&hex::encode(hashes[1])),
            "the refusal names the scenario and the missing announcement: {message}"
        );
    }

    #[test]
    fn emission_runs_from_a_completed_state_file_alone() {
        // No key file, no chain, no minting: a completed state file is the whole
        // input, which is what makes a lost fixture regenerable.
        let dir = scratch_dir("emit-from-state");
        let path = dir.join("clean-state.json");
        let state = minted_state(
            CLEAN_SCENARIO,
            "regtest",
            vec![signed_update(2, "a"), signed_update(3, "b")],
        );
        write_state_atomic(&path, &state).expect("the completed state file is written");

        let reloaded: MintState =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the state file is read"))
                .expect("the state file parses");
        let fixture = build_minted_fixture(
            &reloaded,
            212,
            &bodies_announcing(&reloaded),
            clean_expected(&json!({ "id": MINTED_DID }), 4),
        )
        .expect("a completed state file emits without re-minting");

        assert_eq!(
            fixture.signals.len(),
            2,
            "both announcements are provenance"
        );
        assert_eq!(
            fixture.sidecar.as_ref().expect("the sidecar travels")["updates"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn each_scenario_names_what_no_upstream_vector_covers() {
        let clean = minted_contributions(CLEAN_SCENARIO);
        assert!(
            clean
                .iter()
                .any(|line| line.contains("multi-update sequencing")),
            "got: {clean:?}"
        );
        assert!(
            clean.iter().any(|line| line.contains("deactivation")),
            "got: {clean:?}"
        );
        let fork = minted_contributions(FORK_SCENARIO);
        assert!(
            fork.iter().any(|line| line.contains("late publishing")),
            "got: {fork:?}"
        );
    }

    #[test]
    fn both_scenario_names_map_to_the_names_their_state_files_record() {
        assert_eq!(scenario_name("clean").expect("mapped"), CLEAN_SCENARIO);
        assert_eq!(scenario_name("poisoned").expect("mapped"), FORK_SCENARIO);
        assert_ne!(
            CLEAN_SCENARIO, FORK_SCENARIO,
            "the two scenarios must be distinguishable in a state file, or a resume \
             could continue one as the other"
        );
    }
}
