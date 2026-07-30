#![warn(clippy::unwrap_used)]
//! Panic-sweep policy: test code is exempted via clippy.toml.

use crate::beacon::BeaconType;
use crate::canonical_hash::CanonicalHash as _;
use crate::document::{InitialDocument, ResolutionOptions, ResolutionResult, SidecarData};
use crate::update::UnsecuredUpdate;
use crate::{error::Btcr2Error, identifier::Sha256Hash, update::Update};
use chrono::{DateTime, Utc};
use esploda::bitcoin::{Txid, opcodes::all::OP_RETURN, script::Instruction};
use esploda::esplora::{Status, Transaction};
use onlyerror::Error;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;

const DEFAULT_RPC_BASE_URL: &str = "https://blockstream.info/testnet/api";

/// Errors raised while the resolver FSM walks beacon signals and applies
/// updates. A module-local sentinel enum; spec-conformant errors are produced
/// via the [`From<Error>`] conversion into [`Btcr2Error`].
#[derive(Error, Debug)]
pub enum Error {
    /// Update hash does not match
    UpdateHashMismatch,

    /// Late Publishing Error
    LatePublishingError,

    /// DID:BTCR2 error
    Btcr2Error(#[from] crate::error::Btcr2Error),

    /// A *needed* beacon-signal transaction — one whose announced hash matches a
    /// sidecar update we are expecting — is still unconfirmed; the spec resolver
    /// works in confirmed-block terms. Raised only for needed signals: unrelated
    /// unconfirmed txs on a beacon address are skipped, not surfaced.
    /// Unconfirmed-tx *handling* (waiting on / applying mempool updates) remains
    /// Out of scope; this variant exists so the singleton-beacon happy
    /// path returns a typed Err instead of panicking.
    /// Module-local enum only; `Btcr2Error` (the spec-error enum) is untouched
    #[error("unconfirmed beacon transaction (txid={txid})")]
    UnconfirmedBeaconTx {
        /// Transaction id of the unconfirmed beacon-signal transaction.
        txid: Txid,
    },
}

/// Boundary conversion from the module-local resolver [`enum@Error`] to the
/// spec-error vocabulary [`Btcr2Error`]. This lets the resolver hot path
/// surface spec-conformant Problem Details to callers without leaking the
/// internal sentinel enum.
///
/// Note: `MISSING_UPDATE_DATA` is NOT produced here. The sidecar-miss site in
/// `Resolver::process_beacon_signals` raises
/// `Btcr2Error::MissingUpdateData { update_hash }` directly, because only the
/// call site has the missed `update_hash` (the beacon signal bytes) in scope
/// Routing it through this `From` impl would lose the hash.
impl From<Error> for Btcr2Error {
    fn from(err: Error) -> Self {
        match err {
            Error::UpdateHashMismatch => Btcr2Error::InvalidDidUpdate(
                "update hash does not match the expected beacon-signal hash".into(),
            ),
            Error::LatePublishingError => Btcr2Error::LatePublishingError(
                "late publishing detected at update sort step".into(),
            ),
            // Pass-through: the inner spec error is already authoritative.
            Error::Btcr2Error(e) => e,
            Error::UnconfirmedBeaconTx { txid } => Btcr2Error::InvalidSidecarData(format!(
                "unconfirmed beacon transaction (txid={txid})"
            )),
        }
    }
}

/// State machine for Bitcoin blockchain resolver.
#[derive(Debug)]
pub struct Resolver<T = ()> {
    contemporary_doc: InitialDocument,
    current_version_id: NonZeroU64,
    target_condition: TargetCondition,
    update_hash_history: Vec<Sha256Hash>,
    /// Spec-form sidecar lookup, keyed by JSON Document Hash.
    /// Replaces the old txid-keyed `signals_metadata` HashMap. The hot path is
    /// `update_lookup_table.get(&signal_bytes)`.
    update_lookup_table: HashMap<Sha256Hash, Update>,
    /// Caller-supplied chain tip height for computing `confirmations`.
    /// `None` => `DocumentMetadata.confirmations` is `None` (fail-closed).
    chain_tip_height: Option<u32>,
    /// Block height of the MOST-RECENTLY-APPLIED unique update, the basis for
    /// `confirmations` (resolve.md:31,50). Overwritten on each unique apply; under
    /// the ascending (target_version_id, block_height) sort this ends as the
    /// highest-version applied update's height. The lower-height dedup fold-in
    /// (resolve.md:50 footnote 1) survives only as a defensive guard in the
    /// duplicate branch. `None` until the first update is applied.
    applied_block_height: Option<u32>,
    rpc_host: String,
    request_cache: HashSet<esploda::http::Uri>,

    // Finite State Machine
    fsm: ResolverFsm,
    _type_state: T,
}

impl Resolver {
    // TODO: Why do you have `InitialDocument` here and in `resolution_options.sidecar_data`?
    pub(crate) fn new(initial_doc: InitialDocument, resolution_options: ResolutionOptions) -> Self {
        let target_condition = TargetCondition::from(&resolution_options);
        let chain_tip_height = resolution_options.chain_tip_height;
        let rpc_host = resolution_options
            .esplora_url
            .unwrap_or_else(|| DEFAULT_RPC_BASE_URL.into());
        let update_lookup_table = match resolution_options.sidecar_data {
            Some(SidecarData {
                update_lookup_table,
                ..
            }) => update_lookup_table,
            None => HashMap::new(),
        };

        Self {
            contemporary_doc: initial_doc,
            current_version_id: NonZeroU64::MIN,
            target_condition,
            update_hash_history: vec![],
            update_lookup_table,
            chain_tip_height,
            applied_block_height: None,
            rpc_host,
            request_cache: HashSet::new(),
            fsm: ResolverFsm::Init,
            _type_state: (),
        }
    }

    fn from_waiting_for_responses(resolver: Resolver<WaitingForResponses>) -> Self {
        Self {
            contemporary_doc: resolver.contemporary_doc,
            current_version_id: resolver.current_version_id,
            target_condition: resolver.target_condition,
            update_hash_history: resolver.update_hash_history,
            update_lookup_table: resolver.update_lookup_table,
            chain_tip_height: resolver.chain_tip_height,
            applied_block_height: resolver.applied_block_height,
            rpc_host: resolver.rpc_host,
            request_cache: resolver.request_cache,
            fsm: resolver.fsm,
            _type_state: (),
        }
    }

    /// Advance the resolution FSM one step, returning either a
    /// [`ResolverState::Requests`] (blockchain data the caller must fetch and
    /// feed back) or a [`ResolverState::Resolved`] result (did:btcr2 spec
    /// section 7.2.2.1).
    // TODO: Better name for this?
    pub fn resolve(mut self) -> Result<ResolverState, Error> {
        // Take the FSM state, leaving the default in its place.
        let mut fsm = ResolverFsm::Init;
        std::mem::swap(&mut self.fsm, &mut fsm);

        match fsm {
            ResolverFsm::Init => {
                // This captures Section 7.2.2, step 6.
                if let TargetCondition::VersionId(version_id) = self.target_condition
                    && version_id == self.current_version_id
                {
                    return Ok(ResolverState::Resolved(self.terminal_state()));
                }

                // Step 1 is deferred to step 10.
                // Step 2, 3: unnecessary

                // Step 4. (Create RPC requests)
                self.next_signals_requests()
            }

            ResolverFsm::FindNextSignals(responses) => {
                // Step 4. (Assignment)
                let next_signals = self.find_next_signals(responses)?;

                // Step 5.
                if next_signals.is_empty() {
                    return Ok(ResolverState::Resolved(self.terminal_state()));
                }

                // Process Beacon Signals (resolve.md:121-132): build the tuples
                // (raises MISSING_UPDATE_DATA here, before the version_time bound —
                // resolve.md:131).
                let mut signals = self.process_beacon_signals(next_signals)?;

                // Process updates Array step 1 (resolve.md:151): sort by
                // targetVersionId (ascending) with block_height as a tiebreaker; the
                // FIRST tuple is what the version_time bound is evaluated against.
                signals.sort_unstable_by_key(|s| (s.update.target_version_id, s.block_height));

                // Step 10.
                let mut contemporary_hash = self.contemporary_doc.hash();

                // Most-recently-applied UNIQUE update's version, tracked as a
                // loop-local (no struct field / no public-API change). Under the
                // ascending (target_version_id, block_height) sort at
                // resolver.rs:190 this is simply the last unique apply; it keys the
                // defensive dedup guard in the duplicate branch below.
                let mut most_recent_applied_version: Option<NonZeroU64> = None;

                for AppliedSignal {
                    update,
                    block_height,
                    block_time,
                } in signals
                {
                    // Step 10.1.
                    if update.target_version_id <= self.current_version_id {
                        // confirm_duplicate indexes update_hash_history at
                        // [targetVersionId - 2], where each entry is an UPDATE
                        // hash appended by the apply branch (step 10.2.7 below).
                        // Do NOT push the contemporary DOCUMENT hash here: it
                        // would grow the history out from under confirm_duplicate
                        // and displace a later version's entry, turning a benign
                        // duplicate signal into a false LATE_PUBLISHING.
                        update.confirm_duplicate(&self.update_hash_history)?;

                        // Defensive guard (dedup of the SAME announcement,
                        // resolve.md:50 footnote 1): fold in the lower height when
                        // this duplicate targets the most-recently-applied update.
                        // Under the ascending (target_version_id, block_height) sort
                        // at resolver.rs:190 the lowest-height announcement is ALWAYS
                        // processed FIRST and is already the applied height, so every
                        // later same-update announcement is at a HIGHER height and
                        // this min() is a no-op — unreachable as a state change under
                        // natural signal flow, retained only for robustness against
                        // unsorted input.
                        if most_recent_applied_version == Some(update.target_version_id)
                            && let Some(existing) = self.applied_block_height
                        {
                            self.applied_block_height = Some(existing.min(block_height));
                        }
                    }

                    // Step 10.2.
                    let next_update_version_id = self
                        .current_version_id
                        .checked_add(1)
                        .expect("version_id overflow requires 2^64 updates to a single DID");
                    if update.target_version_id == next_update_version_id {
                        // Process updates §step 3 (resolve.md:153): the versionTime
                        // bound is per UNIQUE applied tuple, evaluated against THIS
                        // tuple's block_time. It sits inside the apply branch (not
                        // the duplicate branch, not once per batch): under the
                        // ascending (target_version_id, block_height) sort a
                        // duplicate announcement is processed before a later-version
                        // unique update, so a high-block_time DUPLICATE must never
                        // abort the loop and suppress a later low-block_time unique
                        // update announced within versionTime. If this unique update
                        // is more recent than the requested time, resolve the
                        // document in effect so far (the earlier version) and apply
                        // no further.
                        if let TargetCondition::Time(time) = &self.target_condition
                            && block_time > *time
                        {
                            return Ok(ResolverState::Resolved(self.terminal_state()));
                        }

                        // Step 10.2.1.
                        if update.source_hash != contemporary_hash {
                            return Err(Btcr2Error::late_publishing(
                                update.source_hash,
                                contemporary_hash,
                            ))?;
                        }

                        // Step 10.2.2 - 10.2.3.
                        self.contemporary_doc.apply_update(&update)?;

                        // Step 10.2.4.
                        self.current_version_id = next_update_version_id;

                        // confirmations = block of the most-recently-applied UNIQUE
                        // update (resolve.md:31,50): overwrite here, so after the
                        // ascending-version loop this holds the highest-version (most
                        // recent) applied update's height.
                        self.applied_block_height = Some(block_height);
                        most_recent_applied_version = Some(update.target_version_id);

                        // resolve.md §"Process updates Array" step 7
                        // — once the document is deactivated, resolve it as the
                        // final didDocument and process no further beacon
                        // signals.
                        if self.contemporary_doc.fields.deactivated {
                            return Ok(ResolverState::Resolved(self.terminal_state()));
                        }

                        // Step 13.
                        // Yes, we need to do 13 here: the spec does not early exit.
                        if let TargetCondition::VersionId(version_id) = self.target_condition
                            && version_id == self.current_version_id
                        {
                            return Ok(ResolverState::Resolved(self.terminal_state()));
                        }

                        // Step 10.2.5 - 10.2.6.
                        let unsecured_update = UnsecuredUpdate::from(&update);

                        // Step 10.2.7 - 10.2.8.
                        self.update_hash_history.push(unsecured_update.hash());

                        // Step 10.2.9.
                        contemporary_hash = self.contemporary_doc.hash();
                    }

                    // Step 10.3.
                    if update.target_version_id
                        > self
                            .current_version_id
                            .checked_add(1)
                            .expect("version_id overflow requires 2^64 updates to a single DID")
                    {
                        return Err(Error::LatePublishingError);
                    }
                }

                // Step 11: unnecessary

                // Step 12.
                let ResolverState::Requests(fsm, signals) = self.next_signals_requests()? else {
                    unreachable!()
                };
                if signals.is_empty() {
                    Ok(ResolverState::Resolved(fsm.terminal_state()))
                } else {
                    Ok(ResolverState::Requests(fsm, signals))
                }
            }
        }
    }

    // Spec section 7.2.2.2
    fn find_next_signals(
        &self,
        transactions: HashMap<BeaconType, Vec<Transaction>>,
    ) -> Result<Vec<NextSignal>, Error> {
        let mut signals = Vec::new();
        for (beacon_type, txs) in transactions {
            for tx in txs {
                // Spec MANDATES the last output (resolve.md:117 + terminology.md:221: Signal
                // Bytes live in the LAST output). Do not scan all outputs — that would be
                // non-conformant. Real-world OP_RETURN+change handling is tracked as a
                // potential upstream spec-amendment.
                let Some(txout) = tx.outputs.last() else {
                    continue;
                };
                // Reject (skip) an output whose script does not parse cleanly — a
                // malformed or over-long OP_RETURN tail must NOT be loosely matched
                // as a signal (strict wire-signal boundary). Collecting as a Result
                // (instead of `.flatten()`, which silently discarded an unparseable
                // trailing push's Err and let a garbage-tailed script masquerade as a
                // valid 2-op signal) rejects the whole output on any parse error,
                // without failing the rest of the transaction batch.
                let Ok(ops) = txout
                    .script_pubkey
                    .instructions()
                    .collect::<Result<Vec<_>, _>>()
                else {
                    continue;
                };

                // Extract the signal bytes
                let [Instruction::Op(OP_RETURN), Instruction::PushBytes(bytes)] = ops[..] else {
                    continue;
                };
                let Ok(signal_arr) = <[u8; 32]>::try_from(bytes.as_bytes()) else {
                    continue;
                };
                let signal_bytes = Sha256Hash::from(signal_arr);

                let (block_time, block_height) = match tx.status {
                    Status::Unconfirmed => {
                        // only a *needed* signal — one whose announced hash is
                        // present in the sidecar update-lookup table — blocks resolution
                        // while its beacon tx is unconfirmed. Unrelated unconfirmed txs on
                        // the beacon address (ordinary mempool traffic) are skipped so the
                        // confirmed history still resolves; a beacon address routinely
                        // carries mempool txs that are not DID updates we hold data for.
                        // Unconfirmed-tx *handling* (waiting on / applying mempool updates)
                        // remains out of scope.
                        if self.update_lookup_table.contains_key(&signal_bytes) {
                            return Err(Error::UnconfirmedBeaconTx { txid: tx.txid });
                        }
                        continue;
                    }
                    Status::Confirmed {
                        block_time,
                        block_height,
                        ..
                    } => (block_time, block_height),
                };

                signals.push(NextSignal {
                    beacon_type,
                    signal_bytes,
                    block_time,
                    block_height,
                });
            }
        }
        Ok(signals)
    }

    fn next_signals_requests(mut self) -> Result<ResolverState, Error> {
        let mut map: HashMap<_, Vec<_>> = HashMap::new();

        for beacon in &self.contemporary_doc.fields.service {
            match beacon.ty {
                BeaconType::Singleton => {
                    // TODO: Move this to Esploda
                    let req = esploda::Req::builder()
                        .uri(format!(
                            "{}/address/{}/txs",
                            self.rpc_host, beacon.descriptor,
                        ))
                        .body(())
                        .expect(
                            "rpc_host + bitcoin Address Display produce a valid HTTP URI; \
                             esploda::Req::body only fails on URI parse",
                        );

                    if !self.request_cache.contains(req.uri()) {
                        self.request_cache.insert(req.uri().clone());
                        map.entry(beacon.ty).or_default().push(req);
                    }
                }
                BeaconType::Cas => {
                    return Err(Error::Btcr2Error(Btcr2Error::Unsupported(
                        "CAS Map beacon resolution is not yet implemented".into(),
                    )));
                }
                BeaconType::SparseMerkleTree => {
                    return Err(Error::Btcr2Error(Btcr2Error::Unsupported(
                        "Sparse Merkle Tree beacon resolution is not yet implemented".into(),
                    )));
                }
            }
        }

        Ok(ResolverState::Requests(Resolver::from_init(self), map))
    }

    // Spec section 7.2.2.3
    fn process_beacon_signals(
        &self,
        beacon_signals: Vec<NextSignal>,
    ) -> Result<Vec<AppliedSignal>, Error> {
        beacon_signals
            .into_iter()
            .map(|beacon_signal| {
                let update = match beacon_signal.beacon_type {
                    BeaconType::Singleton => {
                        // the spec-form sidecar is keyed by JSON
                        // Document Hash; the beacon signal's pushed bytes ARE
                        // that hash. O(1) lookup on the hot path.
                        //
                        // raise the spec error directly here,
                        // where `signal_bytes` (the missed update hash) is in
                        // scope — NOT via `From<resolver::Error>`, which would
                        // lose the hash.
                        self.update_lookup_table
                            .get(&beacon_signal.signal_bytes)
                            .cloned()
                            .ok_or(Error::Btcr2Error(Btcr2Error::MissingUpdateData {
                                update_hash: beacon_signal.signal_bytes,
                            }))?
                    }
                    BeaconType::Cas => {
                        return Err(Error::Btcr2Error(Btcr2Error::Unsupported(
                            "CAS Map beacon resolution is not yet implemented".into(),
                        )));
                    }
                    BeaconType::SparseMerkleTree => {
                        return Err(Error::Btcr2Error(Btcr2Error::Unsupported(
                            "Sparse Merkle Tree beacon resolution is not yet implemented".into(),
                        )));
                    }
                };

                Ok(AppliedSignal {
                    update,
                    block_height: beacon_signal.block_height,
                    block_time: beacon_signal.block_time,
                })
            })
            .collect()
    }
}

impl<T> Resolver<T> {
    /// Construct the terminal [`ResolutionResult`] from the resolver's current
    /// state. Centralizes the metadata-assembly logic so
    /// every terminal arm of [`Resolver::resolve`] returns the spec triple
    /// identically (PATTERNS.md §"ResolverState::Resolved" guidance).
    ///
    /// `confirmations` is computed as
    /// `tip.saturating_sub(applied_block_height).saturating_add(1)`;
    /// `None` when the caller supplied no
    /// chain tip or no update was applied.
    fn terminal_state(&self) -> ResolutionResult {
        let confirmations = match (self.chain_tip_height, self.applied_block_height) {
            (Some(tip), Some(height)) => Some(tip.saturating_sub(height).saturating_add(1)),
            _ => None,
        };
        let document_metadata = crate::document::DocumentMetadata {
            version_id: self.current_version_id,
            confirmations,
            deactivated: self.contemporary_doc.fields.deactivated,
            // spec-OPTIONAL; populated by future operations.
            updated: None,
        };
        ResolutionResult {
            resolution_metadata: crate::document::ResolutionMetadata::default(),
            document: self.contemporary_doc.clone().into(),
            document_metadata,
        }
    }
}

/// A beacon signal paired with the sidecar [`Update`] it resolves to, carrying
/// the confirming block height forward for the confirmations computation
/// Produced by [`Resolver::process_beacon_signals`].
#[derive(Debug)]
struct AppliedSignal {
    update: Update,
    block_height: u32,
    block_time: DateTime<Utc>,
}

impl Resolver<WaitingForResponses> {
    fn from_init(resolver: Resolver) -> Self {
        Self {
            contemporary_doc: resolver.contemporary_doc,
            current_version_id: resolver.current_version_id,
            target_condition: resolver.target_condition,
            update_hash_history: resolver.update_hash_history,
            update_lookup_table: resolver.update_lookup_table,
            chain_tip_height: resolver.chain_tip_height,
            applied_block_height: resolver.applied_block_height,
            rpc_host: resolver.rpc_host,
            request_cache: resolver.request_cache,
            fsm: resolver.fsm,
            _type_state: WaitingForResponses,
        }
    }

    /// Feed the blockchain transactions requested by a
    /// [`ResolverState::Requests`] back into the FSM, returning a [`Resolver`]
    /// ready to be driven another step.
    pub fn process_responses(
        mut self,
        transactions: HashMap<BeaconType, Vec<Transaction>>,
    ) -> Resolver {
        self.fsm = ResolverFsm::FindNextSignals(transactions);

        Resolver::from_waiting_for_responses(self)
    }
}

/// Marker type for FSM.
#[derive(Debug)]
pub struct WaitingForResponses;

#[derive(Debug)]
enum ResolverFsm {
    /// FSM just initialized.
    Init,

    /// FSM is ready to find the next beacon signals.
    FindNextSignals(HashMap<BeaconType, Vec<Transaction>>),
}

/// The result of advancing the resolver FSM one step: either outstanding
/// blockchain requests the caller must satisfy, or the fully resolved DID.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ResolverState {
    /// Requests need to be sent to the blockchain.
    Requests(
        Resolver<WaitingForResponses>,
        HashMap<BeaconType, Vec<esploda::Req>>,
    ),

    /// Document is fully resolved. Carries the spec resolution triple
    /// (`didResolutionMetadata`, `didDocument`, `didDocumentMetadata`) as a
    /// [`ResolutionResult`].
    Resolved(ResolutionResult),
}

#[derive(Debug)]
struct NextSignal {
    beacon_type: BeaconType,
    signal_bytes: Sha256Hash,
    block_time: DateTime<Utc>,
    /// Confirming block height, carried into [`AppliedSignal`] for the
    /// confirmations computation.
    block_height: u32,
}

#[derive(Debug)]
enum TargetCondition {
    VersionId(NonZeroU64),

    Time(DateTime<Utc>),
}

impl From<&ResolutionOptions> for TargetCondition {
    fn from(resolution_options: &ResolutionOptions) -> Self {
        if let Some(version) = resolution_options.version_id {
            Self::VersionId(version)
        } else {
            Self::Time(resolution_options.version_time.unwrap_or_else(Utc::now))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::Document;
    use crate::test_vectors::{
        AssertionKind, DRIVEN_FLOOR, NUMBER_ENCODED_VERSION_ID, SKIP_OVERRIDES, SkipOverride,
        Vector, VectorIdType, discover, expected_driven_with, field_bool, field_hex,
        field_nonzero_version_id, field_str, field_u64, field_version_id,
        network_dirs_with_vectors, read_fixture_or_skip, read_vector_fixture,
        reconcile_driven_with, redundant_overrides, render_summary_with, stale_overrides,
        test_suite_checked_out, unclassified_rows_with,
    };
    use std::collections::BTreeSet;

    /// The discovered vector set, or `None` when the `test-suite/` submodule is
    /// absent — the non-recursive-clone case every op-vector test skips green on.
    ///
    /// The skip probe is the submodule's PRESENCE, not an empty discovery
    /// result. Those are different failures: a checked-out submodule that yields
    /// no vectors is a partial checkout or an upstream layout change, and gating
    /// on `vectors.is_empty()` would report it as "submodule absent" and pass
    /// green — the same silent-coverage-loss the ledger exists to catch.
    fn discovered_vectors_or_skip() -> Option<Vec<Vector>> {
        if !test_suite_checked_out() {
            eprintln!(
                "SKIP: test-suite submodule absent; \
                 run `git submodule update --init --recursive` to enable"
            );
            return None;
        }
        let vectors = discover();
        assert!(
            !vectors.is_empty(),
            "test-suite is checked out but no operation vectors were discovered — \
             a partial checkout or an upstream layout change"
        );
        Some(vectors)
    }

    /// CREATE driver: for EVERY vector discovered under `test-suite/` at
    /// runtime, drive the crate's create path from `create/input.json` and
    /// assert the encoded DID equals the vector's `create/output.json.did` —
    /// re-derived through the real code path, not a trust-the-blob compare.
    ///
    /// KEY (k1): the 33-byte compressed pubkey `genesisBytes` → `IdType::Key` →
    /// `DidComponents` → `Did`. EXTERNAL (x1): the 32-byte `genesisBytes` IS the
    /// intermediate-document hash → `IdType::External` → `Did`. The network
    /// comes from the discovered vector, not a hardcoded constant, so a vector
    /// on any network the crate models derives with the right network nibble.
    ///
    /// Coverage is observed, not declared: the loop accumulates the ids it
    /// actually asserted against and `reconcile_driven` compares that set with
    /// the vector ledger's expectation for `AssertionKind::Derivation`. Dropping
    /// a vector — by deleting it from the walk or by slipping a `continue` into
    /// the loop body — fails the test instead of silently shrinking coverage.
    #[test]
    fn op_vectors_create_derives_expected_did() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };
        drive_derivation(&vectors, SKIP_OVERRIDES);
    }

    /// The CREATE/derivation driver body, over an explicit override table so the
    /// same code path can be exercised with a hand-written skip in place.
    fn drive_derivation(vectors: &[Vector], overrides: &[SkipOverride]) {
        use crate::identifier::{Did, DidComponents, DidVersion, IdType};
        use crate::key::PublicKey;

        let mut observed = BTreeSet::new();
        for vector in vectors {
            if !vector.should_drive_with(AssertionKind::Derivation, overrides) {
                continue;
            }
            let id = &vector.id;

            let input = read_vector_fixture(&format!("{id}/create/input.json"));
            let output = read_vector_fixture(&format!("{id}/create/output.json"));

            assert_eq!(field_u64(&input, "version", id), 1, "{id}: version is 1");
            let genesis_bytes = field_hex(&input, "genesisBytes", id);
            let expected_did = field_str(&output, "did", id);

            // `vector.id_type` is the `<kind>/` directory segment mapped through
            // `id_type_from_kind` and cross-checked against this fixture's own
            // `create/input.json.idType` at discovery time, so branching on it
            // here is branching on both.
            let id_type = match vector.id_type {
                VectorIdType::Key => {
                    assert_eq!(
                        genesis_bytes.len(),
                        33,
                        "{id}: KEY genesisBytes is a 33-byte pubkey"
                    );
                    IdType::from(PublicKey::from_slice(&genesis_bytes).unwrap_or_else(|e| {
                        panic!("{id}: create/input.json.genesisBytes is not a public key: {e}")
                    }))
                }
                VectorIdType::External => {
                    assert_eq!(
                        genesis_bytes.len(),
                        32,
                        "{id}: EXTERNAL genesisBytes is a 32-byte hash"
                    );
                    IdType::from_sha256_hash(&genesis_bytes).unwrap_or_else(|e| {
                        panic!("{id}: create/input.json.genesisBytes is not a sha256 hash: {e}")
                    })
                }
            };

            let components = DidComponents::new(DidVersion::One, vector.network, id_type)
                .unwrap_or_else(|e| panic!("{id}: create/input.json does not form a DID: {e}"));
            let did = Did::try_from(components)
                .unwrap_or_else(|e| panic!("{id}: create/input.json does not form a DID: {e}"));
            assert_eq!(
                did.encode(),
                expected_did,
                "{id}: create-derived DID must equal create/output.json.did"
            );

            observed.insert(id.clone());
        }
        reconcile_driven_with(AssertionKind::Derivation, vectors, &observed, overrides);
    }

    /// CREATE BLESS check, over EVERY vector discovered under `test-suite/` at
    /// runtime: load `other.json.genesisKeys.secret` and derive its public key,
    /// then tie that key to the vector's own artifacts.
    ///
    /// HOW THE KEY IS TIED depends on the id type, because the two have
    /// different genesis sources. For KEY (k1) vectors the descriptor IS the
    /// genesis key, so the derived key must equal
    /// `create/input.json.genesisBytes` — not a hand-edited blob. For EXTERNAL
    /// (x1) vectors the descriptor is a hash of a document supplied out of band,
    /// so the derived key is compared against
    /// `other.json.genesisDocument.verificationMethod[0].publicKeyMultibase`.
    /// Without that second branch an update-less external vector executed
    /// exactly one assertion — that `secp256k1` derives its own public key from
    /// its own secret key — which touches neither the vector's DID nor its
    /// documents while being reported as full coverage.
    ///
    /// Then walk EVERY update step the vector ships — flat `update/` or numbered
    /// `update/NN/` alike — and assert the genesis secret equals that step's
    /// `signingMaterial`, so a multi-step vector is corroborated at every step
    /// rather than only its first. This retires the trust-the-blob concern.
    ///
    /// Coverage is observed, not declared: the loop accumulates the ids it
    /// actually asserted against and `reconcile_driven` compares that set with
    /// the vector ledger's expectation for `AssertionKind::GenesisKey`.
    #[test]
    fn op_vectors_create_genesis_key_corroborated() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };
        drive_genesis_key(&vectors, SKIP_OVERRIDES);
    }

    /// The genesis-key driver body, over an explicit override table so the same
    /// code path can be exercised with a hand-written skip in place.
    fn drive_genesis_key(vectors: &[Vector], overrides: &[SkipOverride]) {
        use crate::key::{PublicKey, PublicKeyExt as _};
        use secp256k1::{Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let mut observed = BTreeSet::new();
        for vector in vectors {
            if !vector.should_drive_with(AssertionKind::GenesisKey, overrides) {
                continue;
            }
            let id = &vector.id;

            let input = read_vector_fixture(&format!("{id}/create/input.json"));
            let other = read_vector_fixture(&format!("{id}/other.json"));

            let secret_hex = field_str(&other, "genesisKeys.secret", id);
            let secret = SecretKey::from_slice(&field_hex(&other, "genesisKeys.secret", id))
                .unwrap_or_else(|e| {
                    panic!("{id}: other.json.genesisKeys.secret is not a secret key: {e}")
                });
            let derived: PublicKey = secret.public_key(&secp);

            // other.json.genesisKeys.public corroborates the derived key.
            assert_eq!(
                hex::encode(derived.serialize()),
                field_str(&other, "genesisKeys.public", id),
                "{id}: derived public key must equal other.json.genesisKeys.public"
            );

            match vector.id_type {
                // For KEY vectors the genesis key IS the descriptor.
                VectorIdType::Key => assert_eq!(
                    hex::encode(derived.serialize()),
                    field_str(&input, "genesisBytes", id),
                    "{id}: KEY genesisBytes must be the genesis public key"
                ),
                // For EXTERNAL vectors the descriptor is a hash of a document
                // supplied out of band, so the key has to be tied to the vector
                // through that document instead. Without this the only assertion
                // an update-less external vector executes is that secp256k1
                // derives its own public key from its own secret key — a test of
                // the dependency, touching neither the vector's DID nor its
                // documents, reported as full genesis-key coverage.
                VectorIdType::External => assert_eq!(
                    derived.to_multikey(),
                    field_str(
                        &other,
                        "genesisDocument.verificationMethod.0.publicKeyMultibase",
                        id
                    ),
                    "{id}: the genesis secret must derive the key the genesis document \
                     publishes as its first verification method"
                ),
            }

            for step in vector.update_layout.step_prefixes() {
                let update_input = read_vector_fixture(&format!("{id}/{step}/input.json"));
                assert_eq!(
                    field_str(&update_input, "signingMaterial", id),
                    secret_hex,
                    "{id}: {step}/input.json signingMaterial must equal \
                     other.json.genesisKeys.secret"
                );
            }

            observed.insert(id.clone());
        }
        reconcile_driven_with(AssertionKind::GenesisKey, vectors, &observed, overrides);
    }

    /// RESOLVE driver: for EVERY vector discovered under `test-suite/` at
    /// runtime, validate the `resolve/output.json` metadata whitelist, and for
    /// the rows the ledger expects driven, drive the FSM to its terminal state
    /// with empty beacon responses and assert the resolved `didDocument` equals
    /// `resolve/output.json.didDocument`.
    ///
    /// TWO SCOPES, deliberately different. WELL-FORMEDNESS checks run for every
    /// discovered vector, driven or not — a schema drift anywhere in the suite
    /// is worth catching, and no maintainer decision could make a malformed
    /// fixture acceptable. POLICY checks — the ones a maintainer might
    /// legitimately want to record as a classified skip — sit BELOW the drive
    /// gate, so a `SKIP_OVERRIDES` entry can reach them. The `versionId`
    /// encoding pin is the concrete case: placed above the gate, an upstream
    /// vector on a new network carrying the known encoding defect would turn the
    /// suite red with no way to record it as a skipped row, leaving only two
    /// remedies (edit driver code, or edit the upstream fixture) for exactly the
    /// situation the escape hatch exists for.
    ///
    /// Only the full FSM drive is reconciled as this vector's `resolve` row:
    /// `observed` is filled after the drive, and `reconcile_driven` compares it
    /// with the ledger's expectation for `AssertionKind::Resolve`. The rows that
    /// are NOT driven are enumerated by the vector ledger as
    /// skipped-with-reason (`NeedsOnChainSignals`, `Unanchored`, `CasDelivery`,
    /// `SmtDelivery`); its summary table is the place to read the coverage
    /// story, not a narrative in this comment.
    ///
    /// Observation-dependent metadata is whitelisted: `deactivated` is asserted
    /// BY VALUE against the vector's stated flag on a driven row; `confirmations`,
    /// `updated` and `created` are environment-derived and drift, so they are
    /// asserted only by presence/type when present, NEVER by literal value.
    /// mutinynet vectors omit `confirmations` entirely and carry `created: null`;
    /// indexing a missing key yields `Value::Null`, which the `is_null` guards
    /// already tolerate. `versionId` carries three separate checks: it is READ
    /// through `version_id_u64`, which accepts the regtest string encoding and
    /// the mutinynet number encoding and panics on anything else; its ENCODING is
    /// pinned to `NUMBER_ENCODED_VERSION_ID`, the explicit set of known-bad
    /// fixtures, in both directions; and on a driven row the resolved value is
    /// COMPARED against the vector's stated one. That last comparison is not yet
    /// a cross-check with independent operands — `is_drivable(Resolve)` requires
    /// `expected_version_id == 1`, so on every driven row the stated value is 1
    /// and the assertion pins the resolver's genesis-era `versionId` to 1. It
    /// becomes a genuine cross-check once past-genesis rows are drivable. The
    /// crate's own emit-a-string / reject-a-number contract is pinned by the
    /// fixture-independent `DocumentMetadata` round-trip test in `document.rs`.
    ///
    /// EXTERNAL (x1) genesis comes from
    /// `resolve/input.json.resolutionOptions.sidecar.genesisDocument` and stays
    /// there on purpose. `other.json.genesisDocument` exists for every external
    /// vector and is byte-identical where both are present, but reading it would
    /// hand the resolver a genesis document the vector intends to be fetched
    /// from content-addressed storage — asserting resolve logic while silently
    /// bypassing the delivery mechanism and leaving no row to mark the gap.
    /// Every row that remains driven has a sidecar genesis document; a missing
    /// one on a driven row is a loud failure, not a fallback. KEY (k1)
    /// resolution needs no sidecar: the genesis document is generated
    /// deterministically from the DID's embedded public key.
    #[test]
    fn op_vectors_resolve_matches_output() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };
        drive_resolve(&vectors, SKIP_OVERRIDES);
    }

    /// The RESOLVE driver body, over an explicit override table so the same code
    /// path can be exercised with a hand-written skip in place.
    fn drive_resolve(vectors: &[Vector], overrides: &[SkipOverride]) {
        use crate::document::IntermediateDocument;
        use crate::identifier::Did;

        let mut observed = BTreeSet::new();
        for vector in vectors {
            let id = &vector.id;

            let input = read_vector_fixture(&format!("{id}/resolve/input.json"));
            let output = read_vector_fixture(&format!("{id}/resolve/output.json"));

            // Well-formedness whitelist (asserted for every discovered vector,
            // driven or not: no maintainer decision makes a malformed fixture
            // acceptable, so none of these belongs below the drive gate).
            let metadata = &output["didDocumentMetadata"];
            if !metadata["versionId"].is_number() {
                assert!(
                    metadata["versionId"].is_string(),
                    "{id}: versionId must be an ASCII string (the specification's encoding)"
                );
            }
            assert!(
                metadata["deactivated"].is_boolean(),
                "{id}: deactivated must be a bool"
            );
            if !metadata["confirmations"].is_null() {
                assert!(
                    metadata["confirmations"].is_number(),
                    "{id}: confirmations is observation-dependent — assert TYPE only"
                );
            }
            if !metadata["updated"].is_null() {
                assert!(
                    metadata["updated"].is_string(),
                    "{id}: updated is observation-dependent — assert TYPE only"
                );
            }
            if !metadata["created"].is_null() {
                assert!(
                    metadata["created"].is_string(),
                    "{id}: created is observation-dependent — assert TYPE only"
                );
            }

            if !vector.should_drive_with(AssertionKind::Resolve, overrides) {
                continue;
            }

            // POLICY, not well-formedness — hence below the drive gate, where a
            // hand-written skip can classify a non-conformant vector instead of
            // leaving "edit driver code or edit the upstream fixture" as the
            // only remedies.
            //
            // The specification requires didDocumentMetadata.versionId to be an
            // ASCII string. Sixteen fixtures encode it as a JSON number, a known
            // upstream defect pinned to an explicit id set and checked in BOTH
            // directions: an unlisted offender fails as a NEW defect rather than
            // being absorbed by the encoding-tolerant read, and a listed vector
            // that is now string-encoded fails saying the list is stale. Keying
            // this on the network directory instead would auto-forgive a newly
            // added defective vector and would red on a partial upstream
            // conformance fix. The ledger's summary reports the running tally.
            let known_bad = NUMBER_ENCODED_VERSION_ID.contains(&id.as_str());
            assert!(
                metadata["versionId"].is_number() == known_bad,
                "{id}: {}",
                if metadata["versionId"].is_number() {
                    "NEW versionId encoding defect — resolve/output.json encodes versionId as a \
                     JSON number, but the specification requires an ASCII string. Fix the \
                     fixture, or add this id to NUMBER_ENCODED_VERSION_ID to record it as \
                     known-bad."
                } else {
                    "versionId is now correctly encoded as an ASCII string — delete this id \
                     from NUMBER_ENCODED_VERSION_ID."
                }
            );

            // The resolved didDocument must parse as a conformant Document.
            // This sits BELOW the drive gate, not with the metadata whitelist:
            // it is an assertion about the document a driven row resolves to,
            // and a skipped row's document is by definition not asserted.
            // `mutinynet/x1/qh66uy2s` makes the difference concrete — its
            // expected document carries `service: []` and so does not parse
            // ("updatable DID document must contain at least one beacon
            // service"), which is corroborating evidence for the ledger's
            // classification of that row as CAS-delivered and skipped.
            let _expected_doc = Document::from_json_string(&output["didDocument"].to_string())
                .unwrap_or_else(|e| {
                    panic!("{id}: resolve/output.json.didDocument must parse as a Document: {e}")
                });

            let did: Did = field_str(&input, "did", id).parse().unwrap_or_else(|e| {
                panic!("{id}: resolve/input.json.did must parse as a DID: {e}")
            });

            let resolution_options = if vector.id_type == VectorIdType::External {
                let genesis = &input["resolutionOptions"]["sidecar"]["genesisDocument"];
                let intermediate =
                    IntermediateDocument::from_json_value(genesis.clone(), vector.network)
                        .unwrap_or_else(|e| {
                            panic!(
                                "{id}: resolve/input.json sidecar genesisDocument must parse as \
                                 an intermediate document: {e}"
                            )
                        });
                let initial_doc = intermediate.into_initial(&did).unwrap_or_else(|e| {
                    panic!("{id}: the sidecar genesis document must bind to the vector's DID: {e}")
                });
                ResolutionOptions {
                    sidecar_data: Some(SidecarData {
                        initial_document: Some(initial_doc),
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            } else {
                ResolutionOptions {
                    sidecar_data: Some(SidecarData::default()),
                    ..Default::default()
                }
            };

            let resolver = Document::resolve(&did, resolution_options)
                .unwrap_or_else(|e| panic!("{id}: the resolver must accept the vector: {e}"));
            let result = resolve_with_no_signals(resolver);

            // The resolved document and the spec test vector agree on EVERY
            // content field — id, the top-level `@context`, verificationMethod
            // (incl. publicKeyMultibase), the SingletonBeacon services +
            // endpoints, and the four relationship sets. Both the KEY (k1) path
            // (genesis generated deterministically) and the EXTERNAL (x1) path
            // (genesis supplied verbatim) emit the spec `@context`
            // (`www.w3.org/ns/did/v1.1` / `btcr2.dev/context/v1`) and no
            // top-level `controller`, so the full content matches with no
            // field masking.
            let got: serde_json::Value = serde_json::from_str(
                &serde_json::to_string(result.document.as_ref())
                    .unwrap_or_else(|e| panic!("{id}: the resolved document must serialize: {e}")),
            )
            .unwrap_or_else(|e| panic!("{id}: the resolved document must round-trip: {e}"));
            let want: serde_json::Value = output["didDocument"].clone();
            assert_eq!(
                got, want,
                "{id}: resolved didDocument content (incl. @context) \
                 must equal resolve/output.json.didDocument"
            );

            assert_eq!(
                result.document_metadata.version_id.get(),
                vector.expected_version_id,
                "{id}: resolved versionId must equal \
                 resolve/output.json.didDocumentMetadata.versionId"
            );
            assert_eq!(
                result.document_metadata.deactivated,
                field_bool(&output, "didDocumentMetadata.deactivated", id),
                "{id}: resolved deactivated must equal \
                 resolve/output.json.didDocumentMetadata.deactivated"
            );

            observed.insert(id.clone());
        }
        reconcile_driven_with(AssertionKind::Resolve, vectors, &observed, overrides);
    }

    /// UPDATE driver: for EVERY vector discovered under `test-suite/` that ships
    /// update steps, walk those steps IN ORDER as a chain — flat `update/` and
    /// numbered `update/NN/` alike — driving `Document::construct_signed_update`
    /// at each step and asserting the produced [`Update`]'s content-bound triple
    /// (`sourceHash`, `targetHash`, `targetVersionId`) against that step's
    /// `update/**/output.json.signedUpdate`.
    ///
    /// A CHAIN, NOT N INDEPENDENT SIGNATURE CHECKS. Three linkage assertions
    /// hold the sequence together:
    ///   1. step ordering — step NN's `sourceVersionId` is NN (1-based), so a
    ///      renumbered or reordered walk fails;
    ///   2. hash continuity — step NN's `signedUpdate.sourceHash` equals step
    ///      NN-1's `targetHash`;
    ///   3. document continuity — the document carried forward from step NN-1's
    ///      `apply_update` equals step NN's stated `sourceDocument`.
    ///
    /// What that adds over `apply_update` alone: `apply_update` ends with
    /// `if self.hash() != update.target_hash { return Err(...) }`, so a
    /// successful application already proves the patched document is
    /// equal-by-JCS-hash to that step's stated `targetHash`. It says nothing
    /// about ORDER or CONTINUITY across steps — that is exactly what (1) and (2)
    /// add. Coverage is observed, not declared: `observed.insert` runs once per
    /// vector AFTER its last step, so a chain that aborts part-way can never be
    /// counted as covered, and `reconcile_driven` compares the accumulated set
    /// with the ledger's expectation for `AssertionKind::UpdateCrypto`.
    ///
    /// The chain starts from step 01's `input.sourceDocument`, which already
    /// carries the real DID — not `other.json.genesisDocument`, whose id is the
    /// `did:btcr2:_` placeholder and would need `into_initial` first.
    ///
    /// SAFE MID-WALK. Deactivation is the TERMINAL step in both multi-update
    /// vectors (`q5m2fh36` 01=add service / 02=deactivate; `qky9e7qz`
    /// 01,02=add service / 03=deactivate), so the walk never applies an update to
    /// an already-deactivated document and never trips `apply_update`'s
    /// "a deactivated DID is terminal" guard. The patches add NON-beacon services
    /// (`DIDCommMessaging`, `DecentralizedWebNode`), which the document parser
    /// retains and ignores.
    ///
    /// The raw `proofValue` is NOT byte-compared: BIP340 Schnorr signing here is
    /// deterministic (no-aux-rand), but the suite's vector was produced by a
    /// different signer that may pin `k` differently, so the bytes need not
    /// match. Instead the produced proof is VERIFIED by applying the update back
    /// to the source document (`InitialDocument::apply_update` runs full BIP340
    /// proof verification), and the proof's cryptosuite is asserted structurally.
    #[test]
    fn op_vectors_update_signs_to_expected_hashes() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };
        drive_update_crypto(&vectors, SKIP_OVERRIDES);
    }

    /// One update step's fixtures plus the update the crate produced from them.
    struct StepFixtures {
        input: serde_json::Value,
        output: serde_json::Value,
        update: Update,
    }

    /// Read one update step's fixtures and drive `construct_signed_update` over
    /// them.
    ///
    /// The update-crypto and end-state drivers both need exactly this sequence —
    /// the two fixture reads, patch deserialization, `targetVersionId` coercion,
    /// verification-method id, secret decoding and the signing call — and the
    /// two copies of it were byte-for-byte identical, so a divergence between
    /// them would have been silent.
    ///
    /// The source document is built straight from the vector's `sourceDocument`
    /// (spec `@context`, no top-level controller), so its JCS hash equals the
    /// vector's `sourceHash` without touching the create-path residuals.
    fn signed_update_for_step(id: &str, step: &str) -> StepFixtures {
        use crate::key::SecretKey;
        use json_patch::Patch;

        let input = read_vector_fixture(&format!("{id}/{step}/input.json"));
        let output = read_vector_fixture(&format!("{id}/{step}/output.json"));

        let ctx = format!("{id} {step}");
        let source_doc = Document::from_json_string(&input["sourceDocument"].to_string())
            .unwrap_or_else(|e| {
                panic!("{ctx}: input.json.sourceDocument must parse as a Document: {e}")
            });
        let patch: Patch = serde_json::from_value(input["patches"].clone())
            .unwrap_or_else(|e| panic!("{ctx}: input.json.patches must be a JSON Patch: {e}"));
        let target_version_id =
            field_nonzero_version_id(&output, "signedUpdate.targetVersionId", &ctx);
        let vm_id = field_str(&input, "verificationMethodId", &ctx);
        let secret = SecretKey::try_from(field_hex(&input, "signingMaterial", &ctx))
            .unwrap_or_else(|e| {
                panic!("{ctx}: input.json.signingMaterial is not a secret key: {e}")
            });

        let update = source_doc
            .construct_signed_update(patch, target_version_id, vm_id, secret)
            .unwrap_or_else(|e| {
                panic!("{ctx}: construct_signed_update must succeed for the vector inputs: {e}")
            });

        StepFixtures {
            input,
            output,
            update,
        }
    }

    /// The UPDATE-crypto driver body, over an explicit override table so the same
    /// code path can be exercised with a hand-written skip in place.
    fn drive_update_crypto(vectors: &[Vector], overrides: &[SkipOverride]) {
        use crate::document::InitialDocument;

        let to_b64 = |h: &Sha256Hash| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.as_bytes())
        };

        let mut observed = BTreeSet::new();
        for vector in vectors {
            if !vector.should_drive_with(AssertionKind::UpdateCrypto, overrides) {
                continue;
            }
            let id = &vector.id;

            let mut previous_target_hash: Option<String> = None;
            let mut carried: Option<InitialDocument> = None;

            for (step_index, step) in vector.update_layout.step_prefixes().iter().enumerate() {
                let StepFixtures {
                    input,
                    output,
                    update,
                } = signed_update_for_step(id, step);

                // (a) Step-index linkage: step NN is update number NN.
                assert_eq!(
                    field_version_id(&input, "sourceVersionId", id),
                    step_index as u64 + 1,
                    "{id}: {step} must be update number {} in the chain",
                    step_index + 1
                );

                let stated_source_hash = field_str(&output, "signedUpdate.sourceHash", id);
                let stated_target_hash = field_str(&output, "signedUpdate.targetHash", id);

                // (b) Hash linkage: this step continues the previous one.
                if let Some(prev) = &previous_target_hash {
                    assert_eq!(
                        stated_source_hash, prev,
                        "{id}: {step} sourceHash must equal the previous step's targetHash"
                    );
                }

                // (c) Document linkage: the document the previous step produced
                // IS this step's stated source. Compared as `Value`s so the diff
                // is on content, not key ordering.
                if let Some(carried_doc) = &carried {
                    let carried_json: serde_json::Value = carried_doc.as_ref().clone();
                    assert_eq!(
                        carried_json, input["sourceDocument"],
                        "{id}: {step} sourceDocument must equal the document produced \
                         by the previous step"
                    );
                }

                // (d) Content-bound triple must equal the vector's signedUpdate.
                assert_eq!(
                    to_b64(&update.source_hash),
                    stated_source_hash,
                    "{id}: {step} sourceHash"
                );
                assert_eq!(
                    to_b64(&update.target_hash),
                    stated_target_hash,
                    "{id}: {step} targetHash"
                );
                assert_eq!(
                    u64::from(update.target_version_id),
                    field_version_id(&output, "signedUpdate.targetVersionId", id),
                    "{id}: {step} targetVersionId"
                );

                // (e) Proof must VERIFY (not byte-compare proofValue): apply the
                // produced update back to the source initial document.
                // apply_update runs full BIP340 proof verification + target-hash
                // check.
                let mut initial =
                    InitialDocument::from_json_string(&input["sourceDocument"].to_string())
                        .unwrap_or_else(|e| {
                            panic!(
                                "{id}: {step} sourceDocument must parse as an initial \
                                 document: {e}"
                            )
                        });
                initial
                    .apply_update(&update)
                    .unwrap_or_else(|e| panic!("{id}: {step} produced proof must verify: {e}"));

                // (f) Structural proof shape.
                assert_eq!(
                    field_str(&output, "signedUpdate.proof.cryptosuite", id),
                    "bip340-jcs-2025",
                    "{id}: {step} vector proof cryptosuite"
                );

                // (g) Carry forward into the next step.
                previous_target_hash = Some(stated_target_hash.to_string());
                carried = Some(initial);
            }

            observed.insert(id.clone());
        }
        reconcile_driven_with(AssertionKind::UpdateCrypto, vectors, &observed, overrides);
    }

    /// END-STATE driver: for every update-bearing vector, apply EVERY update
    /// step in order starting from step 01's stated `sourceDocument`, and assert
    /// the resulting document equals `resolve/output.json.didDocument`.
    ///
    /// This closes the offline document-CONTENT gap for every update-bearing
    /// vector. What remains unassertable for these vectors is chain-derived
    /// only: beacon-signal discovery, `versionId`/confirmation provenance, and
    /// late-publishing detection.
    ///
    /// WHAT THIS ADDS OVER THE UPDATE-CRYPTO DRIVER — this is not duplicate
    /// work. `apply_update` ends with
    /// `if self.hash() != update.target_hash { return Err(...) }`
    /// (`document.rs:1226`), so every successful application already proves the
    /// patched document is equal-by-JCS-hash to that step's stated `targetHash`;
    /// the patch arithmetic is therefore covered already. The genuinely new
    /// content here is exactly ONE link: **the final step's target document
    /// equals `resolve/output.json.didDocument`** — that the chain of stated
    /// hashes actually terminates at the vector's expected resolved document,
    /// rather than at some other document that merely hashes to the last
    /// `targetHash` the fixture states. If that link holds, exact equality
    /// follows structurally; if it does not, the fixture set is internally
    /// inconsistent, which is worth failing on.
    ///
    /// The walk starts from `update/01/input.json.sourceDocument`, which already
    /// carries the real DID — not `other.json.genesisDocument`, whose id is the
    /// `did:btcr2:_` placeholder and would need `into_initial` first.
    ///
    /// SAFE MID-WALK: deactivation is the TERMINAL step in both multi-update
    /// vectors (`q5m2fh36` 01=add service / 02=deactivate; `qky9e7qz` 01,02=add
    /// service / 03=deactivate), so the walk never applies an update to an
    /// already-deactivated document and never trips `apply_update`'s
    /// "a deactivated DID is terminal" guard.
    ///
    /// The comparison is EXACT and needs no key normalization. `InitialDocument`
    /// derives only `Clone, Debug, PartialEq, Eq` (`document.rs:977`) — it is
    /// neither `Serialize` nor `Deserialize` — so the accessor is
    /// `impl AsRef<Value>` (`document.rs:1236`), whose backing `json_data` is
    /// already a `serde_json::Value`. Both sides are therefore `Value`, whose
    /// `PartialEq` compares objects by key set and value rather than by textual
    /// key order. In particular `deactivated` is OMITTED (not `false`) when
    /// unset on both sides, so no key is normalized away here.
    ///
    /// Coverage is observed, not declared: `observed.insert` runs once per
    /// vector AFTER the end-state comparison, so a chain that aborts part-way
    /// can never be counted as covered.
    #[test]
    fn op_vectors_updates_apply_to_expected_end_state() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };
        drive_end_state(&vectors, SKIP_OVERRIDES);
    }

    /// The END-STATE driver body, over an explicit override table so the same
    /// code path can be exercised with a hand-written skip in place.
    fn drive_end_state(vectors: &[Vector], overrides: &[SkipOverride]) {
        use crate::document::InitialDocument;

        let mut observed = BTreeSet::new();
        for vector in vectors {
            if !vector.should_drive_with(AssertionKind::EndState, overrides) {
                continue;
            }
            let id = &vector.id;

            let steps = vector.update_layout.step_prefixes();

            // The walk starts from step 01's stated source document and carries
            // each step's result forward.
            let mut carried: Option<InitialDocument> = None;

            for (step_index, step) in steps.iter().enumerate() {
                let StepFixtures { input, update, .. } = signed_update_for_step(id, step);

                // Step-index linkage, mirrored from the update-crypto driver:
                // step NN is update number NN. Without it a mis-ordered walk
                // surfaces here only as an opaque target-hash mismatch, naming
                // the symptom rather than the cause.
                assert_eq!(
                    field_version_id(&input, "sourceVersionId", id),
                    step_index as u64 + 1,
                    "{id}: {step} must be update number {} in the chain",
                    step_index + 1
                );

                let mut doc = match carried.take() {
                    Some(doc) => doc,
                    None => InitialDocument::from_json_string(&input["sourceDocument"].to_string())
                        .unwrap_or_else(|e| {
                            panic!(
                                "{id}: {step} sourceDocument must parse as an initial \
                                 document: {e}"
                            )
                        }),
                };
                doc.apply_update(&update)
                    .unwrap_or_else(|e| panic!("{id}: applying {step} must succeed: {e}"));
                carried = Some(doc);
            }

            let doc = carried
                .unwrap_or_else(|| panic!("{id}: an end-state row ships at least one update step"));

            let output = read_vector_fixture(&format!("{id}/resolve/output.json"));
            let got: serde_json::Value = doc.as_ref().clone();
            let want: serde_json::Value = output["didDocument"].clone();
            assert_eq!(
                got, want,
                "{id}: applying every update step in order must reproduce \
                 resolve/output.json.didDocument"
            );

            observed.insert(id.clone());
        }
        reconcile_driven_with(AssertionKind::EndState, vectors, &observed, overrides);
    }

    /// The vector ledger's cross-cutting invariant: every discovered
    /// (vector x assertion) row is either driven by one of the drivers above or
    /// carries a stated skip reason, every hand-written skip still matches a row
    /// that exists, and no row's two classifications contradict each other.
    ///
    /// The five drivers each reconcile their own kind's coverage. This test owns
    /// the half none of them can see: that discovery ran and found something, that
    /// coverage has not silently shrunk, that no row fell through the
    /// classification rules, that no skip entry outlived the row it described,
    /// that no hand-written skip duplicates a derived rule, and that a green run
    /// says out loud what it actually checked.
    #[test]
    fn op_vectors_every_row_is_driven_or_skipped_with_reason() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };

        for network_dir in network_dirs_with_vectors() {
            assert!(
                vectors.iter().any(|v| v.network_dir == network_dir),
                "network directory `{network_dir}` was probed as holding vectors but \
                 contributed none"
            );
        }

        check_driven_floor(&vectors);
        check_ledger_invariants(&vectors, SKIP_OVERRIDES);

        eprintln!("{}", render_summary_with(&vectors, SKIP_OVERRIDES));
    }

    /// The coverage ratchet: each assertion kind still drives at least
    /// `DRIVEN_FLOOR` rows.
    ///
    /// `reconcile_driven_with` passes trivially when both sets are empty, so
    /// upstream churn that made every row of a kind skipped-with-a-reason would
    /// zero that kind's coverage while every driver stayed green — only the
    /// stderr summary would change. Resolve is the live exposure: its four rows
    /// all turn on fixture properties outside this repo, and dropping the
    /// external vectors' sidecar genesis document upstream would take it to
    /// zero.
    ///
    /// Takes only the vector set and evaluates against an EMPTY override table
    /// by construction. Reading the live table here would let a legitimate
    /// hand-written skip trip the ratchet, which is exactly the "the escape
    /// hatch turns the suite red when it is used" failure the rest of this
    /// module is built to avoid.
    fn check_driven_floor(vectors: &[Vector]) {
        for (kind, floor) in DRIVEN_FLOOR {
            let driven = expected_driven_with(*kind, vectors, &[]).len();
            assert!(
                driven >= *floor,
                "{kind} coverage fell to {driven} driven row(s), below the floor of {floor}. \
                 Upstream churn or a new derived skip rule has silently shrunk what this suite \
                 checks. Restore the coverage, or lower the floor deliberately and say why."
            );
        }
    }

    /// The cross-cutting ledger checks, over an explicit override table: no
    /// hand-written skip duplicates a derived rule, no row fell through
    /// classification, and no skip entry outlived the row it described.
    fn check_ledger_invariants(vectors: &[Vector], overrides: &[SkipOverride]) {
        let redundant = redundant_overrides(vectors, overrides);
        assert!(
            redundant.is_empty(),
            "{} hand-written skip(s) duplicate a derived rule:\n{}",
            redundant.len(),
            redundant.join("\n"),
        );

        let unclassified = unclassified_rows_with(vectors, overrides);
        assert!(
            unclassified.is_empty(),
            "{} vector row(s) are neither driven nor skipped with a reason:\n{}",
            unclassified.len(),
            unclassified.join("\n"),
        );

        let stale = stale_overrides(overrides, vectors);
        assert!(
            stale.is_empty(),
            "{} SKIP override(s) match no discovered row:\n{}",
            stale.len(),
            stale.join("\n"),
        );
    }

    /// A hand-written skip must keep the suite green when it is used, not turn it
    /// red. The live table is empty by design, so this replays every driver body
    /// and the cross-cutting checks against a table that names one otherwise-driven
    /// row per assertion kind — the shape a real set of entries would take.
    ///
    /// Every kind is covered on purpose. An earlier revision exercised only the
    /// derivation driver, and passed while a populated table still turned other
    /// suite members red; a partial replay is what let that ship.
    ///
    /// The named rows must still exist: `stale_overrides` reporting nothing is the
    /// guard that keeps this test from passing vacuously after an upstream rename.
    ///
    /// The coverage ratchet is replayed here too. A floor evaluated against the
    /// live override table would fire on a legitimate hand-written skip, so this
    /// asserts the opposite: a populated table must NOT trip it.
    #[test]
    fn a_live_skip_override_keeps_every_driver_green() {
        const REASON: &str = "stands in for a hand-written skip; the live table is empty";
        const LIVE_OVERRIDE: &[SkipOverride] = &[
            SkipOverride {
                vector: "regtest/x1/q2fz9mz6",
                kind: AssertionKind::Derivation,
                reason: REASON,
            },
            SkipOverride {
                vector: "regtest/k1/qgpakaw4",
                kind: AssertionKind::GenesisKey,
                reason: REASON,
            },
            SkipOverride {
                vector: "regtest/k1/qgpakaw4",
                kind: AssertionKind::Resolve,
                reason: REASON,
            },
            SkipOverride {
                vector: "mutinynet/x1/q5m2fh36",
                kind: AssertionKind::UpdateCrypto,
                reason: REASON,
            },
            SkipOverride {
                vector: "mutinynet/x1/q5m2fh36",
                kind: AssertionKind::EndState,
                reason: REASON,
            },
        ];

        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };

        // Every entry names a real row, and every one of those rows is driven
        // without it — so each override genuinely changes the expectation.
        assert!(
            stale_overrides(LIVE_OVERRIDE, &vectors).is_empty(),
            "an override names a row that no longer exists — repoint it at a discovered vector"
        );
        for entry in LIVE_OVERRIDE {
            assert!(
                expected_driven_with(entry.kind, &vectors, &[]).contains(entry.vector),
                "{}: without the override the row is driven for {}, so the override changes \
                 something",
                entry.vector,
                entry.kind,
            );
            assert!(
                !expected_driven_with(entry.kind, &vectors, LIVE_OVERRIDE).contains(entry.vector),
                "{}: a live override must remove the row from the {} expectation",
                entry.vector,
                entry.kind,
            );
        }

        // With the overrides live: every driver reconciles against its reduced
        // set and the ledger stays valid.
        drive_derivation(&vectors, LIVE_OVERRIDE);
        drive_genesis_key(&vectors, LIVE_OVERRIDE);
        drive_resolve(&vectors, LIVE_OVERRIDE);
        drive_update_crypto(&vectors, LIVE_OVERRIDE);
        drive_end_state(&vectors, LIVE_OVERRIDE);
        check_ledger_invariants(&vectors, LIVE_OVERRIDE);

        // And the ratchet does not fire: it reads the derived rules alone, so a
        // hand-written skip cannot lower it.
        check_driven_floor(&vectors);
    }

    /// The in-crate transactions fixture, shared by the two unconfirmed-tx tests.
    ///
    /// A beacon-tx UNIT fixture, not a capture of any DID's history: a generic
    /// singleton-beacon transaction carrying a valid OP_RETURN signal output,
    /// confirmed by default and overridden to `confirmed: false` per test. It
    /// bears no relationship to any test-suite vector — `find_next_signals` does
    /// not cross-check transactions against beacon addresses, so these tests
    /// need none. Distinct from `fixtures/chain/`, which holds real captured
    /// per-vector chain snapshots.
    const UNCONFIRMED_FIXTURE: &str = include_str!("../fixtures/singleton-beacon-signal-txs.json");

    /// a *needed* unconfirmed signal — one whose
    /// announced hash is present in the sidecar update-lookup table — must raise a
    /// typed `Err(resolver::Error::UnconfirmedBeaconTx { txid })` (the hidden panic
    /// previously at resolver.rs:227), preserving the txid.
    ///
    /// `Btcr2Error` is untouched.
    #[test]
    fn unconfirmed_needed_signal_returns_err() {
        // `find_next_signals` iterates the supplied `transactions` map and inspects
        // each tx's last output + confirmation status; it does NOT cross-check the
        // tx against the resolver's beacon addresses (that coupling only governs
        // request *generation* in `next_signals_requests`). The resolver doc is
        // re-homed onto the regtest k1 qgpakaw4 vector purely so a valid resolver
        // exists.
        let Some(mut resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };

        // Confirmed pass: discover the update hash this beacon tx announces, reusing
        // the production extraction path rather than re-parsing the OP_RETURN.
        let confirmed_txs: HashMap<BeaconType, Vec<Transaction>> =
            serde_json::from_str(UNCONFIRMED_FIXTURE).unwrap();
        let confirmed_signals = resolver
            .find_next_signals(confirmed_txs)
            .expect("confirmed fixture yields a beacon signal");
        let announced = confirmed_signals[0].signal_bytes;

        // Make that announced hash a *needed* signal by inserting it into the
        // lookup table. find_next_signals only checks key presence, so the mapped
        // Update value is immaterial — borrow a real one from the spec-form fixture.
        let sidecar = SidecarData::from_json_value(
            serde_json::from_str(include_str!(
                "../fixtures/spec-form/sidecar-two-updates.json"
            ))
            .unwrap(),
        )
        .expect("sidecar deserializes");
        resolver
            .update_lookup_table
            .insert(announced, sidecar.updates[0].clone());

        // Unconfirmed pass: the same tx, now in the mempool. A *needed* unconfirmed
        // signal must hard-fail resolution with the txid preserved.
        let mut json: serde_json::Value = serde_json::from_str(UNCONFIRMED_FIXTURE).unwrap();
        let first_tx = &mut json["SingletonBeacon"][0];
        let expected_txid_str = first_tx["txid"].as_str().unwrap().to_string();
        first_tx["status"] = serde_json::json!({ "confirmed": false });
        let unconfirmed_txs: HashMap<BeaconType, Vec<Transaction>> =
            serde_json::from_value(json).unwrap();

        let err = resolver.find_next_signals(unconfirmed_txs).unwrap_err();
        match err {
            Error::UnconfirmedBeaconTx { txid } => {
                assert_eq!(txid.to_string(), expected_txid_str);
            }
            other => panic!("expected UnconfirmedBeaconTx, got {other:?}"),
        }
    }

    /// an unconfirmed beacon tx whose announced hash is NOT a needed signal
    /// (no matching sidecar update) must be SKIPPED, not abort resolution. A real
    /// beacon address routinely carries unrelated mempool txs; one must not hard-
    /// fail an otherwise-resolvable DID.
    #[test]
    fn unconfirmed_unneeded_signal_is_skipped() {
        // Isolate a single beacon tx (the fixture carries several confirmed ones)
        // and mark it unconfirmed, so the only signal in play is the skippable one.
        let json: serde_json::Value = serde_json::from_str(UNCONFIRMED_FIXTURE).unwrap();
        let mut first_tx = json["SingletonBeacon"][0].clone();
        first_tx["status"] = serde_json::json!({ "confirmed": false });
        let json = serde_json::json!({ "SingletonBeacon": [first_tx] });
        let transactions: HashMap<BeaconType, Vec<Transaction>> =
            serde_json::from_value(json).unwrap();

        // Empty sidecar → the announced hash is not present in the lookup table, so
        // the unconfirmed tx is not a signal we are waiting on.
        let Some(resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };

        let signals = resolver
            .find_next_signals(transactions)
            .expect("an unconfirmed tx we hold no sidecar for is skipped, not an error");
        assert!(
            signals.is_empty(),
            "the sole unconfirmed beacon tx was skipped, so no signals are produced"
        );
    }

    /// D-09c (strict wire-signal boundary): a beacon tx whose LAST output is a
    /// malformed/over-long OP_RETURN tail — `[OP_RETURN, <32-byte push>,
    /// <unparseable trailing push opcode>]` — must NOT be matched as a 32-byte
    /// signal. The trailing lone `OP_PUSHBYTES_32` (0x20) with no following data
    /// makes the script instruction iterator yield an `Err`, which the old
    /// `.flatten()` silently dropped, collapsing the script to a 2-op `[OP_RETURN,
    /// PushBytes]` that masqueraded as a valid signal. Rejecting that one output
    /// must not fail the rest of the batch: a well-formed signal in the SAME pass
    /// is still extracted.
    #[test]
    fn malformed_op_return_tail_is_rejected_as_signal() {
        let Some(resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };

        // Well-formed signal (6a 20 <32B>) — must still be extracted.
        let good_signal = Sha256Hash::from([0x11u8; 32]);
        let good_tx = confirmed_signal_tx(good_signal, 100, 1_700_000_000, 0xc1);

        // Malformed tail: OP_RETURN, OP_PUSHBYTES_32 + 32 bytes, then a trailing
        // lone OP_PUSHBYTES_32 (0x20) with NO following data → the instruction
        // iterator yields an Err for that push. The old `.flatten()` dropped it,
        // leaving a 2-op script that loosely matched the exact-2 signal pattern.
        let bad_script = format!("6a20{}20", hex::encode([0x22u8; 32]));
        let bad_txid = "cc".repeat(32);
        let bad_json = serde_json::json!({
            "txid": bad_txid,
            "version": 2,
            "locktime": 0,
            "vin": [],
            "vout": [{ "scriptpubkey": bad_script, "value": 0 }],
            "size": 0,
            "weight": 0,
            "fee": 0,
            "status": {
                "confirmed": true,
                "block_height": 100,
                "block_hash":
                    "0000000000000000000000000000000000000000000000000000000000000000",
                "block_time": 1_700_000_000,
            },
        });
        let bad_tx: Transaction =
            serde_json::from_value(bad_json).expect("synthetic malformed-tail tx deserializes");

        let mut transactions: HashMap<BeaconType, Vec<Transaction>> = HashMap::new();
        transactions.insert(BeaconType::Singleton, vec![bad_tx, good_tx]);

        let signals = resolver
            .find_next_signals(transactions)
            .expect("a malformed OP_RETURN tail is skipped, not an error");

        assert_eq!(
            signals.len(),
            1,
            "only the well-formed output yields a signal; the malformed tail is rejected"
        );
        assert_eq!(
            signals[0].signal_bytes, good_signal,
            "the surviving signal is the well-formed one, not the malformed-tail masquerade"
        );
    }

    /// Build a minimal Singleton-beacon resolver over the regtest k1 qgpakaw4
    /// resolved DID document with a caller-supplied sidecar + chain tip. Shared by
    /// the RESOLVE-NN FSM tests below. Returns `None` (so the caller skips) when
    /// the test-suite submodule is absent.
    fn resolver_with(sidecar: SidecarData, chain_tip_height: Option<u32>) -> Option<Resolver> {
        let resolve_output = read_fixture_or_skip("regtest/k1/qgpakaw4/resolve/output.json")?;
        let resolve_output: serde_json::Value = serde_json::from_str(&resolve_output).unwrap();
        let did_document = resolve_output["didDocument"].to_string();
        let initial_document = InitialDocument::from_json_string(&did_document)
            .expect("regtest k1 qgpakaw4 resolved didDocument parses");

        let resolution_options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height,
            ..Default::default()
        };
        Some(Resolver::new(initial_document, resolution_options))
    }

    /// The DID of the regtest k1 qgpakaw4 vector that `resolver_with` /
    /// `resolver_from_options` build over.
    const QGPAKAW4_DID: &str =
        "did:btcr2:k1qgpakaw4lwemekywf0lyth9hf6j8r2td7gqtrs4aztqfky50jnx7s8gfapup6";

    /// Drive a resolver to its terminal state with empty beacon-signal
    /// responses (no on-chain signals → resolves to the contemporary document).
    fn resolve_with_no_signals(resolver: Resolver) -> ResolutionResult {
        let ResolverState::Requests(next_state, _beacons) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        // Feed empty responses: no beacon signals to process.
        let fsm = next_state.process_responses(HashMap::new());
        match fsm.resolve().expect("empty-signal step resolves") {
            ResolverState::Resolved(result) => result,
            ResolverState::Requests(..) => panic!("expected Resolved with no signals"),
        }
    }

    /// Build a minimal Singleton-beacon resolver over the regtest k1 qgpakaw4
    /// resolved DID document with the given `ResolutionOptions`. Pure construction
    /// — no FSM stepping, no network. Returns `None` (so the caller skips) when
    /// the test-suite submodule is absent.
    fn resolver_from_options(resolution_options: ResolutionOptions) -> Option<Resolver> {
        let resolve_output = read_fixture_or_skip("regtest/k1/qgpakaw4/resolve/output.json")?;
        let resolve_output: serde_json::Value = serde_json::from_str(&resolve_output).unwrap();
        let did_document = resolve_output["didDocument"].to_string();
        let initial_document = InitialDocument::from_json_string(&did_document)
            .expect("regtest k1 qgpakaw4 resolved didDocument parses");
        Some(Resolver::new(initial_document, resolution_options))
    }

    /// `ResolutionOptions.esplora_url = Some(url)` overrides the resolver's
    /// request host; `Resolver::new` reads the caller-injected URL into
    /// `rpc_host`. Pure-construction, fully offline.
    #[test]
    fn esplora_url_some_overrides_rpc_host() {
        let url = "https://node.example/api".to_string();
        let Some(resolver) = resolver_from_options(ResolutionOptions {
            esplora_url: Some(url.clone()),
            ..Default::default()
        }) else {
            return;
        };
        assert_eq!(resolver.rpc_host, url);
    }

    /// `esplora_url = None` falls back to `DEFAULT_RPC_BASE_URL` (testnet).
    /// The const is retained as the fallback. Pure-construction, fully offline.
    #[test]
    fn esplora_url_none_falls_back_to_default() {
        let Some(resolver) = resolver_from_options(ResolutionOptions {
            esplora_url: None,
            ..Default::default()
        }) else {
            return;
        };
        assert_eq!(resolver.rpc_host, DEFAULT_RPC_BASE_URL);
    }

    /// A spec-form sidecar JSON deserializes into `SidecarData`;
    /// `update_lookup_table` contains one entry per spec-form update, keyed by
    /// the JSON Document Hash (`Update::hash()`).
    ///
    /// Spec: did-btcr2/src/operations/resolve.md §Process Sidecar Data lines 62-67
    /// (build a map from hash to update).
    #[test]
    fn sidecar_lookup_table_keyed_by_jcs_hash() {
        let raw = include_str!("../fixtures/spec-form/sidecar-two-updates.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let sidecar = SidecarData::from_json_value(value).expect("sidecar deserializes");

        // Two updates → two lookup-table entries.
        assert_eq!(sidecar.updates.len(), 2);
        assert_eq!(sidecar.update_lookup_table.len(), 2);

        // Each table entry is keyed by the JCS hash of the corresponding update.
        for update in &sidecar.updates {
            let key = update.hash();
            assert!(
                sidecar.update_lookup_table.contains_key(&key),
                "lookup table must be keyed by Update::hash()"
            );
        }
    }

    /// Spec-authority ordering: the
    /// version_time bound must be evaluated against the FIRST tuple AFTER the
    /// (targetVersionId, block_height) sort (resolve.md:151-153), and that choice
    /// must be deterministic regardless of the order in which beacon signals were
    /// discovered (HashMap iteration order is non-deterministic).
    ///
    /// GIVEN two real updates from `sidecar-two-updates.json` and two
    /// `NextSignal`s whose CONSTRUCTION order is reversed relative to their
    /// (targetVersionId, block_height) order, WHEN `process_beacon_signals` + the
    /// new sort runs in a loop (>= 8 iterations), THEN the first tuple (hence the
    /// version_time stop decision) is identical every iteration AND equals the
    /// (targetVersionId, block_height)-minimum tuple.
    #[test]
    fn version_time_bound_is_deterministic_across_signal_order() {
        let raw = include_str!("../fixtures/spec-form/sidecar-two-updates.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let sidecar = SidecarData::from_json_value(value).expect("sidecar deserializes");
        assert_eq!(sidecar.updates.len(), 2);

        // The two updates carry targetVersionId 2 and 3; their signal_bytes are
        // their JSON Document Hashes (Update::hash()), which the lookup table is
        // keyed by.
        let update_lo = sidecar
            .updates
            .iter()
            .min_by_key(|u| u.target_version_id)
            .expect("two updates present")
            .clone();
        let update_hi = sidecar
            .updates
            .iter()
            .max_by_key(|u| u.target_version_id)
            .expect("two updates present")
            .clone();
        assert!(update_lo.target_version_id < update_hi.target_version_id);

        // Give the LOWER-version update the HIGHER block height so the sort key
        // (target_version_id, block_height) is driven by target_version_id, and
        // construct the NextSignals in REVERSED order (hi first) to model a
        // non-deterministic discovery order.
        let signal_hi = NextSignal {
            beacon_type: BeaconType::Singleton,
            signal_bytes: update_hi.hash(),
            block_time: Utc::now(),
            block_height: 50,
        };
        let signal_lo = NextSignal {
            beacon_type: BeaconType::Singleton,
            signal_bytes: update_lo.hash(),
            block_time: Utc::now(),
            block_height: 100,
        };

        let Some(resolver) = resolver_with(sidecar, None) else {
            return;
        };
        let expected_first = (update_lo.target_version_id, 100u32);

        for _ in 0..8 {
            // Rebuild the NextSignal inputs each iteration in the reversed
            // (hi, lo) construction order.
            let next_signals = vec![
                NextSignal {
                    beacon_type: signal_hi.beacon_type,
                    signal_bytes: signal_hi.signal_bytes,
                    block_time: signal_hi.block_time,
                    block_height: signal_hi.block_height,
                },
                NextSignal {
                    beacon_type: signal_lo.beacon_type,
                    signal_bytes: signal_lo.signal_bytes,
                    block_time: signal_lo.block_time,
                    block_height: signal_lo.block_height,
                },
            ];

            let mut signals = resolver
                .process_beacon_signals(next_signals)
                .expect("both updates resolve from the lookup table");
            signals.sort_unstable_by_key(|s| (s.update.target_version_id, s.block_height));

            let first = &signals[0];
            assert_eq!(
                (first.update.target_version_id, first.block_height),
                expected_first,
                "first tuple after sort must be the (target_version_id, block_height)-minimum, \
                 invariant across iterations regardless of discovery order"
            );
        }
    }

    /// `Resolver::resolve` terminal state returns
    /// `ResolverState::Resolved(ResolutionResult { resolution_metadata, document,
    /// document_metadata })` — the spec resolution triple.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md lines 42-48 (return signature).
    #[test]
    fn resolve_returns_the_resolution_triple() {
        let Some(resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };
        let result = resolve_with_no_signals(resolver);

        // Structural: destructuring the triple is a compile-time guarantee;
        // assert the runtime shape — an un-mutated DID document at version 1.
        let ResolutionResult {
            resolution_metadata: _,
            document,
            document_metadata,
        } = result;
        assert_eq!(document.fields.id.encode(), QGPAKAW4_DID);
        assert_eq!(document_metadata.version_id, NonZeroU64::MIN);
        assert!(!document_metadata.deactivated);
        // No chain tip supplied → confirmations is None (fail-closed).
        assert_eq!(document_metadata.confirmations, None);
    }

    /// `DocumentMetadata.version_id` round-trips as an ASCII string.
    /// The exhaustive serde round-trip (json + jcs + numeric-rejection) is pinned
    /// by `document::tests::document_metadata_version_id_round_trips_as_ascii_string`
    /// This resolver-level test asserts the version_id that the
    /// FSM actually produces serializes to the string form.
    ///
    /// Spec: did-btcr2/src/data-structures.md:341 (versionId is ASCII string).
    #[test]
    fn metadata_version_id_is_an_ascii_string() {
        let Some(resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };
        let result = resolve_with_no_signals(resolver);
        let json =
            serde_json::to_string(&result.document_metadata).expect("document metadata serializes");
        // version_id == 1 for an un-updated document; must be the ASCII string "1".
        assert!(
            json.contains(r#""versionId":"1""#),
            "resolver-produced versionId must serialize as ASCII string, got: {json}"
        );
    }

    /// `confirmations == tip - applied_block_height + 1` with
    /// saturating arithmetic (tip > h, tip == h, tip < h) plus the no-tip and
    /// no-applied-update cases. This exercises only `terminal_state`'s formatting
    /// of `applied_block_height`, which is unchanged; the *accounting* of that
    /// height (most-recently-applied unique update, not a running min across
    /// distinct updates) is driven end-to-end by
    /// `confirmations_use_the_most_recently_applied_update` and
    /// `later_duplicate_does_not_raise_confirmations`.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:31,50.
    #[test]
    fn metadata_confirmations_saturate_against_chain_tip() {
        // terminal_state computes confirmations from chain_tip_height +
        // applied_block_height. Drive the field directly to cover the three
        // arithmetic regimes plus the no-tip case.
        let Some(mut resolver) = resolver_with(SidecarData::default(), Some(100)) else {
            return;
        };

        // tip > h: 100 - 90 + 1 = 11.
        resolver.applied_block_height = Some(90);
        assert_eq!(
            resolver.terminal_state().document_metadata.confirmations,
            Some(11)
        );

        // tip == h: 100 - 100 + 1 = 1.
        resolver.applied_block_height = Some(100);
        assert_eq!(
            resolver.terminal_state().document_metadata.confirmations,
            Some(1)
        );

        // tip < h (clock skew / indexer lag): saturating → 0 + 1 = 1.
        resolver.applied_block_height = Some(150);
        assert_eq!(
            resolver.terminal_state().document_metadata.confirmations,
            Some(1)
        );

        // No applied update → confirmations None.
        resolver.applied_block_height = None;
        assert_eq!(
            resolver.terminal_state().document_metadata.confirmations,
            None
        );

        // No chain tip → confirmations None even with an applied height.
        let Some(mut no_tip) = resolver_with(SidecarData::default(), None) else {
            return;
        };
        no_tip.applied_block_height = Some(90);
        assert_eq!(
            no_tip.terminal_state().document_metadata.confirmations,
            None
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // Full-FSM-drive coverage for the versionTime bound and confirmations.
    //
    // These build a self-consistent chain of two signed updates ENTIRELY IN
    // MEMORY from a locally-generated key-based initial document (no on-disk
    // fixture, no test-suite submodule dependency — so they never vacuously
    // SKIP, Pitfall 2), then drive the public resolver FSM end-to-end
    // (Init -> Requests -> process_responses -> resolve -> Resolved) over
    // synthetic confirmed beacon transactions whose OP_RETURN push is each
    // update's JSON Document Hash.
    // ──────────────────────────────────────────────────────────────────────

    /// Fixed secret key for the in-memory chain (`[7u8; 32]`, a valid secp256k1
    /// key). Its public key derives the source DID, so the DID's own
    /// verification method signs the chained updates.
    const CHAIN_SECRET_KEY_BYTES: [u8; 32] = [7u8; 32];

    fn chain_secret_key() -> crate::key::SecretKey {
        crate::key::SecretKey::try_from(CHAIN_SECRET_KEY_BYTES)
            .expect("[7u8; 32] is a valid secp256k1 secret key")
    }

    /// A benign RFC-6902 patch that keeps the document conformant and does not
    /// touch `id`: append the given verification-method id to `assertionMethod`.
    fn chain_benign_patch(vm_id: &str) -> json_patch::Patch {
        serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/assertionMethod/-", "value": vm_id}
        ]))
        .expect("benign patch is a valid RFC 6902 op array")
    }

    /// Build a key-based initial document deterministically from
    /// `CHAIN_SECRET_KEY_BYTES`, then two chained signed updates: update1 (v2)
    /// against the initial doc and update2 (v3) against the post-update-1 doc.
    ///
    /// The chain is self-consistent BY CONSTRUCTION — `update1.source_hash ==
    /// initial.hash()` and `update2.source_hash == (initial + update1).hash()` —
    /// because both updates are derived from the locally-built document each run,
    /// not from committed bytes that could silently drift if
    /// `deterministically_generate`'s output ever changed. This is what makes the
    /// apply loop actually APPLY (rather than reject at the sourceHash check),
    /// and it needs no on-disk fixture and no test-suite submodule.
    fn chained_two_updates() -> (InitialDocument, Update, Update) {
        use crate::document::Document;
        use crate::identifier::{Did, DidComponents, DidVersion, IdType, Network};
        use secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let public_key = chain_secret_key().as_inner().public_key(&secp);
        let id_type = IdType::from(public_key);
        let did: Did = DidComponents::new(DidVersion::One, Network::Mutinynet, id_type)
            .expect("mutinynet is a valid network")
            .try_into()
            .expect("default version + mutinynet + key id type encode to a valid did");

        let initial = InitialDocument::from_did(&did, &ResolutionOptions::default())
            .expect("key-based DID deterministically generates its initial document");
        let document = Document::from(initial.clone());
        let vm_id = format!("{}#initialKey", did.encode());

        let v2 = NonZeroU64::new(2).expect("2 is non-zero");
        let update1 = document
            .construct_signed_update(chain_benign_patch(&vm_id), v2, &vm_id, chain_secret_key())
            .expect("update #1 constructs against the initial document");

        let mut after1 = initial.clone();
        after1
            .apply_update(&update1)
            .expect("update #1 applies to the initial document");
        let doc_after1 = Document::from(after1);

        let v3 = NonZeroU64::new(3).expect("3 is non-zero");
        let update2 = doc_after1
            .construct_signed_update(chain_benign_patch(&vm_id), v3, &vm_id, chain_secret_key())
            .expect("update #2 constructs against the post-update-1 document");

        (initial, update1, update2)
    }

    /// Build a confirmed Singleton-beacon esplora transaction whose LAST output is
    /// `OP_RETURN <signal>` (a 32-byte push of an update's JSON Document Hash).
    /// `txid_seed` gives each tx a distinct, structurally-valid txid.
    fn confirmed_signal_tx(
        signal: Sha256Hash,
        block_height: u32,
        block_time: i64,
        txid_seed: u8,
    ) -> Transaction {
        // OP_RETURN (0x6a) + OP_PUSHBYTES_32 (0x20) + 32-byte hash.
        let script_pubkey = format!("6a20{}", hex::encode(signal.as_bytes()));
        let txid = format!("{txid_seed:02x}").repeat(32);
        let json = serde_json::json!({
            "txid": txid,
            "version": 2,
            "locktime": 0,
            "vin": [],
            "vout": [{ "scriptpubkey": script_pubkey, "value": 0 }],
            "size": 0,
            "weight": 0,
            "fee": 0,
            "status": {
                "confirmed": true,
                "block_height": block_height,
                "block_hash":
                    "0000000000000000000000000000000000000000000000000000000000000000",
                "block_time": block_time,
            },
        });
        serde_json::from_value(json).expect("synthetic esplora transaction JSON deserializes")
    }

    /// A `DateTime<Utc>` from a unix timestamp (seconds).
    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("in-range unix timestamp")
    }

    /// Drive a resolver FSM to its terminal state over a single batch of
    /// Singleton-beacon transactions, mirroring `resolve_with_no_signals`'s
    /// drive-to-terminal shape.
    fn drive_to_resolved(resolver: Resolver, txs: Vec<Transaction>) -> ResolutionResult {
        let ResolverState::Requests(next_state, _requests) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        let mut transactions: HashMap<BeaconType, Vec<Transaction>> = HashMap::new();
        transactions.insert(BeaconType::Singleton, txs);
        let mut state = next_state
            .process_responses(transactions)
            .resolve()
            .expect("processing the beacon signals resolves a step");
        loop {
            match state {
                ResolverState::Resolved(result) => break result,
                ResolverState::Requests(next, _requests) => {
                    state = next
                        .process_responses(HashMap::new())
                        .resolve()
                        .expect("empty-signal step resolves");
                }
            }
        }
    }

    /// Guard (Task 1 anti-vacuity): the in-memory chain's FIRST update's
    /// `source_hash` equals the locally-constructed initial document's `hash()`.
    /// This is what makes the apply loop actually APPLY update1 rather than
    /// reject it at the sourceHash check (resolver.rs step 10.2.1) — the
    /// precondition for every full-drive test below to be
    /// non-vacuous.
    #[test]
    fn chained_two_updates_chains_to_initial_doc() {
        let (initial, update1, update2) = chained_two_updates();
        assert_eq!(
            update1.source_hash,
            initial.hash(),
            "update1.sourceHash must equal the locally-built initial doc hash"
        );
        assert_eq!(
            u64::from(update1.target_version_id),
            2,
            "update1 targets version 2"
        );
        assert_eq!(
            u64::from(update2.target_version_id),
            3,
            "update2 targets version 3"
        );
    }

    /// A resolution whose `versionTime` falls mid-batch returns the
    /// version in EFFECT at that time, not the batch's final version. Two chained
    /// updates arrive (v2 @ block_time T2, v3 @ block_time T3) with
    /// `T2 < versionTime < T3`; the resolved document is v2, NOT v3. The
    /// per-tuple versionTime check inside the apply branch aborts before applying
    /// v3.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:153.
    #[test]
    fn version_time_mid_batch_returns_the_version_in_effect() {
        let (initial, update1, update2) = chained_two_updates();
        let t2 = 1_700_000_000i64;
        let t3 = 1_700_000_200i64;
        let version_time = 1_700_000_100i64; // T2 < T < T3

        let tx_v2 = confirmed_signal_tx(update1.hash(), 100, t2, 0xa1);
        let tx_v3 = confirmed_signal_tx(update2.hash(), 200, t3, 0xa2);

        let sidecar = SidecarData::new(None, vec![update1, update2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(version_time)),
            ..Default::default()
        };
        let resolver = Resolver::new(initial, options);
        let result = drive_to_resolved(resolver, vec![tx_v2, tx_v3]);

        assert_eq!(
            u64::from(result.document_metadata.version_id),
            2,
            "mid-batch versionTime must resolve to the in-effect version (v2), not v3"
        );
    }

    /// Ordering fold-in: a DUPLICATE announcement of v2 at a HIGH
    /// block_time (> versionTime), processed under the ascending
    /// (target_version_id, block_height) sort BEFORE the UNIQUE v3 at a LOW
    /// block_time (< versionTime), must NOT abort the loop. v3 IS still applied.
    /// This pins that the versionTime cutoff lives ONLY in the unique-apply
    /// branch, never on a duplicate tuple — a naive per-every-tuple check would
    /// abort at the high-block_time duplicate and wrongly return v2.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:153.
    #[test]
    fn version_time_cutoff_ignores_duplicate_tuples() {
        let (initial, update1, update2) = chained_two_updates();
        let version_time = 1_700_000_100i64;

        // v2 unique @ height 100, low block_time (< T) -> applied first.
        let tx_v2 = confirmed_signal_tx(update1.hash(), 100, 1_700_000_000, 0xb1);
        // v2 DUPLICATE @ height 200, HIGH block_time (> T) -> processed before v3
        // under the (tvid, height) sort, must NOT abort the loop.
        let tx_v2_dup = confirmed_signal_tx(update1.hash(), 200, 1_700_000_999, 0xb2);
        // v3 unique @ height 300, low block_time (< T) -> must still apply.
        let tx_v3 = confirmed_signal_tx(update2.hash(), 300, 1_700_000_050, 0xb3);

        let sidecar = SidecarData::new(None, vec![update1, update2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(version_time)),
            ..Default::default()
        };
        let resolver = Resolver::new(initial, options);
        let result = drive_to_resolved(resolver, vec![tx_v2, tx_v2_dup, tx_v3]);

        assert_eq!(
            u64::from(result.document_metadata.version_id),
            3,
            "a high-block_time duplicate must not suppress the later within-versionTime unique v3"
        );
    }

    /// `confirmations` derives from the MOST-RECENTLY-APPLIED unique
    /// update's block height, not the running min across distinct updates. Two
    /// distinct updates apply at heights 100 (v2) then 200 (v3); with chain tip
    /// 300, confirmations = 300 - 200 + 1 = 101 (from v3's height), NOT
    /// 300 - 100 + 1 = 201 (the old running-min bug).
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:31,50.
    #[test]
    fn confirmations_use_the_most_recently_applied_update() {
        let (initial, update1, update2) = chained_two_updates();

        let tx_v2 = confirmed_signal_tx(update1.hash(), 100, 1_700_000_000, 0xc1);
        let tx_v3 = confirmed_signal_tx(update2.hash(), 200, 1_700_000_100, 0xc2);

        let sidecar = SidecarData::new(None, vec![update1, update2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height: Some(300),
            ..Default::default()
        };
        let resolver = Resolver::new(initial, options);
        let result = drive_to_resolved(resolver, vec![tx_v2, tx_v3]);

        assert_eq!(
            u64::from(result.document_metadata.version_id),
            3,
            "both updates apply -> version 3"
        );
        assert_eq!(
            result.document_metadata.confirmations,
            Some(101),
            "confirmations must derive from the most-recently-applied update's height (200), \
             not the running min (100)"
        );
    }

    /// Sort-guaranteed dedup: the SAME update (v2) announced twice at
    /// heights 100 then 200 (h_low < h_high). Under the ascending
    /// (target_version_id, block_height) sort the h_low announcement is applied
    /// FIRST and becomes the confirmations height; the later h_high duplicate's
    /// defensive min is a no-op and does NOT raise it. With chain tip 300,
    /// confirmations = 300 - 100 + 1 = 201 (from h_low), never
    /// 300 - 200 + 1 = 101.
    ///
    /// This asserts the SORT-guaranteed lowest-height-first outcome, not a
    /// synthetic lower-than-applied duplicate (which cannot arise under the sort).
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:50 footnote 1.
    #[test]
    fn later_duplicate_does_not_raise_confirmations() {
        let (initial, update1, _update2) = chained_two_updates();

        // Same v2 update announced twice: h_low = 100 (applied first), h_high =
        // 200 (later duplicate). The higher-height duplicate must not raise the
        // applied confirmations height.
        let tx_low = confirmed_signal_tx(update1.hash(), 100, 1_700_000_000, 0xd1);
        let tx_high = confirmed_signal_tx(update1.hash(), 200, 1_700_000_100, 0xd2);

        let sidecar = SidecarData::new(None, vec![update1], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height: Some(300),
            ..Default::default()
        };
        let resolver = Resolver::new(initial, options);
        let result = drive_to_resolved(resolver, vec![tx_low, tx_high]);

        assert_eq!(
            u64::from(result.document_metadata.version_id),
            2,
            "the single update applies -> version 2"
        );
        assert_eq!(
            result.document_metadata.confirmations,
            Some(201),
            "confirmations must derive from the lowest-height (first-applied) announcement (100), \
             not raised by the later higher-height duplicate (200)"
        );
    }

    /// `DocumentMetadata.deactivated` is sourced from
    /// `contemporary_doc.fields.deactivated`. An initial document carries
    /// `false`; flipping the field surfaces `true` in the metadata.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:48 (deactivated REQUIRED in metadata).
    #[test]
    fn metadata_deactivated_follows_the_document() {
        // Un-deactivated initial document → metadata.deactivated == false.
        let Some(resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };
        let result = resolve_with_no_signals(resolver);
        assert!(!result.document_metadata.deactivated);

        // A deactivated contemporary document → metadata.deactivated == true.
        let Some(mut resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };
        resolver.contemporary_doc.fields.deactivated = true;
        assert!(resolver.terminal_state().document_metadata.deactivated);
    }

    /// once the contemporary document is deactivated, the FSM
    /// short-circuits — no further beacon signals mutate the document. The
    /// terminal state reflects `deactivated: true`.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md §"Process updates Array" step 7
    /// (if current_document.deactivated, resolve current_document as didDocument).
    #[test]
    fn deactivated_document_short_circuits_the_walk() {
        // A resolver whose document is already deactivated, driven with empty
        // signals, resolves directly and preserves version_id == 1 (no further
        // update is applied past the short-circuit point).
        let Some(mut resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };
        resolver.contemporary_doc.fields.deactivated = true;
        let version_before = resolver.current_version_id;

        let result = resolve_with_no_signals(resolver);
        assert!(result.document_metadata.deactivated);
        assert_eq!(
            result.document_metadata.version_id, version_before,
            "no update may be applied once deactivated (short-circuit)"
        );
    }

    /// a beacon signal whose `signal_bytes` is NOT present in
    /// `update_lookup_table` raises `Btcr2Error::MissingUpdateData { update_hash }`
    /// directly — not a sidecar-not-found sentinel and not a panic.
    ///
    /// Spec: did-btcr2/src/errors.md:21-23 (MISSING_UPDATE_DATA: BTCR2 Update data
    /// can not be found in either the provided Sidecar Data nor in CAS).
    #[test]
    fn unknown_signal_hash_raises_missing_update_data() {
        // Empty sidecar (the missing-update fixture has zero updates) → empty
        // lookup table.
        let raw = include_str!("../fixtures/spec-form/sidecar-missing-update.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let sidecar = SidecarData::from_json_value(value).expect("sidecar deserializes");
        assert!(sidecar.update_lookup_table.is_empty());

        let Some(resolver) = resolver_with(sidecar, None) else {
            return;
        };

        // Synthesize a beacon signal whose hash is absent from the (empty) table.
        let missing_hash = Sha256Hash::from([7u8; 32]);
        let signal = NextSignal {
            beacon_type: BeaconType::Singleton,
            signal_bytes: missing_hash,
            block_time: Utc::now(),
            block_height: 42,
        };

        let err = resolver
            .process_beacon_signals(vec![signal])
            .expect_err("missing update must error");

        match err {
            Error::Btcr2Error(Btcr2Error::MissingUpdateData { update_hash }) => {
                assert_eq!(update_hash, missing_hash, "error carries the missed hash");
            }
            other => panic!("expected MissingUpdateData, got {other:?}"),
        }
    }

    /// a `CASBeacon` signal reaching `process_beacon_signals` (a
    /// subject-controlled beacon type) returns the typed `Btcr2Error::Unsupported`
    /// instead of panicking — no remote DoS.
    #[test]
    fn cas_signal_returns_unsupported() {
        let Some(resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };

        let signal = NextSignal {
            beacon_type: BeaconType::Cas,
            signal_bytes: Sha256Hash::from([1u8; 32]),
            block_time: Utc::now(),
            block_height: 1,
        };

        let err = resolver
            .process_beacon_signals(vec![signal])
            .expect_err("CAS beacon must error, not panic");
        assert!(
            matches!(err, Error::Btcr2Error(Btcr2Error::Unsupported(_))),
            "expected Unsupported, got {err:?}"
        );
    }

    /// an `SMTBeacon` signal reaching `process_beacon_signals` returns
    /// the typed `Btcr2Error::Unsupported` instead of panicking.
    #[test]
    fn smt_signal_returns_unsupported() {
        let Some(resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };

        let signal = NextSignal {
            beacon_type: BeaconType::SparseMerkleTree,
            signal_bytes: Sha256Hash::from([2u8; 32]),
            block_time: Utc::now(),
            block_height: 1,
        };

        let err = resolver
            .process_beacon_signals(vec![signal])
            .expect_err("SMT beacon must error, not panic");
        assert!(
            matches!(err, Error::Btcr2Error(Btcr2Error::Unsupported(_))),
            "expected Unsupported, got {err:?}"
        );
    }

    /// a contemporary document carrying a `CASBeacon` service drives
    /// the request-building path (`next_signals_requests`, via the Init FSM step)
    /// to the typed `Btcr2Error::Unsupported` instead of a panic.
    #[test]
    fn cas_service_request_returns_unsupported() {
        let Some(mut resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };
        // Subject-controlled: flip the genesis beacon to an unimplemented type.
        resolver.contemporary_doc.fields.service.head.ty = BeaconType::Cas;

        let err = resolver
            .resolve()
            .expect_err("CAS beacon request build must error, not panic");
        assert!(
            matches!(err, Error::Btcr2Error(Btcr2Error::Unsupported(_))),
            "expected Unsupported, got {err:?}"
        );
    }

    /// a contemporary document carrying an `SMTBeacon` service drives
    /// the request-building path to the typed `Btcr2Error::Unsupported`.
    #[test]
    fn smt_service_request_returns_unsupported() {
        let Some(mut resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };
        resolver.contemporary_doc.fields.service.head.ty = BeaconType::SparseMerkleTree;

        let err = resolver
            .resolve()
            .expect_err("SMT beacon request build must error, not panic");
        assert!(
            matches!(err, Error::Btcr2Error(Btcr2Error::Unsupported(_))),
            "expected Unsupported, got {err:?}"
        );
    }
}
