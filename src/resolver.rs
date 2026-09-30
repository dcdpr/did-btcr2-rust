#![warn(clippy::unwrap_used)]
//! Panic-sweep policy: test code is exempted via clippy.toml.

use crate::beacon::BeaconType;
use crate::canonical_hash::CanonicalHash as _;
use crate::document::{
    AnnouncingBlock, InitialDocument, ResolutionOptions, ResolutionResult, SidecarData,
};
use crate::error::{Btcr2Error, ProblemDetails};
use crate::update::UnsecuredUpdate;
use crate::{identifier::Sha256Hash, update::Update};
use chrono::{DateTime, Utc};
use esploda::bitcoin::address::Address;
use esploda::bitcoin::{BlockHash, Txid, opcodes::all::OP_RETURN, script::Instruction};
use esploda::esplora::{Status, Transaction};
use onlyerror::Error;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::num::{NonZeroU32, NonZeroU64};

/// Errors raised while the resolver FSM walks beacon signals and applies
/// updates.
///
/// Two kinds live here. Spec errors — the [`Btcr2Error`] pass-through and the
/// two sentinels the walk raises itself — carry a problem-details body via
/// [`ProblemDetails`]. Driver preconditions (`MissingBlockMediantime`,
/// `MissingChainTip`, `UnrequestedBeaconHistory`) do not:
/// they mean the caller driving the sans-I/O loop did not supply what a
/// request asked for (or supplied something no request asked for), which is
/// a bug in the driver and not a statement about the DID, so they are
/// deliberately not folded into the spec vocabulary.
#[derive(Error, Debug)]
pub enum Error {
    /// Update hash does not match
    UpdateHashMismatch,

    /// Late Publishing Error
    LatePublishingError,

    /// DID:BTCR2 error
    Btcr2Error(#[from] crate::error::Btcr2Error),

    /// The resolver asked for the `mediantime` of the block that confirmed a
    /// beacon signal (the update's proof carries `expires`, or a
    /// `versionTime` bound is in force) and the caller's answer did not
    /// include it. The check cannot run, so resolution stops rather than
    /// applying an update it could not check. A driver precondition, not a
    /// spec error: the update has not been judged.
    #[error("mediantime of block {block_hash} was requested but not supplied")]
    MissingBlockMediantime {
        /// Hash of the block whose mediantime is missing.
        block_hash: BlockHash,
    },

    /// A confirmed beacon signal was met but the caller supplied no chain
    /// tip (`ResolutionOptions::chain_tip_height`), so the signal's
    /// confirmations cannot be counted against `minConf`. A driver
    /// precondition, not a spec error: the tip is the driver's to fetch, and
    /// applying the signal unchecked would silently ignore the gate.
    #[error(
        "beacon signal {txid} confirmed at height {block_height} was met with no chain tip \
         supplied, so its confirmations cannot be counted against minConf"
    )]
    MissingChainTip {
        /// Transaction id of the confirmed beacon signal.
        txid: Txid,
        /// Height of the block that confirmed it.
        block_height: u32,
    },

    /// The caller answered a [`ResolverState::Requests`] with a history keyed
    /// by an address that is not a beacon of the current document, so no
    /// request for it was ever issued. Every tuple must carry the Beacon
    /// Address whose history announced it (resolve.md:152), and that address
    /// can only be one the document declares. A driver precondition, not a
    /// spec error: the history is not judged, it is refused.
    #[error(
        "a history for address {address} was supplied, but the document declares no beacon at \
         that address and the resolver did not request it"
    )]
    UnrequestedBeaconHistory {
        /// The address the supplied history was keyed by.
        address: String,
    },
}

/// Problem details for the spec-level outcomes of a walk; `None` for a driver
/// precondition, which has no spec code because it is not a resolution
/// result.
///
/// Note: `MISSING_UPDATE_DATA` is NOT produced here. The sidecar-miss site in
/// `Resolver::process_beacon_signals` raises
/// `Btcr2Error::MissingUpdateData { update_hash }` directly, because only the
/// call site has the missed `update_hash` (the beacon signal bytes) in scope.
impl ProblemDetails for Error {
    fn details(&self) -> Option<serde_json::Value> {
        match self {
            Error::UpdateHashMismatch => Btcr2Error::InvalidDidUpdate(
                "update hash does not match the expected beacon-signal hash".into(),
            )
            .details(),
            Error::LatePublishingError => Btcr2Error::LatePublishingError(
                "late publishing detected at update sort step".into(),
            )
            .details(),
            // Pass-through: the inner spec error is already authoritative.
            Error::Btcr2Error(e) => e.details(),
            Error::MissingBlockMediantime { .. }
            | Error::MissingChainTip { .. }
            | Error::UnrequestedBeaconHistory { .. } => None,
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
    /// Caller-supplied chain tip height, the basis for every confirmation
    /// count: the `minConf` gate in `find_next_signals` and the terminal
    /// `confirmations`. `None` => no confirmed signal can be processed
    /// (`Error::MissingChainTip`) and `DocumentMetadata.confirmations` is
    /// `None` (fail-closed).
    chain_tip_height: Option<u32>,
    /// `resolutionOptions.minConf` (default 6): a signal with fewer
    /// confirmations than this is skipped by `find_next_signals`.
    min_conf: NonZeroU32,
    /// The media type reported as `didResolutionMetadata.contentType`
    /// (data-structures.md "DID Resolution Metadata"):
    /// `resolutionOptions.accept`, or `application/did` when unset.
    content_type: String,
    /// The spec's `current_block_height` (resolve.md:39): the block height of
    /// the most recently applied update, set in "Apply `update`"
    /// (resolve.md:228). It is the basis for both `confirmations` and the
    /// Find Beacon Signals height condition (resolve.md:134). `None` until an
    /// update applies, which the filter reads as the spec's initial `0` and
    /// `terminal_state` reports as `confirmations = 0` — height 0 is a real
    /// block height, hence the `Option`.
    current_block_height: Option<u32>,
    rpc_host: String,
    request_cache: HashSet<esploda::http::Uri>,
    /// `mediantime` of confirming blocks, fetched for updates whose proof
    /// carries `expires` and for every applicable update under a
    /// `versionTime` bound.
    block_mediantimes: HashMap<BlockHash, DateTime<Utc>>,
    /// Signals already matched to sidecar updates but not yet processed,
    /// parked when an applied update introduced a beacon: Find Beacon Signals
    /// precedes every Process Next Update (resolve.md:41-47), so the new
    /// beacon is scanned first. The next round's tuples are merged into these
    /// and the merged pool re-sorted before processing resumes.
    pending_signals: Vec<AppliedSignal>,

    // Finite State Machine
    fsm: ResolverFsm,
    _type_state: T,
}

impl Resolver {
    // TODO: Why do you have `InitialDocument` here and in `resolution_options.sidecar_data`?
    /// Build a resolver over `initial_doc` with the caller's options.
    ///
    /// `INVALID_OPTIONS` when `versionId` and `versionTime` are both set
    /// (DID Resolution defines them as mutually exclusive and resolve.md
    /// raises the error before any beacon is read), or when `esplora_url` is
    /// absent or not an absolute HTTP(S) base the request URIs can be formed
    /// from — see [`esplora_base`].
    pub(crate) fn new(
        initial_doc: InitialDocument,
        resolution_options: ResolutionOptions,
    ) -> Result<Self, Btcr2Error> {
        if resolution_options.version_id.is_some() && resolution_options.version_time.is_some() {
            return Err(Btcr2Error::InvalidOptions(
                "versionId and versionTime are mutually exclusive; supply at most one".into(),
            ));
        }
        let target_condition = TargetCondition::from(&resolution_options);
        let chain_tip_height = resolution_options.chain_tip_height;
        let min_conf = resolution_options
            .min_conf
            .unwrap_or(ResolutionOptions::DEFAULT_MIN_CONF);
        let content_type = resolution_options
            .accept
            .clone()
            .unwrap_or_else(|| "application/did".to_string());
        let rpc_host = esplora_base(resolution_options.esplora_url.as_deref())?;
        let update_lookup_table = match resolution_options.sidecar_data {
            Some(SidecarData {
                update_lookup_table,
                ..
            }) => update_lookup_table,
            None => HashMap::new(),
        };

        Ok(Self {
            contemporary_doc: initial_doc,
            current_version_id: NonZeroU64::MIN,
            target_condition,
            update_hash_history: vec![],
            update_lookup_table,
            chain_tip_height,
            min_conf,
            content_type,
            current_block_height: None,
            rpc_host,
            request_cache: HashSet::new(),
            block_mediantimes: HashMap::new(),
            pending_signals: Vec::new(),
            fsm: ResolverFsm::Init,
            _type_state: (),
        })
    }

    fn from_waiting_for_responses(resolver: Resolver<WaitingForResponses>) -> Self {
        resolver.with_state(())
    }

    fn from_waiting_for_block_times(resolver: Resolver<WaitingForBlockTimes>) -> Self {
        resolver.with_state(())
    }

    /// Advance the resolution FSM one step, returning either a
    /// [`ResolverState::Requests`] (blockchain data the caller must fetch and
    /// feed back), a [`ResolverState::BlockRequests`], or a
    /// [`ResolverState::Resolved`] result (did:btcr2 spec section 7.2.2.1).
    ///
    /// The loop is the spec's (resolve.md:41-47): scan every beacon not yet
    /// scanned, then take ONE tuple, apply it, and scan again. Each round's
    /// tuples are merged with any parked from an earlier round, sorted, and
    /// applied in order; after every applied update the beacon set is
    /// re-checked, and if the update introduced a beacon the tuples not yet
    /// processed are parked while that beacon's history is fetched. A tuple
    /// from a beacon the document no longer declares by the time it is taken
    /// is ignored (Process Next Update step 4).
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

                // Tuples parked when an applied update introduced the beacon
                // this round scanned. They and the new round form ONE pool.
                let mut signals = std::mem::take(&mut self.pending_signals);

                // Process Next Update step 2 on the MERGED pool: an empty
                // round ends the walk only when nothing is parked behind it.
                if next_signals.is_empty() && signals.is_empty() {
                    return self.history_exhausted();
                }

                // Find Beacon Signals (resolve.md:125-157): build the tuples
                // (raises MISSING_UPDATE_DATA here, before the version_time bound —
                // resolve.md:153-155).
                signals.extend(self.process_beacon_signals(next_signals)?);

                // Process Next Update step 3 (resolve.md:180): sort the union
                // of parked and new tuples by targetVersionId (ascending) with
                // block_height as a tiebreaker; the spec removes the FIRST
                // tuple, and that is what the version_time bound is evaluated
                // against.
                signals.sort_unstable_by_key(|s| (s.update.target_version_id, s.block_height));

                // `may_request` is true: a parked tuple may need its block's
                // mediantime, and this is the first pass over the merged pool.
                self.apply_signals(signals, true)
            }

            ResolverFsm::ApplySignals(signals) => self.apply_signals(signals, false),
        }
    }

    /// Process a sorted pool of matched signals one tuple at a time
    /// (resolve.md "Process Next Update"), re-checking the beacon set after
    /// every applied update. A tuple whose Beacon Address the document no
    /// longer declares when it is taken — removed by an update applied
    /// earlier in the pool — is skipped without being judged at all (step 4,
    /// resolve.md:181). An update that introduced a beacon yields a
    /// [`ResolverState::Requests`] for it, with the tuples not yet processed
    /// parked in `pending_signals` for the next
    /// [`ResolverFsm::FindNextSignals`] to merge. Once the pool is drained
    /// with the beacon set unchanged by the last apply, the walk asks for any
    /// beacon still unscanned or resolves.
    ///
    /// `may_request` is `true` on the first pass over a pool: if any signal
    /// that can still apply needs its confirming block's mediantime — its
    /// proof carries `expires`, or a `versionTime` bound is in force — and
    /// that mediantime is not yet held, the batch is parked in
    /// [`ResolverFsm::ApplySignals`] and a [`ResolverState::BlockRequests`] is
    /// returned. The second pass (after
    /// [`Resolver::<WaitingForBlockTimes>::process_block_times`]) runs with
    /// `false`: a still-missing mediantime is then the caller's error.
    fn apply_signals(
        mut self,
        signals: Vec<AppliedSignal>,
        may_request: bool,
    ) -> Result<ResolverState, Error> {
        // Two checks read the confirming block's mediantime, which the
        // transaction status does not carry: resolve.md "Check update.proof"
        // compares `expires` against it, and "Process Next Update" step 5
        // compares it against `versionTime`. Ask for every block still
        // missing, once; a second pass without it is the caller's error.
        //
        // The mediantime is read in the loop below for any tuple above the
        // current version: the step-5 gate and, on apply, the `expires`
        // check. A signal whose targetVersionId is already at or below the
        // current version at loop entry goes through `confirm_duplicate` only
        // and never reaches either, so its block is not requested. Every
        // higher-version signal is kept: under the ascending version sort it
        // may still apply later in this same batch once the lower versions
        // have. Version is the only exclusion; no time-based cutoff, because a
        // wrongly excluded block becomes a hard `MissingBlockMediantime` on
        // the second pass. Defense in depth: `Document::apply_update`
        // independently rejects an `expires` proof whose mediantime is
        // unavailable, so a mis-filtered block would surface as
        // INVALID_DID_UPDATE, never as a silently skipped check.
        //
        // Beacon presence (Process Next Update step 4, checked per tuple in
        // the loop below) is deliberately NOT a filter here either. Presence
        // is judged when the tuple is taken, and an apply earlier in this
        // same pool can remove a beacon — or re-add one this walk already
        // scanned, which `request_cache` serves without parking the pool —
        // so a tuple filtered out at pool entry could still be the one taken,
        // and its missing mediantime would again be a hard error on the
        // second pass. The cost is one possibly needless block request for a
        // tuple that is then ignored.
        let time_bound = matches!(self.target_condition, TargetCondition::Time(_));
        let missing: BTreeSet<BlockHash> = signals
            .iter()
            .filter(|s| s.update.target_version_id > self.current_version_id)
            .filter(|s| time_bound || s.update.proof.inner.expires.is_some())
            .map(|s| s.block_hash)
            .filter(|hash| !self.block_mediantimes.contains_key(hash))
            .collect();
        if let Some(first) = missing.iter().next().copied() {
            if !may_request {
                return Err(Error::MissingBlockMediantime { block_hash: first });
            }
            let requests = missing
                .iter()
                .map(|hash| self.request(&format!("/block/{hash}")))
                .collect::<Result<Vec<_>, Error>>()?;
            self.fsm = ResolverFsm::ApplySignals(signals);
            return Ok(ResolverState::BlockRequests(
                self.with_state(WaitingForBlockTimes),
                requests,
            ));
        }

        // Step 10.
        let mut contemporary_hash = self.contemporary_doc.hash();

        // Taken one at a time so the unprocessed remainder can be parked when
        // an applied update introduces a beacon.
        let mut signals = signals.into_iter();
        while let Some(AppliedSignal {
            update,
            block_height,
            block_time,
            block_hash,
            beacon_address,
        }) = signals.next()
        {
            // Process Next Update step 4 (resolve.md:181): the tuple's Beacon
            // Address must still be a beacon of the document AT THIS MOMENT —
            // an update applied earlier in this pool may have removed it.
            // Ignored outright: no versionTime gate (step 5), no
            // targetVersionId check (step 6), so neither a duplicate nor a LATE_PUBLISHING outcome can come from
            // it. A key that once controlled a removed beacon cannot advance
            // the document past the version that removed it.
            if !self
                .contemporary_doc
                .fields
                .service
                .iter()
                .any(|beacon| *beacon.address() == beacon_address)
            {
                continue;
            }

            // Step 10.1.
            if update.target_version_id <= self.current_version_id {
                // confirm_duplicate indexes update_hash_history at
                // [targetVersionId - 2], where each entry is an UPDATE
                // hash appended by the apply branch (step 10.2.7 below).
                // Do NOT push the contemporary DOCUMENT hash here: it
                // would grow the history out from under confirm_duplicate
                // and displace a later version's entry, turning a benign
                // duplicate signal into a false LATE_PUBLISHING.
                // A duplicate of the applied update can never lower
                // `current_block_height`: within a pool the ascending sort
                // applies the lowest announcement first, and one from a
                // beacon scanned later is at or above that height by the
                // Find Beacon Signals height condition.
                update.confirm_duplicate(&self.update_hash_history)?;
            }

            // Process Next Update step 5 (resolve.md:182-190): the
            // versionTime bound applies to ANY tuple whose targetVersionId is
            // more than current_version_id (first bullet), evaluated against
            // THIS tuple's block. The duplicate branch above (`<= current`)
            // runs first and never reaches this, which is footnote 4: under
            // the ascending (target_version_id, block_height) sort a duplicate
            // announcement is processed before a later-version unique update,
            // so a DUPLICATE whose block is after versionTime must never abort
            // the loop and suppress a later unique update announced within
            // versionTime. The gate deliberately runs BEFORE the version-gap
            // check (step 10.3): step 5 precedes step 6 in the spec, so a
            // skipped version announced after versionTime resolves the
            // document in effect so far rather than raising LATE_PUBLISHING.
            // A tuple within versionTime falls through to the apply branch
            // or, with a gap, to the gap check.
            //
            // "More recent" is the block's `mediantime` (footnote 5): an
            // equal mediantime applies, there is no tolerance, and every
            // resolver reads the same value off the chain, so every
            // resolver selects the same version — the header timestamp,
            // which a single miner sets, is not used for this. The
            // mediantime was requested above; a hole here is the
            // caller's, never an apply that skipped the bound.
            if update.target_version_id > self.current_version_id
                && let TargetCondition::Time(time) = &self.target_condition
            {
                let mediantime = self
                    .block_mediantimes
                    .get(&block_hash)
                    .copied()
                    .ok_or(Error::MissingBlockMediantime { block_hash })?;
                if mediantime > *time {
                    return Ok(ResolverState::Resolved(self.terminal_state()));
                }
            }

            // Step 10.2.
            let next_update_version_id = self
                .current_version_id
                .checked_add(1)
                .expect("version_id overflow requires 2^64 updates to a single DID");
            if update.target_version_id == next_update_version_id {
                // resolve.md "Apply update" step 1: a sourceHash that does not
                // match the contemporary document is INVALID_DID_UPDATE, not
                // LATE_PUBLISHING (which is reserved for the two
                // version-ordering cases in "Check update.targetVersionId").
                if update.source_hash != contemporary_hash {
                    return Err(Btcr2Error::InvalidDidUpdate(format!(
                        "update sourceHash `{}` does not match the contemporary document hash `{}`",
                        hex::encode(update.source_hash.as_bytes()),
                        hex::encode(contemporary_hash.as_bytes()),
                    ))
                    .into());
                }

                // Step 10.2.2 - 10.2.3.
                let announcing_block = AnnouncingBlock {
                    timestamp: block_time,
                    mediantime: self.block_mediantimes.get(&block_hash).copied(),
                };
                self.contemporary_doc
                    .apply_update(&update, &announcing_block)?;

                // Step 10.2.4.
                self.current_version_id = next_update_version_id;

                // resolve.md "Apply `update`": set `current_block_height` to
                // the tuple's block height. It is both the basis for
                // `confirmations` and the height below which the next Find
                // Beacon Signals finds nothing.
                self.current_block_height = Some(block_height);

                // resolve.md "Process Next Update" step 1: the spec re-checks
                // the requested versionId at the top of every iteration, so
                // the check has to run after each apply — and BEFORE the
                // deactivation check below, because step 1 precedes step 2:
                // a versionId equal to the version a deactivating update
                // produced resolves that (deactivated) document.
                if let TargetCondition::VersionId(version_id) = self.target_condition
                    && version_id == self.current_version_id
                {
                    return Ok(ResolverState::Resolved(self.terminal_state()));
                }

                // resolve.md "Process Next Update" step 2 — once the document
                // is deactivated, resolve it as the final didDocument and
                // process no further beacon signals; a versionId still in
                // force names a version that will never exist (NOT_FOUND).
                if self.contemporary_doc.fields.deactivated {
                    return self.history_exhausted();
                }

                // Step 10.2.5 - 10.2.6.
                let unsecured_update = UnsecuredUpdate::from(&update);

                // Step 10.2.7 - 10.2.8.
                self.update_hash_history.push(unsecured_update.hash());

                // Step 10.2.9.
                contemporary_hash = self.contemporary_doc.hash();

                // Find Beacon Signals runs before every Process Next Update
                // (resolve.md:41-47): a beacon this update introduced is
                // scanned now, and its tuples are merged with the ones still
                // waiting, before the next tuple is taken. `request_cache`
                // makes this a no-op unless the beacon set actually grew.
                let ResolverState::Requests(fsm, requests) = self.next_signals_requests()? else {
                    unreachable!("next_signals_requests only builds Requests")
                };
                self = Resolver::from_waiting_for_responses(fsm);
                if !requests.is_empty() {
                    self.pending_signals = signals.collect();
                    return Ok(ResolverState::Requests(
                        self.with_state(WaitingForResponses),
                        requests,
                    ));
                }
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

        // Step 12. Every apply above already re-checked the beacon set and
        // parked the remainder when it grew, so by the time the pool drains
        // every beacon has been scanned and the history is exhausted (Process
        // Next Update step 2). The `Requests` arm is a defensive guard, not a
        // walk step: it cannot be reached under the per-apply re-check, and
        // if it ever were, issuing the round is the safe answer — a release
        // build must never resolve early on an unscanned beacon.
        let ResolverState::Requests(fsm, signals) = self.next_signals_requests()? else {
            unreachable!()
        };
        if signals.is_empty() {
            Resolver::from_waiting_for_responses(fsm).history_exhausted()
        } else {
            Ok(ResolverState::Requests(fsm, signals))
        }
    }

    /// The walk has nothing left to apply — no more signals, or the document
    /// is deactivated (resolve.md "Process Next Update" step 2). The
    /// document resolves as it stands, unless a `versionId` was requested:
    /// step 1 already resolved an equal one, so a `versionId` still in force
    /// here names a version the history never reached, which is `NOT_FOUND`
    /// rather than a silently earlier document.
    fn history_exhausted(self) -> Result<ResolverState, Error> {
        if let TargetCondition::VersionId(version_id) = self.target_condition
            && version_id != self.current_version_id
        {
            return Err(Error::Btcr2Error(Btcr2Error::NotFound(format!(
                "versionId {version_id} was requested but the DID's history ends at version {}{}",
                self.current_version_id,
                if self.contemporary_doc.fields.deactivated {
                    ", where it is deactivated"
                } else {
                    ""
                }
            ))));
        }
        Ok(ResolverState::Resolved(self.terminal_state()))
    }

    // Spec section 7.2.2.2
    //
    // `histories` is keyed by the address in each request's path (see
    // `ResolverState::Requests`). The requests of a round are built from the
    // contemporary document at the round's start and nothing applies before
    // the answer arrives, so every requested address is still a beacon of
    // that document here and the lookup is exact. A key the document does not
    // declare was never requested and is refused.
    fn find_next_signals(
        &self,
        histories: HashMap<String, Vec<Transaction>>,
    ) -> Result<Vec<NextSignal>, Error> {
        let mut signals = Vec::new();
        for (address, txs) in histories {
            let beacon = self
                .contemporary_doc
                .fields
                .service
                .iter()
                .find(|beacon| beacon.address().to_string() == address)
                .ok_or(Error::UnrequestedBeaconHistory { address })?;
            let beacon_type = beacon.ty;
            let beacon_address = beacon.address().clone();
            for tx in txs {
                // Spec MANDATES the last output (resolve.md:133 + terminology.md:221: Signal
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

                let (block_time, block_height, block_hash) = match tx.status {
                    // resolve.md "Find Beacon Signals": "Unconfirmed mempool
                    // transactions MUST NOT be processed." Skipped whether or
                    // not the sidecar holds the update it announces — a
                    // controller resolving with the full sidecar before its
                    // own broadcast is mined gets the confirmed history, not
                    // an error; the pending update is simply not yet part
                    // of it.
                    Status::Unconfirmed => continue,
                    Status::Confirmed {
                        block_time,
                        block_height,
                        block_hash,
                    } => (block_time, block_height, block_hash),
                };

                // resolve.md "Find Beacon Signals": only transactions whose block
                // height is equal to or more than `current_block_height` are found.
                // `None` (no update applied yet) is the spec's initial height 0.
                // A transaction that is not found raises nothing, so this runs
                // before the chain-tip check.
                if block_height < self.current_block_height.unwrap_or(0) {
                    continue;
                }

                // resolve.md "Find Beacon Signals": the transaction must have
                // at least `minConf` confirmations (6 when not provided).
                // Confirmations are `tip - height + 1` against the caller's
                // tip; a tip behind the block (indexer lag) saturates to one.
                // Fewer than `minConf` is skipped whether or not the sidecar
                // holds the update — the same rule as an unconfirmed
                // transaction — never an error: the signal is not yet part of
                // the settled history. No tip at all is the driver's omission
                // and is reported rather than guessed around.
                let tip = self.chain_tip_height.ok_or(Error::MissingChainTip {
                    txid: tx.txid,
                    block_height,
                })?;
                let confirmations = tip.saturating_sub(block_height).saturating_add(1);
                if confirmations < self.min_conf.get() {
                    continue;
                }

                signals.push(NextSignal {
                    beacon_type,
                    beacon_address: beacon_address.clone(),
                    signal_bytes,
                    block_time,
                    block_height,
                    block_hash,
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
                    let req = self.request(&format!("/address/{}/txs", beacon.descriptor))?;

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
                        // scope — a sentinel mapped later would lose the hash.
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
                    block_hash: beacon_signal.block_hash,
                    beacon_address: beacon_signal.beacon_address,
                })
            })
            .collect()
    }
}

impl<T> Resolver<T> {
    /// A `GET {esplora_url}{path}` request. `path` is built from
    /// document-derived values (a beacon address, a block hash), and the base
    /// was checked by [`esplora_base`], so a failure here means the two do not
    /// compose into a URI after all; it is reported, not assumed away.
    fn request(&self, path: &str) -> Result<esploda::Req, Error> {
        esploda::Req::builder()
            .uri(format!("{}{path}", self.rpc_host))
            .body(())
            .map_err(|e| {
                Error::Btcr2Error(Btcr2Error::InvalidOptions(format!(
                    "esplora_url `{}` does not form a request URI for `{path}`: {e}",
                    self.rpc_host
                )))
            })
    }

    /// Move every field into a resolver in type state `state`. The type-state
    /// marker is the only thing that changes between FSM steps.
    fn with_state<U>(self, state: U) -> Resolver<U> {
        Resolver {
            contemporary_doc: self.contemporary_doc,
            current_version_id: self.current_version_id,
            target_condition: self.target_condition,
            update_hash_history: self.update_hash_history,
            update_lookup_table: self.update_lookup_table,
            chain_tip_height: self.chain_tip_height,
            min_conf: self.min_conf,
            content_type: self.content_type,
            current_block_height: self.current_block_height,
            rpc_host: self.rpc_host,
            request_cache: self.request_cache,
            block_mediantimes: self.block_mediantimes,
            pending_signals: self.pending_signals,
            fsm: self.fsm,
            _type_state: state,
        }
    }

    /// Construct the terminal [`ResolutionResult`] from the resolver's current
    /// state. Centralizes the metadata-assembly logic so
    /// every terminal arm of [`Resolver::resolve`] returns the spec triple
    /// identically (PATTERNS.md §"ResolverState::Resolved" guidance).
    ///
    /// `confirmations` is `tip.saturating_sub(current_block_height)
    /// .saturating_add(1)` for the most recently applied unique update, and
    /// `0` when the tip is known but no update was applied — the spec starts
    /// `block_confirmations` at `0` and lists `confirmations` as REQUIRED
    /// (resolve.md "Process", footnote 2). `None` is reserved for a caller
    /// that supplied no chain tip: nothing can be counted, and an invented
    /// `0` would read as "the update is unconfirmed".
    fn terminal_state(&self) -> ResolutionResult {
        let confirmations = self.chain_tip_height.map(|tip| {
            self.current_block_height
                .map_or(0, |height| tip.saturating_sub(height).saturating_add(1))
        });
        let document_metadata = crate::document::DocumentMetadata {
            version_id: self.current_version_id,
            confirmations,
            deactivated: self.contemporary_doc.fields.deactivated,
            // spec-OPTIONAL; populated by future operations.
            updated: None,
        };
        ResolutionResult {
            resolution_metadata: crate::document::ResolutionMetadata {
                content_type: Some(self.content_type.clone()),
            },
            document: self.contemporary_doc.clone().into(),
            document_metadata,
        }
    }
}

/// Check the caller's Esplora base URL once, up front, so every request URI
/// the resolver later formats from it is well-formed.
///
/// The URL is required: the resolver has no default endpoint, because the
/// right one depends on the DID's network and a silent fallback to one chain
/// would resolve a DID on another chain to its genesis document with no error.
/// It must be an absolute URI with a scheme and a host and carry no query
/// string (a query would end up in the middle of every request path). A
/// trailing slash is dropped so `{base}/address/...` never contains `//`.
fn esplora_base(esplora_url: Option<&str>) -> Result<String, Btcr2Error> {
    let Some(url) = esplora_url else {
        return Err(Btcr2Error::InvalidOptions(
            "esplora_url is required: the resolver builds every beacon request from it and \
             has no default endpoint"
                .into(),
        ));
    };
    let base = url.trim_end_matches('/');
    let uri: esploda::http::Uri = base.parse().map_err(|e| {
        Btcr2Error::InvalidOptions(format!("esplora_url `{url}` is not a valid URI: {e}"))
    })?;
    if uri.scheme().is_none() || uri.authority().is_none() {
        return Err(Btcr2Error::InvalidOptions(format!(
            "esplora_url `{url}` must be an absolute URI with a scheme and a host"
        )));
    }
    if uri.query().is_some() {
        return Err(Btcr2Error::InvalidOptions(format!(
            "esplora_url `{url}` must not carry a query string"
        )));
    }
    Ok(base.to_owned())
}

/// The spec's `updates` tuple (resolve.md:33,150-157): a beacon signal paired
/// with the sidecar [`Update`] it resolves to, the confirming block's
/// metadata (height for the confirmations computation, time and hash for the
/// mediantime checks), and the Beacon Address whose history announced it
/// (resolve.md:152). Produced by [`Resolver::process_beacon_signals`].
#[derive(Debug)]
struct AppliedSignal {
    update: Update,
    block_height: u32,
    block_time: DateTime<Utc>,
    /// Hash of the confirming block: the key under which its `mediantime` is
    /// requested and held when the update's proof carries `expires`.
    block_hash: BlockHash,
    /// The Beacon Address whose history this signal was found in — the
    /// address the round's request named, not anything read off the
    /// transaction. Process Next Update step 4 (resolve.md:181) checks it
    /// against the document's beacons when the tuple is taken.
    beacon_address: Address,
}

impl Resolver<WaitingForResponses> {
    fn from_init(resolver: Resolver) -> Self {
        resolver.with_state(WaitingForResponses)
    }

    /// Feed the blockchain transactions requested by a
    /// [`ResolverState::Requests`] back into the FSM, returning a [`Resolver`]
    /// ready to be driven another step.
    ///
    /// `histories` is keyed by the beacon address exactly as it appears in
    /// each request's path (`/address/{address}/txs` → `address`), and each
    /// value is that address's complete confirmed history (see
    /// [`ResolverState::Requests`]); the resolver cannot tell a truncated page
    /// from a short history. A requested address absent from the map is an
    /// empty history. An address the document declares no beacon at was never
    /// requested, and the next [`Resolver::resolve`] reports it as
    /// [`Error::UnrequestedBeaconHistory`] rather than attributing its
    /// signals to any beacon.
    pub fn process_responses(mut self, histories: HashMap<String, Vec<Transaction>>) -> Resolver {
        self.fsm = ResolverFsm::FindNextSignals(histories);

        Resolver::from_waiting_for_responses(self)
    }
}

impl Resolver<WaitingForBlockTimes> {
    /// Feed back the mediantimes a [`ResolverState::BlockRequests`] asked for,
    /// keyed by block hash.
    pub fn process_block_times(
        mut self,
        mediantimes: HashMap<BlockHash, DateTime<Utc>>,
    ) -> Resolver {
        self.block_mediantimes.extend(mediantimes);

        Resolver::from_waiting_for_block_times(self)
    }
}

/// Marker type for FSM.
#[derive(Debug)]
pub struct WaitingForResponses;

/// Marker: the FSM has asked for the mediantime of one or more blocks.
#[derive(Debug)]
pub struct WaitingForBlockTimes;

#[derive(Debug)]
enum ResolverFsm {
    /// FSM just initialized.
    Init,

    /// FSM is ready to find the next beacon signals, holding each requested
    /// address's history under the address as the request path names it.
    FindNextSignals(HashMap<String, Vec<Transaction>>),

    /// Signals already matched to sidecar updates, held while the caller
    /// fetches the block mediantimes the proof checks need.
    ApplySignals(Vec<AppliedSignal>),
}

/// The result of advancing the resolver FSM one step: either outstanding
/// blockchain requests the caller must satisfy, or the fully resolved DID.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ResolverState {
    /// Requests need to be sent to the blockchain: one
    /// `GET {esplora_url}/address/{address}/txs` per beacon address not yet
    /// scanned, grouped by beacon type. A round can arrive in the middle of
    /// a batch: when an applied update adds a beacon, that beacon is scanned
    /// before the next tuple is processed, and the remaining tuples wait for
    /// the answer. The driver's contract is the same for every round.
    ///
    /// The contract for the answer fed back through
    /// [`Resolver::<WaitingForResponses>::process_responses`]: a map keyed
    /// by the address exactly as it appears in each request's path
    /// (`/address/{address}/txs` → `address`) — every tuple the resolver
    /// builds carries the Beacon Address whose history announced it
    /// (resolve.md:152), and the driver is the only party that knows which
    /// history came from which request. A requested address left out of the
    /// map is an empty history; an address no request named is a driver
    /// error ([`Error::UnrequestedBeaconHistory`]). Under each key, the
    /// COMPLETE confirmed transaction history of that address —
    /// every transaction that spends from it, oldest included — not only the
    /// first page an indexer serves. Esplora answers `/txs` with the first 25
    /// confirmed transactions and pages the rest on
    /// `/txs/chain/{last_seen_txid}`; a driver that fed back a single page
    /// would hide the oldest announcements from the resolver, which would
    /// then see only the newest signals and raise `LATE_PUBLISHING` for a
    /// valid history, or resolve to the genesis document. Paging is the
    /// driver's job because the page size is the indexer's, not the spec's
    /// (`did-btcr2-client` does it). Mempool entries may be included; the
    /// resolver skips them.
    Requests(
        Resolver<WaitingForResponses>,
        HashMap<BeaconType, Vec<esploda::Req>>,
    ),

    /// The resolver needs the `mediantime` of the block that confirmed a
    /// beacon signal: an update's proof carries `expires`
    /// (did-btcr2/src/operations/resolve.md, "Check update.proof"), or a
    /// `versionTime` bound is in force and is compared against the block's
    /// mediantime ("Process Next Update" step 5). One
    /// `GET {rpc_host}/block/{hash}` per block; parse `id` and `mediantime`
    /// from each body and feed them back with
    /// [`Resolver::<WaitingForBlockTimes>::process_block_times`]. A walk with
    /// neither never asks.
    BlockRequests(Resolver<WaitingForBlockTimes>, Vec<esploda::Req>),

    /// Document is fully resolved. Carries the spec resolution triple
    /// (`didResolutionMetadata`, `didDocument`, `didDocumentMetadata`) as a
    /// [`ResolutionResult`].
    Resolved(ResolutionResult),
}

#[derive(Debug)]
struct NextSignal {
    beacon_type: BeaconType,
    /// The Beacon Address whose history this signal was found in, carried
    /// into [`AppliedSignal`] (resolve.md:152).
    beacon_address: Address,
    signal_bytes: Sha256Hash,
    block_time: DateTime<Utc>,
    /// Confirming block height, carried into [`AppliedSignal`] for the
    /// confirmations computation.
    block_height: u32,
    /// Confirming block hash, carried into [`AppliedSignal`] for the
    /// mediantime lookup.
    block_hash: BlockHash,
}

/// Where the walk stops, from `resolutionOptions` (resolve.md "Process Next
/// Update" steps 1 and 5).
#[derive(Debug)]
enum TargetCondition {
    /// `versionId`: stop once `current_version_id` reaches it.
    VersionId(NonZeroU64),

    /// `versionTime`: stop before the first unique update whose block
    /// `mediantime` is after it.
    Time(DateTime<Utc>),

    /// Neither option: apply every confirmed update. There is no implicit
    /// "now" bound — a block whose timestamp is ahead of this resolver's
    /// clock (consensus allows up to two hours) still counts.
    Latest,
}

impl From<&ResolutionOptions> for TargetCondition {
    fn from(resolution_options: &ResolutionOptions) -> Self {
        match (
            resolution_options.version_id,
            resolution_options.version_time,
        ) {
            (Some(version), _) => Self::VersionId(version),
            (None, Some(time)) => Self::Time(time),
            (None, None) => Self::Latest,
        }
    }
}

/// Extract the beacon address from a `/address/{a}/txs` request path.
///
/// The ADDRESS is the routing key, not the URI: the full URI embeds
/// `rpc_host`, which differs between the capture endpoint and whatever the
/// resolver was built with, so a URI match would miss on every fixture.
/// Mirrors `chain_capture::record::address_from_txs_path` — including
/// splitting any query string off first — so capture and replay key on the
/// same string. Shared by every in-crate test driver, because the answer to a
/// [`ResolverState::Requests`] is keyed by this very string.
#[cfg(test)]
pub(crate) fn address_from_txs_uri(uri: &esploda::http::Uri) -> &str {
    // `path_and_query` rather than `path`, so the query split below is the
    // live thing the recorder does rather than a re-statement of what
    // `Uri::path` already guarantees.
    let raw = uri
        .path_and_query()
        .map_or_else(|| uri.path(), |pq| pq.as_str());
    let path = raw.split('?').next().unwrap_or(raw);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let n = segments.len();
    if n >= 3 && segments[n - 1] == "txs" && segments[n - 3] == "address" {
        segments[n - 2]
    } else {
        panic!(
            "the resolver requested `{raw}`, which is not an `/address/{{address}}/txs` \
             endpoint. The capture harness routes on the address in that path, so a new \
             request shape needs a new route here — and a new capture to serve it."
        )
    }
}

/// Answer a [`ResolverState::Requests`] with `txs` as the history of the
/// FIRST address it requested (document order: the request list is built in
/// service order) and nothing for the rest. The single-batch test drivers use
/// this where the announcing beacon is immaterial — every genesis beacon is a
/// declared beacon, so any of them attributes the batch acceptably.
#[cfg(test)]
pub(crate) fn history_under_first_request(
    requests: &HashMap<BeaconType, Vec<esploda::Req>>,
    txs: Vec<Transaction>,
) -> HashMap<String, Vec<Transaction>> {
    let first = requests
        .values()
        .flatten()
        .next()
        .expect("the round requested at least one beacon address");
    HashMap::from([(address_from_txs_uri(first.uri()).to_string(), txs)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::Document;
    use crate::test_vectors::{
        AnnouncementDelivery, AssertionKind, ChainFixture, CodeDivergence, Corpus, DRIVEN_FLOOR,
        ERROR_CODE_DIVERGENCES, GenesisDelivery, NEGATIVE_SET_EXPECTATIONS, NegativeSetExpectation,
        Outcome, RowKey, SKIP_OVERRIDES, SkipOverride, SkipReason, UpdateCryptoExpectation, Vector,
        VectorIdType, confirmations_exact, discover_in, expected_driven_with,
        expected_emitted_code, field_hex, field_nonzero_version_id, field_str, field_u64,
        field_version_id, fixture_announcements, negative_set_expectation,
        network_dirs_with_vectors, parse_outcome, read_chain_fixture, read_chain_fixture_in,
        read_vendor_copy, reconcile_driven_with, redundant_overrides, render_minted_summary,
        render_summary_with, replayed_confirmations, signals_match, stale_overrides,
        test_suite_checked_out, unclassified_rows_with, unused_divergences, vacuous_substring,
        version_id_matches,
    };
    use std::collections::BTreeMap;

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
        let vectors = discover_in(&Corpus::test_suite());
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

            let input = vector.fixture("create/input.json");
            let output = vector.fixture("create/output.json");

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

            observed.insert(RowKey::set(id.clone()));
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
    /// so the derived key is compared against the key that document publishes:
    /// `other.json.genesisDocument.verificationMethod[0].publicKeyMultibase`,
    /// or, when `verificationMethod` is empty, the `publicKeyMultibase` of the
    /// first method embedded in `capabilityInvocation` (a genesis document may
    /// carry its invocation key only there). Without that second branch an
    /// update-less external vector executed exactly one assertion — that
    /// `secp256k1` derives its own public key from its own secret key — which
    /// touches neither the vector's DID nor its documents while being reported
    /// as full coverage.
    ///
    /// Then walk EVERY update step the vector ships — flat `update/` or numbered
    /// `update/NN/` alike. A step's `signingMaterial` must be one of the secrets
    /// the vector declares: `other.json.genesisKeys.secret` or an
    /// `other.json.extraKeys.*.secret` (a key a DID adds by update and then
    /// signs with). Membership alone would accept a step signed by the wrong
    /// declared key, so the step's key is also tied to its own documents: the
    /// public key the secret derives must equal the key of the method the
    /// step's `verificationMethodId` names in its `sourceDocument`, found
    /// through the same capabilityInvocation lookup a resolver uses to verify
    /// the proof.
    ///
    /// The method is looked up wherever `sourceDocument` defines it — in
    /// `verificationMethod` or embedded in a verification relationship — not
    /// only among the invoking methods: a negative set may sign with a key the
    /// document holds but does not authorize for capabilityInvocation, and the
    /// key must still be the one that method publishes. A step naming a method
    /// the document does not define at all is accepted only in a negative set.
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

    /// The `publicKeyMultibase` of the method `vm_id` names in `source_json`,
    /// looked up in `verificationMethod` and among the methods embedded in
    /// every verification relationship, ids compared after resolving them
    /// against the document id. `None` when the document defines no such
    /// method.
    fn named_method_multikey(
        source_json: &serde_json::Value,
        source: &Document,
        vm_id: &str,
        ctx: &str,
    ) -> Option<String> {
        use crate::document::absolutize_did_url;

        let target = absolutize_did_url(vm_id, &source.fields.id);
        [
            "verificationMethod",
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation",
        ]
        .iter()
        .filter_map(|field| source_json[*field].as_array())
        .flatten()
        .filter(|entry| entry.is_object())
        .find(|method| {
            method["id"]
                .as_str()
                .is_some_and(|id| absolutize_did_url(id, &source.fields.id) == target)
        })
        .map(|method| {
            field_str(
                method,
                "publicKeyMultibase",
                &format!("{ctx} sourceDocument {vm_id}"),
            )
            .to_string()
        })
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

            let input = vector.fixture("create/input.json");
            let other = vector.fixture("other.json");

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
                VectorIdType::External => {
                    let genesis = &other["genesisDocument"];
                    let first_method = genesis["verificationMethod"]
                        .as_array()
                        .and_then(|methods| methods.first());
                    let (published, published_as) = match first_method {
                        Some(method) => (method, "its first verification method"),
                        None => (
                            genesis["capabilityInvocation"]
                                .as_array()
                                .and_then(|entries| entries.iter().find(|e| e.is_object()))
                                .unwrap_or_else(|| {
                                    panic!(
                                        "{id}: other.json.genesisDocument has neither a \
                                         verificationMethod entry nor a method embedded in \
                                         capabilityInvocation to tie the genesis key to"
                                    )
                                }),
                            "the first method embedded in its capabilityInvocation",
                        ),
                    };
                    assert_eq!(
                        derived.to_multikey(),
                        field_str(published, "publicKeyMultibase", id),
                        "{id}: the genesis secret must derive the key the genesis document \
                         publishes as {published_as}"
                    );
                }
            }

            // Every secret the vector declares: the genesis key and any key a
            // later update adds.
            let mut declared_secrets = vec![secret_hex.to_string()];
            match &other["extraKeys"] {
                serde_json::Value::Null => {}
                serde_json::Value::Object(keys) => {
                    for (name, key) in keys {
                        declared_secrets.push(
                            field_str(key, "secret", &format!("{id} other.json.extraKeys.{name}"))
                                .to_string(),
                        );
                    }
                }
                other => panic!("{id}: other.json.extraKeys must be an object, got {other}"),
            }

            for step in vector.update_layout.step_prefixes() {
                let ctx = format!("{id} {step}");
                let update_input = vector.fixture(&format!("{step}/input.json"));

                let signing = field_str(&update_input, "signingMaterial", &ctx);
                assert!(
                    declared_secrets.iter().any(|s| s == signing),
                    "{id}: {step}/input.json signingMaterial is neither \
                     other.json.genesisKeys.secret nor any other.json.extraKeys secret"
                );
                let step_key: PublicKey =
                    SecretKey::from_slice(&field_hex(&update_input, "signingMaterial", &ctx))
                        .unwrap_or_else(|e| {
                            panic!(
                                "{id}: {step}/input.json signingMaterial is not a secret key: {e}"
                            )
                        })
                        .public_key(&secp);

                let vm_id = field_str(&update_input, "verificationMethodId", &ctx);
                let source_json = &update_input["sourceDocument"];
                let source =
                    Document::from_json_string(&source_json.to_string()).unwrap_or_else(|e| {
                        panic!(
                            "{id}: {step}/input.json sourceDocument must parse as a Document: {e}"
                        )
                    });
                match named_method_multikey(source_json, &source, vm_id, &ctx) {
                    Some(published) => assert_eq!(
                        step_key.to_multikey(),
                        published,
                        "{id}: {step}/input.json signingMaterial must derive the key of {vm_id}, \
                         the method verificationMethodId names in sourceDocument"
                    ),
                    // A step naming a method its source document lacks is a
                    // deliberately invalid update, which only a set expecting
                    // INVALID_DID_UPDATE can carry: the code resolve.md gives
                    // for an update whose invoking method cannot be resolved.
                    None => assert!(
                        matches!(
                            vector.outcome,
                            Outcome::Error { ref code } if code == "INVALID_DID_UPDATE"
                        ),
                        "{id}: {step}/input.json verificationMethodId {vm_id} names no method \
                         of sourceDocument, yet the set expects {:?} rather than \
                         INVALID_DID_UPDATE",
                        vector.outcome
                    ),
                }
            }

            observed.insert(RowKey::set(id.clone()));
        }
        reconcile_driven_with(AssertionKind::GenesisKey, vectors, &observed, overrides);
    }

    // --- Keyed test sets ---------------------------------------------------
    //
    // Sets in the vendor layout, written to a temp directory at test time and
    // discovered through `discover_in`, for the driver rules the committed
    // corpus does not exercise. They carry secrets, as vendor sets do, so they
    // are never committed: the keys below are fixed test keys that exist only
    // in this source and, for one test's lifetime, in the temp directory.

    /// The genesis secret of every keyed test set.
    const KEYED_GENESIS_SECRET: [u8; 32] = [7u8; 32];
    /// The `other.json.extraKeys["key-1"]` secret of a keyed test set.
    const KEYED_EXTRA_SECRET: [u8; 32] = [8u8; 32];

    /// A corpus under a fresh temp directory, removed when dropped (also when
    /// the test panics).
    struct KeyedSuite {
        root: std::path::PathBuf,
    }

    impl Drop for KeyedSuite {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl KeyedSuite {
        fn corpus(&self) -> Corpus {
            Corpus {
                sets: self.root.join("sets"),
                chain: self.root.join("chain"),
            }
        }

        /// The directory of set `regtest/{kind}/{short_id}`.
        fn set_dir(&self, set: &KeyedSet) -> std::path::PathBuf {
            self.root
                .join("sets/regtest")
                .join(set.kind)
                .join(set.short_id)
        }

        /// Write every file of `set`.
        fn write(&self, set: &KeyedSet) {
            let dir = self.set_dir(set);
            let write = |rel: &str, value: &serde_json::Value| {
                let path = dir.join(rel);
                std::fs::create_dir_all(path.parent().expect("a set file has a parent"))
                    .expect("the keyed set directory is creatable");
                std::fs::write(
                    &path,
                    serde_json::to_string_pretty(value).expect("JSON serializes"),
                )
                .expect("the keyed set file is writable");
            };
            write("create/input.json", &set.create_input);
            write("other.json", &set.other);
            write("resolve/input.json", &set.resolve_input);
            write("resolve/output.json", &set.resolve_output);
            for (index, (input, output)) in set.steps.iter().enumerate() {
                write(&format!("update/{:02}/input.json", index + 1), input);
                write(&format!("update/{:02}/output.json", index + 1), output);
            }
        }

        /// Rewrite one file of `set` in place.
        fn edit(&self, set: &KeyedSet, rel: &str, f: impl FnOnce(&mut serde_json::Value)) {
            let path = self.set_dir(set).join(rel);
            let mut value: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(&path).expect("the keyed set file was written"),
            )
            .expect("the keyed set file is JSON");
            f(&mut value);
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&value).expect("JSON serializes"),
            )
            .expect("the keyed set file is writable");
        }

        fn vectors(&self) -> Vec<Vector> {
            discover_in(&self.corpus())
        }
    }

    /// A fresh keyed corpus root; `tag` names the test in the directory name.
    fn keyed_suite(tag: &str) -> KeyedSuite {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("did-btcr2-keyed-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir_all(root.join("sets")).expect("the keyed corpus root is creatable");
        KeyedSuite { root }
    }

    /// One keyed set's files, in the vendor layout.
    struct KeyedSet {
        kind: &'static str,
        short_id: &'static str,
        create_input: serde_json::Value,
        other: serde_json::Value,
        resolve_input: serde_json::Value,
        resolve_output: serde_json::Value,
        /// `update/NN/input.json` and `output.json`, in order.
        steps: Vec<(serde_json::Value, serde_json::Value)>,
    }

    impl KeyedSet {
        /// The discovered vector id.
        fn id(&self) -> String {
            format!("regtest/{}/{}", self.kind, self.short_id)
        }
    }

    fn keyed_public(secret: [u8; 32]) -> crate::key::PublicKey {
        secp256k1::SecretKey::from_slice(&secret)
            .expect("a fixed test secret is a valid secret key")
            .public_key(&secp256k1::Secp256k1::new())
    }

    fn keyed_secret(secret: [u8; 32]) -> crate::key::SecretKey {
        crate::key::SecretKey::try_from(secret).expect("a fixed test secret is a valid secret key")
    }

    /// An `other.json` key entry: `{secret, public}` in hex.
    fn keyed_entry(secret: [u8; 32]) -> serde_json::Value {
        serde_json::json!({
            "secret": hex::encode(secret),
            "public": hex::encode(keyed_public(secret).serialize()),
        })
    }

    /// The key-based regtest DID of the genesis key and its initial document.
    fn keyed_k1_genesis() -> (crate::identifier::Did, InitialDocument) {
        use crate::identifier::{Did, DidComponents, DidVersion, IdType, Network};
        let did: Did = DidComponents::new(
            DidVersion::One,
            Network::Regtest,
            IdType::from(keyed_public(KEYED_GENESIS_SECRET)),
        )
        .expect("regtest is a valid network")
        .try_into()
        .expect("a key id type encodes to a DID");
        let initial = InitialDocument::from_did(&did, &ResolutionOptions::default())
            .expect("a key-based DID generates its initial document");
        (did, initial)
    }

    /// A patch that appends a non-beacon service, the vendor's usual update.
    fn didcomm_patch() -> serde_json::Value {
        serde_json::json!([{
            "op": "add",
            "path": "/service/-",
            "value": {
                "id": "#didcomm",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "http://example.com/didcomm",
            },
        }])
    }

    /// An `update/NN/input.json` in the vendor shape.
    fn keyed_step_input(
        source: &InitialDocument,
        patch: &serde_json::Value,
        target_version_id: u64,
        vm_id: &str,
        secret: [u8; 32],
    ) -> serde_json::Value {
        serde_json::json!({
            "sourceDocument": source.as_ref(),
            "patches": patch,
            "sourceVersionId": target_version_id - 1,
            "verificationMethodId": vm_id,
            "signingMaterial": hex::encode(secret),
        })
    }

    /// Sign `patch` over `source` through the crate's update path, and return
    /// the step's input and output files and the document it produces.
    fn keyed_step(
        source: &InitialDocument,
        patch: serde_json::Value,
        target_version_id: u64,
        vm_id: &str,
        secret: [u8; 32],
    ) -> (serde_json::Value, serde_json::Value, InitialDocument) {
        let update = Document::from(source.clone())
            .construct_signed_update(
                serde_json::from_value(patch.clone()).expect("the test patch is a JSON Patch"),
                NonZeroU64::new(target_version_id).expect("a target version is non-zero"),
                vm_id,
                keyed_secret(secret),
            )
            .expect("the keyed step signs");
        let mut next = source.clone();
        next.apply_update(&update, &AnnouncingBlock::fixed())
            .expect("the keyed step applies");
        (
            keyed_step_input(source, &patch, target_version_id, vm_id, secret),
            serde_json::json!({ "signedUpdate": update.json }),
            next,
        )
    }

    /// A positive `resolve/output.json` for `doc` at `version_id`.
    fn keyed_resolved(
        doc: &InitialDocument,
        version_id: u64,
        deactivated: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "didResolutionMetadata": { "contentType": "application/did" },
            "didDocument": doc.as_ref(),
            "didDocumentMetadata": {
                "versionId": version_id.to_string(),
                "deactivated": deactivated,
                "confirmations": 1,
            },
        })
    }

    /// A k1 set over the genesis key with the given steps and end state. The
    /// steps' signed updates ride in the sidecar, as in a vendor set whose
    /// resolve is driven.
    fn keyed_k1_set(
        short_id: &'static str,
        did: &crate::identifier::Did,
        with_extra_key: bool,
        steps: Vec<(serde_json::Value, serde_json::Value)>,
        resolve_output: serde_json::Value,
    ) -> KeyedSet {
        let mut other = serde_json::json!({ "genesisKeys": keyed_entry(KEYED_GENESIS_SECRET) });
        if with_extra_key {
            other["extraKeys"] = serde_json::json!({ "key-1": keyed_entry(KEYED_EXTRA_SECRET) });
        }
        let updates: Vec<serde_json::Value> = steps
            .iter()
            .map(|(_, output)| output["signedUpdate"].clone())
            .collect();
        KeyedSet {
            kind: "k1",
            short_id,
            create_input: serde_json::json!({
                "idType": "KEY",
                "version": 1,
                "network": "regtest",
                "genesisBytes": hex::encode(keyed_public(KEYED_GENESIS_SECRET).serialize()),
            }),
            other,
            resolve_input: serde_json::json!({
                "did": did.encode(),
                "resolutionOptions": { "sidecar": { "updates": updates } },
            }),
            resolve_output,
            steps,
        }
    }

    /// A k1 set that adds `#key-1` (the extra key) as an invoking method in
    /// update/01, signed by the genesis key, and signs update/02 with `#key-1`.
    fn keyed_k1_rotation_set() -> KeyedSet {
        use crate::key::PublicKeyExt as _;
        let (did, genesis) = keyed_k1_genesis();
        let d = did.encode();
        let initial_key = format!("{d}#initialKey");
        let key_1 = format!("{d}#key-1");
        let add_key = serde_json::json!([
            {
                "op": "add",
                "path": "/verificationMethod/-",
                "value": {
                    "id": key_1,
                    "type": "Multikey",
                    "controller": d,
                    "publicKeyMultibase": keyed_public(KEYED_EXTRA_SECRET).to_multikey(),
                },
            },
            { "op": "add", "path": "/capabilityInvocation/-", "value": key_1 },
        ]);
        let (in1, out1, v2) = keyed_step(&genesis, add_key, 2, &initial_key, KEYED_GENESIS_SECRET);
        let (in2, out2, v3) = keyed_step(&v2, didcomm_patch(), 3, &key_1, KEYED_EXTRA_SECRET);
        keyed_k1_set(
            "qrotate",
            &did,
            true,
            vec![(in1, out1), (in2, out2)],
            keyed_resolved(&v3, 3, false),
        )
    }

    /// An x1 set whose genesis document has an empty `verificationMethod` and
    /// carries the genesis key embedded in `capabilityInvocation`, with one
    /// update signed by that embedded key.
    fn keyed_x1_embedded_invocation_set() -> KeyedSet {
        use crate::canonical_hash::CanonicalHash as _;
        use crate::document::IntermediateDocument;
        use crate::identifier::{DidVersion, Network};
        use crate::key::PublicKeyExt as _;

        const PLACEHOLDER: &str = "did:btcr2:_";
        // The beacon services of the same key's k1 document, re-homed on the
        // placeholder: regtest addresses the crate derived itself.
        let (k1_did, k1_genesis) = keyed_k1_genesis();
        let services: serde_json::Value = serde_json::from_str(
            &k1_genesis.as_ref()["service"]
                .to_string()
                .replace(k1_did.encode(), PLACEHOLDER),
        )
        .expect("the re-homed services are JSON");
        let genesis_document = serde_json::json!({
            "id": PLACEHOLDER,
            "@context": k1_genesis.as_ref()["@context"],
            "verificationMethod": [],
            "capabilityInvocation": [{
                "id": format!("{PLACEHOLDER}#initialKey"),
                "type": "Multikey",
                "controller": PLACEHOLDER,
                "publicKeyMultibase": keyed_public(KEYED_GENESIS_SECRET).to_multikey(),
            }],
            "service": services,
        });
        let intermediate =
            IntermediateDocument::from_json_value(genesis_document.clone(), Network::Regtest)
                .expect("the embedded-key genesis document is an intermediate document");
        let genesis_bytes = intermediate.hash();
        let (did, initial) = InitialDocument::from_external_intermediate(
            intermediate,
            Some(DidVersion::One),
            Some(Network::Regtest),
        )
        .expect("the embedded-key genesis document becomes an initial document");

        let (in1, out1, v2) = keyed_step(
            &initial,
            didcomm_patch(),
            2,
            &format!("{}#initialKey", did.encode()),
            KEYED_GENESIS_SECRET,
        );
        KeyedSet {
            kind: "x1",
            short_id: "qembedded",
            create_input: serde_json::json!({
                "idType": "EXTERNAL",
                "version": 1,
                "network": "regtest",
                "genesisBytes": hex::encode(genesis_bytes.as_bytes()),
            }),
            other: serde_json::json!({
                "genesisKeys": keyed_entry(KEYED_GENESIS_SECRET),
                "genesisDocument": genesis_document,
            }),
            resolve_input: serde_json::json!({
                "did": did.encode(),
                "resolutionOptions": { "sidecar": { "genesisDocument": genesis_document } },
            }),
            resolve_output: keyed_resolved(&v2, 2, false),
            steps: vec![(in1, out1)],
        }
    }

    /// A step signed by a key `other.json.extraKeys` declares, whose method an
    /// earlier update added, is accepted.
    #[test]
    fn genesis_key_driver_accepts_a_step_signed_by_an_extra_key() {
        let suite = keyed_suite("gk-extra");
        let set = keyed_k1_rotation_set();
        suite.write(&set);
        let vectors = suite.vectors();
        assert_eq!(vectors.len(), 1, "the keyed corpus holds its one set");
        assert_eq!(vectors[0].id, set.id());
        drive_genesis_key(&vectors, &[]);
    }

    /// An x1 genesis document with no `verificationMethod` ties the genesis key
    /// to the method embedded in `capabilityInvocation`.
    #[test]
    fn genesis_key_driver_ties_an_x1_key_to_an_embedded_invocation_method() {
        let suite = keyed_suite("gk-embedded");
        let set = keyed_x1_embedded_invocation_set();
        suite.write(&set);
        let vectors = suite.vectors();
        assert_eq!(vectors.len(), 1, "the keyed corpus holds its one set");
        assert_eq!(
            vectors[0].fixture("other.json")["genesisDocument"]["verificationMethod"],
            serde_json::json!([]),
            "the set exercises the embedded-key branch"
        );
        drive_genesis_key(&vectors, &[]);
    }

    /// A step signed by a secret the vector does not declare fails, naming the
    /// set, the step and `signingMaterial`.
    #[test]
    fn genesis_key_driver_rejects_an_undeclared_signing_secret() {
        let suite = keyed_suite("gk-undeclared");
        let set = keyed_k1_rotation_set();
        suite.write(&set);
        suite.edit(&set, "update/02/input.json", |input| {
            input["signingMaterial"] = serde_json::json!(hex::encode([9u8; 32]));
        });
        let vectors = suite.vectors();
        let message = panic_text(|| drive_genesis_key(&vectors, &[]));
        assert!(
            message.contains(&set.id())
                && message.contains("update/02")
                && message.contains("signingMaterial"),
            "got: {message}"
        );
    }

    /// A declared extra secret used for a method whose key it does not derive
    /// fails, naming the step and the method id.
    #[test]
    fn genesis_key_driver_rejects_a_declared_secret_for_another_method() {
        let suite = keyed_suite("gk-wrong-method");
        let set = keyed_k1_rotation_set();
        suite.write(&set);
        let initial_key = format!(
            "{}#initialKey",
            set.resolve_input["did"]
                .as_str()
                .expect("the set names its DID")
        );
        suite.edit(&set, "update/02/input.json", |input| {
            input["verificationMethodId"] = serde_json::json!(initial_key);
        });
        let vectors = suite.vectors();
        let message = panic_text(|| drive_genesis_key(&vectors, &[]));
        assert!(
            message.contains("update/02") && message.contains(&initial_key),
            "got: {message}"
        );
    }

    /// Sign `patch` over `source` WITHOUT the deactivated-document guard of
    /// `construct_signed_update`, the way another implementation could: the
    /// unsigned update the crate builds, signed with the same proof
    /// configuration.
    fn keyed_hand_signed_update(
        source: &InitialDocument,
        patch: &serde_json::Value,
        target_version_id: u64,
        vm_id: &str,
        secret: [u8; 32],
    ) -> serde_json::Value {
        use crate::cryptosuite::CryptoSuite;
        use crate::zcap::derive_root_capability;
        use crate::zcap::proof::{CryptoSuiteName, ProofInner, ProofPurpose, ProofType};

        let source = Document::from(source.clone());
        let (unsigned, _, _) = source
            .construct_unsigned_update(
                &serde_json::from_value(patch.clone()).expect("the test patch is a JSON Patch"),
                NonZeroU64::new(target_version_id).expect("a target version is non-zero"),
            )
            .expect("the patch applies to the source document");
        let inner = ProofInner {
            id: None,
            proof_type: ProofType::DataIntegrityProof,
            proof_purpose: ProofPurpose::CapabilityInvocation,
            verification_method: vm_id.to_string(),
            cryptosuite: CryptoSuiteName::Jcs,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            previous_proof: None,
            nonce: None,
            context: vec![],
            capability: derive_root_capability(source.fields.id.clone()),
            capability_action: "Write".to_string(),
            invocation_target: None,
        };
        let proof = CryptoSuite
            .create_proof(&unsigned, inner, &keyed_secret(secret))
            .expect("the hand-built update signs");
        let mut signed = unsigned.as_ref().clone();
        signed["proof"] = serde_json::to_value(&proof).expect("the proof serializes");
        signed
    }

    /// A k1 set whose update/01 deactivates the DID and whose update/02, over
    /// the deactivated document, is hand-signed: the main resolve output is the
    /// deactivated document at version 2.
    fn keyed_k1_deactivated_then_updated_set() -> KeyedSet {
        let (did, genesis) = keyed_k1_genesis();
        let initial_key = format!("{}#initialKey", did.encode());
        let deactivate =
            serde_json::json!([{ "op": "add", "path": "/deactivated", "value": true }]);
        let (in1, out1, v2) =
            keyed_step(&genesis, deactivate, 2, &initial_key, KEYED_GENESIS_SECRET);
        let patch = didcomm_patch();
        let signed = keyed_hand_signed_update(&v2, &patch, 3, &initial_key, KEYED_GENESIS_SECRET);
        let in2 = keyed_step_input(&v2, &patch, 3, &initial_key, KEYED_GENESIS_SECRET);
        keyed_k1_set(
            "qdeactivated",
            &did,
            false,
            vec![
                (in1, out1),
                (in2, serde_json::json!({ "signedUpdate": signed })),
            ],
            keyed_resolved(&v2, 2, true),
        )
    }

    /// An update over a deactivated source: the end-state walk stops at the
    /// resolved version, and the update-crypto driver checks both steps.
    #[test]
    fn update_drivers_handle_an_update_over_a_deactivated_source() {
        let suite = keyed_suite("deactivated");
        let set = keyed_k1_deactivated_then_updated_set();
        suite.write(&set);
        let vectors = suite.vectors();
        assert_eq!(vectors.len(), 1, "the keyed corpus holds its one set");
        assert_eq!(
            vectors[0].fixture("update/02/input.json")["sourceDocument"]["deactivated"],
            serde_json::json!(true),
            "update/02 is over a deactivated source"
        );
        drive_end_state(&vectors, &[]);
        drive_update_crypto(&vectors, &[]);
        drive_genesis_key(&vectors, &[]);
    }

    /// A flipped proofValue on the update over a deactivated source fails the
    /// update-crypto driver, naming the step.
    #[test]
    fn update_crypto_rejects_a_tampered_proof_over_a_deactivated_source() {
        let suite = keyed_suite("deactivated-proof");
        let set = keyed_k1_deactivated_then_updated_set();
        suite.write(&set);
        suite.edit(&set, "update/02/output.json", |output| {
            let proof_value = output["signedUpdate"]["proof"]["proofValue"]
                .as_str()
                .expect("the proof carries a proofValue")
                .to_string();
            // Swap the last base58 character for another one, so the value
            // still decodes but to a different signature.
            let last = proof_value
                .chars()
                .last()
                .expect("a proofValue is non-empty");
            let swapped = if last == '2' { '3' } else { '2' };
            output["signedUpdate"]["proof"]["proofValue"] = serde_json::json!(format!(
                "{}{swapped}",
                &proof_value[..proof_value.len() - 1]
            ));
        });
        let vectors = suite.vectors();
        let message = panic_text(|| drive_update_crypto(&vectors, &[]));
        assert!(
            message.contains(&set.id())
                && message.contains("update/02")
                && message.contains("proof"),
            "got: {message}"
        );
    }

    /// An altered sourceHash on the update over a deactivated source fails the
    /// update-crypto driver, naming the step and sourceHash.
    #[test]
    fn update_crypto_rejects_a_tampered_source_hash_over_a_deactivated_source() {
        let suite = keyed_suite("deactivated-source-hash");
        let set = keyed_k1_deactivated_then_updated_set();
        suite.write(&set);
        suite.edit(&set, "update/02/output.json", |output| {
            output["signedUpdate"]["sourceHash"] =
                serde_json::json!(hash_b64(&Sha256Hash::from([0u8; 32])));
        });
        let vectors = suite.vectors();
        let message = panic_text(|| drive_update_crypto(&vectors, &[]));
        assert!(
            message.contains(&set.id())
                && message.contains("update/02")
                && message.contains("sourceHash must be the JSON Document Hash of sourceDocument"),
            "got: {message}"
        );
    }

    /// The version cutoff hides nothing at or below the resolved version: a
    /// set resolved at version 2 whose expected document is not what update/01
    /// produces still fails the end-state driver.
    #[test]
    fn end_state_still_fails_below_the_resolved_version() {
        let suite = keyed_suite("end-state-mismatch");
        let set = keyed_k1_rotation_set();
        suite.write(&set);
        // Resolved at version 2, but expecting the version-3 document.
        suite.edit(&set, "resolve/output.json", |output| {
            output["didDocumentMetadata"]["versionId"] = serde_json::json!("2");
        });
        let vectors = suite.vectors();
        let message = panic_text(|| drive_end_state(&vectors, &[]));
        assert!(
            message.contains(&set.id()) && message.contains("resolve/output.json.didDocument"),
            "got: {message}"
        );
    }

    /// The version cutoff only trims the end of the walk: an inflated target
    /// on a step before the last fails both update drivers, naming the step,
    /// before the cutoff can skip it. The step is re-signed at the inflated
    /// target, so its own proof verifies and the version check is what fails.
    #[test]
    fn update_drivers_reject_an_inflated_target_version_before_the_last_step() {
        let suite = keyed_suite("inflated-target-early");
        let set = keyed_k1_rotation_set();
        suite.write(&set);
        let resigned = keyed_resigned_at_target(&set.steps[0].0, 5, KEYED_GENESIS_SECRET);
        suite.edit(&set, "update/01/output.json", |output| {
            output["signedUpdate"] = resigned;
        });
        let vectors = suite.vectors();
        for message in [
            panic_text(|| drive_end_state(&vectors, &[])),
            panic_text(|| drive_update_crypto(&vectors, &[])),
        ] {
            assert!(
                message.contains(&set.id())
                    && message.contains("update/01")
                    && message.contains("targetVersionId must be sourceVersionId + 1"),
                "got: {message}"
            );
        }
    }

    /// An inflated target on the final step would otherwise drop that step
    /// from the end-state walk unseen: a set resolved at version 3 whose
    /// expected document is the version-2 one, with update/02 re-signed to
    /// target version 4, fails both update drivers, naming the step.
    #[test]
    fn update_drivers_reject_an_inflated_target_version_on_the_last_step() {
        let suite = keyed_suite("inflated-target-last");
        let set = keyed_k1_rotation_set();
        suite.write(&set);
        let v2 = set.steps[1].0["sourceDocument"].clone();
        suite.edit(&set, "resolve/output.json", |output| {
            output["didDocument"] = v2;
        });
        let resigned = keyed_resigned_at_target(&set.steps[1].0, 4, KEYED_EXTRA_SECRET);
        suite.edit(&set, "update/02/output.json", |output| {
            output["signedUpdate"] = resigned;
        });
        let vectors = suite.vectors();
        for message in [
            panic_text(|| drive_end_state(&vectors, &[])),
            panic_text(|| drive_update_crypto(&vectors, &[])),
        ] {
            assert!(
                message.contains(&set.id())
                    && message.contains("update/02")
                    && message.contains("targetVersionId must be sourceVersionId + 1"),
                "got: {message}"
            );
        }
    }

    /// A step's `signedUpdate` re-signed over the same source, patch and
    /// method at `target_version_id`, so its proof still verifies.
    fn keyed_resigned_at_target(
        input: &serde_json::Value,
        target_version_id: u64,
        secret: [u8; 32],
    ) -> serde_json::Value {
        let source = InitialDocument::from_json_string(&input["sourceDocument"].to_string())
            .expect("the keyed step's sourceDocument is an initial document");
        let vm_id = input["verificationMethodId"]
            .as_str()
            .expect("the keyed step names its method");
        keyed_hand_signed_update(&source, &input["patches"], target_version_id, vm_id, secret)
    }

    /// Each step's own proof is checked before any other update-crypto check:
    /// an edited `targetVersionId` left unsigned fails on the proof, naming
    /// the step, not on the version linkage the edit also breaks.
    #[test]
    fn update_crypto_checks_each_step_proof_before_its_versions() {
        let suite = keyed_suite("unsigned-target-edit");
        let set = keyed_k1_rotation_set();
        suite.write(&set);
        suite.edit(&set, "update/02/output.json", |output| {
            output["signedUpdate"]["targetVersionId"] = serde_json::json!(4);
        });
        let vectors = suite.vectors();
        let message = panic_text(|| drive_update_crypto(&vectors, &[]));
        assert!(
            message.contains(&set.id())
                && message.contains("update/02")
                && message.contains("the vendor signedUpdate proof must verify under the key")
                && !message.contains("targetVersionId must be sourceVersionId + 1"),
            "got: {message}"
        );
    }

    /// The version cutoff trusts the vendor's resolved version, so it is
    /// allowed only where the resolve driver confirms it: the same set with
    /// its updates withheld from the sidecar (CAS-delivered, so its Resolve
    /// row is skipped) fails the end-state driver, naming the set.
    #[test]
    fn end_state_cutoff_requires_a_driven_resolve_row() {
        let suite = keyed_suite("end-state-cutoff-unconfirmed");
        let set = keyed_k1_deactivated_then_updated_set();
        suite.write(&set);
        suite.edit(&set, "resolve/input.json", |input| {
            input["resolutionOptions"] = serde_json::json!({});
        });
        let vectors = suite.vectors();
        assert!(
            !vectors[0].should_drive_with(AssertionKind::Resolve, &[]),
            "without sidecar updates the set's Resolve row is not driven"
        );
        let message = panic_text(|| drive_end_state(&vectors, &[]));
        assert!(
            message.contains(&set.id())
                && message.contains("update/02")
                && message.contains("Resolve row is not driven"),
            "got: {message}"
        );
    }

    /// A negative-set resolve output expecting `INVALID_DID_UPDATE`.
    fn keyed_invalid_update_output() -> serde_json::Value {
        serde_json::json!({
            "didDocument": null,
            "didDocumentMetadata": {},
            "didResolutionMetadata": { "error": "INVALID_DID_UPDATE" },
        })
    }

    /// A negative k1 set whose update/01 adds `#key-1` to `verificationMethod`
    /// only, and whose update/02 is hand-signed with the extra key under
    /// `#key-1`, a method the document holds but does not authorize for
    /// capabilityInvocation.
    fn keyed_k1_unauthorized_method_set() -> KeyedSet {
        use crate::key::PublicKeyExt as _;
        let (did, genesis) = keyed_k1_genesis();
        let d = did.encode();
        let initial_key = format!("{d}#initialKey");
        let key_1 = format!("{d}#key-1");
        let add_key = serde_json::json!([{
            "op": "add",
            "path": "/verificationMethod/-",
            "value": {
                "id": key_1,
                "type": "Multikey",
                "controller": d,
                "publicKeyMultibase": keyed_public(KEYED_EXTRA_SECRET).to_multikey(),
            },
        }]);
        let (in1, out1, v2) = keyed_step(&genesis, add_key, 2, &initial_key, KEYED_GENESIS_SECRET);
        let patch = didcomm_patch();
        let signed = keyed_hand_signed_update(&v2, &patch, 3, &key_1, KEYED_EXTRA_SECRET);
        let in2 = keyed_step_input(&v2, &patch, 3, &key_1, KEYED_EXTRA_SECRET);
        keyed_k1_set(
            "qunauthorized",
            &did,
            true,
            vec![
                (in1, out1),
                (in2, serde_json::json!({ "signedUpdate": signed })),
            ],
            keyed_invalid_update_output(),
        )
    }

    /// A k1 set whose one update names `#unknown`, a method the document does
    /// not define, hand-signed with the genesis key.
    fn keyed_k1_unknown_method_set(resolve_output: serde_json::Value) -> KeyedSet {
        let (did, genesis) = keyed_k1_genesis();
        let unknown = format!("{}#unknown", did.encode());
        let patch = didcomm_patch();
        let signed = keyed_hand_signed_update(&genesis, &patch, 2, &unknown, KEYED_GENESIS_SECRET);
        let input = keyed_step_input(&genesis, &patch, 2, &unknown, KEYED_GENESIS_SECRET);
        keyed_k1_set(
            "qunknown",
            &did,
            false,
            vec![(input, serde_json::json!({ "signedUpdate": signed }))],
            resolve_output,
        )
    }

    /// A step signed by a declared key under a method the document holds but
    /// does not authorize is accepted: the key is still the method's.
    #[test]
    fn genesis_key_driver_ties_a_key_to_a_non_invoking_method() {
        let suite = keyed_suite("gk-unauthorized");
        let set = keyed_k1_unauthorized_method_set();
        suite.write(&set);
        let vectors = suite.vectors();
        assert!(
            vectors[0].is_negative(),
            "the set expects the resolve to fail"
        );
        drive_genesis_key(&vectors, &[]);
    }

    /// A step naming a method the document does not define is accepted in a
    /// set expecting INVALID_DID_UPDATE and fails, naming the step and the
    /// method, in a positive one and in a negative set expecting another code.
    #[test]
    fn genesis_key_driver_accepts_an_undefined_method_only_in_a_negative_set() {
        let suite = keyed_suite("gk-unknown-negative");
        let set = keyed_k1_unknown_method_set(keyed_invalid_update_output());
        suite.write(&set);
        drive_genesis_key(&suite.vectors(), &[]);

        let (_, genesis) = keyed_k1_genesis();
        let suite = keyed_suite("gk-unknown-positive");
        let set = keyed_k1_unknown_method_set(keyed_resolved(&genesis, 1, false));
        suite.write(&set);
        let vectors = suite.vectors();
        let message = panic_text(|| drive_genesis_key(&vectors, &[]));
        assert!(
            message.contains(&set.id())
                && message.contains("update/01")
                && message.contains("#unknown")
                && message.contains("names no method"),
            "got: {message}"
        );

        let suite = keyed_suite("gk-unknown-other-code");
        let set = keyed_k1_unknown_method_set(serde_json::json!({
            "didDocument": null,
            "didDocumentMetadata": {},
            "didResolutionMetadata": { "error": "INVALID_DID" },
        }));
        suite.write(&set);
        let vectors = suite.vectors();
        let message = panic_text(|| drive_genesis_key(&vectors, &[]));
        assert!(
            message.contains(&set.id())
                && message.contains("update/01")
                && message.contains("names no method")
                && message.contains("INVALID_DID_UPDATE"),
            "got: {message}"
        );
    }

    /// RESOLVE driver: for EVERY vector discovered under `test-suite/` at
    /// runtime, validate the `resolve/output.json` metadata whitelist, and for
    /// the rows the ledger expects driven, drive the FSM to its terminal state
    /// and assert the resolved `didDocument` equals
    /// `resolve/output.json.didDocument`.
    ///
    /// A genesis-era row is driven with empty beacon responses. A PAST-GENESIS
    /// row is driven from this repository's captured chain snapshot for that
    /// vector (`fixtures/chain/`), served round by round through
    /// [`drive_to_resolved_from_capture`]. Both are the same assertion kind and
    /// the same claim — "this vector resolves to its expected output"; where the
    /// beacon transactions came from is a driver detail, not a second kind of
    /// coverage.
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
    /// skipped-with-reason (`CasDelivery`, `SmtDelivery`,
    /// `UnsupportedBeaconType`, `ExpectedError`); its summary table is the place to read the
    /// coverage story, not a narrative in this comment.
    ///
    /// Observation-dependent metadata is whitelisted: `deactivated` is asserted
    /// BY VALUE against the vector's stated flag on a driven row; `updated` and
    /// `created` are environment-derived and drift, so they are asserted only by
    /// presence/type when present, NEVER by literal value. `confirmations` stays
    /// type-only in the whitelist that runs for EVERY discovered vector, and is
    /// additionally asserted on a driven ON-CHAIN row: as AT LEAST the vector's
    /// stated number, which every replayed positive pair must state. It is a
    /// fixed input rather than a
    /// drifting observation because the captured tip is pinned into the
    /// resolution options. `versionId` is READ by discovery through the strict
    /// string reader `metadata_version_id`, which refuses a JSON number by
    /// path, and on a driven row the resolved value is COMPARED against the
    /// vector's recorded string. The crate's own emit-a-string /
    /// reject-a-number contract is pinned by the fixture-independent
    /// `DocumentMetadata` round-trip test in `document.rs`.
    ///
    /// A main pair that records an error asserts its CODE, mapped through
    /// `ERROR_CODE_DIVERGENCES`. Resolution options are assembled in one place,
    /// [`case_options`], for the main pair and every `resolve/NN/` case alike.
    #[test]
    fn op_vectors_resolve_matches_output() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };
        drive_resolve_with(&vectors, SKIP_OVERRIDES, ERROR_CODE_DIVERGENCES);
        assert_divergences_used(&vectors);
    }

    /// RESOLVE-OPTION driver over the checked-out suite: every `resolve/NN/`
    /// case the ledger expects driven, one row per case
    /// ([`drive_resolve_options_with`]).
    #[test]
    fn op_vectors_resolve_cases_match_output() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };
        drive_resolve_options_with(&vectors, SKIP_OVERRIDES, ERROR_CODE_DIVERGENCES);
        assert_divergences_used(&vectors);
    }

    /// Every `ERROR_CODE_DIVERGENCES` entry is used by a driven negative row of
    /// the checked-out suite, so an entry cannot outlive the vector it excused.
    fn assert_divergences_used(vectors: &[Vector]) {
        let unused = unused_divergences(vectors, SKIP_OVERRIDES, ERROR_CODE_DIVERGENCES);
        assert!(
            unused.is_empty(),
            "unused ERROR_CODE_DIVERGENCES entries:\n{}",
            unused.join("\n")
        );
    }

    /// The `versionTime` a replay probe resolves at: one second before the
    /// earliest `mediantime` among the blocks confirming the capture's
    /// announcements, which is inside the walk's reach but before its first
    /// update.
    ///
    /// **Panics** naming the set and the block when the capture holds no
    /// `/block/{hash}` body for one of its announcements: the capture tool
    /// records every announcement's block, so a missing one is a defective
    /// capture, not a probe to skip.
    fn version_time_probe_bound(f: &ChainFixture, id: &str) -> DateTime<Utc> {
        match f.earliest_signal_mediantime() {
            Ok(earliest) => ts(earliest - 1),
            Err(missing) => panic!(
                "{id}: the versionTime probe compares against block mediantimes and the \
                 capture holds no `/block/{missing}` body; re-run capture to record the \
                 announcements' blocks"
            ),
        }
    }

    /// A resolved document as comparable JSON.
    ///
    /// One function so the terminal document, the genesis reference and the
    /// versionTime probe are all compared on the same footing — two of those
    /// comparisons are between documents this suite produced, and a difference
    /// in how they were rendered would read as a difference in what was
    /// resolved.
    fn resolved_document_json(document: &Document, id: &str) -> serde_json::Value {
        serde_json::from_str(
            &serde_json::to_string(document.as_ref())
                .unwrap_or_else(|e| panic!("{id}: the resolved document must serialize: {e}")),
        )
        .unwrap_or_else(|e| panic!("{id}: the resolved document must round-trip: {e}"))
    }

    /// The code and detail an error carries. The code is the fragment after
    /// `#` of its problem-details `type`, e.g. `NOT_FOUND` out of
    /// `https://www.w3.org/ns/did#NOT_FOUND`.
    ///
    /// An error with no problem details is a failure of the harness or the
    /// driver, not an answer the specification defines, so it panics rather than
    /// being compared against an expected code.
    ///
    /// Beside the code, the problem-details `detail`: the cause, in this
    /// crate's words. `Display` is not the cause: a wrapped spec error
    /// displays only its wrapper's summary. Every spec error carries a string
    /// detail, so a missing one panics like a missing `type`.
    fn emitted_code_and_detail<E: ProblemDetails + std::fmt::Display>(
        err: &E,
        ctx: &str,
    ) -> (String, String) {
        let details = err
            .details()
            .unwrap_or_else(|| panic!("{ctx}: `{err}` is a driver error, not a spec error code"));
        let kind = details["type"].as_str().unwrap_or_else(|| {
            panic!("{ctx}: the problem details of `{err}` carry no string `type`: {details}")
        });
        let code = kind
            .rsplit_once('#')
            .map(|(_, code)| code.to_string())
            .unwrap_or_else(|| panic!("{ctx}: problem-details type `{kind}` has no `#CODE`"));
        let detail = details["detail"].as_str().unwrap_or_else(|| {
            panic!("{ctx}: the problem details of `{err}` carry no string `detail`: {details}")
        });
        (code, detail.to_string())
    }

    /// The rejection-cause check of a negative set's main Resolve pair.
    ///
    /// A set with an entry in `table` must be rejected with a detail that
    /// contains every one of the entry's cause substrings. Every live negative
    /// set has an entry, enforced by `negative_set_table_matches_the_corpus`;
    /// an entry whose cause list is empty is one whose Resolve row is not
    /// driven. Only synthetic corpora and keyed suites have no entry, and they
    /// are held to their code alone. The mismatches are collected and reported together by [`CauseCheck::finish`],
    /// so a wrong entry names every set it touches, on every network.
    struct CauseCheck<'t> {
        table: &'t [NegativeSetExpectation],
        mismatches: Vec<String>,
    }

    impl<'t> CauseCheck<'t> {
        fn new(table: &'t [NegativeSetExpectation]) -> Self {
            Self {
                table,
                mismatches: Vec::new(),
            }
        }

        fn check(&mut self, vector: &Vector, ctx: &str, detail: &str) {
            let Some(entry) = negative_set_expectation(self.table, vector) else {
                return;
            };
            for want in entry.cause {
                if !detail.contains(want) {
                    self.mismatches.push(format!(
                        "{ctx} ({}): the rejection cause must contain {want:?}, got detail \
                         {detail:?}",
                        entry.scenario
                    ));
                }
            }
        }

        fn finish(self) {
            assert!(
                self.mismatches.is_empty(),
                "{} rejection(s) differ from their scenario's cause:\n{}",
                self.mismatches.len(),
                self.mismatches.join("\n")
            );
        }
    }

    /// The chain snapshot a set's resolves replay, or `None` for a set resolved
    /// with no signals fed.
    ///
    /// A set replays a capture exactly when it carries `signals.json`, even for
    /// a genesis-state case: `confirmations: 0` needs the recorded tip. Before
    /// anything is driven, the announcements that capture serves must equal
    /// `signals.json` exactly ([`signals_match`]), so a replay can never pass on
    /// a chain other than the one the set records. A set without `signals.json`
    /// records no chain and is resolved with no signals fed.
    fn replay_fixture(vector: &Vector) -> Option<ChainFixture> {
        let id = &vector.id;
        let signals = vector.signals.as_ref()?;
        let fixture = read_chain_fixture_in(&vector.corpus.chain, id);
        signals_match(&signals.entries, &fixture_announcements(&fixture)).unwrap_or_else(|e| {
            panic!(
                "{id}: signals.json and the replayed chain disagree — {e}. Re-capture \
                     the set rather than editing either file"
            )
        });
        Some(fixture)
    }

    /// The resolution options a resolve input asks for: its
    /// `resolutionOptions.sidecar` verbatim, its target condition (`versionId`,
    /// `versionTime`) and `minConf`, and the replay tip.
    ///
    /// ONE assembly for every vector shape and every case. For the main pair
    /// it builds the same options `chain_capture::capture::resolution_options_for`
    /// builds: the capture tool refuses a main input that carries `versionId`,
    /// `versionTime` or `minConf`, so on every main pair it captures those three
    /// are absent here too, and only the sidecar and the tip remain. The
    /// `resolve/NN/` cases carry them; those are replayed, never captured.
    /// `SidecarData::from_json_value` always builds `update_lookup_table` and
    /// sets `genesis_document` from the wire `genesisDocument` field;
    /// `resolve_external` bridges that into the initial document itself
    /// (`document.rs`'s `resolve_external_bridges_genesis_document_from_serde_path`
    /// proves it, and `SidecarData::initial_document` is documented there as
    /// the legacy in-memory shortcut). The capture tool assembles options
    /// exactly this way, and capture and replay MUST match — otherwise the
    /// refuse-to-write gate can bless a fixture this suite then fails on.
    ///
    /// Do NOT reintroduce an `IntermediateDocument` branch for `x1` vectors.
    /// `other.json.genesisDocument` exists for every external vector and is
    /// byte-identical where both are present, but reading it would hand the
    /// resolver a genesis document the vector intends to be fetched from
    /// content-addressed storage — asserting resolve logic while silently
    /// bypassing the delivery mechanism and leaving no row to mark the gap.
    ///
    /// Some vectors omit `resolutionOptions.sidecar` entirely: a resolve with
    /// nothing supplied out of band. Indexing yields `Value::Null`, which does
    /// not deserialize, so an absent sidecar is normalized to `{}` — the same
    /// empty `SidecarData`. That is a normalization of the INPUT VALUE, not a
    /// second assembly, and the capture tool reads an absent sidecar as `{}`
    /// too. A replayed set always records its signals ([`replay_fixture`]), so
    /// the gate is the signals record, not the sidecar: an empty sidecar is not
    /// vacuous, and a set whose update is withheld on purpose ships none.
    ///
    /// Pinning the replay tip is what makes `confirmations` a fixed input
    /// rather than a moving observation. With no capture there is no tip, as
    /// before.
    fn case_options(
        input: &serde_json::Value,
        fixture: Option<&ChainFixture>,
        ctx: &str,
    ) -> ResolutionOptions {
        let requested = &input["resolutionOptions"];
        let sidecar_json = requested["sidecar"].clone();
        let sidecar_json = if sidecar_json.is_null() {
            serde_json::json!({})
        } else {
            sidecar_json
        };
        let sidecar = SidecarData::from_json_value(sidecar_json)
            .unwrap_or_else(|e| panic!("{ctx}: resolutionOptions.sidecar must parse: {e}"));

        let version_id = (!requested["versionId"].is_null()).then(|| {
            let raw = field_str(input, "resolutionOptions.versionId", ctx);
            raw.parse::<NonZeroU64>().unwrap_or_else(|e| {
                panic!("{ctx}: resolutionOptions.versionId {raw:?} is not a positive integer: {e}")
            })
        });
        let version_time = (!requested["versionTime"].is_null()).then(|| {
            let raw = field_str(input, "resolutionOptions.versionTime", ctx);
            DateTime::parse_from_rfc3339(raw)
                .unwrap_or_else(|e| {
                    panic!("{ctx}: resolutionOptions.versionTime {raw:?} is not RFC 3339: {e}")
                })
                .with_timezone(&Utc)
        });
        let min_conf = (!requested["minConf"].is_null()).then(|| {
            let raw = field_u64(input, "resolutionOptions.minConf", ctx);
            u32::try_from(raw)
                .ok()
                .and_then(NonZeroU32::new)
                .unwrap_or_else(|| {
                    panic!("{ctx}: resolutionOptions.minConf {raw} is not a positive u32")
                })
        });

        ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height: fixture.map(|f| f.tip_height),
            version_id,
            version_time,
            min_conf,
            ..test_options()
        }
    }

    /// [`resolve_with_no_signals`] surfacing a walk error instead of panicking,
    /// for a case that expects one.
    fn try_resolve_with_no_signals(resolver: Resolver) -> Result<ResolutionResult, Error> {
        let ResolverState::Requests(next_state, _beacons) = resolver.resolve()? else {
            panic!("expected Requests from Init step");
        };
        match next_state.process_responses(HashMap::new()).resolve()? {
            ResolverState::Resolved(result) => Ok(result),
            ResolverState::Requests(..) => panic!("expected Resolved with no signals"),
            ResolverState::BlockRequests(..) => {
                panic!("unexpected block request: no signal was fed, so no update applied")
            }
        }
    }

    /// Drive one resolve pair — the main `resolve/` pair or one `resolve/NN/`
    /// case — and assert its expected outcome. Returns the resolved
    /// `confirmations` (`None` for an expected error), so a caller can assert
    /// more strictly than the corpus rule does.
    ///
    /// AN EXPECTED ERROR asserts the CODE: the error's problem-details type
    /// fragment must equal the recorded code mapped through `divergences`
    /// ([`expected_emitted_code`]). On the main pair of a negative set it also
    /// asserts the CAUSE through `causes` ([`CauseCheck`]): the detail must
    /// carry the scenario's cause substrings, in this crate's own wording. The
    /// recorded `errorMessage` is another implementation's text and is never
    /// compared. A DID that does
    /// not parse is an outcome too (`INVALID_DID` / `METHOD_NOT_SUPPORTED`), as
    /// is an error `Document::resolve` raises before any request
    /// (`INVALID_OPTIONS`).
    ///
    /// A RESOLVED DOCUMENT compares four things. `didDocument` in full, on every
    /// content field and with no masking. `versionId` through
    /// [`version_id_matches`]: as a string when the output encodes it as one.
    /// `deactivated` by value. `confirmations` through
    /// [`replayed_confirmations`]: AT LEAST the recorded number — a recorded
    /// value was taken at the set's recorded tip, and a later tip only adds
    /// confirmations — and EQUAL to the derived count, which pins the block
    /// the resolver counts from: `0` at genesis, where no update was applied,
    /// and past genesis, on a set with `signals.json`, the count the record
    /// gives. A replayed positive pair, main or `resolve/NN/`, must record the
    /// number: one that records none fails by name.
    ///
    /// Observation-dependent `updated` and `created` are never compared by
    /// value.
    fn drive_case(
        vector: &Vector,
        case_dir: &str,
        outcome: &Outcome,
        fixture: Option<&ChainFixture>,
        divergences: &[CodeDivergence],
        causes: &mut CauseCheck,
    ) -> Option<u32> {
        use crate::identifier::Did;

        let id = &vector.id;
        let ctx = format!("{id} {case_dir}");
        let input = vector.fixture(&format!("{case_dir}/input.json"));
        let output = vector.fixture(&format!("{case_dir}/output.json"));

        let result: Result<ResolutionResult, (String, String)> =
            match field_str(&input, "did", &ctx).parse::<Did>() {
                Err(e) => Err(emitted_code_and_detail(&Btcr2Error::from(e), &ctx)),
                Ok(did) => match Document::resolve(&did, case_options(&input, fixture, &ctx)) {
                    Err(e) => Err(emitted_code_and_detail(&e, &ctx)),
                    Ok(resolver) => match fixture {
                        Some(f) => drive_to_resolved_from_capture(resolver, f, id),
                        None => try_resolve_with_no_signals(resolver),
                    }
                    .map_err(|e| emitted_code_and_detail(&e, &ctx)),
                },
            };

        match outcome {
            Outcome::Error { code } => {
                let spec = expected_emitted_code(code, divergences);
                match result {
                    Err((emitted, detail)) => {
                        assert!(
                            emitted == spec,
                            "{ctx}: expected error {code} (emit {spec}), got {emitted}: {detail}"
                        );
                        if case_dir == "resolve" && vector.is_negative() {
                            causes.check(vector, &ctx, &detail);
                        }
                    }
                    Ok(resolved) => panic!(
                        "{ctx}: expected error {code} (emit {spec}), but the resolve succeeded \
                         at versionId {}",
                        resolved.document_metadata.version_id
                    ),
                }
                None
            }
            Outcome::Positive {
                deactivated,
                confirmations,
                ..
            } => {
                // The expected didDocument must parse as a conformant Document.
                // `mutinynet/x1/qh66uy2s` makes the point: its expected document
                // carries `service: []` and does not parse, corroborating the
                // ledger's classification of that row as CAS-delivered and
                // skipped.
                Document::from_json_string(&output["didDocument"].to_string()).unwrap_or_else(
                    |e| panic!("{ctx}/output.json didDocument must parse as a Document: {e}"),
                );
                let result = result.unwrap_or_else(|(code, detail)| {
                    panic!("{ctx}: expected a resolved document, got error {code}: {detail}")
                });

                // Every content field — id, `@context`, verificationMethod,
                // beacon services and endpoints, the four relationship sets.
                assert_eq!(
                    resolved_document_json(&result.document, &ctx),
                    output["didDocument"],
                    "{ctx}: resolved didDocument content (incl. @context) must equal \
                     output.json didDocument"
                );
                version_id_matches(result.document_metadata.version_id.get(), outcome)
                    .unwrap_or_else(|e| panic!("{ctx}: {e}"));
                assert_eq!(
                    result.document_metadata.deactivated, *deactivated,
                    "{ctx}: resolved deactivated must equal output.json \
                     didDocumentMetadata.deactivated"
                );

                if let Some(f) = fixture {
                    assert!(
                        confirmations.is_some(),
                        "{ctx}: a replayed positive resolve must record \
                         didDocumentMetadata.confirmations"
                    );
                    // At least the recorded value is all the corpus promises,
                    // but it would accept a resolver that anchors its count on
                    // an earlier block than the one announcing the resolved
                    // version, which only ever reports more — and at genesis,
                    // where every set states 0, any count. So the resolver's
                    // own count must also be the derived one.
                    replayed_confirmations(
                        result.document_metadata.confirmations,
                        *confirmations,
                        vector.signals.as_ref(),
                        result.document_metadata.version_id.get(),
                    )
                    .unwrap_or_else(|e| panic!("{ctx}: {e} (replayed at tip {})", f.tip_height));
                }
                result.document_metadata.confirmations
            }
        }
    }

    /// The RESOLVE driver body (the main `resolve/` pair of every set), over
    /// explicit override and error-code divergence tables so the same code path
    /// can be exercised with a hand-written skip or a local divergence in place.
    ///
    /// WHAT THE PROBES ON AN ON-CHAIN ROW BUY. The terminal assertion says the
    /// resolver ended up at the vector's expected document; on its own it cannot
    /// distinguish a resolver that WALKED the chain from one that landed on the
    /// answer without reading it. Two probes close that, on a replayed main
    /// pair that expects a version past genesis ([`walk_probes_apply`]):
    ///
    /// 1. The genesis reference — the same DID, the same options, resolved with
    ///    no signals fed — must DIFFER from the terminal document. A replay in
    ///    which nothing was applied fails here.
    /// 2. A `versionTime` one second before the earliest announcing block's
    ///    `mediantime` must return version 1 and that same genesis document,
    ///    having issued at least one request against the same capture. It needs
    ///    the capture's `/block/{hash}` bodies, and a capture missing one fails
    ///    naming the block.
    ///
    /// THERE IS DELIBERATELY NO `versionId = 1` PROBE here, and one must not be
    /// "restored". At `Init` the FSM returns `Resolved` when a `VersionId`
    /// target equals `current_version_id`, which starts at 1 — so `VersionId(1)`
    /// issues zero requests, never touches the capture, and cannot distinguish a
    /// real walk from a short-circuit. Mid-walk target conditions are covered
    /// where a set records them, as `resolve/NN/` cases
    /// ([`drive_resolve_options_with`]).
    ///
    /// A negative set's rejection is held to its cause in
    /// [`NEGATIVE_SET_EXPECTATIONS`] as well as to its code
    /// ([`drive_resolve_with_expectations`]).
    fn drive_resolve_with(
        vectors: &[Vector],
        overrides: &[SkipOverride],
        divergences: &[CodeDivergence],
    ) {
        drive_resolve_with_expectations(vectors, overrides, divergences, NEGATIVE_SET_EXPECTATIONS);
    }

    /// [`drive_resolve_with`] over an explicit negative-set table, so a wrong
    /// expected cause can be exercised in place.
    fn drive_resolve_with_expectations(
        vectors: &[Vector],
        overrides: &[SkipOverride],
        divergences: &[CodeDivergence],
        table: &[NegativeSetExpectation],
    ) {
        use crate::identifier::Did;

        let mut causes = CauseCheck::new(table);
        let mut observed = BTreeSet::new();
        for vector in vectors {
            let id = &vector.id;

            let input = vector.fixture("resolve/input.json");
            let output = vector.fixture("resolve/output.json");

            // Well-formedness (asserted for every discovered vector, driven or
            // not: no maintainer decision makes a malformed fixture acceptable,
            // so none of these belongs below the drive gate). An expected
            // error has no document and no metadata to whitelist.
            let metadata = &output["didDocumentMetadata"];
            if vector.is_negative() {
                assert!(
                    output["didDocument"].is_null(),
                    "{id}: an expected-error resolve/output.json carries a null didDocument"
                );
            } else {
                assert!(
                    metadata["versionId"].is_string(),
                    "{id}: versionId must be an ASCII string (the specification's encoding)"
                );
                assert!(
                    metadata["deactivated"].is_boolean(),
                    "{id}: deactivated must be a bool"
                );
                if !metadata["confirmations"].is_null() {
                    assert!(
                        metadata["confirmations"].is_number(),
                        "{id}: confirmations must be a number"
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
            }

            if !vector.should_drive_with(AssertionKind::Resolve, overrides) {
                continue;
            }

            let fixture = replay_fixture(vector);
            drive_case(
                vector,
                "resolve",
                &vector.outcome,
                fixture.as_ref(),
                divergences,
                &mut causes,
            );

            if let (Some(f), true) = (&fixture, walk_probes_apply(vector)) {
                let did: Did = field_str(&input, "did", id).parse().unwrap_or_else(|e| {
                    panic!("{id}: resolve/input.json.did must parse as a DID: {e}")
                });
                let terminal = &output["didDocument"];

                // The walk changed the document. The genesis reference is an
                // independent producer of the pre-walk state: same DID, same
                // options, no signals fed, so the resolver applies nothing.
                let genesis = resolve_with_no_signals(
                    Document::resolve(&did, case_options(&input, Some(f), id)).unwrap_or_else(
                        |e| panic!("{id}: the resolver must accept the vector: {e}"),
                    ),
                );
                let genesis_json = resolved_document_json(&genesis.document, id);
                assert_eq!(
                    genesis.document_metadata.version_id.get(),
                    1,
                    "{id}: a resolve with no signals fed is the genesis state"
                );
                assert_ne!(
                    &genesis_json, terminal,
                    "{id}: the chain-driven walk must change the document; if genesis equals \
                     the terminal state the replay proved nothing"
                );

                // And it stops where asked. One second before the earliest
                // announcing block's mediantime is inside the walk's reach but
                // before its first update, so the bound — which the FSM cannot
                // short-circuit — must hold the answer at genesis.
                let bound = version_time_probe_bound(f, id);
                let options = ResolutionOptions {
                    version_time: Some(bound),
                    ..case_options(&input, Some(f), id)
                };
                let probe_resolver = Document::resolve(&did, options)
                    .unwrap_or_else(|e| panic!("{id}: the resolver must accept the vector: {e}"));
                let (probe, rounds) = drive_capture_rounds(probe_resolver, f, id);
                let probe = probe.unwrap_or_else(|e| {
                    panic!("{id}: the versionTime probe must resolve off the capture: {e}")
                });
                assert!(
                    !rounds.is_empty(),
                    "{id}: the versionTime probe must READ the chain — a bound that resolved \
                     without issuing a request proves nothing about stopping"
                );
                assert_eq!(
                    probe.document_metadata.version_id.get(),
                    1,
                    "{id}: a versionTime one second before the earliest announcing block's \
                     mediantime ({bound}) must resolve to version 1"
                );
                assert_eq!(
                    resolved_document_json(&probe.document, id),
                    genesis_json,
                    "{id}: a versionTime before the first update must resolve the genesis \
                     document"
                );
            }

            observed.insert(RowKey::set(id.clone()));
        }
        causes.finish();
        reconcile_driven_with(AssertionKind::Resolve, vectors, &observed, overrides);
    }

    /// Whether the two walk probes of [`drive_resolve_with`] apply to a set's
    /// replayed main pair: only when it expects a version past genesis.
    ///
    /// A set with `signals.json` replays its capture even when its main pair
    /// expects version 1 — its signals may sit below the default `minConf` at
    /// the recorded tip, or on a beacon a later update removed. The genesis
    /// reference would then rightly equal the terminal document, and there is
    /// no first update for a `versionTime` probe to stop before. A negative
    /// set expects no version at all.
    fn walk_probes_apply(vector: &Vector) -> bool {
        vector
            .expected_version_id()
            .is_some_and(|version| version > 1)
    }

    /// RESOLVE-OPTION driver: every `resolve/NN/` case of every set, over
    /// explicit override and error-code divergence tables.
    ///
    /// One row per case, keyed `{id} resolve/{NN}`. A case is driven exactly
    /// like the main pair ([`drive_case`]): the main input's options plus the
    /// case's own `versionId`, `versionTime` or `minConf`, replayed off the
    /// set's capture, with the same comparison rules. A case inherits its
    /// set's skip reasons, so a case of a set the resolver cannot replay is
    /// skipped with the set's reason, not driven.
    fn drive_resolve_options_with(
        vectors: &[Vector],
        overrides: &[SkipOverride],
        divergences: &[CodeDivergence],
    ) {
        let mut causes = CauseCheck::new(NEGATIVE_SET_EXPECTATIONS);
        let mut observed = BTreeSet::new();
        for vector in vectors {
            let cases: Vec<_> = vector
                .resolve_cases
                .iter()
                .filter(|case| {
                    vector.should_drive_row_with(
                        AssertionKind::ResolveOption,
                        Some(&case.name),
                        overrides,
                    )
                })
                .collect();
            if cases.is_empty() {
                continue;
            }
            let fixture = replay_fixture(vector);
            for case in cases {
                drive_case(
                    vector,
                    &format!("resolve/{}", case.name),
                    &case.outcome,
                    fixture.as_ref(),
                    divergences,
                    &mut causes,
                );
                observed.insert(RowKey::case(vector.id.clone(), case.name.clone()));
            }
        }
        causes.finish();
        reconcile_driven_with(AssertionKind::ResolveOption, vectors, &observed, overrides);
    }

    /// The set of the `options` synthetic corpus: the minted four-version
    /// mutinynet chain reshaped into the regenerated layout, with eleven
    /// `resolve/NN/` cases (see `fixtures/layout/README.md`).
    const OPTIONS_SET: &str = "mutinynet/k1/q5pew2jc";

    /// The `options` corpus, discovered. It lives in this repository, so it
    /// never skips: an absent or empty corpus is a failure.
    fn options_vectors() -> Vec<Vector> {
        let vectors = discover_in(&Corpus::synthetic("options"));
        assert_eq!(
            vectors.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
            [OPTIONS_SET],
            "the options corpus holds exactly its one set"
        );
        vectors
    }

    /// Run `f`, which must panic, and return its panic message.
    fn panic_text(f: impl FnOnce()) -> String {
        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
            .expect_err("the drive must fail");
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// The outcome of case `name` of the options set, for mutation.
    fn case_outcome<'a>(vectors: &'a mut [Vector], name: &str) -> &'a mut Outcome {
        &mut vectors[0]
            .resolve_cases
            .iter_mut()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("the options set has a resolve/{name} case"))
            .outcome
    }

    /// The recorded `confirmations` of a positive outcome, for mutation.
    fn recorded_confirmations(outcome: &mut Outcome) -> &mut Option<u64> {
        match outcome {
            Outcome::Positive { confirmations, .. } => confirmations,
            Outcome::Error { code } => panic!("expected a positive outcome, found error {code}"),
        }
    }

    /// The options corpus end to end: derivation, the main resolve pair and all
    /// eleven option cases driven off the replayed minted chain, and the ledger
    /// invariants over the corpus.
    ///
    /// The genesis-key, update-crypto and end-state drivers are not called: the
    /// reshaped set carries no minting secret. That those rows are CLASSIFIED
    /// as driven is asserted here; the drivers themselves run on the checked-out
    /// suite.
    #[test]
    fn synthetic_options_corpus_drives_every_case() {
        let vectors = options_vectors();
        drive_derivation(&vectors, &[]);
        drive_resolve_with(&vectors, &[], ERROR_CODE_DIVERGENCES);
        drive_resolve_options_with(&vectors, &[], ERROR_CODE_DIVERGENCES);
        check_ledger_invariants(&vectors, &[]);

        let cases = expected_driven_with(AssertionKind::ResolveOption, &vectors, &[]);
        assert_eq!(
            cases.len(),
            11,
            "one resolve-option row per case: {cases:?}"
        );
        for kind in [
            AssertionKind::Derivation,
            AssertionKind::GenesisKey,
            AssertionKind::Resolve,
            AssertionKind::UpdateCrypto,
            AssertionKind::EndState,
        ] {
            assert!(
                expected_driven_with(kind, &vectors, &[]).contains(&RowKey::set(OPTIONS_SET)),
                "{OPTIONS_SET}: the {kind} row is classified as driven"
            );
        }
    }

    /// Drive the main pair and every positive case of each set and require the
    /// resolved `confirmations` to EQUAL the recorded value. Returns the
    /// `(case, recorded)` pairs checked.
    fn check_exact_confirmations(vectors: &[Vector]) -> Vec<(String, Option<u64>)> {
        let mut causes = CauseCheck::new(NEGATIVE_SET_EXPECTATIONS);
        let mut checked = Vec::new();
        for vector in vectors {
            let fixture = replay_fixture(vector);
            let pairs = std::iter::once(("resolve".to_string(), &vector.outcome)).chain(
                vector
                    .resolve_cases
                    .iter()
                    .map(|case| (format!("resolve/{}", case.name), &case.outcome)),
            );
            for (case_dir, outcome) in pairs {
                let Outcome::Positive { confirmations, .. } = outcome else {
                    continue;
                };
                let resolved = drive_case(
                    vector,
                    &case_dir,
                    outcome,
                    fixture.as_ref(),
                    ERROR_CODE_DIVERGENCES,
                    &mut causes,
                );
                confirmations_exact(resolved, *confirmations)
                    .unwrap_or_else(|e| panic!("{} {case_dir}: {e}", vector.id));
                checked.push((case_dir, *confirmations));
            }
        }
        causes.finish();
        checked
    }

    /// On the pinned options set the resolver's `confirmations` EQUAL the
    /// recorded ones, for the main pair and every positive case.
    ///
    /// The corpus rule stays "at least the recorded value", because an upstream
    /// set's recorded tip may lag the tip its capture is replayed at. Here the
    /// replay tip is the recorded tip by construction, and the recorded values
    /// were computed by hand as `tip - height + 1`, so equality is the stronger
    /// and correct check: it also catches a resolver that over-reports, which
    /// `>=` cannot.
    #[test]
    fn synthetic_options_confirmations_are_exact_at_the_pinned_tip() {
        let checked = check_exact_confirmations(&options_vectors());
        let expected: Vec<(String, Option<u64>)> = [
            ("resolve", 6),
            ("resolve/01", 0),
            ("resolve/02", 8),
            ("resolve/03", 7),
            ("resolve/05", 0),
            ("resolve/06", 8),
            ("resolve/07", 7),
            ("resolve/09", 0),
            ("resolve/10", 7),
        ]
        .into_iter()
        .map(|(case, conf)| (case.to_string(), Some(conf)))
        .collect();
        assert_eq!(
            checked, expected,
            "the main pair and every positive case, with the hand-computed confirmations"
        );
    }

    /// The set of the `below-min-conf` synthetic corpus: the options set's
    /// chain copied at an earlier tip, where every signal sits below the
    /// default `minConf` (see `fixtures/layout/README.md`).
    const BELOW_MIN_CONF_SET: &str = "mutinynet/k1/q5pew2jc";

    /// A positive set with `signals.json` whose main pair expects version 1
    /// replays its capture, and its Resolve row passes: the walk probes, which
    /// need a version past genesis, do not run on it.
    #[test]
    fn synthetic_signals_below_min_conf_resolve_at_genesis() {
        let vectors = discover_in(&Corpus::synthetic("below-min-conf"));
        assert_eq!(
            vectors.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
            [BELOW_MIN_CONF_SET],
            "the below-min-conf corpus holds exactly its one set"
        );
        let vector = &vectors[0];
        assert!(!vector.is_negative() && vector.signals.is_some());
        assert_eq!(vector.expected_version_id(), Some(1));
        assert!(
            replay_fixture(vector).is_some(),
            "a set with signals.json replays its capture even at genesis"
        );
        drive_resolve_with(&vectors, &[], ERROR_CODE_DIVERGENCES);
        check_ledger_invariants(&vectors, &[]);
    }

    /// The walk probes run on a set expecting a version past genesis and on no
    /// other: not at genesis, and not on an expected error.
    #[test]
    fn walk_probes_apply_only_past_genesis() {
        assert!(walk_probes_apply(&options_vectors()[0]));
        assert!(!walk_probes_apply(
            &discover_in(&Corpus::synthetic("below-min-conf"))[0]
        ));
        assert!(!walk_probes_apply(&fork_vectors("withheld")[0]));
    }

    /// A replayed main input with no `resolutionOptions.sidecar`, as 20 sets of
    /// the regenerated suite ship it.
    fn replayed_input_without_sidecar() -> (serde_json::Value, ChainFixture) {
        let vectors = options_vectors();
        let mut input = vectors[0].fixture("resolve/input.json");
        input["resolutionOptions"]
            .as_object_mut()
            .expect("the main input carries resolutionOptions")
            .remove("sidecar");
        let fixture = read_chain_fixture_in(&vectors[0].corpus.chain, OPTIONS_SET);
        (input, fixture)
    }

    /// A replayed set may omit the sidecar: it reads as `{}`, as the capture
    /// tool reads it, because the set's signals record is the gate.
    #[test]
    fn case_options_reads_an_absent_sidecar_as_empty_when_signals_are_recorded() {
        let (input, fixture) = replayed_input_without_sidecar();
        let options = case_options(&input, Some(&fixture), OPTIONS_SET);
        let sidecar = options
            .sidecar_data
            .expect("the sidecar is always supplied");
        assert!(
            sidecar.updates.is_empty() && sidecar.genesis_document.is_none(),
            "an absent sidecar is the empty one"
        );
        assert_eq!(options.chain_tip_height, Some(fixture.tip_height));
    }

    /// A resolver reporting fewer confirmations than recorded fails the row.
    #[test]
    fn synthetic_options_fewer_confirmations_than_recorded_fail() {
        let mut vectors = options_vectors();
        *recorded_confirmations(&mut vectors[0].outcome) = Some(7);
        let message = panic_text(|| drive_resolve_with(&vectors, &[], &[]));
        assert!(
            message.contains("confirmations") && message.contains('6') && message.contains('7'),
            "the failure names confirmations and both values: {message}"
        );
    }

    /// More confirmations than recorded pass the corpus rule but fail the
    /// exact check on the pinned set: the two rules are genuinely different.
    #[test]
    fn synthetic_options_more_confirmations_than_recorded_fail_only_the_exact_check() {
        let mut vectors = options_vectors();
        *recorded_confirmations(&mut vectors[0].outcome) = Some(5);
        drive_resolve_with(&vectors, &[], ERROR_CODE_DIVERGENCES);
        let message = panic_text(|| {
            check_exact_confirmations(&vectors);
        });
        assert!(
            message.contains("confirmations") && message.contains('5') && message.contains('6'),
            "the exact check names confirmations and both values: {message}"
        );
    }

    /// The resolver's count must be the one `signals.json` gives, not merely
    /// at least the recorded one: with the record's tip moved one block on,
    /// the resolver's unchanged count still clears the recorded lower bound
    /// but no longer equals the derived count, and the drive fails naming it.
    #[test]
    fn synthetic_options_confirmations_must_equal_the_count_signals_json_gives() {
        let mut vectors = options_vectors();
        vectors[0]
            .signals
            .as_mut()
            .expect("the options set carries signals.json")
            .recorded_tip += 1;
        let message = panic_text(|| drive_resolve_with(&vectors, &[], ERROR_CODE_DIVERGENCES));
        assert!(
            message.contains(OPTIONS_SET)
                && message.contains("must equal")
                && message.contains("derived from signals.json"),
            "got: {message}"
        );
    }

    /// A positive `resolve/NN` case that records no `confirmations` fails by
    /// name: provenance from the latest signal fits only the main pair, and
    /// case `02` stops at v2, two updates before it.
    #[test]
    fn synthetic_options_case_without_confirmations_fails_by_name() {
        let mut vectors = options_vectors();
        *recorded_confirmations(case_outcome(&mut vectors, "02")) = None;
        let message =
            panic_text(|| drive_resolve_options_with(&vectors, &[], ERROR_CODE_DIVERGENCES));
        assert!(
            message.contains("resolve/02")
                && message.contains("must record didDocumentMetadata.confirmations"),
            "the failure names the case and the missing member, rather than a \
             provenance mismatch against the wrong block: {message}"
        );
    }

    /// A replayed main pair that records no `confirmations` fails by name, as a
    /// case does: every replayed positive resolve records the number.
    #[test]
    fn synthetic_options_main_pair_without_confirmations_fails_by_name() {
        let mut vectors = options_vectors();
        *recorded_confirmations(&mut vectors[0].outcome) = None;
        let message = panic_text(|| drive_resolve_with(&vectors, &[], &[]));
        assert!(
            message.contains(OPTIONS_SET)
                && message.contains("must record didDocumentMetadata.confirmations"),
            "the failure names the set and the missing member: {message}"
        );
    }

    /// A capture missing the `/block/{hash}` body of one of its announcements
    /// fails the versionTime probe naming the set and the block, rather than
    /// skipping it.
    #[test]
    fn version_time_probe_bound_panics_naming_a_missing_block() {
        let vectors = options_vectors();
        let mut fixture = read_chain_fixture_in(&vectors[0].corpus.chain, OPTIONS_SET);
        version_time_probe_bound(&fixture, OPTIONS_SET);
        let dropped: Vec<String> = std::mem::take(&mut fixture.blocks).into_keys().collect();
        assert!(
            !dropped.is_empty(),
            "the options capture records its announcements' blocks"
        );
        let message = panic_text(|| {
            version_time_probe_bound(&fixture, OPTIONS_SET);
        });
        assert!(
            message.contains(OPTIONS_SET)
                && dropped
                    .iter()
                    .any(|hash| message.contains(&format!("/block/{hash}"))),
            "the failure names the set and the missing block: {message}"
        );
    }

    /// A negative case asserts the code: a recorded code the resolver does not
    /// emit fails, naming both.
    #[test]
    fn synthetic_options_wrong_error_code_fails() {
        let mut vectors = options_vectors();
        *case_outcome(&mut vectors, "04") = Outcome::Error {
            code: "INVALID_DID".to_string(),
        };
        let message =
            panic_text(|| drive_resolve_options_with(&vectors, &[], ERROR_CODE_DIVERGENCES));
        assert!(
            message.contains("NOT_FOUND") && message.contains("INVALID_DID"),
            "the failure names the emitted and the expected code: {message}"
        );
    }

    /// A recorded code that diverges from the specification passes only
    /// through the divergence table passed in, which then asserts the
    /// specification's code is emitted — and the entry counts as used.
    #[test]
    fn synthetic_options_error_code_maps_through_the_divergence_table() {
        const LOCAL: &[CodeDivergence] = &[CodeDivergence {
            vector_code: "NOT_FOUND_IN_VECTOR",
            spec_code: "NOT_FOUND",
            issue: "stands in for an upstream thread",
        }];
        let untouched = options_vectors();
        assert_eq!(
            unused_divergences(&untouched, &[], LOCAL).len(),
            1,
            "no case records the vector code yet, so the entry is unused"
        );

        let mut vectors = options_vectors();
        *case_outcome(&mut vectors, "04") = Outcome::Error {
            code: "NOT_FOUND_IN_VECTOR".to_string(),
        };
        drive_resolve_options_with(&vectors, &[], LOCAL);
        assert!(unused_divergences(&vectors, &[], LOCAL).is_empty());

        let message =
            panic_text(|| drive_resolve_options_with(&vectors, &[], ERROR_CODE_DIVERGENCES));
        assert!(
            message.contains("NOT_FOUND_IN_VECTOR") && message.contains("got NOT_FOUND"),
            "without the entry the divergent code fails: {message}"
        );
    }

    /// A case expecting an error whose resolve succeeds fails, naming the
    /// version it resolved to.
    #[test]
    fn synthetic_options_unexpected_success_fails() {
        let mut vectors = options_vectors();
        *case_outcome(&mut vectors, "02") = Outcome::Error {
            code: "NOT_FOUND".to_string(),
        };
        let message =
            panic_text(|| drive_resolve_options_with(&vectors, &[], ERROR_CODE_DIVERGENCES));
        assert!(
            message.contains("resolve/02") && message.contains("versionId 2"),
            "{message}"
        );
    }

    /// `versionId` is compared as a string for string-encoded outputs: a
    /// recorded `"02"` does not match a resolved 2.
    #[test]
    fn synthetic_options_version_id_is_compared_as_a_string() {
        let mut vectors = options_vectors();
        match case_outcome(&mut vectors, "02") {
            Outcome::Positive {
                version_id_string, ..
            } => *version_id_string = "02".to_string(),
            Outcome::Error { .. } => panic!("resolve/02 is positive"),
        }
        let message =
            panic_text(|| drive_resolve_options_with(&vectors, &[], ERROR_CODE_DIVERGENCES));
        assert!(message.contains("\"02\""), "{message}");
    }

    /// Every replay first checks the capture against `signals.json`: a file
    /// missing one of the chain's announcements fails both drivers by name.
    #[test]
    fn synthetic_options_signals_json_mismatch_fails_the_drive() {
        let mut vectors = options_vectors();
        vectors[0]
            .signals
            .as_mut()
            .expect("the options set carries signals.json")
            .entries
            .pop();
        for message in [
            panic_text(|| drive_resolve_with(&vectors, &[], ERROR_CODE_DIVERGENCES)),
            panic_text(|| drive_resolve_options_with(&vectors, &[], ERROR_CODE_DIVERGENCES)),
        ] {
            assert!(message.contains("signals.json"), "{message}");
        }
    }

    /// A hand-written skip of one option case keeps the options drivers green
    /// and removes exactly that row.
    #[test]
    fn synthetic_options_skip_override_names_one_case() {
        const OVERRIDE: &[SkipOverride] = &[SkipOverride {
            vector: OPTIONS_SET,
            kind: AssertionKind::ResolveOption,
            case: Some("07"),
            reason: "stands in for a hand-written skip",
        }];
        let vectors = options_vectors();
        let driven = expected_driven_with(AssertionKind::ResolveOption, &vectors, OVERRIDE);
        assert_eq!(driven.len(), 10);
        assert!(!driven.contains(&RowKey::case(OPTIONS_SET, "07")));
        drive_resolve_options_with(&vectors, OVERRIDE, ERROR_CODE_DIVERGENCES);
        check_ledger_invariants(&vectors, OVERRIDE);
    }

    /// The set of the `late-code` and `withheld` synthetic corpora: the minted
    /// regtest late-publishing fork reshaped into the regenerated layout (see
    /// `fixtures/layout/README.md`).
    const FORK_SET: &str = "regtest/k1/qgph42l3";

    /// A negative synthetic corpus, discovered fresh: exactly the fork set.
    fn fork_vectors(corpus: &str) -> Vec<Vector> {
        let vectors = discover_in(&Corpus::synthetic(corpus));
        assert_eq!(
            vectors.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
            [FORK_SET],
            "the {corpus} corpus holds exactly its one set"
        );
        vectors
    }

    /// The late-code set records `LATE_PUBLISHING_ERROR`. Through the
    /// divergence entry its Resolve row is driven off the replayed fork and
    /// asserts the resolver emits `LATE_PUBLISHING`, and the entry counts as
    /// used.
    ///
    /// The genesis-key, update-crypto and end-state drivers are not called on
    /// synthetic corpora: the reshaped sets carry no signing key, and those
    /// rows are driven on the checked-out suite.
    #[test]
    fn synthetic_late_code_asserts_the_specification_code() {
        let vectors = fork_vectors("late-code");
        assert!(vectors[0].is_negative());
        drive_derivation(&vectors, &[]);
        drive_resolve_with(&vectors, &[], ERROR_CODE_DIVERGENCES);
        check_ledger_invariants(&vectors, &[]);
        assert!(
            unused_divergences(&vectors, &[], ERROR_CODE_DIVERGENCES).is_empty(),
            "the late-code Resolve row uses the entry"
        );
    }

    /// Without the divergence entry the late-code row fails, naming the
    /// recorded code and the one the resolver emitted: the mapping is
    /// load-bearing, not decorative.
    #[test]
    fn synthetic_late_code_fails_without_its_divergence() {
        let vectors = fork_vectors("late-code");
        let message = panic_text(|| drive_resolve_with(&vectors, &[], &[]));
        assert!(
            message.contains("expected error LATE_PUBLISHING_ERROR")
                && message.contains("got LATE_PUBLISHING"),
            "the failure names both codes: {message}"
        );
    }

    /// On both negative sets the end-state row skips as expected-error, and
    /// nothing else; derivation, genesis-key, update-crypto and resolve stay
    /// classified as driven. The genesis-key and update-crypto rows are
    /// classification only: the set carries no signing key, and those drivers
    /// are not called on synthetic corpora.
    #[test]
    fn synthetic_negative_sets_skip_update_rows_as_expected_error() {
        for corpus in ["late-code", "withheld"] {
            let vectors = fork_vectors(corpus);
            assert_eq!(
                vectors[0].skip_reasons_with(AssertionKind::EndState, &[]),
                BTreeSet::from([SkipReason::ExpectedError]),
                "{corpus}: the end-state row skips as an expected error"
            );
            assert!(
                expected_driven_with(AssertionKind::EndState, &vectors, &[]).is_empty(),
                "{corpus}: no end-state row is driven"
            );
            for kind in [
                AssertionKind::Derivation,
                AssertionKind::GenesisKey,
                AssertionKind::UpdateCrypto,
                AssertionKind::Resolve,
            ] {
                assert!(
                    expected_driven_with(kind, &vectors, &[]).contains(&RowKey::set(FORK_SET)),
                    "{corpus}: the {kind} row is classified as driven"
                );
            }
            assert!(
                expected_driven_with(AssertionKind::ResolveOption, &vectors, &[]).is_empty(),
                "{corpus}: the set has no resolve cases"
            );
        }
    }

    /// The withheld set has the files of a CAS-announced update set — update
    /// steps and a sidecar without `updates` — but its expected error makes it
    /// negative, so it is not read as CAS. Its Resolve row is driven and the
    /// resolver emits `MISSING_UPDATE_DATA` off the replayed fork, with the
    /// production divergence table.
    #[test]
    fn synthetic_withheld_update_is_negative_not_cas() {
        let vectors = fork_vectors("withheld");
        let delivery = vectors[0].delivery;
        assert!(
            delivery.negative,
            "an expected error makes the set negative"
        );
        assert_ne!(
            delivery.announcement,
            Some(AnnouncementDelivery::Cas),
            "a negative set is never read as CAS-announced"
        );
        assert!(
            vectors[0]
                .skip_reasons_with(AssertionKind::Resolve, &[])
                .is_empty(),
            "the withheld Resolve row carries no skip reason"
        );
        drive_derivation(&vectors, &[]);
        drive_resolve_with(&vectors, &[], ERROR_CODE_DIVERGENCES);
        check_ledger_invariants(&vectors, &[]);

        // The same drive fails if the resolver's code is not the recorded one.
        let mut wrong = fork_vectors("withheld");
        wrong[0].outcome = Outcome::Error {
            code: "LATE_PUBLISHING".to_string(),
        };
        let message = panic_text(|| drive_resolve_with(&wrong, &[], ERROR_CODE_DIVERGENCES));
        assert!(
            message.contains("got MISSING_UPDATE_DATA"),
            "the failure names the emitted code: {message}"
        );
    }

    /// The set of the `withheld-genesis` synthetic corpus: an external set with
    /// no sidecar `genesisDocument`, expecting `NOT_FOUND`.
    const WITHHELD_GENESIS_SET: &str = "mutinynet/x1/qh66uy2s";

    /// An external set that withholds its genesis document on purpose has the
    /// files of a CAS-genesis set; only its expected error tells them apart.
    /// Its Resolve row is classified negative, driven with no genesis source,
    /// and asserts the resolver's `NOT_FOUND` — it is not left unclassified.
    #[test]
    fn synthetic_withheld_genesis_is_driven_not_unclassified() {
        let vectors = discover_in(&Corpus::synthetic("withheld-genesis"));
        assert_eq!(
            vectors.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
            [WITHHELD_GENESIS_SET],
            "the withheld-genesis corpus holds exactly its one set"
        );
        let vector = &vectors[0];
        assert!(vector.is_negative() && !vector.has_sidecar_genesis_document);
        assert_eq!(vector.delivery.genesis, GenesisDelivery::Sidecar);
        assert!(
            vector.is_drivable(AssertionKind::Resolve)
                && vector
                    .skip_reasons_with(AssertionKind::Resolve, &[])
                    .is_empty(),
            "the Resolve row is drivable and carries no skip reason"
        );
        drive_derivation(&vectors, &[]);
        drive_resolve_with(&vectors, &[], ERROR_CODE_DIVERGENCES);
        check_ledger_invariants(&vectors, &[]);

        // The drive asserts the code: a different recorded code fails.
        let mut wrong = vectors.clone();
        wrong[0].outcome = Outcome::Error {
            code: "INVALID_DID".to_string(),
        };
        let message = panic_text(|| drive_resolve_with(&wrong, &[], ERROR_CODE_DIVERGENCES));
        assert!(
            message.contains("got NOT_FOUND"),
            "the failure names the emitted code: {message}"
        );
    }

    /// A positive external set with no sidecar `genesisDocument` still needs
    /// one to be driven: its genesis is CAS-delivered.
    #[test]
    fn a_positive_external_set_without_a_sidecar_genesis_is_not_drivable() {
        let shapes = discover_in(&Corpus::synthetic("shapes"));
        let cas_genesis = shapes
            .iter()
            .find(|v| v.id == WITHHELD_GENESIS_SET)
            .expect("the shapes corpus holds the CAS-genesis set");
        assert!(!cas_genesis.is_negative() && !cas_genesis.has_sidecar_genesis_document);
        assert!(!cas_genesis.is_drivable(AssertionKind::Resolve));
        assert!(!cas_genesis.is_drivable(AssertionKind::ResolveOption));
    }

    /// A divergence entry that no driven negative case records is reported by
    /// the guard: the options corpus records no `LATE_PUBLISHING_ERROR`.
    #[test]
    fn synthetic_unused_divergence_is_reported() {
        let unused = unused_divergences(&options_vectors(), &[], ERROR_CODE_DIVERGENCES);
        assert_eq!(unused.len(), 1, "{unused:?}");
        assert!(unused[0].contains("LATE_PUBLISHING_ERROR"), "{unused:?}");
    }

    /// A hand-written skip of one negative resolve case removes exactly that
    /// row: the drivers and the ledger checks stay green, ten cases stay
    /// driven, and the coverage summary counts the skipped row and prints its
    /// reason.
    #[test]
    fn a_skip_override_on_one_resolve_case_keeps_the_drivers_green() {
        const REASON: &str = "stands in for a hand-written skip of one resolve case";
        const OVERRIDE: &[SkipOverride] = &[SkipOverride {
            vector: OPTIONS_SET,
            kind: AssertionKind::ResolveOption,
            case: Some("04"),
            reason: REASON,
        }];
        let vectors = options_vectors();

        let driven = expected_driven_with(AssertionKind::ResolveOption, &vectors, OVERRIDE);
        assert_eq!(driven.len(), 10, "{driven:?}");
        assert!(!driven.contains(&RowKey::case(OPTIONS_SET, "04")));
        drive_resolve_with(&vectors, OVERRIDE, ERROR_CODE_DIVERGENCES);
        drive_resolve_options_with(&vectors, OVERRIDE, ERROR_CODE_DIVERGENCES);
        check_ledger_invariants(&vectors, OVERRIDE);

        let summary = render_summary_with(&vectors, OVERRIDE);
        let row: Vec<&str> = summary
            .lines()
            .find(|line| line.trim_start().starts_with("resolve-option "))
            .unwrap_or_else(|| panic!("the summary has a resolve-option row:\n{summary}"))
            .split_whitespace()
            .collect();
        assert_eq!(row, ["resolve-option", "10", "1"], "{summary}");
        assert!(summary.contains(REASON), "{summary}");
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
    /// A STEP OVER A DEACTIVATED SOURCE is not re-derived: this crate refuses
    /// to construct it, and a deactivated DID is terminal, so no resolver
    /// applies it. The refusal is asserted, and the vendor's `signedUpdate` is
    /// checked on its own terms — hashes against `sourceDocument`, proof
    /// verified under the key `sourceDocument` names — by
    /// [`check_update_over_deactivated_source`]. The ordering, hash and
    /// document linkage still hold it to the step before it; nothing carries
    /// past it.
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

    /// The driver compares each negative set with its table entry: flipping
    /// one entry's expected outcome makes the driver fail on that scenario's
    /// set, naming the set and the scenario. Both directions are exercised, a
    /// passing scenario expected to fail and a failing one expected to pass.
    #[test]
    fn a_flipped_negative_set_expectation_fails_naming_the_set() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };
        let find = |pred: fn(&UpdateCryptoExpectation) -> bool| {
            NEGATIVE_SET_EXPECTATIONS
                .iter()
                .position(|e| pred(&e.update_crypto))
                .expect("the table holds both outcomes")
        };
        let passing = find(|u| matches!(u, UpdateCryptoExpectation::Passes));
        let failing = find(|u| matches!(u, UpdateCryptoExpectation::FailsAt(_)));

        for (index, flipped_to) in [
            (passing, UpdateCryptoExpectation::FailsAt(&["x"])),
            (failing, UpdateCryptoExpectation::Passes),
        ] {
            let mut flipped = NEGATIVE_SET_EXPECTATIONS.to_vec();
            flipped[index].update_crypto = flipped_to;
            let scenario = flipped[index].scenario;

            let subset: Vec<Vector> = vectors
                .iter()
                .filter(|v| {
                    v.network_dir == "regtest"
                        && v.is_negative()
                        && negative_set_expectation(&flipped, v).map(|e| e.scenario)
                            == Some(scenario)
                })
                .cloned()
                .collect();
            assert_eq!(subset.len(), 1, "{scenario} has one regtest set");

            let message = panic_text(|| drive_update_crypto_with(&subset, &[], &flipped));
            assert!(
                message.contains(&subset[0].id) && message.contains(scenario),
                "{scenario}: the failure names the set and the scenario: {message}"
            );
        }
    }

    /// The Resolve driver compares a negative set's rejection detail with its
    /// scenario's cause, on a set with update steps (n24) and on one without
    /// (n04, the genesis-hash comparison): with the scenario's cause replaced
    /// by text no rejection carries, the driver fails on the regtest set,
    /// naming the set, the scenario and the cause check, although the code
    /// still matches.
    #[test]
    fn a_wrong_expected_cause_fails_naming_the_set() {
        let Some(vectors) = discovered_vectors_or_skip() else {
            return;
        };
        for scenario in ["n24", "n04"] {
            let mut wrong = NEGATIVE_SET_EXPECTATIONS.to_vec();
            let at = wrong
                .iter()
                .position(|e| e.scenario == scenario)
                .unwrap_or_else(|| panic!("the table has an {scenario} entry"));
            wrong[at].cause = &["this text is not in any rejection"];

            let subset: Vec<Vector> = vectors
                .iter()
                .filter(|v| {
                    v.network_dir == "regtest"
                        && v.is_negative()
                        && negative_set_expectation(&wrong, v).map(|e| e.scenario) == Some(scenario)
                })
                .cloned()
                .collect();
            assert_eq!(subset.len(), 1, "{scenario} has one regtest set");

            drive_resolve_with_expectations(
                &subset,
                &[],
                ERROR_CODE_DIVERGENCES,
                NEGATIVE_SET_EXPECTATIONS,
            );
            let message = panic_text(|| {
                drive_resolve_with_expectations(&subset, &[], ERROR_CODE_DIVERGENCES, &wrong)
            });
            assert!(
                message.contains(&subset[0].id)
                    && message.contains(scenario)
                    && message.contains("rejection cause"),
                "the failure names the set, the scenario and the cause check: {message}"
            );
        }
    }

    /// A negative set with no table entry is refused by name, never passed
    /// silently: here a keyed negative set, which carries no scenario id.
    #[test]
    fn update_crypto_refuses_a_negative_set_without_a_table_entry() {
        let suite = keyed_suite("uc-no-entry");
        let set = keyed_k1_unknown_method_set(keyed_invalid_update_output());
        suite.write(&set);
        let vectors = suite.vectors();
        assert!(vectors[0].is_negative());
        let message = panic_text(|| drive_update_crypto(&vectors, &[]));
        assert!(
            message.contains(&set.id())
                && message.contains("needs a negative-set expectation entry"),
            "got: {message}"
        );
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
    fn signed_update_for_step(vector: &Vector, step: &str) -> StepFixtures {
        use crate::key::SecretKey;
        use json_patch::Patch;

        let input = vector.fixture(&format!("{step}/input.json"));
        let output = vector.fixture(&format!("{step}/output.json"));

        let ctx = format!("{} {step}", vector.id);
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

    /// Pin an update step's version numbers to its place in the walk: step
    /// `step_index` (zero-based) is update number `step_index + 1`, so its
    /// `sourceVersionId` is `step_index + 1` and its
    /// `signedUpdate.targetVersionId` is one above that.
    ///
    /// Both update drivers run this before anything branches on a version
    /// number. The update the drivers build takes its target version FROM
    /// `signedUpdate.targetVersionId`, so comparing the two afterwards is a
    /// tautology; only the source version ties the target to the chain. With
    /// both pinned, the targets rise by one per step, so any cutoff on them
    /// trims only the end of the walk.
    fn check_step_versions(
        input: &serde_json::Value,
        output: &serde_json::Value,
        step_index: usize,
        ctx: &str,
    ) {
        let source_version = field_version_id(input, "sourceVersionId", ctx);
        assert_eq!(
            source_version,
            step_index as u64 + 1,
            "{ctx}: must be update number {} in the chain",
            step_index + 1
        );
        assert_eq!(
            field_version_id(output, "signedUpdate.targetVersionId", ctx),
            source_version + 1,
            "{ctx}: signedUpdate.targetVersionId must be sourceVersionId + 1"
        );
    }

    /// A JSON Document Hash in the base64url (no padding) form `sourceHash`
    /// and `targetHash` are stored in.
    fn hash_b64(hash: &Sha256Hash) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_bytes())
    }

    /// Check an update step whose `sourceDocument` is deactivated, and return
    /// its `output.json`.
    ///
    /// Such a step cannot be re-derived: `construct_signed_update` refuses a
    /// deactivated source, which is this crate's policy (the specification only
    /// requires resolution to stop at a deactivated document). So the refusal
    /// is asserted, and the vendor's `signedUpdate` is checked on its own
    /// terms instead: its `sourceHash` and `targetHash` must be the JSON
    /// Document Hashes of `sourceDocument` before and after the patch, its
    /// patch must be the step's, its proof must name the step's
    /// `verificationMethodId`, and the proof must verify under the key that
    /// method has in `sourceDocument`. The update is never applied.
    fn check_update_over_deactivated_source(vector: &Vector, step: &str) -> serde_json::Value {
        use crate::cryptosuite::CryptoSuite;
        use crate::document::absolutize_did_url;
        use crate::key::SecretKey;
        use crate::zcap::proof::ProofPurpose;
        use json_patch::Patch;

        let input = vector.fixture(&format!("{step}/input.json"));
        let output = vector.fixture(&format!("{step}/output.json"));
        let ctx = format!("{} {step}", vector.id);

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

        match source_doc.construct_signed_update(patch.clone(), target_version_id, vm_id, secret) {
            Err(Btcr2Error::InvalidDidUpdate(msg)) if msg.contains("deactivated") => {}
            other => panic!(
                "{ctx}: construct_signed_update must refuse an update over a deactivated \
                 sourceDocument, got {other:?}"
            ),
        }

        let (_, source_hash, target_hash) = source_doc
            .construct_unsigned_update(&patch, target_version_id)
            .unwrap_or_else(|e| panic!("{ctx}: the patch must apply to sourceDocument: {e}"));
        assert_eq!(
            hash_b64(&source_hash),
            field_str(&output, "signedUpdate.sourceHash", &ctx),
            "{ctx}: signedUpdate.sourceHash must be the JSON Document Hash of sourceDocument"
        );
        assert_eq!(
            hash_b64(&target_hash),
            field_str(&output, "signedUpdate.targetHash", &ctx),
            "{ctx}: signedUpdate.targetHash must be the JSON Document Hash of sourceDocument \
             with the patch applied"
        );
        assert_eq!(
            output["signedUpdate"]["patch"], input["patches"],
            "{ctx}: signedUpdate.patch must be the step's patches"
        );

        let vendor = Update::from_json_value(output["signedUpdate"].clone())
            .unwrap_or_else(|e| panic!("{ctx}: signedUpdate must parse as an update: {e}"));
        assert_eq!(
            vendor.proof.inner.verification_method,
            absolutize_did_url(vm_id, &source_doc.fields.id),
            "{ctx}: the proof must name the step's verificationMethodId"
        );
        let key = source_doc
            .fields
            .invoking_public_key(&vendor.proof.inner.verification_method)
            .unwrap_or_else(|e| {
                panic!("{ctx}: the proof's verificationMethod must be an invoking method of sourceDocument: {e}")
            });
        CryptoSuite
            .data_integrity_verify_proof(key, &vendor, &ProofPurpose::CapabilityInvocation)
            .unwrap_or_else(|e| {
                panic!("{ctx}: the signedUpdate proof must verify under the key sourceDocument names: {e}")
            });

        output
    }

    /// The UPDATE-crypto driver body, over an explicit override table so the same
    /// code path can be exercised with a hand-written skip in place. Negative
    /// sets are held to their entry in [`NEGATIVE_SET_EXPECTATIONS`].
    fn drive_update_crypto(vectors: &[Vector], overrides: &[SkipOverride]) {
        drive_update_crypto_with(vectors, overrides, NEGATIVE_SET_EXPECTATIONS);
    }

    /// The update-crypto driver over an explicit negative-set expectation
    /// table.
    ///
    /// A positive set must pass every check of [`update_crypto_set`]. A
    /// negative set must have an entry in `table`, and its outcome must be the
    /// entry's: a `Passes` set must pass, and a `FailsAt` set must fail with a
    /// message carrying every recorded substring. A `NoUpdateSteps` set ships
    /// no update steps, so update-crypto never applies to it; driving one is a
    /// mismatch. Every mismatching set is
    /// collected, and the driver then fails naming each set and its scenario.
    fn drive_update_crypto_with(
        vectors: &[Vector],
        overrides: &[SkipOverride],
        table: &[NegativeSetExpectation],
    ) {
        let mut observed = BTreeSet::new();
        let mut mismatches: Vec<String> = Vec::new();
        for vector in vectors {
            if !vector.should_drive_with(AssertionKind::UpdateCrypto, overrides) {
                continue;
            }
            let id = &vector.id;
            if vector.is_negative() {
                let Some(entry) = negative_set_expectation(table, vector) else {
                    panic!(
                        "{id}: a negative set driven by update-crypto \
                         needs a negative-set expectation entry (scenario {:?})",
                        vector.scenario_id
                    )
                };
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    update_crypto_set(vector)
                }))
                .map_err(|payload| {
                    payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                });
                mismatches.extend(update_crypto_mismatch(id, entry, outcome));
            } else {
                update_crypto_set(vector);
            }
            observed.insert(RowKey::set(id.clone()));
        }
        assert!(
            mismatches.is_empty(),
            "{} negative set(s) differ from their expectation entry:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
        reconcile_driven_with(AssertionKind::UpdateCrypto, vectors, &observed, overrides);
    }

    /// Whether a negative set's update-crypto outcome differs from its
    /// entry, as the line to report; `None` when it agrees. `outcome` is the
    /// panic text of a failing run, or `Err(None)` when the panic payload is
    /// not text.
    ///
    /// A `NoUpdateSteps` entry never agrees: update-crypto does not apply to
    /// such a set. A `FailsAt` entry with no substrings or a vacuous one (see
    /// [`vacuous_substring`]) never agrees either: it would match almost any
    /// failure, the harness's own included. A payload that is not text cannot be matched against any
    /// entry.
    fn update_crypto_mismatch(
        id: &str,
        entry: &NegativeSetExpectation,
        outcome: Result<(), Option<String>>,
    ) -> Option<String> {
        let scenario = entry.scenario;
        let note = if entry.note.is_empty() {
            String::new()
        } else {
            format!("\n  recorded: {}", entry.note)
        };
        match (entry.update_crypto, outcome) {
            (UpdateCryptoExpectation::NoUpdateSteps, _) => Some(format!(
                "{id} ({scenario}): the entry says the set ships no update steps, but \
                 update-crypto drove it{note}"
            )),
            (UpdateCryptoExpectation::FailsAt(subs), _)
                if subs.is_empty() || subs.iter().any(|s| vacuous_substring(s)) =>
            {
                Some(format!(
                    "{id} ({scenario}): the entry's FailsAt substrings {subs:?} match any \
                     failure, so they cannot pin this one{note}"
                ))
            }
            (_, Err(None)) => Some(format!(
                "{id} ({scenario}): update-crypto panicked with a payload that is not text, so \
                 it cannot be matched against the entry{note}"
            )),
            (UpdateCryptoExpectation::Passes, Ok(())) => None,
            (UpdateCryptoExpectation::Passes, Err(Some(msg))) => Some(format!(
                "{id} ({scenario}): update-crypto must pass for this negative set, but \
                 failed: {msg}{note}"
            )),
            (UpdateCryptoExpectation::FailsAt(subs), Ok(())) => Some(format!(
                "{id} ({scenario}): update-crypto must fail with {subs:?} for this \
                 negative set, but passed{note}"
            )),
            (UpdateCryptoExpectation::FailsAt(subs), Err(Some(msg))) => {
                (!subs.iter().all(|sub| msg.contains(sub))).then(|| {
                    format!(
                        "{id} ({scenario}): update-crypto must fail with {subs:?}, but \
                         failed with: {msg}{note}"
                    )
                })
            }
        }
    }

    /// The comparison of a negative set's update-crypto outcome with its entry
    /// refuses what cannot be matched: a `NoUpdateSteps` entry, a `FailsAt`
    /// entry with no substrings or a vacuous one, and a panic payload that is
    /// not text. A vacuous substring is refused even when the failure carries
    /// it: the refusal comes before any matching. It agrees only when a
    /// `Passes` set passes and a `FailsAt` set fails carrying every substring.
    #[test]
    fn update_crypto_mismatch_refuses_what_cannot_be_matched() {
        const ID: &str = "regtest/k1/qgppexmy";
        fn entry(update_crypto: UpdateCryptoExpectation) -> NegativeSetExpectation {
            NegativeSetExpectation {
                scenario: "n24",
                update_crypto,
                cause: &["x"],
                note: "",
            }
        }
        let fail = |msg: &str| Err(Some(msg.to_string()));
        use UpdateCryptoExpectation::{FailsAt, NoUpdateSteps, Passes};

        assert_eq!(update_crypto_mismatch(ID, &entry(Passes), Ok(())), None);
        assert_eq!(
            update_crypto_mismatch(
                ID,
                &entry(FailsAt(&["update sourceHash", "not Multikey"])),
                fail("a update sourceHash b not Multikey c")
            ),
            None
        );

        let carries_them = "the hash of the key: not Multikey";
        type RunOutcome = Result<(), Option<String>>;
        let refused: [(UpdateCryptoExpectation, RunOutcome, &str); 14] = [
            (
                FailsAt(&["not Multikey"]),
                Err(None),
                "a payload that is not text",
            ),
            (Passes, Err(None), "a payload that is not text"),
            (FailsAt(&[]), fail("anything"), "match any failure"),
            (FailsAt(&[]), Err(None), "match any failure"),
            (FailsAt(&[""]), fail("anything"), "match any failure"),
            (FailsAt(&[" "]), fail(carries_them), "match any failure"),
            (FailsAt(&[":"]), fail(carries_them), "match any failure"),
            (FailsAt(&["hash"]), fail(carries_them), "match any failure"),
            (
                FailsAt(&[" not Multikey"]),
                fail(carries_them),
                "match any failure",
            ),
            (FailsAt(&["not Multikey"]), Ok(()), "but passed"),
            (
                FailsAt(&["not Multikey"]),
                fail("unrelated failure"),
                "but failed with: unrelated failure",
            ),
            (Passes, fail("y"), "must pass for this negative set"),
            (NoUpdateSteps, Ok(()), "ships no update steps"),
            (NoUpdateSteps, fail("y"), "ships no update steps"),
        ];
        for (expectation, outcome, want) in refused {
            let line = update_crypto_mismatch(ID, &entry(expectation), outcome.clone())
                .unwrap_or_else(|| panic!("{expectation:?} with {outcome:?} must be refused"));
            assert!(
                line.contains(ID) && line.contains("(n24)") && line.contains(want),
                "{expectation:?} with {outcome:?}: {line}"
            );
        }
        let line = update_crypto_mismatch(ID, &entry(NoUpdateSteps), Err(None))
            .expect("NoUpdateSteps with an unreadable payload is refused");
        assert!(line.contains("ships no update steps"), "{line}");
    }

    /// Check a step's own `signedUpdate` proof under the key its
    /// `sourceDocument` names. `None` for a step over a deactivated source,
    /// whose proof [`check_update_over_deactivated_source`] already checks.
    fn vendor_proof(vector: &Vector, step: &str) -> Option<Result<(), String>> {
        use crate::cryptosuite::CryptoSuite;
        use crate::zcap::proof::ProofPurpose;

        let input = vector.fixture(&format!("{step}/input.json"));
        if input["sourceDocument"]["deactivated"] == serde_json::Value::Bool(true) {
            return None;
        }
        let output = vector.fixture(&format!("{step}/output.json"));
        let check = || -> Result<(), String> {
            let vendor = Update::from_json_value(output["signedUpdate"].clone())
                .map_err(|e| format!("signedUpdate does not parse as an update: {e}"))?;
            let source_doc = Document::from_json_string(&input["sourceDocument"].to_string())
                .map_err(|e| format!("sourceDocument does not parse: {e}"))?;
            let key = source_doc
                .fields
                .invoking_public_key(&vendor.proof.inner.verification_method)
                .map_err(|e| format!("no invoking key for the proof's verificationMethod: {e}"))?;
            CryptoSuite
                .data_integrity_verify_proof(key, &vendor, &ProofPurpose::CapabilityInvocation)
                .map_err(|e| format!("proof does not verify: {e}"))
        };
        Some(check())
    }

    /// The update-crypto checks over one set, panicking on the first that
    /// fails:
    ///
    /// - every step's own `signedUpdate` proof verifies under the key its
    ///   `sourceDocument` names ([`vendor_proof`]), before anything else, so a
    ///   set that fails a later check still has each signature pinned;
    /// - (a) version linkage: step NN is update number NN and targets the
    ///   next version;
    /// - (b) hash linkage and (c) document linkage to the previous step;
    /// - (f) the proof's cryptosuite;
    /// - (d) the re-derived hashes equal the stated ones, and (e) the
    ///   re-derived proof verifies when the update is applied.
    ///
    /// A step over a deactivated `sourceDocument` is checked by
    /// [`check_update_over_deactivated_source`] instead of being re-derived;
    /// the step linkage checks apply to it like to any other step.
    fn update_crypto_set(vector: &Vector) {
        use crate::document::InitialDocument;

        let to_b64 = hash_b64;
        let id = &vector.id;

        for step in vector.update_layout.step_prefixes() {
            if let Some(Err(e)) = vendor_proof(vector, &step) {
                panic!(
                    "{id} {step}: \
                     the vendor signedUpdate proof must verify under the key its sourceDocument names: {e}"
                )
            }
        }

        let mut previous_target_hash: Option<String> = None;
        let mut carried: Option<InitialDocument> = None;

        for (step_index, step) in vector.update_layout.step_prefixes().iter().enumerate() {
            let input = vector.fixture(&format!("{step}/input.json"));

            // (a) Version linkage: step NN is update number NN, and it
            // targets the next version.
            check_step_versions(
                &input,
                &vector.fixture(&format!("{step}/output.json")),
                step_index,
                &format!("{id} {step}"),
            );

            let (output, update) =
                if input["sourceDocument"]["deactivated"] == serde_json::Value::Bool(true) {
                    (check_update_over_deactivated_source(vector, step), None)
                } else {
                    let StepFixtures { output, update, .. } = signed_update_for_step(vector, step);
                    (output, Some(update))
                };

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

            // (f) Structural proof shape.
            assert_eq!(
                field_str(&output, "signedUpdate.proof.cryptosuite", id),
                "bip340-jcs-2025",
                "{id}: {step} vector proof cryptosuite"
            );

            // A step over a deactivated source was checked on its own terms
            // and is never applied, so nothing carries past it.
            let Some(update) = update else {
                previous_target_hash = Some(stated_target_hash.to_string());
                carried = None;
                continue;
            };

            // (d) Content-bound hashes must equal the vector's
            // signedUpdate. The target version is not compared here: the
            // update was built from it, and (a) ties it to the chain.
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
                .apply_update(&update, &AnnouncingBlock::fixed())
                .unwrap_or_else(|e| panic!("{id}: {step} produced proof must verify: {e}"));

            // (g) Carry forward into the next step.
            previous_target_hash = Some(stated_target_hash.to_string());
            carried = Some(initial);
        }
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
    /// THE WALK STOPS AT THE RESOLVED VERSION: a step whose
    /// `signedUpdate.targetVersionId` exceeds the main `resolve/output.json`
    /// `versionId` is one no resolver applies — an update over a deactivated
    /// DID, one announced on a beacon the document has since removed, or one
    /// whose signal lies past the resolution height — so it is not applied
    /// here either. The cutoff is read from the files, and every step's
    /// versions are first pinned to its place in the walk
    /// ([`check_step_versions`]), so the targets rise by one per step and the
    /// cutoff can only trim the end: every step at or below the resolved
    /// version is applied, and a mismatch there still fails. A skipped step's
    /// own content is the update-crypto driver's to
    /// check. The resolved version is the vendor's claim, and only the resolve
    /// driver ties it to what a resolver actually does, so the cutoff is
    /// allowed only on a set whose Resolve row is driven: a cutoff anywhere
    /// else fails, naming the set.
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
            let output = vector.fixture("resolve/output.json");

            // The resolved version, read as metadata (a string `versionId`);
            // each step's target is read as an update-payload integer.
            let resolved_version_id =
                match parse_outcome(&output, &format!("{id}/resolve/output.json")) {
                    Outcome::Positive { version_id, .. } => version_id,
                    Outcome::Error { code } => {
                        panic!("{id}: an end-state row resolves to a document, got error {code}")
                    }
                };

            // The walk starts from step 01's stated source document and carries
            // each step's result forward.
            let mut carried: Option<InitialDocument> = None;

            for (step_index, step) in steps.iter().enumerate() {
                let ctx = format!("{id} {step}");
                let step_output = vector.fixture(&format!("{step}/output.json"));

                // Version linkage, mirrored from the update-crypto driver and
                // checked before the cutoff branches on the target: step NN is
                // update number NN and targets the next version. Without it an
                // inflated target would drop its step from the walk unseen,
                // and a mis-ordered walk would surface only as an opaque
                // target-hash mismatch.
                check_step_versions(
                    &vector.fixture(&format!("{step}/input.json")),
                    &step_output,
                    step_index,
                    &ctx,
                );

                let target_version_id =
                    field_nonzero_version_id(&step_output, "signedUpdate.targetVersionId", &ctx);
                if target_version_id.get() > resolved_version_id {
                    // The cutoff trusts the vendor's resolved version; only
                    // the resolve driver confirms that a resolver stops
                    // there, so the cutoff is allowed only where it runs.
                    assert!(
                        vector.should_drive_with(AssertionKind::Resolve, overrides),
                        "{id}: {step} targets version {target_version_id} above the resolved \
                         version {resolved_version_id}, but the set's Resolve row is not \
                         driven, so nothing confirms the resolver stops there"
                    );
                    continue;
                }

                let StepFixtures { input, update, .. } = signed_update_for_step(vector, step);

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
                doc.apply_update(&update, &AnnouncingBlock::fixed())
                    .unwrap_or_else(|e| panic!("{id}: applying {step} must succeed: {e}"));
                carried = Some(doc);
            }

            let doc = carried.unwrap_or_else(|| {
                panic!("{id}: an end-state row applies at least one update step")
            });

            let got: serde_json::Value = doc.as_ref().clone();
            let want: serde_json::Value = output["didDocument"].clone();
            assert_eq!(
                got, want,
                "{id}: applying every update step up to the resolved version in order \
                 must reproduce resolve/output.json.didDocument"
            );

            observed.insert(RowKey::set(id.clone()));
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
        // The minted section is emitted from this test's tail, OUTSIDE the
        // absent-submodule skip: the minted scenarios are driven from fixtures
        // in this repository, so their coverage is exactly what still holds when
        // the submodule is gone — which is when a reader most needs to be told
        // what a green run still checked.
        if let Some(vectors) = discovered_vectors_or_skip() {
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

        eprintln!("{}", render_minted_summary());
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
                vector: "regtest/k1/qgp45a3y",
                kind: AssertionKind::Derivation,
                case: None,
                reason: REASON,
            },
            SkipOverride {
                vector: "regtest/k1/qgp45a3y",
                kind: AssertionKind::GenesisKey,
                case: None,
                reason: REASON,
            },
            SkipOverride {
                vector: "regtest/k1/qgp45a3y",
                kind: AssertionKind::Resolve,
                case: None,
                reason: REASON,
            },
            SkipOverride {
                vector: "regtest/k1/qgph7nre",
                kind: AssertionKind::UpdateCrypto,
                case: None,
                reason: REASON,
            },
            SkipOverride {
                vector: "regtest/k1/qgph7nre",
                kind: AssertionKind::EndState,
                case: None,
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
                expected_driven_with(entry.kind, &vectors, &[])
                    .contains(&RowKey::set(entry.vector)),
                "{}: without the override the row is driven for {}, so the override changes \
                 something",
                entry.vector,
                entry.kind,
            );
            assert!(
                !expected_driven_with(entry.kind, &vectors, LIVE_OVERRIDE)
                    .contains(&RowKey::set(entry.vector)),
                "{}: a live override must remove the row from the {} expectation",
                entry.vector,
                entry.kind,
            );
        }

        // With the overrides live: every driver reconciles against its reduced
        // set and the ledger stays valid.
        drive_derivation(&vectors, LIVE_OVERRIDE);
        drive_genesis_key(&vectors, LIVE_OVERRIDE);
        drive_resolve_with(&vectors, LIVE_OVERRIDE, ERROR_CODE_DIVERGENCES);
        drive_resolve_options_with(&vectors, LIVE_OVERRIDE, ERROR_CODE_DIVERGENCES);
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
    /// bears no relationship to any test-suite vector — `find_next_signals`
    /// attributes a history to the declared beacon it is keyed under and does
    /// not cross-check the transaction bytes against that address, so these
    /// tests serve it under the resolver's first beacon. Distinct from
    /// `fixtures/chain/`, which holds real captured per-vector chain snapshots.
    const UNCONFIRMED_FIXTURE: &str = include_str!("../fixtures/singleton-beacon-signal-txs.json");

    /// The `SingletonBeacon` list of [`UNCONFIRMED_FIXTURE`] (or of a JSON
    /// value shaped like it), keyed as the history of `resolver`'s first
    /// declared beacon — the shape `find_next_signals` takes.
    fn fixture_txs_under_first_beacon(
        resolver: &Resolver,
        json: serde_json::Value,
    ) -> HashMap<String, Vec<Transaction>> {
        let txs: Vec<Transaction> = serde_json::from_value(json["SingletonBeacon"].clone())
            .expect("the fixture's SingletonBeacon list deserializes");
        HashMap::from([(first_beacon_address(resolver).to_string(), txs)])
    }

    /// The address of `resolver`'s first declared beacon: the attribution the
    /// unit tests give a synthetic signal when which beacon announced it does
    /// not matter, only that a declared one did.
    fn first_beacon_address(resolver: &Resolver) -> Address {
        resolver.contemporary_doc.fields.service[0]
            .address()
            .clone()
    }

    /// An unconfirmed announcement is skipped even when the sidecar holds the
    /// update it announces (a *needed* signal): the spec says mempool
    /// transactions are not processed, and a controller resolving with the
    /// full sidecar before its own broadcast is mined must get the confirmed
    /// history rather than an error.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (unconfirmed mempool transactions MUST NOT be processed).
    #[test]
    fn unconfirmed_needed_signal_is_skipped() {
        // `find_next_signals` takes each history under the declared beacon it
        // is keyed by and inspects each tx's last output + confirmation
        // status; it does NOT cross-check the tx bytes against that beacon's
        // address (the key is the attribution). The resolver doc is re-homed
        // onto the regtest k1 qgpakaw4 vector purely so a valid resolver with
        // a declared beacon exists to key the fixture under.
        let mut resolver = resolver_with(SidecarData::default(), Some(TEST_CHAIN_TIP));

        // Confirmed pass: discover the update hash this beacon tx announces, reusing
        // the production extraction path rather than re-parsing the OP_RETURN.
        let confirmed_txs = fixture_txs_under_first_beacon(
            &resolver,
            serde_json::from_str(UNCONFIRMED_FIXTURE).unwrap(),
        );
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

        // Unconfirmed pass: the same tx, now in the mempool, on its own. A needed
        // unconfirmed signal is not processed: no signal, no error.
        let json: serde_json::Value = serde_json::from_str(UNCONFIRMED_FIXTURE).unwrap();
        let mut first_tx = json["SingletonBeacon"][0].clone();
        first_tx["status"] = serde_json::json!({ "confirmed": false });
        let unconfirmed_txs = fixture_txs_under_first_beacon(
            &resolver,
            serde_json::json!({ "SingletonBeacon": [first_tx] }),
        );

        let signals = resolver
            .find_next_signals(unconfirmed_txs)
            .expect("an unconfirmed announcement is skipped, not an error");
        assert!(
            signals.is_empty(),
            "the needed-but-unconfirmed announcement yields no signal"
        );
    }

    /// The end-to-end shape of the same rule: v2 confirmed and v3 still in the
    /// mempool, both in the sidecar, resolve to version 2 — the confirmed
    /// history — rather than aborting on the pending announcement.
    #[test]
    fn pending_announcement_resolves_to_the_confirmed_version() {
        let (initial, update1, update2) = chained_two_updates();
        let tx_v2 = confirmed_signal_tx(update1.hash(), 100, 1_700_000_000, 0xa7);
        let tx_v3 = unconfirmed_signal_tx(update2.hash(), 0xa8);

        let sidecar = SidecarData::new(None, vec![update1, update2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let result = drive_to_resolved(resolver, vec![tx_v2, tx_v3]);

        assert_eq!(
            u64::from(result.document_metadata.version_id),
            2,
            "the confirmed v2 applies; the pending v3 is not processed and is not an error"
        );
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

        // Empty sidecar → the announced hash is not present in the lookup table, so
        // the unconfirmed tx is not a signal we are waiting on.
        let resolver = resolver_with(SidecarData::default(), None);
        let transactions = fixture_txs_under_first_beacon(&resolver, json);

        let signals = resolver
            .find_next_signals(transactions)
            .expect("an unconfirmed tx we hold no sidecar for is skipped, not an error");
        assert!(
            signals.is_empty(),
            "the sole unconfirmed beacon tx was skipped, so no signals are produced"
        );
    }

    /// Strict wire-signal boundary: a beacon tx whose LAST output is a
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
        let resolver = resolver_with(SidecarData::default(), Some(TEST_CHAIN_TIP));

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

        let transactions = HashMap::from([(
            first_beacon_address(&resolver).to_string(),
            vec![bad_tx, good_tx],
        )]);

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
    /// the RESOLVE-NN FSM tests below. The document is the in-repository copy
    /// of that vendor file at `19f8d424`, so this never skips: an absent copy
    /// is a failure.
    fn resolver_with(sidecar: SidecarData, chain_tip_height: Option<u32>) -> Resolver {
        let resolve_output = read_vendor_copy("regtest/k1/qgpakaw4/resolve/output.json");
        let did_document = resolve_output["didDocument"].to_string();
        let initial_document = InitialDocument::from_json_string(&did_document)
            .expect("regtest k1 qgpakaw4 resolved didDocument parses");

        let resolution_options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height,
            ..test_options()
        };
        Resolver::new(initial_document, resolution_options).expect("the options are valid")
    }

    /// The Esplora base every offline resolver test is built against. The
    /// resolver only ever formats request URIs from it; nothing is fetched.
    const TEST_ESPLORA_URL: &str = "http://esplora.test/api";

    /// The chain tip every offline resolver test measures confirmations
    /// against unless it pins its own. Far above every synthetic height (100
    /// to 700) and above the regtest fixture heights (2.2 million), so under
    /// the default `minConf` of six every confirmed signal in these tests is
    /// settled; the tests OF the gate pin a tip of their own.
    const TEST_CHAIN_TIP: u32 = 3_000_000;

    /// `ResolutionOptions` for an offline resolver test: the required Esplora
    /// base and a settled chain tip filled in, everything else default. Tests
    /// spread their own fields over it.
    fn test_options() -> ResolutionOptions {
        ResolutionOptions {
            esplora_url: Some(TEST_ESPLORA_URL.to_string()),
            chain_tip_height: Some(TEST_CHAIN_TIP),
            ..Default::default()
        }
    }

    /// The DID of the regtest k1 qgpakaw4 vector that `resolver_with` /
    /// `resolver_from_options` build over.
    const QGPAKAW4_DID: &str =
        "did:btcr2:k1qgpakaw4lwemekywf0lyth9hf6j8r2td7gqtrs4aztqfky50jnx7s8gfapup6";

    /// Drive a resolver to its terminal state with empty beacon-signal
    /// responses (no on-chain signals → resolves to the contemporary document).
    fn resolve_with_no_signals(resolver: Resolver) -> ResolutionResult {
        try_resolve_with_no_signals(resolver).expect("an empty-signal resolve succeeds")
    }

    /// Build a minimal Singleton-beacon resolver over the regtest k1 qgpakaw4
    /// resolved DID document with the given `ResolutionOptions`. Pure construction
    /// — no FSM stepping, no network. The document is the in-repository copy
    /// of that vendor file at `19f8d424`, so this never skips: an absent copy
    /// is a failure.
    fn resolver_from_options(resolution_options: ResolutionOptions) -> Resolver {
        let resolve_output = read_vendor_copy("regtest/k1/qgpakaw4/resolve/output.json");
        let did_document = resolve_output["didDocument"].to_string();
        let initial_document = InitialDocument::from_json_string(&did_document)
            .expect("regtest k1 qgpakaw4 resolved didDocument parses");
        Resolver::new(initial_document, resolution_options).expect("the options are valid")
    }

    /// `ResolutionOptions.esplora_url = Some(url)` overrides the resolver's
    /// request host; `Resolver::new` reads the caller-injected URL into
    /// `rpc_host`. Pure-construction, fully offline.
    #[test]
    fn esplora_url_some_overrides_rpc_host() {
        let url = "https://node.example/api".to_string();
        let resolver = resolver_from_options(ResolutionOptions {
            esplora_url: Some(url.clone()),
            ..test_options()
        });
        assert_eq!(resolver.rpc_host, url);
    }

    /// `esplora_url = None` is `INVALID_OPTIONS`: the resolver has no default
    /// endpoint, because a fallback to one chain would resolve a DID of
    /// another chain to its genesis document with no error. Pure-construction,
    /// fully offline.
    #[test]
    fn esplora_url_none_is_invalid_options() {
        let (_did, initial) = chain_initial_document();
        let err = Resolver::new(
            initial,
            ResolutionOptions {
                esplora_url: None,
                ..Default::default()
            },
        )
        .expect_err("a missing esplora_url must be rejected");
        let Btcr2Error::InvalidOptions(detail) = &err else {
            panic!("expected InvalidOptions, got {err:?}");
        };
        assert!(
            detail.contains("esplora_url is required"),
            "the detail names the missing option: {detail}"
        );
    }

    /// An `esplora_url` the request URIs cannot be formed from is
    /// `INVALID_OPTIONS` at construction, never a panic on the request path:
    /// a space in the host, a bare path with no scheme or host, and a query
    /// string are each rejected by name. A trailing slash is tolerated and
    /// dropped so the request paths carry no `//`.
    #[test]
    fn esplora_url_is_validated_at_construction() {
        let (_did, initial) = chain_initial_document();
        for (url, names) in [
            ("http://bad host/api", "is not a valid URI"),
            ("/api", "must be an absolute URI"),
            (
                "http://esplora.test/api?x=1",
                "must not carry a query string",
            ),
        ] {
            let err = Resolver::new(
                initial.clone(),
                ResolutionOptions {
                    esplora_url: Some(url.to_string()),
                    ..Default::default()
                },
            )
            .expect_err("an unusable esplora_url must be rejected");
            let Btcr2Error::InvalidOptions(detail) = &err else {
                panic!("expected InvalidOptions for `{url}`, got {err:?}");
            };
            assert!(
                detail.contains(url) && detail.contains(names),
                "`{url}`: the detail names the URL and the reason: {detail}"
            );
        }

        let resolver = Resolver::new(
            initial,
            ResolutionOptions {
                esplora_url: Some("http://esplora.test/api/".to_string()),
                ..Default::default()
            },
        )
        .expect("a trailing slash is tolerated");
        assert_eq!(resolver.rpc_host, "http://esplora.test/api");
        let ResolverState::Requests(_next, beacons) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        for req in beacons.values().flatten() {
            let uri = req.uri().to_string();
            assert!(
                uri.starts_with("http://esplora.test/api/address/") && !uri.contains("//address"),
                "the request URI is the base plus the path, got {uri}"
            );
        }
    }

    /// `versionId` and `versionTime` together are `INVALID_OPTIONS`, raised
    /// by `Resolver::new` before any beacon request is built; either one on
    /// its own is accepted. Pure construction, fully offline.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process" (raise
    /// `INVALID_OPTIONS` if both are provided; DID Resolution defines them as
    /// mutually exclusive).
    #[test]
    fn version_id_and_version_time_together_are_invalid_options() {
        use crate::error::ProblemDetails as _;

        let (_did, initial) = chain_initial_document();
        let err = Resolver::new(
            initial.clone(),
            ResolutionOptions {
                version_id: Some(NonZeroU64::new(2).expect("2 is non-zero")),
                version_time: Some(ts(1_700_000_000)),
                ..test_options()
            },
        )
        .expect_err("versionId and versionTime together must be rejected");
        let Btcr2Error::InvalidOptions(detail) = &err else {
            panic!("expected InvalidOptions, got {err:?}");
        };
        assert!(
            detail.contains("versionId") && detail.contains("versionTime"),
            "the detail names both options: {detail}"
        );
        assert_eq!(
            err.details()
                .expect("InvalidOptions yields problem details")["type"],
            "https://www.w3.org/ns/did#INVALID_OPTIONS"
        );

        // Each option alone is a valid resolution.
        Resolver::new(
            initial.clone(),
            ResolutionOptions {
                version_id: Some(NonZeroU64::new(2).expect("2 is non-zero")),
                ..test_options()
            },
        )
        .expect("versionId alone is valid");
        Resolver::new(
            initial,
            ResolutionOptions {
                version_time: Some(ts(1_700_000_000)),
                ..test_options()
            },
        )
        .expect("versionTime alone is valid");
    }

    /// With no `accept` option, `didResolutionMetadata.contentType` is
    /// `application/did`, the default representation.
    ///
    /// Spec: did-btcr2/src/data-structures.md "DID Resolution Metadata" (a
    /// resolver returning a bare DID document MUST use the media type
    /// `application/did`; `contentType` records the media type of the DID
    /// document itself).
    #[test]
    fn content_type_defaults_to_application_did_when_accept_is_unset() {
        let (_did, initial) = chain_initial_document();
        let resolver = Resolver::new(
            initial,
            ResolutionOptions {
                accept: None,
                ..test_options()
            },
        )
        .expect("options are valid");
        let result = drive_to_resolved(resolver, vec![]);
        assert_eq!(
            result.resolution_metadata.content_type.as_deref(),
            Some("application/did"),
            "data-structures.md: the default representation is application/did"
        );
    }

    /// A caller-supplied `accept` option is echoed as
    /// `didResolutionMetadata.contentType`.
    ///
    /// Spec: did-btcr2/src/data-structures.md "DID Resolution Metadata"
    /// (`contentType` records the media type of the DID document itself) and
    /// "DID Resolution Options" (`accept`, the caller's preferred media type).
    #[test]
    fn content_type_echoes_the_accept_option() {
        let (_did, initial) = chain_initial_document();
        let resolver = Resolver::new(
            initial,
            ResolutionOptions {
                accept: Some("application/did+ld+json".to_string()),
                ..test_options()
            },
        )
        .expect("options are valid");
        let result = drive_to_resolved(resolver, vec![]);
        assert_eq!(
            result.resolution_metadata.content_type.as_deref(),
            Some("application/did+ld+json"),
            "data-structures.md: contentType records the requested media type"
        );
    }

    /// The same rejection reaches a `Document::resolve` caller as the
    /// document-level error wrapping `INVALID_OPTIONS`.
    #[test]
    fn document_resolve_surfaces_invalid_options() {
        let (did, _initial) = chain_initial_document();
        let err = Document::resolve(
            &did,
            ResolutionOptions {
                version_id: Some(NonZeroU64::MIN),
                version_time: Some(ts(1_700_000_000)),
                ..test_options()
            },
        )
        .expect_err("versionId and versionTime together must be rejected");
        assert!(
            matches!(
                err,
                crate::document::Error::Btcr2Error(Btcr2Error::InvalidOptions(_))
            ),
            "expected InvalidOptions, got {err:?}"
        );
    }

    /// A spec-form sidecar JSON deserializes into `SidecarData`;
    /// `update_lookup_table` contains one entry per spec-form update, keyed by
    /// the JSON Document Hash (`Update::hash()`).
    ///
    /// Spec: did-btcr2/src/operations/resolve.md §Process Sidecar Data lines 69-74
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
    /// (targetVersionId, block_height) sort (resolve.md:180-185), and that choice
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
        let resolver = resolver_with(sidecar, None);
        let signal_hi = NextSignal {
            beacon_type: BeaconType::Singleton,
            beacon_address: first_beacon_address(&resolver),
            signal_bytes: update_hi.hash(),
            block_time: Utc::now(),
            block_height: 50,
            block_hash: zero_block_hash(),
        };
        let signal_lo = NextSignal {
            beacon_type: BeaconType::Singleton,
            beacon_address: first_beacon_address(&resolver),
            signal_bytes: update_lo.hash(),
            block_time: Utc::now(),
            block_height: 100,
            block_hash: zero_block_hash(),
        };
        let expected_first = (update_lo.target_version_id, 100u32);

        for _ in 0..8 {
            // Rebuild the NextSignal inputs each iteration in the reversed
            // (hi, lo) construction order.
            let next_signals = vec![
                NextSignal {
                    beacon_type: signal_hi.beacon_type,
                    beacon_address: signal_hi.beacon_address.clone(),
                    signal_bytes: signal_hi.signal_bytes,
                    block_time: signal_hi.block_time,
                    block_height: signal_hi.block_height,
                    block_hash: signal_hi.block_hash,
                },
                NextSignal {
                    beacon_type: signal_lo.beacon_type,
                    beacon_address: signal_lo.beacon_address.clone(),
                    signal_bytes: signal_lo.signal_bytes,
                    block_time: signal_lo.block_time,
                    block_height: signal_lo.block_height,
                    block_hash: signal_lo.block_hash,
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
    /// Spec: did-btcr2/src/operations/resolve.md lines 48-57 (return signature).
    #[test]
    fn resolve_returns_the_resolution_triple() {
        let resolver = resolver_with(SidecarData::default(), None);
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

    /// A never-updated DID resolved with a chain tip reports `confirmations:
    /// 0` on the wire — present, as the spec requires — not an omitted key.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process" (`block_confirmations`
    /// starts at `0`; `confirmations` is REQUIRED in `didDocumentMetadata`).
    #[test]
    fn genesis_resolve_with_a_tip_reports_zero_confirmations() {
        let resolver = resolver_with(SidecarData::default(), Some(TEST_CHAIN_TIP));
        let result = resolve_with_no_signals(resolver);
        assert_eq!(result.document_metadata.confirmations, Some(0));
        let json =
            serde_json::to_string(&result.document_metadata).expect("document metadata serializes");
        assert!(
            json.contains(r#""confirmations":0"#),
            "confirmations is emitted as 0, not omitted: {json}"
        );
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
        let resolver = resolver_with(SidecarData::default(), None);
        let result = resolve_with_no_signals(resolver);
        let json =
            serde_json::to_string(&result.document_metadata).expect("document metadata serializes");
        // version_id == 1 for an un-updated document; must be the ASCII string "1".
        assert!(
            json.contains(r#""versionId":"1""#),
            "resolver-produced versionId must serialize as ASCII string, got: {json}"
        );
    }

    /// `confirmations == tip - current_block_height + 1` with
    /// saturating arithmetic (tip > h, tip == h, tip < h), `0` when the tip is
    /// known but nothing applied, and `None` without a tip. This exercises only `terminal_state`'s formatting
    /// of `current_block_height`, which is unchanged; the *accounting* of that
    /// height (most-recently-applied unique update, not a running min across
    /// distinct updates) is driven end-to-end by
    /// `confirmations_use_the_most_recently_applied_update` and
    /// `later_duplicate_does_not_raise_confirmations`.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:38,58.
    #[test]
    fn metadata_confirmations_saturate_against_chain_tip() {
        // terminal_state computes confirmations from chain_tip_height +
        // current_block_height. Drive the field directly to cover the three
        // arithmetic regimes plus the no-tip case.
        let mut resolver = resolver_with(SidecarData::default(), Some(100));

        // tip > h: 100 - 90 + 1 = 11.
        resolver.current_block_height = Some(90);
        assert_eq!(
            resolver.terminal_state().document_metadata.confirmations,
            Some(11)
        );

        // tip == h: 100 - 100 + 1 = 1.
        resolver.current_block_height = Some(100);
        assert_eq!(
            resolver.terminal_state().document_metadata.confirmations,
            Some(1)
        );

        // tip < h (clock skew / indexer lag): saturating → 0 + 1 = 1.
        resolver.current_block_height = Some(150);
        assert_eq!(
            resolver.terminal_state().document_metadata.confirmations,
            Some(1)
        );

        // Tip known, no applied update → confirmations 0: the spec's starting
        // value, and REQUIRED in the metadata, so it is emitted rather than
        // omitted.
        resolver.current_block_height = None;
        assert_eq!(
            resolver.terminal_state().document_metadata.confirmations,
            Some(0)
        );

        // No chain tip → confirmations None even with an applied height.
        let mut no_tip = resolver_with(SidecarData::default(), None);
        no_tip.current_block_height = Some(90);
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

    /// The key-based DID derived from `CHAIN_SECRET_KEY_BYTES` and the initial
    /// document it deterministically generates — three Singleton beacons
    /// (P2PKH, P2WPKH, P2TR) over a mutinynet identifier.
    fn chain_initial_document() -> (crate::identifier::Did, InitialDocument) {
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

        (did, initial)
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

        let (did, initial) = chain_initial_document();
        let document = Document::from(initial.clone());
        let vm_id = format!("{}#initialKey", did.encode());

        let v2 = NonZeroU64::new(2).expect("2 is non-zero");
        let update1 = document
            .construct_signed_update(chain_benign_patch(&vm_id), v2, &vm_id, chain_secret_key())
            .expect("update #1 constructs against the initial document");

        let mut after1 = initial.clone();
        after1
            .apply_update(&update1, &AnnouncingBlock::fixed())
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
        confirmed_signal_tx_in_block(
            signal,
            block_height,
            block_time,
            &"00".repeat(32),
            txid_seed,
        )
    }

    /// A Singleton-beacon esplora transaction announcing `signal` that is
    /// still in the mempool (`status.confirmed == false`).
    fn unconfirmed_signal_tx(signal: Sha256Hash, txid_seed: u8) -> Transaction {
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
            "status": { "confirmed": false },
        });
        serde_json::from_value(json)
            .expect("synthetic unconfirmed esplora transaction deserializes")
    }

    /// `confirmed_signal_tx` with the confirming block's hash chosen by the
    /// caller, for tests that need signals in distinct blocks.
    fn confirmed_signal_tx_in_block(
        signal: Sha256Hash,
        block_height: u32,
        block_time: i64,
        block_hash_hex: &str,
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
                "block_hash": block_hash_hex,
                "block_time": block_time,
            },
        });
        serde_json::from_value(json).expect("synthetic esplora transaction JSON deserializes")
    }

    /// A `DateTime<Utc>` from a unix timestamp (seconds).
    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("in-range unix timestamp")
    }

    /// The all-zero block hash every synthetic confirmed status carries
    /// (`confirmed_signal_tx`).
    fn zero_block_hash() -> BlockHash {
        "00".repeat(32)
            .parse()
            .expect("64 hex zeros parse as a block hash")
    }

    /// Header timestamp of the synthetic block that confirms the `expires`
    /// signal in the block-mediantime tests.
    const HEADER_TIME: i64 = 1_700_000_000;
    /// `expires` an hour after the header time.
    const EXPIRES: i64 = 1_700_003_600;

    /// A v2 update against `chain_initial_document` whose proof carries
    /// `expires` (= `EXPIRES`) and no `created`, with the sidecar holding it and
    /// the confirmed Singleton signal announcing it at `HEADER_TIME`.
    fn update_with_expires() -> (InitialDocument, Update, Transaction) {
        let (did, initial) = chain_initial_document();
        let document = Document::from(initial.clone());
        let vm_id = format!("{}#initialKey", did.encode());
        let update = signed_update_with_expires(
            &document,
            &did,
            &vm_id,
            &chain_benign_patch(&vm_id),
            NonZeroU64::new(2).expect("2 is non-zero"),
        );
        let tx = confirmed_signal_tx(update.hash(), 100, HEADER_TIME, 0xd1);
        (initial, update, tx)
    }

    /// Sign `patch` against `document` targeting `target`, with the proof
    /// carrying `expires` (= `EXPIRES`) and no `created`.
    fn signed_update_with_expires(
        document: &Document,
        did: &crate::identifier::Did,
        vm_id: &str,
        patch: &json_patch::Patch,
        target: NonZeroU64,
    ) -> Update {
        let (unsigned, _, _) = document
            .construct_unsigned_update(patch, target)
            .expect("update constructs against the given document");
        crate::test_signing::sign_unsigned_update_for_test(
            &unsigned,
            did,
            vm_id,
            &chain_secret_key(),
            None,
            Some(ts(EXPIRES)),
        )
    }

    /// Drive `update_with_expires` from Init through the first signal round and
    /// return the `BlockRequests` the resolver must raise for it.
    fn drive_to_block_requests() -> (Resolver<WaitingForBlockTimes>, Vec<esploda::Req>) {
        let (initial, update, tx) = update_with_expires();
        drive_first_round_to_block_requests(initial, vec![update], tx)
    }

    /// Drive `initial` (with `sidecar_updates` as the sidecar) from Init through
    /// a first signal round carrying `tx` and return the `BlockRequests` the
    /// resolver must raise for it. The sidecar is fixed at `Resolver::new`, so
    /// every update a later round will announce must already be in it.
    fn drive_first_round_to_block_requests(
        initial: InitialDocument,
        sidecar_updates: Vec<Update>,
        tx: Transaction,
    ) -> (Resolver<WaitingForBlockTimes>, Vec<esploda::Req>) {
        let sidecar = SidecarData::new(None, sidecar_updates, None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        assert!(
            resolver.block_mediantimes.is_empty(),
            "a fresh resolver holds no block mediantimes"
        );

        let ResolverState::Requests(next_state, requests) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        let transactions = history_under_first_request(&requests, vec![tx]);
        match next_state
            .process_responses(transactions)
            .resolve()
            .expect("a proof carrying expires asks for the block, not an error")
        {
            ResolverState::BlockRequests(next, requests) => (next, requests),
            other => panic!("expected BlockRequests for a proof carrying expires, got {other:?}"),
        }
    }

    /// Drive a post-`process_block_times` resolver to its terminal state with
    /// empty beacon rounds; a second block request is a test failure.
    fn drive_after_block_times(resolver: Resolver) -> Result<ResolutionResult, Error> {
        let mut state = resolver.resolve()?;
        loop {
            match state {
                ResolverState::Resolved(result) => break Ok(result),
                ResolverState::Requests(next, _requests) => {
                    state = next.process_responses(HashMap::new()).resolve()?;
                }
                ResolverState::BlockRequests(..) => {
                    panic!("the resolver asked for a block it was already given")
                }
            }
        }
    }

    /// Answer the first-round block request for the all-zero block with a
    /// mediantime `expires` is not before, and step the resolver once: the v2
    /// apply happens and the FSM asks for the next beacon round, whose
    /// requests are returned so the answer can be keyed by their address.
    fn answer_first_block_and_expect_next_round(
        next: Resolver<WaitingForBlockTimes>,
    ) -> (
        Resolver<WaitingForResponses>,
        HashMap<BeaconType, Vec<esploda::Req>>,
    ) {
        let mut mediantimes = HashMap::new();
        mediantimes.insert(zero_block_hash(), ts(HEADER_TIME - 3600));
        match next
            .process_block_times(mediantimes)
            .resolve()
            .expect("the first-round update applies once its block time is known")
        {
            ResolverState::Requests(next, requests) => (next, requests),
            other => panic!("expected the next beacon round after the first apply, got {other:?}"),
        }
    }

    /// A v2 update whose proof carries `expires` AND appends the rotated
    /// beacon, with its confirmed Singleton signal at `HEADER_TIME` in the
    /// all-zero block. The beacon-set change is what gives the resolver a
    /// second beacon round to announce more signals in; a benign v2 would
    /// resolve straight after round 1 (every address is queried once).
    fn rotating_update_with_expires()
    -> (crate::identifier::Did, InitialDocument, Update, Transaction) {
        let (did, initial) = chain_initial_document();
        let document = Document::from(initial.clone());
        let vm_id = format!("{}#initialKey", did.encode());
        let update = signed_update_with_expires(
            &document,
            &did,
            &vm_id,
            &chain_beacon_rotation_patch(&did),
            NonZeroU64::new(2).expect("2 is non-zero"),
        );
        let tx = confirmed_signal_tx(update.hash(), 100, HEADER_TIME, 0xd1);
        (did, initial, update, tx)
    }

    /// A duplicate announcement of an already-applied update never costs a
    /// block request, even when its proof carries `expires`: a signal with
    /// `targetVersionId <= current_version_id` only runs the duplicate check
    /// and never reads the block time, so there is nothing to fetch.
    ///
    /// The duplicate sits in a DIFFERENT block from the first announcement: a
    /// same-block duplicate would pass vacuously because the resolver already
    /// holds that block's mediantime from round 1.
    #[test]
    fn resolver_never_requests_blocks_for_duplicate_announcements() {
        let (_did, initial, update, tx) = rotating_update_with_expires();
        let (next, requests) =
            drive_first_round_to_block_requests(initial, vec![update.clone()], tx);
        assert_eq!(
            requests.len(),
            1,
            "round 1: one confirming block, one request"
        );
        let (next, requests) = answer_first_block_and_expect_next_round(next);

        let duplicate = confirmed_signal_tx_in_block(
            update.hash(),
            105,
            HEADER_TIME + 600,
            &"11".repeat(32),
            0xd2,
        );
        let transactions = history_under_first_request(&requests, vec![duplicate]);
        let result = match next
            .process_responses(transactions)
            .resolve()
            .expect("a duplicate announcement is not an error")
        {
            ResolverState::Resolved(result) => result,
            ResolverState::Requests(next, _requests) => {
                drive_after_block_times(next.process_responses(HashMap::new()))
                    .expect("empty rounds resolve")
            }
            other @ ResolverState::BlockRequests(..) => {
                panic!("a duplicate announcement must not ask for its block, got {other:?}")
            }
        };
        assert_eq!(result.document_metadata.version_id.get(), 2);
    }

    /// A round mixing a duplicate announcement (already applied v2, block
    /// `11..11`) with an applicable v3 update whose proof carries `expires`
    /// (block `22..22`) asks for exactly ONE block — the applicable signal's —
    /// and, once answered, applies v3.
    #[test]
    fn resolver_requests_only_the_applicable_block_in_a_mixed_round() {
        let (did, initial, update1, tx1) = rotating_update_with_expires();
        let vm_id = format!("{}#initialKey", did.encode());

        let mut after1 = initial.clone();
        after1
            .apply_update(&update1, &AnnouncingBlock::fixed())
            .expect("update #1 applies to the initial document");
        let update2 = signed_update_with_expires(
            &Document::from(after1),
            &did,
            &vm_id,
            &chain_benign_patch(&vm_id),
            NonZeroU64::new(3).expect("3 is non-zero"),
        );

        let (next, requests) = drive_first_round_to_block_requests(
            initial,
            vec![update1.clone(), update2.clone()],
            tx1,
        );
        assert_eq!(
            requests.len(),
            1,
            "round 1: one confirming block, one request"
        );
        let (next, requests) = answer_first_block_and_expect_next_round(next);

        let duplicate = confirmed_signal_tx_in_block(
            update1.hash(),
            105,
            HEADER_TIME + 600,
            &"11".repeat(32),
            0xd3,
        );
        let applicable = confirmed_signal_tx_in_block(
            update2.hash(),
            106,
            HEADER_TIME + 1200,
            &"22".repeat(32),
            0xd4,
        );
        let transactions = history_under_first_request(&requests, vec![duplicate, applicable]);
        let (next, requests) = match next
            .process_responses(transactions)
            .resolve()
            .expect("an applicable proof carrying expires asks for its block")
        {
            ResolverState::BlockRequests(next, requests) => (next, requests),
            other => panic!("expected BlockRequests for the applicable signal, got {other:?}"),
        };
        assert_eq!(
            requests.len(),
            1,
            "only the applicable signal's block is requested, got {:?}",
            requests
                .iter()
                .map(|r| r.uri().path().to_string())
                .collect::<Vec<_>>()
        );
        let path = requests[0].uri().path().to_string();
        assert!(
            path.ends_with(&format!("/block/{}", "22".repeat(32))),
            "the request is for the applicable signal's block, got {path}"
        );

        let block_22: BlockHash = "22"
            .repeat(32)
            .parse()
            .expect("64 hex digits parse as a block hash");
        let mut mediantimes = HashMap::new();
        mediantimes.insert(block_22, ts(HEADER_TIME - 3600));
        let result = drive_after_block_times(next.process_block_times(mediantimes))
            .expect("expires after the mediantime applies");
        assert_eq!(result.document_metadata.version_id.get(), 3);
    }

    /// A sidecar update whose proof carries `expires` makes the resolver ask
    /// for the confirming block's mediantime — one `GET /block/{hash}` — and,
    /// once given a mediantime `expires` is not before, applies the update.
    #[test]
    fn resolver_requests_block_mediantime_when_a_proof_carries_expires() {
        let (next, requests) = drive_to_block_requests();
        assert_eq!(requests.len(), 1, "one confirming block, one request");
        let path = requests[0].uri().path().to_string();
        assert!(
            path.ends_with(
                "/block/0000000000000000000000000000000000000000000000000000000000000000"
            ),
            "the request is GET /block/{{hash}} for the confirming block, got {path}"
        );

        let mut mediantimes = HashMap::new();
        mediantimes.insert(zero_block_hash(), ts(HEADER_TIME - 3600));
        let result = drive_after_block_times(next.process_block_times(mediantimes))
            .expect("expires after the mediantime applies");
        assert_eq!(result.document_metadata.version_id.get(), 2);
    }

    /// The fetched mediantime is what `expires` is checked against: a
    /// mediantime after `expires` rejects the update as INVALID_DID_UPDATE.
    #[test]
    fn resolver_rejects_expires_before_the_fetched_mediantime() {
        let (next, _requests) = drive_to_block_requests();
        let mut mediantimes = HashMap::new();
        mediantimes.insert(zero_block_hash(), ts(EXPIRES + 1));
        let err = drive_after_block_times(next.process_block_times(mediantimes))
            .expect_err("expires before the mediantime must be rejected");
        match err {
            Error::Btcr2Error(Btcr2Error::InvalidDidUpdate(msg)) => assert!(
                msg.contains("expires is before the announcing block"),
                "unexpected rejection message: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// Answering the block round without the requested block is a typed
    /// error naming the block, not an apply and not a second request.
    #[test]
    fn resolver_errors_when_the_requested_mediantime_is_not_supplied() {
        let (next, _requests) = drive_to_block_requests();
        let err = next
            .process_block_times(HashMap::new())
            .resolve()
            .expect_err("a withheld mediantime must not apply the update");
        match &err {
            Error::MissingBlockMediantime { block_hash } => {
                assert_eq!(*block_hash, zero_block_hash());
            }
            other => panic!("expected MissingBlockMediantime, got {other:?}"),
        }
        // A driver precondition, not a judgement of the update: it carries no
        // spec problem-details body, so it can never be reported as
        // INVALID_DID_UPDATE.
        assert!(
            err.details().is_none(),
            "a missing mediantime is a driver error with no spec code, got {:?}",
            err.details()
        );
        assert!(
            err.to_string().contains(&zero_block_hash().to_string()),
            "the message names the block that was not supplied: {err}"
        );
    }

    /// The spec-level outcomes of a walk keep their problem-details bodies:
    /// the pass-through and the late-publishing sentinel both render the
    /// registered `LATE_PUBLISHING` type.
    #[test]
    fn walk_errors_carry_their_spec_problem_details() {
        let sentinel = Error::LatePublishingError;
        assert_eq!(
            sentinel.details().expect("late publishing has a body")["type"]
                .as_str()
                .and_then(|t| t.rsplit('#').next()),
            Some("LATE_PUBLISHING")
        );
        let passthrough = Error::Btcr2Error(Btcr2Error::MissingUpdateData {
            update_hash: Sha256Hash::from([0u8; 32]),
        });
        assert_eq!(
            passthrough.details().expect("a spec error has a body")["type"]
                .as_str()
                .and_then(|t| t.rsplit('#').next()),
            Some("MISSING_UPDATE_DATA")
        );
    }

    /// Updates whose proofs carry no `expires` never trigger a block request:
    /// the chained two-update drive still reaches version 3 through
    /// `Requests` rounds only (the `BlockRequests` arm in `drive_to_resolved`
    /// panics).
    #[test]
    fn resolver_never_requests_blocks_without_expires() {
        let (initial, update1, update2) = chained_two_updates();
        let tx1 = confirmed_signal_tx(update1.hash(), 100, HEADER_TIME, 0xe1);
        let tx2 = confirmed_signal_tx(update2.hash(), 101, HEADER_TIME + 600, 0xe2);
        let sidecar = SidecarData::new(None, vec![update1, update2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        assert!(resolver.block_mediantimes.is_empty());

        let result = drive_to_resolved(resolver, vec![tx1, tx2]);
        assert_eq!(result.document_metadata.version_id.get(), 3);
    }

    /// Extract the block hash from a `/block/{hash}` request path. The hash is
    /// the routing key into [`ChainFixture::blocks`], for the same reason
    /// [`address_from_txs_uri`] keys on the address.
    fn block_hash_from_block_uri(uri: &esploda::http::Uri) -> &str {
        let path = uri.path();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let n = segments.len();
        if n >= 2 && segments[n - 2] == "block" {
            segments[n - 1]
        } else {
            panic!(
                "the resolver requested `{path}`, which is not a `/block/{{hash}}` endpoint. \
                 The capture harness routes block requests on the hash in that path."
            )
        }
    }

    /// Parse a captured `/block/{hash}` body the way the client does: the
    /// `id` field is the key, `mediantime` the value.
    fn block_mediantime_from_fixture_body(body: &serde_json::Value) -> (BlockHash, DateTime<Utc>) {
        let block_hash: BlockHash = body["id"]
            .as_str()
            .expect("a captured block body carries a string `id`")
            .parse()
            .expect("a captured block body's `id` is a hex block hash");
        let mediantime = ts(body["mediantime"]
            .as_i64()
            .expect("a captured block body carries an integer `mediantime`"));
        (block_hash, mediantime)
    }

    /// How many request rounds a captured replay may take before it is treated
    /// as non-terminating. Three is already more than any committed scenario
    /// needs (a genesis round plus one per beacon rotation); eight leaves room
    /// without letting a resolver that never converges hang the test run.
    const CAPTURE_ROUND_BOUND: usize = 8;

    /// Drive the FSM to a terminal state, serving every request from `fixture`,
    /// and return the address set requested in EACH round, in round order.
    ///
    /// Mirrors `did_btcr2_client::Client::resolve` exactly: read the requests
    /// out of `ResolverState::Requests`, serve each one, feed the results back
    /// keyed by the address each request named. The ONE difference is where
    /// the bytes come from.
    ///
    /// The round log is built here rather than bolted on later because it is how
    /// the deactivation short-circuit becomes OBSERVABLE: "process no further
    /// beacon signals" is a claim about a request that must NOT be made, and
    /// only a record of what WAS requested can check it. Returning it costs
    /// nothing for callers that ignore it.
    fn drive_capture_rounds(
        resolver: Resolver,
        fixture: &ChainFixture,
        id: &str,
    ) -> (Result<ResolutionResult, Error>, Vec<Vec<String>>) {
        drive_capture_within(resolver, fixture, id, CAPTURE_ROUND_BOUND)
    }

    /// [`drive_capture_rounds`] with the round bound spelled out, so the
    /// non-termination guard can be exercised without minting eight chained
    /// beacon rotations to reach the real bound.
    fn drive_capture_within(
        resolver: Resolver,
        fixture: &ChainFixture,
        id: &str,
        max_rounds: usize,
    ) -> (Result<ResolutionResult, Error>, Vec<Vec<String>>) {
        let mut rounds: Vec<Vec<String>> = Vec::new();
        let mut state = match resolver.resolve() {
            Ok(state) => state,
            Err(e) => return (Err(e), rounds),
        };

        loop {
            let (next_state, beacons) = match state {
                ResolverState::Resolved(result) => return (Ok(result), rounds),
                ResolverState::Requests(next_state, beacons) => (next_state, beacons),
                ResolverState::BlockRequests(next_state, requests) => {
                    // An update proof carries `expires`: serve each
                    // `/block/{hash}` body from the fixture's `blocks` map,
                    // keyed by the body's own `id` the way the client does.
                    let mut requested: Vec<String> = Vec::new();
                    let mut mediantimes: HashMap<BlockHash, DateTime<Utc>> = HashMap::new();
                    for req in &requests {
                        let hash = block_hash_from_block_uri(req.uri());
                        requested.push(format!("block/{hash}"));
                        let body = fixture.blocks.get(hash).unwrap_or_else(|| {
                            panic!(
                                "{id}: the resolver asked for block {hash} (an update proof \
                                 carries `expires`) but the fixture holds no `/block/{hash}` \
                                 body; re-run capture — `cargo run -p chain-capture -- capture \
                                 --network {} --vector {id}`. Rounds so far: {rounds:?}",
                                fixture.network
                            )
                        });
                        let (block_hash, mediantime) = block_mediantime_from_fixture_body(body);
                        mediantimes.insert(block_hash, mediantime);
                    }
                    rounds.push(requested);
                    state = match next_state.process_block_times(mediantimes).resolve() {
                        Ok(state) => state,
                        Err(e) => return (Err(e), rounds),
                    };
                    continue;
                }
            };

            if rounds.len() >= max_rounds {
                panic!(
                    "{id}: the resolver was still requesting beacon signals after \
                     {max_rounds} round(s) and has not converged. Rounds so far: {rounds:?}"
                );
            }

            // Logged BEFORE anything is served, so the unrouted-address panic
            // below can print what this round asked for.
            let requested: Vec<String> = beacons
                .values()
                .flatten()
                .map(|req| address_from_txs_uri(req.uri()).to_string())
                .collect();
            rounds.push(requested);

            let mut responses: HashMap<String, Vec<Transaction>> = HashMap::new();
            for req in beacons.into_values().flatten() {
                let address = address_from_txs_uri(req.uri());
                let txs = fixture.addresses.get(address).unwrap_or_else(|| {
                    panic!(
                        "{id}: no captured response for address {address}; re-run capture \
                         or add the address — `cargo run -p chain-capture -- capture \
                         --network {} --vector {id}`. Rounds so far: {rounds:?}",
                        fixture.network
                    )
                });
                // A key present with an empty list IS a captured state and
                // is served as zero transactions; only an ABSENT key is a
                // failure, which is why the lookup above does not default.
                responses
                    .entry(address.to_string())
                    .or_default()
                    .extend(txs.iter().cloned());
            }

            state = match next_state.process_responses(responses).resolve() {
                Ok(state) => state,
                Err(e) => return (Err(e), rounds),
            };
        }
    }

    /// Drive to a terminal state, discarding the round log.
    ///
    /// Thin wrapper over [`drive_capture_rounds`] for the callers that only need
    /// the result.
    fn drive_to_resolved_from_capture(
        resolver: Resolver,
        fixture: &ChainFixture,
        id: &str,
    ) -> Result<ResolutionResult, Error> {
        drive_capture_rounds(resolver, fixture, id).0
    }

    /// Drive a resolver FSM to its terminal state over a single batch of
    /// Singleton-beacon transactions, mirroring `resolve_with_no_signals`'s
    /// drive-to-terminal shape and surfacing any FSM error to the caller.
    fn try_drive_to_resolved(
        resolver: Resolver,
        txs: Vec<Transaction>,
    ) -> Result<ResolutionResult, Error> {
        let ResolverState::Requests(next_state, requests) = resolver.resolve()? else {
            panic!("expected Requests from Init step");
        };
        let transactions = history_under_first_request(&requests, txs);
        let mut state = next_state.process_responses(transactions).resolve()?;
        loop {
            match state {
                ResolverState::Resolved(result) => break Ok(result),
                ResolverState::Requests(next, _requests) => {
                    state = next.process_responses(HashMap::new()).resolve()?;
                }
                ResolverState::BlockRequests(..) => {
                    panic!("unexpected block request: no update in this test carries proof.expires")
                }
            }
        }
    }

    /// [`try_drive_to_resolved`] for the callers that expect success.
    fn drive_to_resolved(resolver: Resolver, txs: Vec<Transaction>) -> ResolutionResult {
        try_drive_to_resolved(resolver, txs)
            .expect("the resolver reaches a terminal state without error")
    }

    /// Guard (Task 1 anti-vacuity): the in-memory chain's FIRST update's
    /// `source_hash` equals the locally-constructed initial document's `hash()`.
    /// This is what makes the apply loop actually APPLY update1 rather than
    /// reject it at the sourceHash check (resolve.md "Apply update" step 1) — the
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

    /// A block hash from a repeated byte, for tests that need signals in
    /// distinct blocks.
    fn block_hash_of(byte: u8) -> BlockHash {
        format!("{byte:02x}")
            .repeat(32)
            .parse()
            .expect("64 hex digits parse as a block hash")
    }

    /// Drive a resolver to its terminal state over one batch of
    /// Singleton-beacon transactions, answering every block request from
    /// `mediantimes` (a block the map does not hold is a test failure) and
    /// returning the block hashes that were requested alongside the result.
    fn try_drive_serving_blocks(
        resolver: Resolver,
        txs: Vec<Transaction>,
        mediantimes: &HashMap<BlockHash, DateTime<Utc>>,
    ) -> (Result<ResolutionResult, Error>, Vec<BlockHash>) {
        let mut requested = Vec::new();
        let mut state = match resolver.resolve() {
            Ok(state) => state,
            Err(e) => return (Err(e), requested),
        };
        let mut first_round = Some(txs);
        loop {
            state = match state {
                ResolverState::Resolved(result) => return (Ok(result), requested),
                ResolverState::Requests(next, requests) => {
                    let transactions = match first_round.take() {
                        Some(txs) => history_under_first_request(&requests, txs),
                        None => HashMap::new(),
                    };
                    match next.process_responses(transactions).resolve() {
                        Ok(state) => state,
                        Err(e) => return (Err(e), requested),
                    }
                }
                ResolverState::BlockRequests(next, requests) => {
                    let mut answers = HashMap::new();
                    for req in &requests {
                        let hash: BlockHash = block_hash_from_block_uri(req.uri())
                            .parse()
                            .expect("the request path carries a block hash");
                        let mediantime = *mediantimes.get(&hash).unwrap_or_else(|| {
                            panic!(
                                "the resolver asked for block {hash}, which this test did not stage"
                            )
                        });
                        requested.push(hash);
                        answers.insert(hash, mediantime);
                    }
                    match next.process_block_times(answers).resolve() {
                        Ok(state) => state,
                        Err(e) => return (Err(e), requested),
                    }
                }
            };
        }
    }

    /// A resolution whose `versionTime` falls mid-batch returns the version
    /// in EFFECT at that time, not the batch's final version. Two chained
    /// updates arrive (v2 in block `aa`, v3 in block `bb`) with `mediantime(aa)
    /// < versionTime < mediantime(bb)`; the resolved document is v2, NOT v3.
    /// The per-tuple versionTime check on every tuple above the current
    /// version aborts before applying v3.
    ///
    /// The header timestamps are set the OTHER way round — `aa` after
    /// versionTime, `bb` before it — so a comparison against the header time
    /// would return v3 (or v1). Only the mediantime rule yields v2.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 5
    /// and footnote 5 (the tuple's block `mediantime` is after `versionTime`).
    #[test]
    fn version_time_mid_batch_returns_the_version_in_effect() {
        let (initial, update1, update2) = chained_two_updates();
        let version_time = 1_700_000_100i64;

        let tx_v2 = confirmed_signal_tx_in_block(
            update1.hash(),
            100,
            version_time + 500,
            &"aa".repeat(32),
            0xa1,
        );
        let tx_v3 = confirmed_signal_tx_in_block(
            update2.hash(),
            200,
            version_time - 500,
            &"bb".repeat(32),
            0xa2,
        );
        let mediantimes = HashMap::from([
            (block_hash_of(0xaa), ts(version_time - 100)),
            (block_hash_of(0xbb), ts(version_time + 100)),
        ]);

        let sidecar = SidecarData::new(None, vec![update1, update2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(version_time)),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, requested) =
            try_drive_serving_blocks(resolver, vec![tx_v2, tx_v3], &mediantimes);
        let result = result.expect("the walk resolves");

        assert_eq!(
            u64::from(result.document_metadata.version_id),
            2,
            "mid-batch versionTime must resolve to the in-effect version (v2) by mediantime, not v3"
        );
        let mut requested = requested;
        requested.sort();
        assert_eq!(
            requested,
            vec![block_hash_of(0xaa), block_hash_of(0xbb)],
            "a versionTime bound asks for every applicable signal's block, once"
        );
    }

    /// An update whose block `mediantime` EQUALS `versionTime` applies: the
    /// comparison has no tolerance and equal is not "after".
    #[test]
    fn version_time_equal_to_the_mediantime_applies_the_update() {
        let (initial, update1, _update2) = chained_two_updates();
        let version_time = 1_700_000_100i64;
        let tx = confirmed_signal_tx_in_block(
            update1.hash(),
            100,
            version_time + 3600,
            &"aa".repeat(32),
            0xa3,
        );
        let mediantimes = HashMap::from([(block_hash_of(0xaa), ts(version_time))]);

        let sidecar = SidecarData::new(None, vec![update1], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(version_time)),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, _) = try_drive_serving_blocks(resolver, vec![tx], &mediantimes);
        assert_eq!(
            u64::from(
                result
                    .expect("the walk resolves")
                    .document_metadata
                    .version_id
            ),
            2,
            "a mediantime equal to versionTime is not after it: the update applies"
        );
    }

    /// Under a `versionTime` bound the block is required even when no proof
    /// carries `expires`: withholding it is the typed driver error, not an
    /// apply that skipped the bound and not a silent stop.
    #[test]
    fn version_time_bound_requires_the_block_mediantime() {
        let (initial, update1, _update2) = chained_two_updates();
        let tx = confirmed_signal_tx_in_block(
            update1.hash(),
            100,
            1_700_000_000,
            &"aa".repeat(32),
            0xa4,
        );
        let sidecar = SidecarData::new(None, vec![update1], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(1_700_000_100)),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");

        let ResolverState::Requests(next, requests) = resolver.resolve().expect("Init step") else {
            panic!("expected Requests from Init step");
        };
        let transactions = history_under_first_request(&requests, vec![tx]);
        let ResolverState::BlockRequests(next, requests) = next
            .process_responses(transactions)
            .resolve()
            .expect("a versionTime bound asks for the block")
        else {
            panic!("expected BlockRequests under a versionTime bound");
        };
        assert_eq!(requests.len(), 1);

        let err = next
            .process_block_times(HashMap::new())
            .resolve()
            .expect_err("a withheld mediantime must not apply the update");
        assert!(
            matches!(err, Error::MissingBlockMediantime { block_hash } if block_hash == block_hash_of(0xaa)),
            "got {err:?}"
        );
    }

    /// Ordering fold-in: a DUPLICATE announcement of v2 in a block whose
    /// mediantime is AFTER versionTime, processed under the ascending
    /// (target_version_id, block_height) sort BEFORE the UNIQUE v3 in a block
    /// whose mediantime is BEFORE versionTime, must NOT abort the loop. v3 IS
    /// still applied. This pins that the versionTime cutoff never fires on a
    /// duplicate tuple (`targetVersionId <= current_version_id`), only on a
    /// tuple above the current version — a naive per-every-tuple check would
    /// abort at the late duplicate and wrongly return v2.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 5,
    /// footnote 4.
    #[test]
    fn version_time_cutoff_ignores_duplicate_tuples() {
        let (initial, update1, update2) = chained_two_updates();
        let version_time = 1_700_000_100i64;

        // v2 unique @ height 100, block aa (mediantime < T) -> applied first.
        let tx_v2 = confirmed_signal_tx_in_block(
            update1.hash(),
            100,
            1_700_000_000,
            &"aa".repeat(32),
            0xb1,
        );
        // v2 DUPLICATE @ height 200, block bb (mediantime > T) -> processed
        // before v3 under the (tvid, height) sort, must NOT abort the loop.
        let tx_v2_dup = confirmed_signal_tx_in_block(
            update1.hash(),
            200,
            1_700_000_999,
            &"bb".repeat(32),
            0xb2,
        );
        // v3 unique @ height 300, block cc (mediantime < T) -> must still apply.
        let tx_v3 = confirmed_signal_tx_in_block(
            update2.hash(),
            300,
            1_700_000_050,
            &"cc".repeat(32),
            0xb3,
        );
        let mediantimes = HashMap::from([
            (block_hash_of(0xaa), ts(version_time - 100)),
            (block_hash_of(0xbb), ts(version_time + 900)),
            (block_hash_of(0xcc), ts(version_time - 50)),
        ]);

        let sidecar = SidecarData::new(None, vec![update1, update2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(version_time)),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, _) =
            try_drive_serving_blocks(resolver, vec![tx_v2, tx_v2_dup, tx_v3], &mediantimes);

        assert_eq!(
            u64::from(
                result
                    .expect("the walk resolves")
                    .document_metadata
                    .version_id
            ),
            3,
            "a late-mediantime duplicate must not suppress the later within-versionTime unique v3"
        );
    }

    /// The versionTime bound gates ANY tuple whose targetVersionId is more
    /// than current_version_id, not only the next version. Genesis (v1) plus
    /// a lone v3 announcement — no v2 anywhere — with `versionTime` before
    /// v3's block mediantime resolves v1: the walk stops at the bound before
    /// the version-gap check, so the missing v2 is never a LATE_PUBLISHING.
    /// A gate confined to the `== current + 1` apply branch would fall
    /// through to the gap check and raise LATE_PUBLISHING instead.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 5
    /// (first bullet: `targetVersionId` more than `current_version_id`),
    /// evaluated before step 6.
    #[test]
    fn version_time_bound_gates_a_tuple_beyond_the_next_version() {
        let (initial, _update1, update2) = chained_two_updates();
        let mediantime_cc = 1_700_000_100i64;

        // v3 @ height 300, block cc (mediantime > T); v2 is announced nowhere.
        let tx_v3 = confirmed_signal_tx_in_block(
            update2.hash(),
            300,
            1_700_000_050,
            &"cc".repeat(32),
            0xc3,
        );
        let mediantimes = HashMap::from([(block_hash_of(0xcc), ts(mediantime_cc))]);

        let sidecar = SidecarData::new(None, vec![update2.clone()], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(mediantime_cc - 50)),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, requested) = try_drive_serving_blocks(resolver, vec![tx_v3], &mediantimes);

        let result = result.expect("a skipped version announced after versionTime resolves v1");
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            1,
            "the document in effect at versionTime is the genesis document"
        );
        assert!(
            requested.contains(&block_hash_of(0xcc)),
            "the bound is evaluated against the tuple's own block mediantime, got {requested:?}"
        );
    }

    /// Control for the test above: the same lone v3 announcement with
    /// `versionTime` AFTER its block mediantime passes the step-5 gate and
    /// reaches the version-gap check, which raises LATE_PUBLISHING because
    /// v2 was never announced.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 5
    /// (no condition holds) then step 6, "Check update.targetVersionId".
    #[test]
    fn version_time_after_a_skipped_version_is_late_publishing() {
        let (initial, _update1, update2) = chained_two_updates();
        let mediantime_cc = 1_700_000_100i64;

        let tx_v3 = confirmed_signal_tx_in_block(
            update2.hash(),
            300,
            1_700_000_050,
            &"cc".repeat(32),
            0xc3,
        );
        let mediantimes = HashMap::from([(block_hash_of(0xcc), ts(mediantime_cc))]);

        let sidecar = SidecarData::new(None, vec![update2.clone()], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(mediantime_cc + 50)),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, _) = try_drive_serving_blocks(resolver, vec![tx_v3], &mediantimes);

        let err = result.expect_err("a version gap within versionTime is late publishing");
        assert!(matches!(err, Error::LatePublishingError), "got {err:?}");
    }

    /// With neither `versionId` nor `versionTime` requested there is no time
    /// cutoff at all: an update confirmed in a block whose header timestamp is
    /// ahead of this resolver's clock (Bitcoin consensus allows up to two
    /// hours) is still applied. A resolver that silently bounded the walk at
    /// "now" would return version 1 here and a different answer minutes later.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 5
    /// (the cutoff applies only "if `resolutionOptions.versionTime` is
    /// provided").
    #[test]
    fn no_version_bound_applies_a_block_timestamped_in_the_future() {
        let (initial, update1, _update2) = chained_two_updates();
        let ninety_minutes_ahead = (Utc::now() + chrono::Duration::minutes(90)).timestamp();
        let tx = confirmed_signal_tx(update1.hash(), 100, ninety_minutes_ahead, 0xb4);

        let sidecar = SidecarData::new(None, vec![update1], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_id: None,
            version_time: None,
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        assert!(
            matches!(resolver.target_condition, TargetCondition::Latest),
            "no versionId and no versionTime is the unbounded walk"
        );
        let result = drive_to_resolved(resolver, vec![tx]);

        assert_eq!(
            u64::from(result.document_metadata.version_id),
            2,
            "an update in a block timestamped ahead of the resolver's clock must still apply"
        );
    }

    /// A `versionId` the history never reaches is `NOT_FOUND`, not a silently
    /// earlier document: on a three-version chain, `versionId: 5` fails once
    /// every beacon has been scanned, while `versionId: 3` (the last version)
    /// and `versionId: 2` (mid-walk) resolve.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" steps
    /// 1 and 2 (raise `NOT_FOUND` if `updates` is empty and `versionId` is
    /// provided).
    #[test]
    fn version_id_beyond_the_history_is_not_found() {
        use crate::error::ProblemDetails as _;

        let (initial, update1, update2) = chained_two_updates();
        let make = |version_id: u64| {
            let tx_v2 = confirmed_signal_tx(update1.hash(), 100, 1_700_000_000, 0xe5);
            let tx_v3 = confirmed_signal_tx(update2.hash(), 200, 1_700_000_100, 0xe6);
            let sidecar =
                SidecarData::new(None, vec![update1.clone(), update2.clone()], None, None);
            let options = ResolutionOptions {
                sidecar_data: Some(sidecar),
                version_id: NonZeroU64::new(version_id),
                ..test_options()
            };
            let resolver = Resolver::new(initial.clone(), options).expect("the options are valid");
            try_drive_to_resolved(resolver, vec![tx_v2, tx_v3])
        };

        for reachable in [2u64, 3] {
            let result = make(reachable).expect("a version the history reaches resolves");
            assert_eq!(result.document_metadata.version_id.get(), reachable);
        }

        let err = make(5).expect_err("a version the history never reaches is NOT_FOUND");
        let Error::Btcr2Error(spec @ Btcr2Error::NotFound(detail)) = &err else {
            panic!("expected NotFound, got {err:?}");
        };
        assert!(
            detail.contains("versionId 5") && detail.contains("version 3"),
            "the detail names the requested and the reached version: {detail}"
        );
        assert_eq!(
            spec.details().expect("NotFound yields problem details")["type"],
            "https://www.w3.org/ns/did#NOT_FOUND"
        );
    }

    /// On a DID deactivated at version 2, `versionId: 2` resolves the
    /// deactivated document (step 1 runs before step 2) and `versionId: 3` is
    /// `NOT_FOUND` — the deactivation is terminal, so that version never
    /// exists and the walk says so instead of returning version 2.
    #[test]
    fn version_id_past_a_deactivation_is_not_found() {
        let (did, initial) = chain_initial_document();
        let vm_id = format!("{}#initialKey", did.encode());
        let deactivate = Document::from(initial.clone())
            .deactivate(
                &vm_id,
                chain_secret_key(),
                NonZeroU64::new(2).expect("2 is non-zero"),
            )
            .expect("the deactivation constructs against the initial document");

        let make = |version_id: u64| {
            let tx = confirmed_signal_tx(deactivate.hash(), 100, 1_700_000_000, 0xe7);
            let sidecar = SidecarData::new(None, vec![deactivate.clone()], None, None);
            let options = ResolutionOptions {
                sidecar_data: Some(sidecar),
                version_id: NonZeroU64::new(version_id),
                ..test_options()
            };
            let resolver = Resolver::new(initial.clone(), options).expect("the options are valid");
            try_drive_to_resolved(resolver, vec![tx])
        };

        let at_two = make(2).expect("the version the deactivation produced resolves");
        assert_eq!(at_two.document_metadata.version_id.get(), 2);
        assert!(
            at_two.document_metadata.deactivated,
            "versionId 2 is the deactivated document itself"
        );

        let err = make(3).expect_err("no version follows a deactivation");
        match &err {
            Error::Btcr2Error(Btcr2Error::NotFound(detail)) => assert!(
                detail.contains("versionId 3") && detail.contains("deactivated"),
                "the detail says the history ended deactivated: {detail}"
            ),
            other => panic!("expected NotFound, got {other:?}"),
        }

        // And with no versionId the deactivated document resolves as before.
        let latest = {
            let tx = confirmed_signal_tx(deactivate.hash(), 100, 1_700_000_000, 0xe8);
            let sidecar = SidecarData::new(None, vec![deactivate.clone()], None, None);
            let resolver = Resolver::new(
                initial,
                ResolutionOptions {
                    sidecar_data: Some(sidecar),
                    ..test_options()
                },
            )
            .expect("the options are valid");
            drive_to_resolved(resolver, vec![tx])
        };
        assert!(latest.document_metadata.deactivated);
        assert_eq!(latest.document_metadata.version_id.get(), 2);
    }

    /// The `minConf` boundary, with the default of six: a signal at height
    /// 100 has five confirmations against tip 104 and is skipped (the walk
    /// resolves to version 1, and skipping a NEEDED signal is not an error),
    /// and six against tip 105, at which it applies.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals" (at
    /// least `resolutionOptions.minConf` confirmations, 6 when not provided).
    #[test]
    fn signal_below_min_conf_is_skipped_and_at_min_conf_applies() {
        let (initial, update1, _update2) = chained_two_updates();
        let announced_at = 100;

        for (tip, expected_version) in [(104, 1), (105, 2)] {
            let tx = confirmed_signal_tx(update1.hash(), announced_at, 1_700_000_000, 0xc5);
            let sidecar = SidecarData::new(None, vec![update1.clone()], None, None);
            let options = ResolutionOptions {
                sidecar_data: Some(sidecar),
                chain_tip_height: Some(tip),
                min_conf: None,
                ..test_options()
            };
            let resolver = Resolver::new(initial.clone(), options).expect("the options are valid");
            assert_eq!(
                resolver.min_conf,
                ResolutionOptions::DEFAULT_MIN_CONF,
                "no minConf supplied is the default of six"
            );
            let result = try_drive_to_resolved(resolver, vec![tx])
                .expect("a signal short of minConf is skipped, never an error");
            assert_eq!(
                u64::from(result.document_metadata.version_id),
                expected_version,
                "tip {tip}: {} confirmations against minConf 6",
                tip - announced_at + 1
            );
        }
    }

    /// `minConf: 1` applies a signal in the tip block itself (one
    /// confirmation), which the default would skip. The same chain, the same
    /// tip; only the option differs.
    #[test]
    fn min_conf_one_applies_a_one_confirmation_signal() {
        let (initial, update1, _update2) = chained_two_updates();
        let tip = 100;

        for (min_conf, expected_version) in [(None, 1), (Some(NonZeroU32::MIN), 2)] {
            let tx = confirmed_signal_tx(update1.hash(), tip, 1_700_000_000, 0xc6);
            let sidecar = SidecarData::new(None, vec![update1.clone()], None, None);
            let options = ResolutionOptions {
                sidecar_data: Some(sidecar),
                chain_tip_height: Some(tip),
                min_conf,
                ..test_options()
            };
            let resolver = Resolver::new(initial.clone(), options).expect("the options are valid");
            let result = drive_to_resolved(resolver, vec![tx]);
            assert_eq!(
                u64::from(result.document_metadata.version_id),
                expected_version,
                "minConf {min_conf:?}: a one-confirmation signal"
            );
            if expected_version == 2 {
                assert_eq!(
                    result.document_metadata.confirmations,
                    Some(1),
                    "the applied signal sits in the tip block"
                );
            }
        }
    }

    /// A confirmed signal met with no chain tip is a typed driver error
    /// naming the transaction and its height — not an apply, not a skip: the
    /// gate cannot be evaluated and the resolver does not guess. It carries
    /// no spec problem-details body, because it is not a resolution result.
    #[test]
    fn confirmed_signal_without_chain_tip_is_a_driver_error() {
        let (initial, update1, _update2) = chained_two_updates();
        let tx = confirmed_signal_tx(update1.hash(), 100, 1_700_000_000, 0xc7);
        let expected_txid = tx.txid;
        let sidecar = SidecarData::new(None, vec![update1], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height: None,
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");

        let err = try_drive_to_resolved(resolver, vec![tx])
            .expect_err("a confirmed signal with no tip to count against must not resolve");
        match &err {
            Error::MissingChainTip { txid, block_height } => {
                assert_eq!(*txid, expected_txid);
                assert_eq!(*block_height, 100);
            }
            other => panic!("expected MissingChainTip, got {other:?}"),
        }
        assert!(
            err.details().is_none(),
            "a missing tip is a driver error with no spec code"
        );
    }

    /// With no chain tip a walk that meets no confirmed signal still resolves
    /// (the genesis document, `confirmations: None`): the tip is required to
    /// count a signal, not to start.
    #[test]
    fn no_signals_resolve_without_a_chain_tip() {
        let (initial, update1, _update2) = chained_two_updates();
        let pending = unconfirmed_signal_tx(update1.hash(), 0xc8);
        let sidecar = SidecarData::new(None, vec![update1], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height: None,
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let result = drive_to_resolved(resolver, vec![pending]);
        assert_eq!(u64::from(result.document_metadata.version_id), 1);
        assert_eq!(result.document_metadata.confirmations, None);
    }

    /// `confirmations` derives from the MOST-RECENTLY-APPLIED unique
    /// update's block height, not the running min across distinct updates. Two
    /// distinct updates apply at heights 100 (v2) then 200 (v3); with chain tip
    /// 300, confirmations = 300 - 200 + 1 = 101 (from v3's height), NOT
    /// 300 - 100 + 1 = 201 (the old running-min bug).
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:38,58.
    #[test]
    fn confirmations_use_the_most_recently_applied_update() {
        let (initial, update1, update2) = chained_two_updates();

        let tx_v2 = confirmed_signal_tx(update1.hash(), 100, 1_700_000_000, 0xc1);
        let tx_v3 = confirmed_signal_tx(update2.hash(), 200, 1_700_000_100, 0xc2);

        let sidecar = SidecarData::new(None, vec![update1, update2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height: Some(300),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
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
    /// FIRST and becomes the confirmations height; a duplicate never
    /// overwrites the height, so the later h_high one does NOT raise it. With
    /// chain tip 300,
    /// confirmations = 300 - 100 + 1 = 201 (from h_low), never
    /// 300 - 200 + 1 = 101.
    ///
    /// This asserts the SORT-guaranteed lowest-height-first outcome, not a
    /// synthetic lower-than-applied duplicate (which cannot arise under the sort).
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:58 footnote 2.
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
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
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

    /// A sourceHash that does not match the contemporary document is
    /// INVALID_DID_UPDATE (resolve.md "Apply update" step 1), not
    /// LATE_PUBLISHING. The update's proof verifies and its targetHash is
    /// correct for the initial document, so the sourceHash check is the ONLY
    /// thing that can reject it: with the check removed, this update applies
    /// and the resolver reaches version 2.
    #[test]
    fn source_hash_mismatch_raises_invalid_did_update() {
        let (did, initial) = chain_initial_document();
        let document = Document::from(initial.clone());
        let vm_id = format!("{}#initialKey", did.encode());
        let patch = chain_benign_patch(&vm_id);
        let v2 = NonZeroU64::new(2).expect("2 is non-zero");

        // Real targetHash for this patch over the initial document; the
        // sourceHash is deliberately not the initial document's hash.
        let (_, _, target_hash) = document
            .construct_unsigned_update(&patch, v2)
            .expect("v2 update constructs against the initial document");
        let wrong_source_hash = Sha256Hash::from([0xab; 32]);
        assert_ne!(
            wrong_source_hash,
            initial.hash(),
            "the deliberately wrong sourceHash must differ from the initial document hash"
        );
        let unsigned = UnsecuredUpdate::construct(&patch, wrong_source_hash, target_hash, v2);
        let update = crate::test_signing::sign_unsigned_update_for_test(
            &unsigned,
            &did,
            &vm_id,
            &chain_secret_key(),
            None,
            None,
        );

        let tx = confirmed_signal_tx(update.hash(), 100, 1_700_000_000, 0xd1);
        let sidecar = SidecarData::new(None, vec![update], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height: Some(300),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let err = try_drive_to_resolved(resolver, vec![tx])
            .expect_err("a sourceHash mismatch must reject the update");
        match err {
            Error::Btcr2Error(Btcr2Error::InvalidDidUpdate(msg)) => assert!(
                msg.contains("sourceHash"),
                "unexpected rejection message: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// The minted multi-update chain, replayed from the snapshot taken of the
    /// chain it was published on.
    ///
    /// WHAT THIS COVERS THAT NO UPSTREAM VECTOR CAN. Every vendor vector whose
    /// resolution is past genesis carries exactly one update announced from one
    /// beacon address, so four properties have nowhere else to be observed:
    ///
    /// 1. **Multi-update sequencing across rotating beacons.** Three updates
    ///    (v2, v3, v4) were announced from three DIFFERENT beacon addresses in
    ///    three different blocks. Applying them in the wrong order fails at the
    ///    `sourceHash` chain check, so reaching version 4 is evidence the walk
    ///    ordered them by version and height rather than by arrival.
    /// 2. **The on-chain deactivation short-circuit.** The v4 update sets
    ///    `deactivated`, and this is the only chain where a resolver could go on
    ///    to request more signals afterwards — see the round-log assertion below.
    /// 3. **`confirmations` provenance with something to choose between.** Three
    ///    signals at three heights means the assertion "the resolver used the
    ///    MOST RECENT applied update's block" can fail; on a single-signal vendor
    ///    row there is only one height it could have used.
    /// 4. **Mid-walk version bounds.** On a two-version chain `versionId = 1`
    ///    short-circuits at `Init` and `versionId = 2` is the terminal state, so
    ///    no bound stops the walk in the MIDDLE. This chain has four versions,
    ///    which makes 2 and 3 real bounds.
    ///
    /// Everything asserted against — the DID, the network, the heights, the
    /// block times, the tip, the sidecar and the expected document — is read out
    /// of the fixture. Re-minting the scenario onto a different chain therefore
    /// regenerates the data without touching this test.
    ///
    /// Unconditional: the fixture lives in this repository, not in the
    /// `test-suite/` submodule, so there is nothing to skip on.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md — "Process Next Update"
    /// steps 1, 2, 3 and 5 (resolve.md:176-185).
    #[test]
    fn minted_chain_sequences_updates_across_rotating_beacons() {
        use crate::identifier::Did;

        let id = "minted/clean-rotating-beacons";
        let f = read_chain_fixture(id);
        let did: Did = f
            .did
            .as_deref()
            .unwrap_or_else(|| panic!("{id}: a minted fixture records the DID it published"))
            .parse()
            .unwrap_or_else(|e| panic!("{id}: the fixture's DID must parse: {e}"));
        let expected = f
            .expected
            .as_ref()
            .unwrap_or_else(|| panic!("{id}: a minted fixture records its expected resolution"));
        let sidecar_json = f.sidecar.clone().unwrap_or_else(|| {
            panic!("{id}: a minted fixture carries the sidecar it was minted with")
        });

        // ONE options assembly, exactly as `drive_resolve` does it: the sidecar
        // object verbatim plus the captured tip. Every drive below differs ONLY
        // in its target condition, so a bound cannot silently be testing a
        // different resolution.
        let make_options = |version_id: Option<NonZeroU64>, version_time: Option<DateTime<Utc>>| {
            let sidecar = SidecarData::from_json_value(sidecar_json.clone())
                .unwrap_or_else(|e| panic!("{id}: the fixture's sidecar must parse: {e}"));
            ResolutionOptions {
                sidecar_data: Some(sidecar),
                chain_tip_height: Some(f.tip_height),
                version_id,
                version_time,
                ..test_options()
            }
        };
        let resolver_for = |version_id, version_time| {
            Document::resolve(&did, make_options(version_id, version_time))
                .unwrap_or_else(|e| panic!("{id}: the resolver must accept the minted DID: {e}"))
        };

        // --- The chain is still the chain this test was written for ----------
        //
        // Read off the fixture rather than written down, so a re-mint that lost
        // the rotation (or collapsed the three announcements into one block)
        // fails HERE, by name, instead of silently weakening every assertion
        // below into a restatement of a single-signal row.
        let heights: BTreeSet<u32> = f.signals.iter().map(|s| s.block_height).collect();
        let addresses: BTreeSet<&str> = f.signals.iter().map(|s| s.address.as_str()).collect();
        assert_eq!(
            f.signals.len(),
            3,
            "{id}: this scenario is three announced updates; the capture holds {} signal(s)",
            f.signals.len()
        );
        assert_eq!(
            heights.len(),
            3,
            "{id}: the three announcements must sit in three DISTINCT blocks, or sequencing \
             by block height is not being exercised — heights: {heights:?}"
        );
        assert_eq!(
            addresses.len(),
            3,
            "{id}: the three announcements must come from three DISTINCT beacon addresses, or \
             beacon rotation is not being exercised — addresses: {addresses:?}"
        );

        // --- The terminal state ---------------------------------------------
        let (result, rounds) = drive_capture_rounds(resolver_for(None, None), &f, id);
        let result =
            result.unwrap_or_else(|e| panic!("{id}: the minted clean chain must resolve: {e}"));
        let terminal_json = resolved_document_json(&result.document, id);

        assert_eq!(
            terminal_json, expected["didDocument"],
            "{id}: the resolved didDocument must equal the fixture's expected didDocument"
        );
        assert_eq!(
            result.document_metadata.version_id.get(),
            4,
            "{id}: three applied updates walk genesis (1) to version 4"
        );
        assert!(
            result.document_metadata.deactivated,
            "{id}: the terminal update sets `deactivated`, so the resolved metadata must say so"
        );
        // Cross-check the fixture's own expected metadata block. `versionId` is
        // an ASCII STRING per the specification; asserting the ENCODING here
        // keeps a minted fixture from drifting into a number encoding.
        assert_eq!(
            expected["didDocumentMetadata"]["versionId"].as_str(),
            Some("4"),
            "{id}: the fixture's expected versionId must be the ASCII string \"4\", not a \
             JSON number"
        );
        assert_eq!(
            expected["didDocumentMetadata"]["deactivated"].as_bool(),
            Some(true),
            "{id}: the fixture's expected metadata must record the deactivation"
        );

        // --- confirmations, by provenance, with a real choice ----------------
        let latest = f
            .latest_signal()
            .unwrap_or_else(|| panic!("{id}: the capture must carry at least one beacon signal"));
        assert_eq!(
            latest.block_height,
            heights.iter().copied().max().expect("three heights"),
            "{id}: the announcement carrying the last update must also be the one in \
             the highest block — the fixture reader requires the two orders to agree, \
             so a divergence is a fixture problem and not something to assert around \
             here"
        );
        assert_eq!(
            result.document_metadata.confirmations,
            Some(
                f.tip_height
                    .saturating_sub(latest.block_height)
                    .saturating_add(1)
            ),
            "{id}: confirmations must derive from the MOST-RECENTLY-APPLIED update's block \
             ({} at tip {}), not the first applied update's block and not the tip",
            latest.block_height,
            f.tip_height
        );

        // --- The genesis reference ------------------------------------------
        //
        // An independent producer of the pre-walk state: same DID, same options,
        // no signals fed, so the resolver applies nothing.
        let genesis = resolve_with_no_signals(resolver_for(None, None));
        let genesis_json = resolved_document_json(&genesis.document, id);
        assert_eq!(
            genesis.document_metadata.version_id.get(),
            1,
            "{id}: a resolve with no signals fed is the genesis state"
        );
        let genesis_beacons: BTreeSet<String> = genesis
            .document
            .beacons()
            .map(|beacon| beacon.descriptor.to_string())
            .collect();

        // --- The mid-walk re-scan and the deactivation short-circuit, observed
        // --- by what WAS and was NOT asked -----------------------------------
        //
        // The v2 update adds a FOURTH beacon service and v3 is announced from
        // it, between two announcements from genesis beacons. The beacon set
        // is re-checked after every applied update, so the walk asks for the
        // added beacon's history right after v2 applies (round 2) and takes
        // v3 from that answer before v4. The deactivating v4 then resolves
        // the document immediately: no round follows it. Everything is read
        // off the capture — the genesis beacons off the no-signal resolve, the
        // added one as the announcing address the genesis document does not
        // carry — so a re-mint does not touch this test. A resolver that did
        // not re-scan would meet v4 with version 2 in force and raise
        // LATE_PUBLISHING above; one that did not stop at `deactivated` would
        // issue a third round and be caught here.
        assert_eq!(
            rounds.len(),
            2,
            "{id}: the beacon v2 adds is scanned after v2 applies, and applying the \
             deactivating update must resolve immediately and process no further beacon \
             signals — rounds: {rounds:?}"
        );
        let requested: BTreeSet<String> = rounds[0].iter().cloned().collect();
        assert_eq!(
            requested, genesis_beacons,
            "{id}: the first round must request exactly the genesis document's beacon \
             addresses"
        );
        let added: Vec<&str> = addresses
            .iter()
            .copied()
            .filter(|address| !genesis_beacons.contains(*address))
            .collect();
        assert_eq!(
            added.len(),
            1,
            "{id}: exactly one announcement must come from a beacon the genesis document \
             does not carry — the one v2 adds; announcing addresses: {addresses:?}"
        );
        let added = added[0];
        assert_eq!(
            rounds[1],
            vec![added.to_string()],
            "{id}: the second round must request exactly the beacon the v2 update added"
        );
        let added_height = f
            .signals
            .iter()
            .find(|s| s.address == added)
            .map(|s| s.block_height)
            .expect("the added beacon announces exactly one signal");
        let (first, last) = (
            *heights.iter().next().expect("three heights"),
            *heights.iter().next_back().expect("three heights"),
        );
        assert!(
            first < added_height && added_height < last,
            "{id}: the announcement from the added beacon must sit BETWEEN the two \
             announcements from genesis beacons, or the re-scan is not what sequences \
             this history — added at {added_height}, genesis at {first} and {last}"
        );

        // --- versionId = 1: the documented Init-time short-circuit -----------
        //
        // NOT a walk probe. At `Init` the FSM returns `Resolved` when a
        // `VersionId` target equals `current_version_id`, which starts at 1, so
        // this bound issues ZERO requests and never touches the capture. That is
        // exactly why `drive_resolve` does not use it on the vendor rows. It is
        // pinned HERE as the documented behaviour it is: an empty round log.
        let (v1, v1_rounds) =
            drive_capture_rounds(resolver_for(Some(NonZeroU64::MIN), None), &f, id);
        let v1 = v1.unwrap_or_else(|e| panic!("{id}: the versionId = 1 bound must resolve: {e}"));
        assert!(
            v1_rounds.is_empty(),
            "{id}: a versionId bound equal to the starting version short-circuits at Init and \
             must issue NO beacon requests — rounds: {v1_rounds:?}"
        );
        assert_eq!(
            v1.document_metadata.version_id.get(),
            1,
            "{id}: the versionId = 1 bound resolves version 1"
        );
        assert_eq!(
            resolved_document_json(&v1.document, id),
            genesis_json,
            "{id}: the versionId = 1 short-circuit must restate the genesis document"
        );

        // --- versionId = 2 and 3: the walk stops in the MIDDLE ----------------
        let (v2, v2_rounds) = drive_capture_rounds(
            resolver_for(Some(NonZeroU64::new(2).expect("2 is non-zero")), None),
            &f,
            id,
        );
        let v2 = v2.unwrap_or_else(|e| panic!("{id}: the versionId = 2 bound must resolve: {e}"));
        let v2_json = resolved_document_json(&v2.document, id);
        assert!(
            !v2_rounds.is_empty(),
            "{id}: a mid-walk versionId bound must READ the chain — a bound that resolved \
             without issuing a request proves nothing about stopping"
        );
        assert_eq!(
            v2.document_metadata.version_id.get(),
            2,
            "{id}: the versionId = 2 bound must stop after the first applied update"
        );

        let (v3, _v3_rounds) = drive_capture_rounds(
            resolver_for(Some(NonZeroU64::new(3).expect("3 is non-zero")), None),
            &f,
            id,
        );
        let v3 = v3.unwrap_or_else(|e| panic!("{id}: the versionId = 3 bound must resolve: {e}"));
        let v3_json = resolved_document_json(&v3.document, id);
        assert_eq!(
            v3.document_metadata.version_id.get(),
            3,
            "{id}: the versionId = 3 bound must stop after the second applied update"
        );

        // Four stages of one chain, pairwise distinct. Two equal stages would
        // mean an update did not apply — and the versionId assertions above
        // cannot see that, because they read a counter rather than the document.
        let stages = [
            ("genesis", &genesis_json),
            ("version 2", &v2_json),
            ("version 3", &v3_json),
            ("the terminal version 4", &terminal_json),
        ];
        for (i, (left_name, left)) in stages.iter().enumerate() {
            for (right_name, right) in &stages[i + 1..] {
                assert_ne!(
                    left, right,
                    "{id}: the four stages of this chain must be pairwise distinct; {left_name} \
                     equals {right_name}, which means an update did not apply"
                );
            }
        }

        // --- The time bound, against a real captured block mediantime ---------
        let bound = version_time_probe_bound(&f, id);
        let (before, before_rounds) = drive_capture_rounds(resolver_for(None, Some(bound)), &f, id);
        let before =
            before.unwrap_or_else(|e| panic!("{id}: the versionTime bound must resolve: {e}"));
        assert!(
            !before_rounds.is_empty(),
            "{id}: the versionTime bound must READ the chain"
        );
        assert_eq!(
            before.document_metadata.version_id.get(),
            1,
            "{id}: a versionTime one second before the earliest announcing block's \
             mediantime ({bound}) must resolve to version 1"
        );
        assert_eq!(
            resolved_document_json(&before.document, id),
            genesis_json,
            "{id}: a versionTime before the first update must resolve the genesis document"
        );
    }

    /// The minted late-publishing fork, replayed from the snapshot taken of the
    /// chain it was published on.
    ///
    /// THE FORK IS A HISTORICAL FACT, NOT A REPLAY-TIME ARRANGEMENT. Two
    /// conflicting updates, both claiming version 2, were signed and announced
    /// from the SAME beacon address in two different blocks. Both transactions
    /// are on the chain; the capture holds them; the sidecar holds both payloads.
    /// The resolver is therefore rejecting a history that actually exists,
    /// rather than a hand-assembled pair of in-memory structs — which is what
    /// the unit-level `confirm_duplicate` tests in `update.rs` do, and what no
    /// upstream vector demonstrates at all.
    ///
    /// The chain is read from the fixture, so this test covers whichever chain
    /// the scenario was last minted on.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:211 (Confirm Duplicate Update,
    /// `LATE_PUBLISHING` when the hashes differ).
    #[test]
    fn minted_fork_raises_late_publishing() {
        use crate::error::ProblemDetails as _;
        use crate::identifier::Did;

        let id = "minted/late-publishing-fork";
        let f = read_chain_fixture(id);
        let did: Did = f
            .did
            .as_deref()
            .unwrap_or_else(|| panic!("{id}: a minted fixture records the DID it published"))
            .parse()
            .unwrap_or_else(|e| panic!("{id}: the fixture's DID must parse: {e}"));
        let expected = f
            .expected
            .as_ref()
            .unwrap_or_else(|| panic!("{id}: a minted fixture records its expected resolution"));
        let sidecar_json = f.sidecar.clone().unwrap_or_else(|| {
            panic!("{id}: a minted fixture carries the sidecar it was minted with")
        });

        // --- The fork is still there ----------------------------------------
        //
        // Asserted BEFORE driving, so a re-mint that lost the anomaly fails here
        // by name instead of surfacing as a confusing resolver failure — or,
        // worse, as a green run of a test that no longer has a fork to reject.
        let addresses: BTreeSet<&str> = f.signals.iter().map(|s| s.address.as_str()).collect();
        let heights: BTreeSet<u32> = f.signals.iter().map(|s| s.block_height).collect();
        assert_eq!(
            f.signals.len(),
            2,
            "{id}: the fork is two announcements; the capture holds {} signal(s)",
            f.signals.len()
        );
        assert_eq!(
            addresses.len(),
            1,
            "{id}: both conflicting announcements must come from ONE beacon address — \
             addresses: {addresses:?}"
        );
        assert_eq!(
            heights.len(),
            2,
            "{id}: the two announcements must sit in two DISTINCT blocks, or the later one is \
             not late — heights: {heights:?}"
        );

        let updates = sidecar_json["updates"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: the fixture's sidecar must carry an updates array"));
        assert_eq!(
            updates.len(),
            2,
            "{id}: the fork's sidecar must carry BOTH conflicting update payloads; it carries {}",
            updates.len()
        );
        for (i, update) in updates.iter().enumerate() {
            assert_eq!(
                update["targetVersionId"].as_u64(),
                Some(2),
                "{id}: sidecar update {i} must claim version 2 — a fork is two updates at the \
                 SAME version"
            );
        }
        assert_ne!(
            updates[0], updates[1],
            "{id}: the two version-2 updates must DIFFER; two identical announcements are a \
             benign duplicate, not a fork"
        );

        // --- The resolver rejects the history --------------------------------
        let sidecar = SidecarData::from_json_value(sidecar_json.clone())
            .unwrap_or_else(|e| panic!("{id}: the fixture's sidecar must parse: {e}"));
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            chain_tip_height: Some(f.tip_height),
            ..test_options()
        };
        let resolver = Document::resolve(&did, options)
            .unwrap_or_else(|e| panic!("{id}: the resolver must accept the minted DID: {e}"));
        let (result, rounds) = drive_capture_rounds(resolver, &f, id);

        assert!(
            !rounds.is_empty(),
            "{id}: the rejection must come from READING the chain, not from refusing the DID"
        );
        let error = match result {
            Err(error) => error,
            Ok(resolved) => panic!(
                "{id}: resolving a forked history must fail, but it resolved to version {} — \
                 the resolver walked past a conflicting same-version announcement",
                resolved.document_metadata.version_id.get()
            ),
        };
        // Matched on the VARIANT, not on a formatted string: the outer error's
        // Display is a fixed sentence, so a message comparison would pass for
        // any FSM error at all. The lower-height branch applies (signals are
        // sorted ascending by (targetVersionId, block_height)) and the
        // higher-height one reaches `confirm_duplicate`, whose hash mismatch
        // raises this.
        let Error::Btcr2Error(btcr2_error @ Btcr2Error::LatePublishingError(_)) = &error else {
            panic!("{id}: a forked history must raise a late-publishing error, got {error:?}");
        };

        // The fixture's recorded expectation IS the crate's problem-details code
        // for the variant just matched — the two are tied here rather than both
        // being spelled out as a literal in two places.
        let details = btcr2_error
            .details()
            .unwrap_or_else(|| panic!("{id}: the late-publishing error must carry a details body"));
        let code = details["type"]
            .as_str()
            .and_then(|ty| ty.rsplit('#').next())
            .unwrap_or_else(|| panic!("{id}: the details body must carry a `type` URL"));
        assert_eq!(
            expected["error"].as_str(),
            Some(code),
            "{id}: the fixture's expected error must be the problem-details code this variant \
             reports"
        );
    }

    /// `DocumentMetadata.deactivated` is sourced from
    /// `contemporary_doc.fields.deactivated`. An initial document carries
    /// `false`; flipping the field surfaces `true` in the metadata.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:56 (deactivated REQUIRED in metadata).
    #[test]
    fn metadata_deactivated_follows_the_document() {
        // Un-deactivated initial document → metadata.deactivated == false.
        let resolver = resolver_with(SidecarData::default(), None);
        let result = resolve_with_no_signals(resolver);
        assert!(!result.document_metadata.deactivated);

        // A deactivated contemporary document → metadata.deactivated == true.
        let mut resolver = resolver_with(SidecarData::default(), None);
        resolver.contemporary_doc.fields.deactivated = true;
        assert!(resolver.terminal_state().document_metadata.deactivated);
    }

    /// once the contemporary document is deactivated, the FSM
    /// short-circuits — no further beacon signals mutate the document. The
    /// terminal state reflects `deactivated: true`.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md §"Process Next Update" step 2 (resolve.md:177-179)
    /// (if current_document.deactivated, resolve current_document as didDocument).
    #[test]
    fn deactivated_document_short_circuits_the_walk() {
        // A resolver whose document is already deactivated, driven with empty
        // signals, resolves directly and preserves version_id == 1 (no further
        // update is applied past the short-circuit point).
        let mut resolver = resolver_with(SidecarData::default(), None);
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
    /// Spec: did-btcr2/src/errors.md:25-27 (MISSING_UPDATE_DATA: data needed to
    /// find what a Beacon Signal announces is in neither the Sidecar Data nor CAS).
    #[test]
    fn unknown_signal_hash_raises_missing_update_data() {
        // Empty sidecar (the missing-update fixture has zero updates) → empty
        // lookup table.
        let raw = include_str!("../fixtures/spec-form/sidecar-missing-update.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let sidecar = SidecarData::from_json_value(value).expect("sidecar deserializes");
        assert!(sidecar.update_lookup_table.is_empty());

        let resolver = resolver_with(sidecar, None);

        // Synthesize a beacon signal whose hash is absent from the (empty) table.
        let missing_hash = Sha256Hash::from([7u8; 32]);
        let signal = NextSignal {
            beacon_type: BeaconType::Singleton,
            beacon_address: first_beacon_address(&resolver),
            signal_bytes: missing_hash,
            block_time: Utc::now(),
            block_height: 42,
            block_hash: zero_block_hash(),
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
        let resolver = resolver_with(SidecarData::default(), None);

        let signal = NextSignal {
            beacon_type: BeaconType::Cas,
            beacon_address: first_beacon_address(&resolver),
            signal_bytes: Sha256Hash::from([1u8; 32]),
            block_time: Utc::now(),
            block_height: 1,
            block_hash: zero_block_hash(),
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
        let resolver = resolver_with(SidecarData::default(), None);

        let signal = NextSignal {
            beacon_type: BeaconType::SparseMerkleTree,
            beacon_address: first_beacon_address(&resolver),
            signal_bytes: Sha256Hash::from([2u8; 32]),
            block_time: Utc::now(),
            block_height: 1,
            block_hash: zero_block_hash(),
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
        let mut resolver = resolver_with(SidecarData::default(), None);
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
        let mut resolver = resolver_with(SidecarData::default(), None);
        resolver.contemporary_doc.fields.service.head.ty = BeaconType::SparseMerkleTree;

        let err = resolver
            .resolve()
            .expect_err("SMT beacon request build must error, not panic");
        assert!(
            matches!(err, Error::Btcr2Error(Btcr2Error::Unsupported(_))),
            "expected Unsupported, got {err:?}"
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // Captured-chain replay: serving the resolver's OWN request URIs from the
    // bodies a capture recorded, keyed on the beacon address.
    // ──────────────────────────────────────────────────────────────────────

    /// A mutinynet address none of the three deterministically generated
    /// beacons uses, so a rotation onto it is observable as a NEW request in a
    /// SECOND round. Lifted from a committed mutinynet capture, so it is a real
    /// address of the right network rather than a hand-assembled string.
    const ROTATED_BEACON_ADDRESS: &str = "tb1q7mss0haz2pjzh6kry4ythrat3mpk4rj5hhgy4l";

    /// A second testnet-family address, distinct from the genesis beacons and
    /// from [`ROTATED_BEACON_ADDRESS`], for a beacon introduced by a later
    /// update than the one that introduced the rotated beacon (the BIP 173
    /// P2WPKH test vector).
    const SECOND_ROTATED_BEACON_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    fn test_uri(uri: &str) -> esploda::http::Uri {
        uri.parse().expect("a valid test URI")
    }

    /// The beacon addresses a document declares, in document order — which is
    /// the order the FSM emits its requests in.
    fn chain_beacon_addresses(initial: &InitialDocument) -> Vec<String> {
        let mut addresses = Vec::new();
        for beacon in &initial.fields.service {
            addresses.push(beacon.address().to_string());
        }
        addresses
    }

    /// A [`ChainFixture`] holding exactly the given captured address responses.
    ///
    /// Built directly rather than read off disk: these tests pin the pump's
    /// ROUTING, and their bodies come from `confirmed_signal_tx`, whose
    /// `Transaction` values a JSON envelope would have to round-trip through a
    /// serializer the type does not provide. `signals` stays empty because the
    /// pump never reads it — `read_chain_fixture` is what re-derives it.
    fn capture_fixture(addresses: Vec<(&str, Vec<Transaction>)>) -> ChainFixture {
        ChainFixture {
            vector: "mutinynet/k1/synthetic".to_string(),
            endpoint: "http://localhost:3000".to_string(),
            network: "mutinynet".to_string(),
            tip_height: 900,
            signals: Vec::new(),
            addresses: addresses
                .into_iter()
                .map(|(address, txs)| (address.to_string(), txs))
                .collect(),
            did: None,
            sidecar: None,
            expected: None,
            blocks: BTreeMap::new(),
        }
    }

    /// A patch that APPENDS a Singleton beacon at [`ROTATED_BEACON_ADDRESS`] —
    /// the beacon-set change that forces the resolver into a second request
    /// round (every address is queried once, so an unchanged beacon set
    /// resolves after the first round).
    fn chain_beacon_rotation_patch(did: &crate::identifier::Did) -> json_patch::Patch {
        chain_beacon_addition_patch(did, "rotatedBeacon", ROTATED_BEACON_ADDRESS)
    }

    /// A patch that APPENDS a Singleton beacon with service id
    /// `{did}#{fragment}` at `address`.
    fn chain_beacon_addition_patch(
        did: &crate::identifier::Did,
        fragment: &str,
        address: &str,
    ) -> json_patch::Patch {
        serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/service/-", "value": {
                "id": format!("{}#{fragment}", did.encode()),
                "type": "SingletonBeacon",
                "serviceEndpoint": format!("bitcoin:{address}"),
            }}
        ]))
        .expect("the beacon addition patch is a valid RFC 6902 op array")
    }

    /// The initial document plus a signed v2 update that APPENDS a Singleton
    /// beacon at [`ROTATED_BEACON_ADDRESS`] — the beacon-set change that forces
    /// the resolver into a second request round.
    fn chained_beacon_rotation() -> (InitialDocument, Update) {
        use crate::document::Document;

        let (did, initial) = chain_initial_document();
        let document = Document::from(initial.clone());
        let vm_id = format!("{}#initialKey", did.encode());
        let patch = chain_beacon_rotation_patch(&did);

        let v2 = NonZeroU64::new(2).expect("2 is non-zero");
        let update = document
            .construct_signed_update(patch, v2, &vm_id, chain_secret_key())
            .expect("the rotation update constructs against the initial document");

        (initial, update)
    }

    /// The routing key is the address in the path.
    #[test]
    fn routing_by_address_from_txs_uri_reads_the_address() {
        let uri = test_uri(
            "http://localhost:3000/address/bcrt1ql8r8ql90we9d4k70z5wsufurnu3c5pxyk3ku8n/txs",
        );
        assert_eq!(
            address_from_txs_uri(&uri),
            "bcrt1ql8r8ql90we9d4k70z5wsufurnu3c5pxyk3ku8n"
        );
    }

    /// The host is irrelevant: a capture is taken against a local endpoint and
    /// replayed against whatever `rpc_host` the resolver was built with, so a
    /// full-URI match would miss on every fixture.
    #[test]
    fn routing_by_address_from_txs_uri_ignores_the_host() {
        let uri = test_uri(&format!(
            "https://blockstream.info/testnet/api/address/{ROTATED_BEACON_ADDRESS}/txs"
        ));
        assert_eq!(address_from_txs_uri(&uri), ROTATED_BEACON_ADDRESS);
    }

    /// A query string is not part of the key, exactly as in the recorder.
    #[test]
    fn routing_by_address_from_txs_uri_ignores_a_query_string() {
        let uri = test_uri(&format!(
            "http://localhost:3000/address/{ROTATED_BEACON_ADDRESS}/txs?after_txid=deadbeef"
        ));
        assert_eq!(address_from_txs_uri(&uri), ROTATED_BEACON_ADDRESS);
    }

    /// A request shape the harness cannot route names the shape it received, so
    /// a future FSM change says what it produced rather than only that it was
    /// wrong.
    #[test]
    #[should_panic(expected = "/address/tb1qexample/utxo")]
    fn routing_by_address_from_txs_uri_panics_on_another_endpoint_shape() {
        let uri = test_uri("http://localhost:3000/address/tb1qexample/utxo");
        let _ = address_from_txs_uri(&uri);
    }

    /// The first round asks for every beacon the genesis document declares, and
    /// an address captured with no transactions is served as zero transactions
    /// rather than treated as a routing failure.
    #[test]
    fn capture_pump_logs_every_address_the_first_round_requested() {
        let (_did, initial) = chain_initial_document();
        let addresses = chain_beacon_addresses(&initial);
        let fixture = capture_fixture(
            addresses
                .iter()
                .map(|address| (address.as_str(), Vec::new()))
                .collect(),
        );

        let resolver = Resolver::new(initial, test_options()).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/all-empty");

        let result = result.expect("a capture with no signals resolves to the genesis document");
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            1,
            "no signals were announced, so the document stays at version 1"
        );
        assert_eq!(
            rounds,
            vec![addresses],
            "one round, asking for every declared beacon address"
        );
    }

    /// Several addresses' transactions merge into ONE `BeaconType::Singleton`
    /// entry, exactly as the production loop merges them — two updates
    /// announced from two different beacons both apply.
    #[test]
    fn capture_pump_merges_several_addresses_into_one_singleton_entry() {
        let (initial, update1, update2) = chained_two_updates();
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2 = confirmed_signal_tx(update1.hash(), 100, 1_700_000_000, 0xf1);
        let tx_v3 = confirmed_signal_tx(update2.hash(), 200, 1_700_000_100, 0xf2);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v2]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), vec![tx_v3]),
        ]);

        let sidecar = SidecarData::new(None, vec![update1, update2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let result = drive_to_resolved_from_capture(resolver, &fixture, "test/two-beacons")
            .expect("both announcements apply");

        assert_eq!(
            u64::from(result.document_metadata.version_id),
            3,
            "an update announced from a second beacon address must still apply"
        );
    }

    /// An applied update that adds a beacon forces a SECOND round, and the pump
    /// serves that round from the capture too. A harness that fed one batch and
    /// then empty responses would resolve identically while never asking.
    #[test]
    fn capture_pump_serves_a_second_round_when_an_update_rotates_the_beacon_set() {
        let (initial, update) = chained_beacon_rotation();
        let addresses = chain_beacon_addresses(&initial);
        let tx = confirmed_signal_tx(update.hash(), 700, 1_700_000_000, 0xd1);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, Vec::new()),
        ]);

        let sidecar = SidecarData::new(None, vec![update], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/rotation");

        let result = result.expect("the rotation resolves");
        assert_eq!(u64::from(result.document_metadata.version_id), 2);
        assert_eq!(
            rounds.len(),
            2,
            "the added beacon is a second round: {rounds:?}"
        );
        assert_eq!(rounds[0], addresses, "round 1 asks for the genesis beacons");
        assert_eq!(
            rounds[1],
            vec![ROTATED_BEACON_ADDRESS.to_string()],
            "round 2 asks only for the beacon the update introduced"
        );
    }

    /// The initial document plus three chained signed updates: v2 APPENDS a
    /// Singleton beacon at [`ROTATED_BEACON_ADDRESS`], v3 and v4 are benign.
    /// Announcing v3 from the added beacon and v4 from a genesis beacon is the
    /// history that only resolves if the beacon set is re-checked after every
    /// applied update rather than after every batch.
    fn chained_rotation_then_two_more() -> (InitialDocument, Update, Update, Update) {
        use crate::document::Document;

        let (did, initial) = chain_initial_document();
        let vm_id = format!("{}#initialKey", did.encode());

        let v2 = NonZeroU64::new(2).expect("2 is non-zero");
        let update_v2 = Document::from(initial.clone())
            .construct_signed_update(
                chain_beacon_rotation_patch(&did),
                v2,
                &vm_id,
                chain_secret_key(),
            )
            .expect("the rotation update constructs against the initial document");

        let mut after_v2 = initial.clone();
        after_v2
            .apply_update(&update_v2, &AnnouncingBlock::fixed())
            .expect("the rotation update applies to the initial document");

        let v3 = NonZeroU64::new(3).expect("3 is non-zero");
        let update_v3 = Document::from(after_v2.clone())
            .construct_signed_update(chain_benign_patch(&vm_id), v3, &vm_id, chain_secret_key())
            .expect("update #3 constructs against the post-rotation document");

        let mut after_v3 = after_v2;
        after_v3
            .apply_update(&update_v3, &AnnouncingBlock::fixed())
            .expect("update #3 applies to the post-rotation document");

        let v4 = NonZeroU64::new(4).expect("4 is non-zero");
        let update_v4 = Document::from(after_v3)
            .construct_signed_update(chain_benign_patch(&vm_id), v4, &vm_id, chain_secret_key())
            .expect("update #4 constructs against the post-update-3 document");

        (initial, update_v2, update_v3, update_v4)
    }

    /// Genesis beacons A, B, C; v2 (from A) adds D; v3 from D; v4 from A.
    /// resolve.md:41-47 runs Find Beacon Signals before EVERY Process Next
    /// Update, so D is scanned right after v2 applies and v3 is found before
    /// v4 is judged. A resolver that only re-checks the beacon set at the end
    /// of a batch meets v4 with version 2 in force and raises LATE_PUBLISHING.
    #[test]
    fn interleaved_history_across_a_rotated_in_beacon_resolves() {
        let (initial, update_v2, update_v3, update_v4) = chained_rotation_then_two_more();
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0xa2);
        let tx_v3 = confirmed_signal_tx(update_v3.hash(), 300, 1_700_000_100, 0xa3);
        let tx_v4 = confirmed_signal_tx(update_v4.hash(), 400, 1_700_000_200, 0xa4);
        // A's history is deliberately out of order: the sort, not the
        // indexer's ordering, decides which tuple is taken first.
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v4, tx_v2]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, vec![tx_v3]),
        ]);

        let sidecar = SidecarData::new(None, vec![update_v2, update_v3, update_v4], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/interleaved");

        let result = result.expect("v3 is announced from the beacon v2 added, so v4 is not a gap");
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            4,
            "all three updates apply once the added beacon has been scanned"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "exactly two rounds: the genesis beacons, then the added beacon — scanned \
             before v4 is judged, not after the batch"
        );
    }

    /// v2 is announced twice: at height 200 on a genesis beacon, and again at
    /// height 150 on the beacon v2 itself adds. The genesis round applies the
    /// height-200 announcement, which sets `current_block_height` to 200. The
    /// added beacon is scanned after that, and its height-150 announcement sits
    /// below the current block height, so Find Beacon Signals never finds it:
    /// `confirmations` derive from the applied v2's block.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (resolve.md:134) and "Apply `update`" (resolve.md:228).
    #[test]
    fn a_lower_duplicate_on_the_added_beacon_is_not_found() {
        let (initial, update_v2, _update_v3, _update_v4) = chained_rotation_then_two_more();
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2_high = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0xb2);
        let tx_v2_low = confirmed_signal_tx(update_v2.hash(), 150, 1_699_999_900, 0xb3);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v2_high]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, vec![tx_v2_low]),
        ]);

        let sidecar = SidecarData::new(None, vec![update_v2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/lower-duplicate");

        let result = result.expect("an announcement below the current block height is not found");
        assert_eq!(u64::from(result.document_metadata.version_id), 2);
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the added beacon is scanned after v2 applies"
        );
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 200 + 1),
            "confirmations derive from the applied v2's block; the lower announcement \
             on the added beacon is never found"
        );
    }

    /// Resolve a history where v2 (announced on genesis beacon A at height
    /// 200) adds beacon D at [`ROTATED_BEACON_ADDRESS`], D's history is
    /// `added_beacon_txs`, genesis beacons B and C are empty, and the sidecar
    /// holds `sidecar`. Returns the result, the request rounds and the genesis
    /// beacon addresses.
    fn resolve_with_added_beacon_history(
        initial: InitialDocument,
        update_v2: &Update,
        added_beacon_txs: Vec<Transaction>,
        sidecar: Vec<Update>,
        id: &str,
        a_txid_seed: u8,
    ) -> (
        Result<ResolutionResult, Error>,
        Vec<Vec<String>>,
        Vec<String>,
    ) {
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, a_txid_seed);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v2]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, added_beacon_txs),
        ]);
        let options = ResolutionOptions {
            sidecar_data: Some(SidecarData::new(None, sidecar, None, None)),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, id);
        (result, rounds, addresses)
    }

    /// v2 (announced at height 200) adds beacon D; D's history announces a
    /// DIFFERENT update that also targets version 2, at height 150. D is
    /// scanned once v2 has applied, with `current_block_height` at 200, so the
    /// conflicting announcement is never found: no tuple, no Confirm Duplicate
    /// Update, no LATE_PUBLISHING. A key that controls a beacon from height H
    /// cannot rewrite the history before H.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (resolve.md:134).
    #[test]
    fn a_conflicting_announcement_below_the_current_height_is_not_found() {
        let (initial, update_v2, _update_v3, _update_v4) = chained_rotation_then_two_more();
        let (_initial, conflicting_v2, _update3) = chained_two_updates();
        assert_eq!(
            conflicting_v2.target_version_id, update_v2.target_version_id,
            "both updates target version 2"
        );
        assert_ne!(
            conflicting_v2.hash(),
            update_v2.hash(),
            "the two version-2 updates are different updates"
        );
        let tx_conflict = confirmed_signal_tx(conflicting_v2.hash(), 150, 1_699_999_900, 0x71);
        let (result, rounds, addresses) = resolve_with_added_beacon_history(
            initial,
            &update_v2,
            vec![tx_conflict],
            vec![update_v2.clone(), conflicting_v2],
            "test/conflict-below-height",
            0x70,
        );

        let result = result.expect("a conflicting announcement below the height is not found");
        assert_eq!(u64::from(result.document_metadata.version_id), 2);
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 200 + 1),
            "confirmations derive from the applied v2's block"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the added beacon is scanned after v2 applies"
        );
    }

    /// v2 (announced at height 200) adds beacon D; D's history announces v4 at
    /// height 150 while v3 is never announced. The v4 announcement sits below
    /// the current block height when D is scanned, so it is never found and
    /// the version gap raises no LATE_PUBLISHING.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (resolve.md:134).
    #[test]
    fn a_version_gap_below_the_current_height_is_not_found() {
        let (initial, update_v2, _update_v3, update_v4) = chained_rotation_then_two_more();
        let tx_v4 = confirmed_signal_tx(update_v4.hash(), 150, 1_699_999_900, 0x73);
        let (result, rounds, addresses) = resolve_with_added_beacon_history(
            initial,
            &update_v2,
            vec![tx_v4],
            vec![update_v2.clone(), update_v4],
            "test/gap-below-height",
            0x72,
        );

        let result = result.expect("a version gap below the height is not found");
        assert_eq!(u64::from(result.document_metadata.version_id), 2);
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 200 + 1),
            "confirmations derive from the applied v2's block"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the added beacon is scanned after v2 applies"
        );
    }

    /// v2 (announced at height 200) adds beacon D; D's history announces v3 at
    /// height 150 and the sidecar does not hold v3. The announcement is below
    /// the current block height when D is scanned, so it is never found and
    /// the absent update raises no MISSING_UPDATE_DATA.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (resolve.md:134, :155).
    #[test]
    fn an_unknown_hash_below_the_current_height_is_not_missing_update_data() {
        let (initial, update_v2, update_v3, _update_v4) = chained_rotation_then_two_more();
        let tx_v3 = confirmed_signal_tx(update_v3.hash(), 150, 1_699_999_900, 0x75);
        let (result, rounds, addresses) = resolve_with_added_beacon_history(
            initial,
            &update_v2,
            vec![tx_v3],
            vec![update_v2.clone()],
            "test/unknown-below-height",
            0x74,
        );

        let result = result.expect("an announcement below the height is not found");
        assert_eq!(u64::from(result.document_metadata.version_id), 2);
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 200 + 1),
            "confirmations derive from the applied v2's block"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the added beacon is scanned after v2 applies"
        );
    }

    /// v2 (announced at height 200) adds beacon D; D's history announces v3 in
    /// the same block, height 200. "Equal to or more than"
    /// `current_block_height` keeps it, so v3 applies.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (resolve.md:134).
    #[test]
    fn a_later_update_at_the_introducing_height_is_found_and_applied() {
        let (initial, update_v2, update_v3, _update_v4) = chained_rotation_then_two_more();
        let tx_v3 = confirmed_signal_tx(update_v3.hash(), 200, 1_700_000_000, 0x77);
        let (result, rounds, addresses) = resolve_with_added_beacon_history(
            initial,
            &update_v2,
            vec![tx_v3],
            vec![update_v2.clone(), update_v3],
            "test/later-at-height",
            0x76,
        );

        let result = result.expect("an announcement at the current block height is found");
        assert_eq!(u64::from(result.document_metadata.version_id), 3);
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 200 + 1),
            "confirmations derive from v3's block"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the added beacon is scanned after v2 applies"
        );
    }

    /// v2 (announced at height 200) adds beacon D; D's history announces a
    /// DIFFERENT update that also targets version 2, in the same block. The
    /// announcement is at the current block height, so it is found, reaches
    /// Confirm Duplicate Update, and raises LATE_PUBLISHING.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (resolve.md:134) and Confirm Duplicate Update (resolve.md:211).
    #[test]
    fn a_conflicting_announcement_at_the_introducing_height_is_late_publishing() {
        let (initial, update_v2, _update_v3, _update_v4) = chained_rotation_then_two_more();
        let (_initial, conflicting_v2, _update3) = chained_two_updates();
        assert_eq!(
            conflicting_v2.target_version_id, update_v2.target_version_id,
            "both updates target version 2"
        );
        assert_ne!(
            conflicting_v2.hash(),
            update_v2.hash(),
            "the two version-2 updates are different updates"
        );
        let tx_conflict = confirmed_signal_tx(conflicting_v2.hash(), 200, 1_700_000_000, 0x79);
        let (result, rounds, addresses) = resolve_with_added_beacon_history(
            initial,
            &update_v2,
            vec![tx_conflict],
            vec![update_v2.clone(), conflicting_v2],
            "test/conflict-at-height",
            0x78,
        );

        let err = result.expect_err("a conflicting announcement at the height is found");
        assert!(
            matches!(err, Error::Btcr2Error(Btcr2Error::LatePublishingError(_))),
            "expected LATE_PUBLISHING from Confirm Duplicate Update, got {err:?}"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the added beacon is scanned after v2 applies"
        );
    }

    /// The initial document plus two chained signed updates that each ADD a
    /// beacon: v2 appends a Singleton beacon at [`ROTATED_BEACON_ADDRESS`] (it
    /// equals the v2 of [`chained_rotation_then_two_more`]), v3 appends one at
    /// [`SECOND_ROTATED_BEACON_ADDRESS`].
    fn chained_rotation_then_second_rotation() -> (InitialDocument, Update, Update) {
        use crate::document::Document;

        let (did, initial) = chain_initial_document();
        let vm_id = format!("{}#initialKey", did.encode());

        let v2 = NonZeroU64::new(2).expect("2 is non-zero");
        let update_v2 = Document::from(initial.clone())
            .construct_signed_update(
                chain_beacon_rotation_patch(&did),
                v2,
                &vm_id,
                chain_secret_key(),
            )
            .expect("the rotation update constructs against the initial document");

        let mut after_v2 = initial.clone();
        after_v2
            .apply_update(&update_v2, &AnnouncingBlock::fixed())
            .expect("the rotation update applies to the initial document");

        let v3 = NonZeroU64::new(3).expect("3 is non-zero");
        let update_v3 = Document::from(after_v2)
            .construct_signed_update(
                chain_beacon_addition_patch(
                    &did,
                    "secondRotatedBeacon",
                    SECOND_ROTATED_BEACON_ADDRESS,
                ),
                v3,
                &vm_id,
                chain_secret_key(),
            )
            .expect("the second rotation constructs against the post-rotation document");

        (initial, update_v2, update_v3)
    }

    /// Chained introduction: v2 at height 200 (on genesis beacon A) adds beacon
    /// D; v3 at height 300 (on D) adds beacon E; E's history announces a
    /// DIFFERENT version-3 update at height 250. D is scanned with
    /// `current_block_height` at 200 and E with it at 300, so the conflicting
    /// v3 at 250 — above the first introducing height, below the second — is
    /// never found: no LATE_PUBLISHING, and `confirmations` derive from v3's
    /// block, not v2's.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (resolve.md:134) and "Apply `update`" (resolve.md:228).
    #[test]
    fn a_signal_below_a_later_introducing_height_is_not_found() {
        let (initial, update_v2, v3_adds_e) = chained_rotation_then_second_rotation();
        let (_initial, rotation_v2, conflicting_v3, _update_v4) = chained_rotation_then_two_more();
        assert_eq!(
            rotation_v2.hash(),
            update_v2.hash(),
            "both builders share v2"
        );
        assert_eq!(
            conflicting_v3.target_version_id, v3_adds_e.target_version_id,
            "both updates target version 3"
        );
        assert_eq!(
            conflicting_v3.source_hash, v3_adds_e.source_hash,
            "both version-3 updates are built on the same post-v2 document"
        );
        assert_ne!(
            conflicting_v3.hash(),
            v3_adds_e.hash(),
            "the two version-3 updates are different updates"
        );
        let addresses = chain_beacon_addresses(&initial);
        assert!(
            !addresses.contains(&SECOND_ROTATED_BEACON_ADDRESS.to_string()),
            "beacon E is not a genesis beacon"
        );

        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0x7a);
        let tx_v3 = confirmed_signal_tx(v3_adds_e.hash(), 300, 1_700_000_100, 0x7b);
        let tx_conflict = confirmed_signal_tx(conflicting_v3.hash(), 250, 1_700_000_050, 0x7c);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v2]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, vec![tx_v3]),
            (SECOND_ROTATED_BEACON_ADDRESS, vec![tx_conflict]),
        ]);

        let sidecar =
            SidecarData::new(None, vec![update_v2, v3_adds_e, conflicting_v3], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) =
            drive_capture_rounds(resolver, &fixture, "test/chained-introduction");

        let result =
            result.expect("the conflicting v3 on E sits below the height E was scanned at");
        assert_eq!(u64::from(result.document_metadata.version_id), 3);
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 300 + 1),
            "confirmations derive from v3's block"
        );
        assert_eq!(
            rounds,
            vec![
                addresses,
                vec![ROTATED_BEACON_ADDRESS.to_string()],
                vec![SECOND_ROTATED_BEACON_ADDRESS.to_string()],
            ],
            "D is scanned after v2 applies and E after v3 applies"
        );
    }

    /// Genesis beacons A, B, C; v2 at height 200 on A adds D; v3 at height 100
    /// on B; v4 at height 150 on D. The first scan (height 0) finds v2 and v3;
    /// v2 applies, `current_block_height` becomes 200 and v3 is parked while D
    /// is scanned. D is scanned once, at 200, so v4 at 150 is never found. The
    /// parked v3 came from the earlier scan and is not re-filtered: it applies
    /// and lowers `current_block_height` to 100. D is in `scanned_beacons`, so
    /// it is not scanned again at the lower height.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md state (resolve.md:34), "Find
    /// Beacon Signals" (resolve.md:129, :134) and "Apply `update`"
    /// (resolve.md:228).
    #[test]
    fn a_parked_update_below_the_introducing_height_still_applies() {
        let (initial, update_v2, update_v3, update_v4) = chained_rotation_then_two_more();
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0x7d);
        let tx_v3 = confirmed_signal_tx(update_v3.hash(), 100, 1_700_000_100, 0x7e);
        let tx_v4 = confirmed_signal_tx(update_v4.hash(), 150, 1_700_000_200, 0x7f);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v2]),
            (addresses[1].as_str(), vec![tx_v3]),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, vec![tx_v4]),
        ]);

        let sidecar = SidecarData::new(None, vec![update_v2, update_v3, update_v4], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/parked-below-height");

        let result = result.expect("the parked v3 applies; v4 on D is never found");
        assert_eq!(u64::from(result.document_metadata.version_id), 3);
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 100 + 1),
            "confirmations derive from v3's block"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "D is scanned once, after v2 applies"
        );
    }

    /// Find Beacon Signals drops a transaction whose block height is below
    /// `current_block_height`, keeps one at that height, and reads whatever
    /// the height currently is. A transaction that is not found raises
    /// nothing: the height condition is checked before the chain tip, so a
    /// missing tip is reported only for a transaction that is found.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (resolve.md:134, :139).
    #[test]
    fn find_next_signals_skips_transactions_below_the_current_block_height() {
        let (_initial, update_v2, update_v3, _update_v4) = chained_rotation_then_two_more();
        let (_did, initial) = chain_initial_document();
        let addresses = chain_beacon_addresses(&initial);
        let mut resolver = Resolver::new(initial, test_options()).expect("the options are valid");
        let histories = || {
            HashMap::from([(
                addresses[0].clone(),
                vec![
                    confirmed_signal_tx(update_v2.hash(), 199, 1_700_000_000, 0x60),
                    confirmed_signal_tx(update_v3.hash(), 200, 1_700_000_100, 0x61),
                ],
            )])
        };

        resolver.current_block_height = None;
        let signals = resolver
            .find_next_signals(histories())
            .expect("no height: every confirmed transaction is found");
        assert_eq!(signals.len(), 2, "height 0 finds both transactions");

        resolver.current_block_height = Some(200);
        let signals = resolver
            .find_next_signals(histories())
            .expect("height 200: the transaction at 200 is found");
        assert_eq!(signals.len(), 1, "only the transaction at 200 is found");
        assert_eq!(signals[0].block_height, 200);
        assert_eq!(signals[0].signal_bytes, update_v3.hash());

        resolver.current_block_height = Some(300);
        let signals = resolver
            .find_next_signals(histories())
            .expect("height 300: nothing is found, nothing is raised");
        assert!(signals.is_empty(), "both transactions are below 300");

        resolver.chain_tip_height = None;
        resolver.current_block_height = Some(200);
        let below = HashMap::from([(
            addresses[0].clone(),
            vec![confirmed_signal_tx(
                update_v2.hash(),
                199,
                1_700_000_000,
                0x62,
            )],
        )]);
        let signals = resolver
            .find_next_signals(below)
            .expect("a transaction below the height is not found, so no tip is needed");
        assert!(signals.is_empty());

        let at = HashMap::from([(
            addresses[0].clone(),
            vec![confirmed_signal_tx(
                update_v3.hash(),
                200,
                1_700_000_100,
                0x63,
            )],
        )]);
        let err = resolver
            .find_next_signals(at)
            .expect_err("a found transaction still needs the chain tip");
        assert!(
            matches!(err, Error::MissingChainTip { .. }),
            "expected MissingChainTip, got {err:?}"
        );
    }

    /// The sidecar lookup table is keyed by each sidecar update's recomputed
    /// JSON Document Hash, so an update that does not hash to the signal bytes
    /// is never matched to the signal. Here the sidecar holds a version-2
    /// update with the same sourceHash and targetVersionId as the announced
    /// one — only its hash differs — and the announcement resolves to
    /// MISSING_UPDATE_DATA naming the signal bytes, rather than applying the
    /// wrong update. The matching update resolves as usual.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals"
    /// (resolve.md:153-156), sidecar arm.
    #[test]
    fn a_sidecar_update_not_hashing_to_the_signal_bytes_is_missing_update_data() {
        let (initial, update1, _update2) = chained_two_updates();
        let (_initial, other_v2, _update_v3, _update_v4) = chained_rotation_then_two_more();
        assert_ne!(other_v2.hash(), update1.hash(), "different updates");
        assert_eq!(
            other_v2.source_hash, update1.source_hash,
            "both updates are built on the initial document"
        );
        assert_eq!(
            other_v2.target_version_id, update1.target_version_id,
            "both updates target version 2"
        );
        let addresses = chain_beacon_addresses(&initial);
        let options = || ResolutionOptions {
            sidecar_data: Some(SidecarData::new(None, vec![update1.clone()], None, None)),
            ..test_options()
        };

        let fixture = capture_fixture(vec![
            (
                addresses[0].as_str(),
                vec![confirmed_signal_tx(
                    other_v2.hash(),
                    200,
                    1_700_000_000,
                    0x64,
                )],
            ),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, Vec::new()),
        ]);
        let resolver = Resolver::new(initial.clone(), options()).expect("the options are valid");
        let (result, _rounds) = drive_capture_rounds(resolver, &fixture, "test/foreign-hash");
        match result.expect_err("no sidecar update hashes to the signal bytes") {
            Error::Btcr2Error(Btcr2Error::MissingUpdateData { update_hash }) => {
                assert_eq!(
                    update_hash,
                    other_v2.hash(),
                    "the error names the signal bytes"
                );
            }
            other => panic!("expected MissingUpdateData, got {other:?}"),
        }

        let fixture = capture_fixture(vec![
            (
                addresses[0].as_str(),
                vec![confirmed_signal_tx(
                    update1.hash(),
                    200,
                    1_700_000_000,
                    0x65,
                )],
            ),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
        ]);
        let resolver = Resolver::new(initial, options()).expect("the options are valid");
        let (result, _rounds) = drive_capture_rounds(resolver, &fixture, "test/matching-hash");
        let result = result.expect("the matching update is found and applied");
        assert_eq!(u64::from(result.document_metadata.version_id), 2);
    }

    /// The beacon v2 adds has no history. Its round is empty, but the tuples
    /// parked while it was fetched (v3, v4) are still waiting and must still
    /// apply: an empty round ends the walk only when nothing is parked.
    #[test]
    fn parked_signals_still_apply_when_the_rotated_in_beacon_has_no_history() {
        let (initial, update_v2, update_v3, update_v4) = chained_rotation_then_two_more();
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0xb2);
        let tx_v3 = confirmed_signal_tx(update_v3.hash(), 300, 1_700_000_100, 0xb3);
        let tx_v4 = confirmed_signal_tx(update_v4.hash(), 400, 1_700_000_200, 0xb4);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v2, tx_v4]),
            (addresses[1].as_str(), vec![tx_v3]),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, Vec::new()),
        ]);

        let sidecar = SidecarData::new(None, vec![update_v2, update_v3, update_v4], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/parked");

        let result = result.expect("the parked tuples apply after the empty round");
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            4,
            "v3 and v4 were parked behind the added beacon's round and must still apply"
        );
        assert_eq!(
            rounds.len(),
            2,
            "the genesis round, then the added beacon's (empty) round: {rounds:?}"
        );
        assert_eq!(
            rounds[1],
            vec![ROTATED_BEACON_ADDRESS.to_string()],
            "round 2 asks only for the beacon v2 introduced"
        );
    }

    /// The interleaved history under a `versionTime` bound. The parked v4 is
    /// judged against the bound on the merged pool, through the block-
    /// mediantime request path: the merged batch asks for the one block it
    /// does not hold yet (v3's), v3's mediantime is within the bound and v4's
    /// is not, so the walk resolves version 3.
    #[test]
    fn interleaved_history_under_a_version_time_bound_requests_the_parked_tuples_blocks() {
        let (initial, update_v2, update_v3, update_v4) = chained_rotation_then_two_more();
        let addresses = chain_beacon_addresses(&initial);
        let t0: i64 = 1_700_000_000;
        let block_aa = "aa".repeat(32);
        let block_bb = "bb".repeat(32);
        let block_cc = "cc".repeat(32);
        let tx_v2 = confirmed_signal_tx_in_block(update_v2.hash(), 200, t0, &block_aa, 0xc2);
        let tx_v3 = confirmed_signal_tx_in_block(update_v3.hash(), 300, t0 + 100, &block_bb, 0xc3);
        let tx_v4 = confirmed_signal_tx_in_block(update_v4.hash(), 400, t0 + 200, &block_cc, 0xc4);
        let mut fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v4, tx_v2]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, vec![tx_v3]),
        ]);
        for (hash, mediantime) in [
            (&block_aa, t0),
            (&block_bb, t0 + 100),
            (&block_cc, t0 + 200),
        ] {
            fixture.blocks.insert(
                hash.clone(),
                serde_json::json!({ "id": hash, "mediantime": mediantime }),
            );
        }

        let sidecar = SidecarData::new(None, vec![update_v2, update_v3, update_v4], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(t0 + 150)),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) =
            drive_capture_rounds(resolver, &fixture, "test/interleaved-version-time");

        let result = result.expect("the bound resolves the document in effect at versionTime");
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            3,
            "v4's block mediantime is after the bound; v3's is within it"
        );
        assert_eq!(rounds.len(), 4, "rounds: {rounds:?}");
        assert_eq!(rounds[0], addresses, "round 1 asks for the genesis beacons");
        let mut first_blocks = rounds[1].clone();
        first_blocks.sort();
        assert_eq!(
            first_blocks,
            vec![format!("block/{block_aa}"), format!("block/{block_cc}")],
            "the genesis batch asks for the blocks of both tuples above the current version"
        );
        assert_eq!(
            rounds[2],
            vec![ROTATED_BEACON_ADDRESS.to_string()],
            "the added beacon is scanned after v2 applies, with v4 parked"
        );
        assert_eq!(
            rounds[3],
            vec![format!("block/{block_bb}")],
            "the merged pool asks only for the block it does not hold yet (v3's)"
        );
    }

    /// v3 exists nowhere: not on the genesis beacons and not on the beacon v2
    /// added. The added beacon is scanned BEFORE the gap is judged, and the
    /// gap is then real, so LATE_PUBLISHING is still raised.
    #[test]
    fn a_genuine_version_gap_still_raises_late_publishing_after_a_rotation() {
        let (initial, update_v2, _update_v3, update_v4) = chained_rotation_then_two_more();
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0xd5);
        let tx_v4 = confirmed_signal_tx(update_v4.hash(), 400, 1_700_000_200, 0xd6);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v2, tx_v4]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, Vec::new()),
        ]);

        let sidecar = SidecarData::new(None, vec![update_v2, update_v4], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/version-gap");

        let err = result.expect_err("version 3 was never announced anywhere");
        assert!(
            matches!(err, Error::LatePublishingError),
            "expected LatePublishingError, got {err:?}"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the added beacon was scanned before the gap was judged"
        );
    }

    /// A patch that REPLACES the first genesis beacon (A, `/service/0`) with a
    /// Singleton beacon at [`ROTATED_BEACON_ADDRESS`] (D): the beacon-set
    /// change under which A's later signals must be ignored (Process Next
    /// Update step 4) while D's round is still forced.
    fn chain_beacon_replacement_patch(did: &crate::identifier::Did) -> json_patch::Patch {
        serde_json::from_value(serde_json::json!([
            {"op": "remove", "path": "/service/0"},
            {"op": "add", "path": "/service/-", "value": {
                "id": format!("{}#rotatedBeacon", did.encode()),
                "type": "SingletonBeacon",
                "serviceEndpoint": format!("bitcoin:{ROTATED_BEACON_ADDRESS}"),
            }}
        ]))
        .expect("the replacement patch is a valid RFC 6902 op array")
    }

    /// A patch that REMOVES the first genesis beacon (A, `/service/0`) and
    /// adds nothing: the beacon set shrinks, so no second round is forced and
    /// A's later tuples are judged in the SAME pool that removed A.
    fn chain_beacon_removal_patch() -> json_patch::Patch {
        serde_json::from_value(serde_json::json!([
            {"op": "remove", "path": "/service/0"}
        ]))
        .expect("the removal patch is a valid RFC 6902 op array")
    }

    /// The initial document plus three chained signed updates: v2 REPLACES
    /// genesis beacon A with D, v3 and v4 are benign. Built exactly like
    /// [`chained_rotation_then_two_more`], differing only in v2's patch.
    fn chained_replacement_then_two_more() -> (InitialDocument, Update, Update, Update) {
        let (did, initial) = chain_initial_document();
        let vm_id = format!("{}#initialKey", did.encode());

        let v2 = NonZeroU64::new(2).expect("2 is non-zero");
        let update_v2 = Document::from(initial.clone())
            .construct_signed_update(
                chain_beacon_replacement_patch(&did),
                v2,
                &vm_id,
                chain_secret_key(),
            )
            .expect("the replacement update constructs against the initial document");

        let mut after_v2 = initial.clone();
        after_v2
            .apply_update(&update_v2, &AnnouncingBlock::fixed())
            .expect("the replacement update applies to the initial document");

        let v3 = NonZeroU64::new(3).expect("3 is non-zero");
        let update_v3 = Document::from(after_v2.clone())
            .construct_signed_update(chain_benign_patch(&vm_id), v3, &vm_id, chain_secret_key())
            .expect("update #3 constructs against the post-replacement document");

        let mut after_v3 = after_v2;
        after_v3
            .apply_update(&update_v3, &AnnouncingBlock::fixed())
            .expect("update #3 applies to the post-replacement document");

        let v4 = NonZeroU64::new(4).expect("4 is non-zero");
        let update_v4 = Document::from(after_v3)
            .construct_signed_update(chain_benign_patch(&vm_id), v4, &vm_id, chain_secret_key())
            .expect("update #4 constructs against the post-update-3 document");

        (initial, update_v2, update_v3, update_v4)
    }

    /// The initial document plus two chained signed updates: v2 REMOVES
    /// genesis beacon A (adds nothing), v3 is benign against the two-beacon
    /// document.
    fn chained_removal_then_one_more() -> (InitialDocument, Update, Update) {
        let (did, initial) = chain_initial_document();
        let vm_id = format!("{}#initialKey", did.encode());

        let v2 = NonZeroU64::new(2).expect("2 is non-zero");
        let update_v2 = Document::from(initial.clone())
            .construct_signed_update(chain_beacon_removal_patch(), v2, &vm_id, chain_secret_key())
            .expect("the removal update constructs against the initial document");

        let mut after_v2 = initial.clone();
        after_v2
            .apply_update(&update_v2, &AnnouncingBlock::fixed())
            .expect("the removal update applies to the initial document");

        let v3 = NonZeroU64::new(3).expect("3 is non-zero");
        let update_v3 = Document::from(after_v2)
            .construct_signed_update(chain_benign_patch(&vm_id), v3, &vm_id, chain_secret_key())
            .expect("update #3 constructs against the post-removal document");

        (initial, update_v2, update_v3)
    }

    /// Genesis beacons A, B, C; v2 (announced from B) removes A and adds D;
    /// A's history then announces a v3 that chains correctly onto v2. v3 is
    /// ignored: by the time its tuple is taken, A is no longer a beacon of
    /// the document.
    ///
    /// Parked path: v2's apply adds D, so v3's tuple is parked while D's
    /// (empty) round is fetched and re-enters through `pending_signals`; the
    /// presence check runs on the merged pool. Without the rule v3 would
    /// apply (its sourceHash matches) and the key that controlled A would
    /// have advanced a document that rotated away from it.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 4
    /// (resolve.md:181).
    #[test]
    fn a_signal_from_a_removed_beacon_is_ignored() {
        let (initial, update_v2, update_v3, _update_v4) = chained_replacement_then_two_more();
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0xe2);
        let tx_v3 = confirmed_signal_tx(update_v3.hash(), 300, 1_700_000_100, 0xe3);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v3]),
            (addresses[1].as_str(), vec![tx_v2]),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, Vec::new()),
        ]);

        let sidecar = SidecarData::new(None, vec![update_v2, update_v3], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/removed-beacon");

        let result = result.expect("an ignored tuple is not an error");
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            2,
            "v3 was announced from a beacon v2 removed, so it is ignored"
        );
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 200 + 1),
            "confirmations derive from v2's block; the ignored tuple set nothing"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the genesis round, then the round for the beacon v2 added"
        );
    }

    /// Under a `versionTime` bound, an ignored tuple is ignored BEFORE the
    /// bound is evaluated (step 4 precedes step 5): v2 removes A in block
    /// `aa`; A's history announces v3 in block `bb`; both blocks are within
    /// the bound. v3 must NOT apply — not because of the bound (it is within
    /// it) but because A is gone — and the walk continues to its end.
    ///
    /// Same-pool path: the removal adds no beacon, so nothing is parked and
    /// v3's tuple is taken from the very pool whose earlier apply removed A.
    /// The block round asks for both blocks (the mediantime pre-pass does not
    /// filter on beacon presence), and no beacon round follows.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 4
    /// (resolve.md:181) before step 5 (resolve.md:182-185).
    #[test]
    fn an_ignored_tuple_does_not_stop_a_version_time_walk() {
        let (initial, update_v2, update_v3) = chained_removal_then_one_more();
        let addresses = chain_beacon_addresses(&initial);
        let t0: i64 = 1_700_000_000;
        let block_aa = "aa".repeat(32);
        let block_bb = "bb".repeat(32);
        let tx_v2 = confirmed_signal_tx_in_block(update_v2.hash(), 200, t0, &block_aa, 0xe4);
        let tx_v3 = confirmed_signal_tx_in_block(update_v3.hash(), 300, t0 + 100, &block_bb, 0xe5);
        let mut fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v3]),
            (addresses[1].as_str(), vec![tx_v2]),
            (addresses[2].as_str(), Vec::new()),
        ]);
        for (hash, mediantime) in [(&block_aa, t0), (&block_bb, t0 + 100)] {
            fixture.blocks.insert(
                hash.clone(),
                serde_json::json!({ "id": hash, "mediantime": mediantime }),
            );
        }

        let sidecar = SidecarData::new(None, vec![update_v2, update_v3], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            version_time: Some(ts(t0 + 200)),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) =
            drive_capture_rounds(resolver, &fixture, "test/removed-beacon-version-time");

        let result = result.expect("the walk ends normally after the ignored tuple");
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            2,
            "v3's block is within the bound; it is skipped because A was removed, not \
             because of versionTime"
        );
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 200 + 1),
            "confirmations derive from v2's block"
        );
        assert_eq!(rounds.len(), 2, "rounds: {rounds:?}");
        assert_eq!(rounds[0], addresses, "round 1 asks for the genesis beacons");
        let mut blocks = rounds[1].clone();
        blocks.sort();
        assert_eq!(
            blocks,
            vec![format!("block/{block_aa}"), format!("block/{block_bb}")],
            "the pre-pass asks for both tuples' blocks; presence is judged per tuple, later"
        );
    }

    /// A version gap on a REMOVED beacon is not a gap at all: v2 removes A
    /// and adds D; A's history announces v4 and nothing anywhere announces
    /// v3. Because A's tuple is ignored before its `targetVersionId` is
    /// checked (step 4 precedes step 6), no LATE_PUBLISHING is raised and the
    /// document resolves at version 2. Contrast
    /// `a_genuine_version_gap_still_raises_late_publishing_after_a_rotation`,
    /// where the same gap on a beacon still declared IS late publishing.
    ///
    /// Parked path: v4 is parked behind D's empty round and re-enters through
    /// `pending_signals`.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 4
    /// (resolve.md:181) before step 6 (resolve.md:186).
    #[test]
    fn a_removed_beacons_version_gap_is_ignored_not_late_publishing() {
        let (initial, update_v2, _update_v3, update_v4) = chained_replacement_then_two_more();
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0xe6);
        let tx_v4 = confirmed_signal_tx(update_v4.hash(), 400, 1_700_000_200, 0xe7);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_v4]),
            (addresses[1].as_str(), vec![tx_v2]),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, Vec::new()),
        ]);

        let sidecar = SidecarData::new(None, vec![update_v2, update_v4], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/removed-beacon-gap");

        let result = result.expect("a gap announced only from a removed beacon is ignored");
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            2,
            "v4 from the removed beacon is ignored before its version is checked"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the added beacon was still scanned before the pool drained"
        );
    }

    /// A conflicting v2 on a REMOVED beacon never reaches Confirm Duplicate
    /// Update: v2 (announced from B at height 200) removes A and adds D; A's
    /// history announces a DIFFERENT update that also targets version 2, at
    /// height 250. Under the ascending (version, height) sort B's v2 is
    /// taken first and applies; A's v2' is then ignored — no hash comparison,
    /// no LATE_PUBLISHING — and the document resolves at version 2 with no A
    /// beacon.
    ///
    /// A LOWER-height conflicting v2 on A is not a reachable "ignored" case:
    /// the sort takes it first, while A is still present, so it applies and
    /// B's v2 becomes the conflict — which is the ordinary late-publishing
    /// outcome, not this rule.
    ///
    /// Parked path: v2' is parked behind D's empty round.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 4
    /// (resolve.md:181) before step 6 and Confirm Duplicate Update
    /// (resolve.md:205).
    #[test]
    fn a_removed_beacons_conflicting_announcement_never_reaches_confirm_duplicate() {
        let (initial, update_v2, _update_v3, _update_v4) = chained_replacement_then_two_more();
        let (_initial, conflicting_v2, _update3) = chained_two_updates();
        assert_eq!(
            conflicting_v2.target_version_id, update_v2.target_version_id,
            "both updates target version 2"
        );
        assert_ne!(
            conflicting_v2.hash(),
            update_v2.hash(),
            "the two version-2 updates are different updates"
        );
        let addresses = chain_beacon_addresses(&initial);
        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0xe8);
        let tx_conflict = confirmed_signal_tx(conflicting_v2.hash(), 250, 1_700_000_050, 0xe9);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx_conflict]),
            (addresses[1].as_str(), vec![tx_v2]),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, Vec::new()),
        ]);

        let sidecar = SidecarData::new(None, vec![update_v2, conflicting_v2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let (result, rounds) =
            drive_capture_rounds(resolver, &fixture, "test/removed-beacon-conflict");

        let result = result.expect("a conflicting announcement from a removed beacon is ignored");
        assert_eq!(u64::from(result.document_metadata.version_id), 2);
        assert_eq!(
            result.document_metadata.confirmations,
            Some(TEST_CHAIN_TIP - 200 + 1),
            "confirmations derive from the applied v2's block"
        );
        assert!(
            !result
                .document
                .fields
                .service
                .iter()
                .any(|beacon| beacon.address().to_string() == addresses[0]),
            "the resolved document no longer declares beacon A"
        );
        assert_eq!(
            rounds,
            vec![addresses, vec![ROTATED_BEACON_ADDRESS.to_string()]],
            "the added beacon was scanned; the conflict was parked and then ignored"
        );
    }

    /// A history keyed by an address the document declares no beacon at was
    /// never requested: the driver has mislabelled its answer, and the
    /// resolver refuses it as a driver error rather than attributing its
    /// signals to some beacon. The error is a precondition, not a resolution
    /// outcome, so it carries no problem-details body.
    #[test]
    fn a_history_for_an_undeclared_address_is_a_driver_error() {
        let (initial, update_v2, _update_v3) = chained_two_updates();
        let tx_v2 = confirmed_signal_tx(update_v2.hash(), 200, 1_700_000_000, 0xea);
        let sidecar = SidecarData::new(None, vec![update_v2], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let ResolverState::Requests(next, requests) = resolver.resolve().expect("Init step") else {
            panic!("expected Requests from Init step");
        };
        assert!(
            !requests
                .values()
                .flatten()
                .any(|req| address_from_txs_uri(req.uri()) == ROTATED_BEACON_ADDRESS),
            "the genesis document declares no beacon at the rotated address"
        );

        let mislabelled = HashMap::from([(ROTATED_BEACON_ADDRESS.to_string(), vec![tx_v2])]);
        let err = next
            .process_responses(mislabelled)
            .resolve()
            .expect_err("a history for an undeclared address is refused");
        assert!(
            matches!(&err, Error::UnrequestedBeaconHistory { address } if address == ROTATED_BEACON_ADDRESS),
            "expected UnrequestedBeaconHistory naming the address, got {err:?}"
        );
        assert!(
            err.details().is_none(),
            "a driver precondition carries no spec problem details"
        );
    }

    /// A request the capture has no key for is a bug in the fixture or in the
    /// addresses the resolver derived. Serving an empty array instead — the
    /// permissive default the client crate's fake transport uses — would let a
    /// resolver that derived the WRONG addresses pass.
    #[test]
    #[should_panic(expected = "no captured response for")]
    fn capture_pump_panics_on_an_address_the_fixture_never_captured() {
        let (initial, update) = chained_beacon_rotation();
        let addresses = chain_beacon_addresses(&initial);
        let tx = confirmed_signal_tx(update.hash(), 700, 1_700_000_000, 0xd2);
        // The rotated beacon is deliberately absent.
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
        ]);

        let sidecar = SidecarData::new(None, vec![update], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let _ = drive_capture_rounds(resolver, &fixture, "minted/late-publishing-fork");
    }

    /// The FSM's own error is RETURNED, not raised as a panic, so a scenario
    /// minted to fail can assert the error it must produce.
    #[test]
    fn capture_pump_returns_an_fsm_error_instead_of_panicking() {
        let (initial, update1, _update2) = chained_two_updates();
        let addresses = chain_beacon_addresses(&initial);
        let tx = confirmed_signal_tx(update1.hash(), 700, 1_700_000_000, 0xe1);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
        ]);

        // No sidecar: the announced update hash resolves to no update data.
        let resolver = Resolver::new(initial, test_options()).expect("the options are valid");
        let (result, rounds) = drive_capture_rounds(resolver, &fixture, "test/missing-update");

        let err = result.expect_err("an announcement with no update data must error");
        assert!(
            matches!(err, Error::Btcr2Error(Btcr2Error::MissingUpdateData { .. })),
            "expected MissingUpdateData, got {err:?}"
        );
        assert_eq!(
            rounds.len(),
            1,
            "the round that produced the error is still logged"
        );
    }

    /// A resolve that keeps asking for beacon signals fails visibly rather than
    /// hanging CI. Driven through the bounded form with a bound of one, because
    /// provoking the real bound would take eight chained beacon rotations to
    /// say the same thing.
    #[test]
    #[should_panic(expected = "still requesting beacon signals after 1 round")]
    fn capture_pump_panics_when_the_resolve_does_not_converge() {
        let (initial, update) = chained_beacon_rotation();
        let addresses = chain_beacon_addresses(&initial);
        let tx = confirmed_signal_tx(update.hash(), 700, 1_700_000_000, 0xd3);
        let fixture = capture_fixture(vec![
            (addresses[0].as_str(), vec![tx]),
            (addresses[1].as_str(), Vec::new()),
            (addresses[2].as_str(), Vec::new()),
            (ROTATED_BEACON_ADDRESS, Vec::new()),
        ]);

        let sidecar = SidecarData::new(None, vec![update], None, None);
        let options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..test_options()
        };
        let resolver = Resolver::new(initial, options).expect("the options are valid");
        let _ = drive_capture_within(resolver, &fixture, "test/rotation", 1);
    }

    /// The discarding wrapper is the same pump: same result, log dropped.
    #[test]
    fn capture_pump_wrapper_drops_the_round_log() {
        let (_did, initial) = chain_initial_document();
        let addresses = chain_beacon_addresses(&initial);
        let fixture = capture_fixture(
            addresses
                .iter()
                .map(|address| (address.as_str(), Vec::new()))
                .collect(),
        );

        let resolver = Resolver::new(initial, test_options()).expect("the options are valid");
        let result = drive_to_resolved_from_capture(resolver, &fixture, "test/all-empty")
            .expect("a capture with no signals resolves");
        assert_eq!(u64::from(result.document_metadata.version_id), 1);
    }
}
