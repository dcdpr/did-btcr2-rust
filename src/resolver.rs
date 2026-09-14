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
/// `MissingChainTip`) do not:
/// they mean the caller driving the sans-I/O loop did not supply what a
/// request asked for, which is a bug in the driver and not a statement about
/// the DID, so they are deliberately not folded into the spec vocabulary.
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
            Error::MissingBlockMediantime { .. } | Error::MissingChainTip { .. } => None,
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
    /// Block height of the MOST-RECENTLY-APPLIED unique update, the basis for
    /// `confirmations` (resolve.md:38,57). Overwritten on each unique apply; under
    /// the ascending (target_version_id, block_height) sort this ends as the
    /// highest-version applied update's height. The lower-height dedup fold-in
    /// (resolve.md:57 footnote 2) survives only as a defensive guard in the
    /// duplicate branch. `None` until the first update is applied.
    applied_block_height: Option<u32>,
    rpc_host: String,
    request_cache: HashSet<esploda::http::Uri>,
    /// `mediantime` of confirming blocks, fetched for updates whose proof
    /// carries `expires` and for every applicable update under a
    /// `versionTime` bound.
    block_mediantimes: HashMap<BlockHash, DateTime<Utc>>,
    /// Signals already matched to sidecar updates but not yet processed,
    /// parked when an applied update introduced a beacon: Find Beacon Signals
    /// precedes every Process Next Update (resolve.md:40-46), so the new
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
            applied_block_height: None,
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
    /// The loop is the spec's (resolve.md:40-46): scan every beacon not yet
    /// scanned, then take ONE tuple, apply it, and scan again. Each round's
    /// tuples are merged with any parked from an earlier round, sorted, and
    /// applied in order; after every applied update the beacon set is
    /// re-checked, and if the update introduced a beacon the tuples not yet
    /// processed are parked while that beacon's history is fetched.
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

                // Find Beacon Signals (resolve.md:122-146): build the tuples
                // (raises MISSING_UPDATE_DATA here, before the version_time bound —
                // resolve.md:145-147).
                signals.extend(self.process_beacon_signals(next_signals)?);

                // Process Next Update step 3 (resolve.md:167): sort the union
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
    /// every applied update. An update that introduced a beacon yields a
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
        // compares `expires` against it, and "Process Next Update" step 4
        // compares it against `versionTime`. Ask for every block still
        // missing, once; a second pass without it is the caller's error.
        //
        // The mediantime is read in the loop below for any tuple above the
        // current version: the step-4 gate and, on apply, the `expires`
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

        // Most-recently-applied UNIQUE update's version, tracked as a
        // loop-local (no struct field / no public-API change). Under the
        // ascending (target_version_id, block_height) sort in `resolve` this is
        // simply the last unique apply; it keys the defensive dedup guard in the
        // duplicate branch below.
        let mut most_recent_applied_version: Option<NonZeroU64> = None;

        // Taken one at a time so the unprocessed remainder can be parked when
        // an applied update introduces a beacon.
        let mut signals = signals.into_iter();
        while let Some(AppliedSignal {
            update,
            block_height,
            block_time,
            block_hash,
        }) = signals.next()
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
                // resolve.md:57 footnote 2): fold in the lower height when
                // this duplicate targets the most-recently-applied update.
                // Under the ascending (target_version_id, block_height) sort
                // in `resolve` the lowest-height announcement is ALWAYS
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

            // Process Next Update step 4 (resolve.md:168-177): the
            // versionTime bound applies to ANY tuple whose targetVersionId is
            // more than current_version_id (first bullet), evaluated against
            // THIS tuple's block. The duplicate branch above (`<= current`)
            // runs first and never reaches this, which is footnote 4: under
            // the ascending (target_version_id, block_height) sort a duplicate
            // announcement is processed before a later-version unique update,
            // so a DUPLICATE whose block is after versionTime must never abort
            // the loop and suppress a later unique update announced within
            // versionTime. The gate deliberately runs BEFORE the version-gap
            // check (step 10.3): step 4 precedes step 6 in the spec, so a
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
                    )))?;
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

                // confirmations = block of the most-recently-applied UNIQUE
                // update (resolve.md:38,57): overwrite here, so after the
                // ascending-version loop this holds the highest-version (most
                // recent) applied update's height.
                self.applied_block_height = Some(block_height);
                most_recent_applied_version = Some(update.target_version_id);

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
                // (resolve.md:40-46): a beacon this update introduced is
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

        // Step 12.
        let ResolverState::Requests(fsm, signals) = self.next_signals_requests()? else {
            unreachable!()
        };
        if signals.is_empty() {
            // Every beacon has been scanned and every update applied: the
            // history is exhausted (Process Next Update step 2).
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
    fn find_next_signals(
        &self,
        transactions: HashMap<BeaconType, Vec<Transaction>>,
    ) -> Result<Vec<NextSignal>, Error> {
        let mut signals = Vec::new();
        for (beacon_type, txs) in transactions {
            for tx in txs {
                // Spec MANDATES the last output (resolve.md:126 + terminology.md:221: Signal
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
            applied_block_height: self.applied_block_height,
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
    /// `confirmations` is `tip.saturating_sub(applied_block_height)
    /// .saturating_add(1)` for the most recently applied unique update, and
    /// `0` when the tip is known but no update was applied — the spec starts
    /// `block_confirmations` at `0` and lists `confirmations` as REQUIRED
    /// (resolve.md "Process", footnote 2). `None` is reserved for a caller
    /// that supplied no chain tip: nothing can be counted, and an invented
    /// `0` would read as "the update is unconfirmed".
    fn terminal_state(&self) -> ResolutionResult {
        let confirmations = self.chain_tip_height.map(|tip| {
            self.applied_block_height
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
            resolution_metadata: crate::document::ResolutionMetadata::default(),
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

/// A beacon signal paired with the sidecar [`Update`] it resolves to, carrying
/// the confirming block height forward for the confirmations computation
/// Produced by [`Resolver::process_beacon_signals`].
#[derive(Debug)]
struct AppliedSignal {
    update: Update,
    block_height: u32,
    block_time: DateTime<Utc>,
    /// Hash of the confirming block: the key under which its `mediantime` is
    /// requested and held when the update's proof carries `expires`.
    block_hash: BlockHash,
}

impl Resolver<WaitingForResponses> {
    fn from_init(resolver: Resolver) -> Self {
        resolver.with_state(WaitingForResponses)
    }

    /// Feed the blockchain transactions requested by a
    /// [`ResolverState::Requests`] back into the FSM, returning a [`Resolver`]
    /// ready to be driven another step. Each address's list must be its
    /// complete confirmed history (see [`ResolverState::Requests`]); the
    /// resolver cannot tell a truncated page from a short history.
    pub fn process_responses(
        mut self,
        transactions: HashMap<BeaconType, Vec<Transaction>>,
    ) -> Resolver {
        self.fsm = ResolverFsm::FindNextSignals(transactions);

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

    /// FSM is ready to find the next beacon signals.
    FindNextSignals(HashMap<BeaconType, Vec<Transaction>>),

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
    /// [`Resolver::<WaitingForResponses>::process_responses`]: for each
    /// request, the COMPLETE confirmed transaction history of that address —
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
    /// mediantime ("Process Next Update" step 4). One
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
/// Update" steps 1 and 4).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::Document;
    use crate::test_vectors::{
        AssertionKind, ChainFixture, DRIVEN_FLOOR, FIXTURES_WITHOUT_SIGNAL_BLOCKS,
        NUMBER_ENCODED_VERSION_ID, SKIP_OVERRIDES, SkipOverride, Vector, VectorIdType, discover,
        expected_driven_with, field_bool, field_hex, field_nonzero_version_id, field_str,
        field_u64, field_version_id, network_dirs_with_vectors, read_chain_fixture,
        read_fixture_or_skip, read_vector_fixture, reconcile_driven_with, redundant_overrides,
        render_minted_summary, render_summary_with, stale_overrides, test_suite_checked_out,
        unclassified_rows_with,
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
    /// skipped-with-reason (`Unanchored`, `CasDelivery`, `SmtDelivery`,
    /// `UnsupportedBeaconType`); its summary table is the place to read the
    /// coverage story, not a narrative in this comment.
    ///
    /// Observation-dependent metadata is whitelisted: `deactivated` is asserted
    /// BY VALUE against the vector's stated flag on a driven row; `updated` and
    /// `created` are environment-derived and drift, so they are asserted only by
    /// presence/type when present, NEVER by literal value. `confirmations` stays
    /// type-only in the whitelist that runs for EVERY discovered vector, and is
    /// additionally asserted on a driven ON-CHAIN row — by VALUE against the
    /// vector's stated number on the frozen regtest chain, and by PROVENANCE
    /// (derived from the most-recently-applied update's captured block height)
    /// on the still-mining mutinynet chain, which states none. It is a fixed
    /// input there rather than a drifting observation because the captured tip
    /// is pinned into the resolution options. mutinynet vectors omit
    /// `confirmations` entirely and carry `created: null`; indexing a missing key
    /// yields `Value::Null`, which the `is_null` guards already tolerate.
    /// `versionId` carries three separate checks: it is READ through
    /// `version_id_u64`, which accepts the regtest string encoding and the
    /// mutinynet number encoding and panics on anything else; its ENCODING is
    /// pinned to `NUMBER_ENCODED_VERSION_ID`, the explicit set of known-bad
    /// fixtures, in both directions; and on a driven row the resolved value is
    /// COMPARED against the vector's stated one. That comparison IS a
    /// cross-check with independent operands on the seven rows fed from captured
    /// chain fixtures: their stated version is 2, and the resolver only reaches
    /// it by applying an update announced by a captured beacon transaction. The
    /// crate's own emit-a-string / reject-a-number contract is pinned by the
    /// fixture-independent `DocumentMetadata` round-trip test in `document.rs`.
    ///
    /// RESOLUTION OPTIONS ARE ASSEMBLED IN ONE PLACE, from the vector's
    /// `resolutionOptions.sidecar` object verbatim, matching the capture tool's
    /// `resolution_options_for`. EXTERNAL (x1) genesis therefore comes from
    /// `resolve/input.json.resolutionOptions.sidecar.genesisDocument`, which
    /// `resolve_external` bridges into the initial document itself.
    /// `other.json.genesisDocument` exists for every external vector and is
    /// byte-identical where both are present, but reading it would hand the
    /// resolver a genesis document the vector intends to be fetched from
    /// content-addressed storage — asserting resolve logic while silently
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

    /// The `versionTime` a replay probe resolves at: one second before the
    /// earliest `mediantime` among the blocks confirming the capture's
    /// announcements, which is inside the walk's reach but before its first
    /// update. `None`, with a `SKIP` line naming the block and the re-capture
    /// command, when the fixture holds no `/block/{hash}` body to read that
    /// mediantime from — a capture taken before the tool recorded blocks. The
    /// set of such fixtures is pinned by `FIXTURES_WITHOUT_SIGNAL_BLOCKS`, so
    /// the skip is a ledger entry rather than a silent loss, and a re-capture
    /// turns the probe back on.
    fn version_time_probe_bound(f: &ChainFixture, id: &str) -> Option<DateTime<Utc>> {
        match f.earliest_signal_mediantime() {
            Ok(earliest) => Some(ts(earliest - 1)),
            Err(missing) => {
                assert!(
                    FIXTURES_WITHOUT_SIGNAL_BLOCKS.contains(&id),
                    "{id}: the capture holds no `/block/{missing}` body and is not listed in \
                     FIXTURES_WITHOUT_SIGNAL_BLOCKS"
                );
                eprintln!(
                    "SKIP: {id}: the versionTime probe compares against block mediantimes and \
                     the capture holds no `/block/{missing}` body; re-run capture to record the \
                     announcements' blocks"
                );
                None
            }
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

    /// The RESOLVE driver body, over an explicit override table so the same code
    /// path can be exercised with a hand-written skip in place.
    ///
    /// WHAT THE PROBES ON AN ON-CHAIN ROW BUY. The terminal assertion says the
    /// resolver ended up at the vector's expected document; on its own it cannot
    /// distinguish a resolver that WALKED v1 -> v2 from one that landed on the
    /// answer without reading the chain. Two probes close that:
    ///
    /// 1. The genesis reference — the same DID, the same options, resolved with
    ///    no signals fed — must DIFFER from the terminal document. A replay in
    ///    which nothing was applied fails here.
    /// 2. A `versionTime` one second before the earliest announcing block's
    ///    `mediantime` must return version 1 and that same genesis document,
    ///    having issued at least one request against the same capture. This
    ///    is the versionTime path's first coverage against REAL block times —
    ///    the unit tests use timestamps we chose — and it is the only
    ///    stop-where-asked bound observable on these rows. It needs the
    ///    capture's `/block/{hash}` bodies; a capture taken without them skips
    ///    the probe by name (`FIXTURES_WITHOUT_SIGNAL_BLOCKS`).
    ///
    /// THERE IS DELIBERATELY NO `versionId = 1` PROBE, and one must not be
    /// "restored". At `Init` the FSM returns `Resolved` when a `VersionId`
    /// target equals `current_version_id`, which starts at 1 — so `VersionId(1)`
    /// issues zero requests, never touches the capture, and cannot distinguish a
    /// real walk from a short-circuit. It would restate the genesis reference
    /// that probe 1 already builds independently. These rows have no other
    /// non-trivial `version_id` bound either: their expected version is 2, which
    /// is the terminal state. A mid-walk `version_id` bound is real coverage
    /// only on a chain with more than two versions.
    fn drive_resolve(vectors: &[Vector], overrides: &[SkipOverride]) {
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

            // Past genesis means the walk has to be fed real beacon signals, and
            // they come from this repository's captured chain snapshot for the
            // row. An absent capture panics by name rather than degrading into a
            // no-signal resolve that would then fail the versionId assertion for
            // an unrelated-looking reason.
            let on_chain = vector.expected_version_id > 1;
            let fixture = on_chain.then(|| read_chain_fixture(id));

            // ONE assembly for every vector shape, matching
            // `chain_capture::capture::resolution_options_for` line for line.
            // `SidecarData::from_json_value` always builds `update_lookup_table`
            // and sets `genesis_document` from the wire `genesisDocument` field;
            // `resolve_external` bridges that into the initial document itself
            // (`document.rs`'s `resolve_external_bridges_genesis_document_from_serde_path`
            // proves it, and `SidecarData::initial_document` is documented there
            // as the legacy in-memory shortcut). The capture tool assembles
            // options exactly this way, and capture and replay MUST match —
            // otherwise the refuse-to-write gate can bless a fixture this suite
            // then fails on.
            //
            // Do NOT reintroduce an `IntermediateDocument` branch for `x1`
            // vectors.
            //
            // Six vectors omit `resolutionOptions.sidecar` entirely (of the
            // driven rows, `mutinynet/k1/q5puld7y`): a resolve with nothing
            // supplied out of band. Indexing yields `Value::Null`, which is not
            // a JSON object and does not deserialize, so an absent sidecar is
            // normalized to `{}` — which yields the same empty `SidecarData` the
            // old default arm produced. That is a normalization of the INPUT
            // VALUE, not a second assembly: there is still exactly one
            // `SidecarData::from_json_value` call. The capture tool refuses an
            // absent sidecar instead, because a capture validated against zero
            // updates would pass vacuously; a genesis-era replay has nothing to
            // be vacuous about, since its whole expected document is asserted.
            let sidecar_json = input["resolutionOptions"]["sidecar"].clone();
            assert!(
                !on_chain || sidecar_json.is_object(),
                "{id}: a past-genesis vector must carry a \
                 resolve/input.json resolutionOptions.sidecar object — its beacon \
                 signals announce update hashes that are delivered out of band"
            );
            let sidecar_json = if sidecar_json.is_null() {
                serde_json::json!({})
            } else {
                sidecar_json
            };
            //
            // Wrapped in a factory because `Document::resolve` CONSUMES its
            // options and this row runs three resolutions — the terminal drive
            // and the two probes below. They must differ ONLY in the target
            // condition, or a probe would be testing a different resolution;
            // and a second hand-built assembly here would be exactly the
            // divergence the single assembly exists to prevent.
            //
            // Pinning the captured tip is also what makes `confirmations` a
            // fixed input rather than a moving observation.
            let make_options = |version_time: Option<DateTime<Utc>>| {
                let sidecar =
                    SidecarData::from_json_value(sidecar_json.clone()).unwrap_or_else(|e| {
                        panic!("{id}: resolve/input.json resolutionOptions.sidecar must parse: {e}")
                    });
                ResolutionOptions {
                    sidecar_data: Some(sidecar),
                    chain_tip_height: fixture.as_ref().map(|f| f.tip_height),
                    version_time,
                    ..test_options()
                }
            };

            let resolver = Document::resolve(&did, make_options(None))
                .unwrap_or_else(|e| panic!("{id}: the resolver must accept the vector: {e}"));
            let result = match &fixture {
                Some(f) => drive_to_resolved_from_capture(resolver, f, id)
                    .unwrap_or_else(|e| panic!("{id}: the captured chain must resolve: {e}")),
                None => resolve_with_no_signals(resolver),
            };

            // The resolved document and the spec test vector agree on EVERY
            // content field — id, the top-level `@context`, verificationMethod
            // (incl. publicKeyMultibase), the SingletonBeacon services +
            // endpoints, and the four relationship sets. Both the KEY (k1) path
            // (genesis generated deterministically) and the EXTERNAL (x1) path
            // (genesis supplied verbatim) emit the spec `@context`
            // (`www.w3.org/ns/did/v1.1` / `btcr2.dev/context/v1`) and no
            // top-level `controller`, so the full content matches with no
            // field masking.
            let got = resolved_document_json(&result.document, id);
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

            if let Some(f) = &fixture {
                let signal = f.latest_signal().unwrap_or_else(|| {
                    panic!("{id}: the captured fixture must carry at least one beacon signal")
                });
                let derived = f
                    .tip_height
                    .saturating_sub(signal.block_height)
                    .saturating_add(1);
                match output["didDocumentMetadata"]["confirmations"].as_u64() {
                    // Frozen chain: the vector states a number, and the captured
                    // tip must reproduce it. Four vectors check one tip from four
                    // directions, so a bad tip or bad arithmetic cannot pass.
                    Some(expected) => assert_eq!(
                        result.document_metadata.confirmations,
                        Some(expected as u32),
                        "{id}: resolved confirmations must equal \
                         resolve/output.json.didDocumentMetadata.confirmations against the \
                         captured tip {}",
                        f.tip_height
                    ),
                    // Still-mining chain: the vector states no number, so assert
                    // PROVENANCE — confirmations must derive from the
                    // MOST-RECENTLY-APPLIED update's block.
                    //
                    // Honest about its strength: on a single-signal row this is a
                    // consistency check (the resolver used the captured signal's
                    // height rather than the tip, zero, or None), because there is
                    // only one height it could have used. It becomes a real "did
                    // it pick the LATEST?" test on a multi-signal chain, which is
                    // what a minted scenario supplies.
                    None => assert_eq!(
                        result.document_metadata.confirmations,
                        Some(derived),
                        "{id}: resolved confirmations must derive from the \
                         most-recently-applied update's block ({} at tip {})",
                        signal.block_height,
                        f.tip_height
                    ),
                }

                // The walk changed the document. The genesis reference is an
                // independent producer of the pre-walk state: same DID, same
                // options, no signals fed, so the resolver applies nothing.
                let genesis = resolve_with_no_signals(
                    Document::resolve(&did, make_options(None)).unwrap_or_else(|e| {
                        panic!("{id}: the resolver must accept the vector: {e}")
                    }),
                );
                let genesis_json = resolved_document_json(&genesis.document, id);
                assert_eq!(
                    genesis.document_metadata.version_id.get(),
                    1,
                    "{id}: a resolve with no signals fed is the genesis state"
                );
                assert_ne!(
                    genesis_json, got,
                    "{id}: the chain-driven walk must change the document; if genesis equals \
                     the terminal state the replay proved nothing"
                );

                // And it stops where asked. One second before the earliest
                // announcing block's mediantime is inside the walk's reach but
                // before its first update, so the bound — which the FSM cannot
                // short-circuit — must hold the answer at genesis.
                if let Some(bound) = version_time_probe_bound(f, id) {
                    let probe_resolver = Document::resolve(&did, make_options(Some(bound)))
                        .unwrap_or_else(|e| {
                            panic!("{id}: the resolver must accept the vector: {e}")
                        });
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
            }

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
                    .apply_update(&update, &AnnouncingBlock::fixed())
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
                doc.apply_update(&update, &AnnouncingBlock::fixed())
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
        // `find_next_signals` iterates the supplied `transactions` map and inspects
        // each tx's last output + confirmation status; it does NOT cross-check the
        // tx against the resolver's beacon addresses (that coupling only governs
        // request *generation* in `next_signals_requests`). The resolver doc is
        // re-homed onto the regtest k1 qgpakaw4 vector purely so a valid resolver
        // exists.
        let Some(mut resolver) = resolver_with(SidecarData::default(), Some(TEST_CHAIN_TIP)) else {
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

        // Unconfirmed pass: the same tx, now in the mempool, on its own. A needed
        // unconfirmed signal is not processed: no signal, no error.
        let json: serde_json::Value = serde_json::from_str(UNCONFIRMED_FIXTURE).unwrap();
        let mut first_tx = json["SingletonBeacon"][0].clone();
        first_tx["status"] = serde_json::json!({ "confirmed": false });
        let unconfirmed_txs: HashMap<BeaconType, Vec<Transaction>> =
            serde_json::from_value(serde_json::json!({ "SingletonBeacon": [first_tx] })).unwrap();

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
        let Some(resolver) = resolver_with(SidecarData::default(), Some(TEST_CHAIN_TIP)) else {
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
            ..test_options()
        };
        Some(Resolver::new(initial_document, resolution_options).expect("the options are valid"))
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
            ResolverState::BlockRequests(..) => {
                panic!("unexpected block request: no update in this test carries proof.expires")
            }
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
        Some(Resolver::new(initial_document, resolution_options).expect("the options are valid"))
    }

    /// `ResolutionOptions.esplora_url = Some(url)` overrides the resolver's
    /// request host; `Resolver::new` reads the caller-injected URL into
    /// `rpc_host`. Pure-construction, fully offline.
    #[test]
    fn esplora_url_some_overrides_rpc_host() {
        let url = "https://node.example/api".to_string();
        let Some(resolver) = resolver_from_options(ResolutionOptions {
            esplora_url: Some(url.clone()),
            ..test_options()
        }) else {
            return;
        };
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
    /// (targetVersionId, block_height) sort (resolve.md:167-171), and that choice
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
            block_hash: zero_block_hash(),
        };
        let signal_lo = NextSignal {
            beacon_type: BeaconType::Singleton,
            signal_bytes: update_lo.hash(),
            block_time: Utc::now(),
            block_height: 100,
            block_hash: zero_block_hash(),
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
                    block_hash: signal_hi.block_hash,
                },
                NextSignal {
                    beacon_type: signal_lo.beacon_type,
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

    /// A never-updated DID resolved with a chain tip reports `confirmations:
    /// 0` on the wire — present, as the spec requires — not an omitted key.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process" (`block_confirmations`
    /// starts at `0`; `confirmations` is REQUIRED in `didDocumentMetadata`).
    #[test]
    fn genesis_resolve_with_a_tip_reports_zero_confirmations() {
        let Some(resolver) = resolver_with(SidecarData::default(), Some(TEST_CHAIN_TIP)) else {
            return;
        };
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
    /// saturating arithmetic (tip > h, tip == h, tip < h), `0` when the tip is
    /// known but nothing applied, and `None` without a tip. This exercises only `terminal_state`'s formatting
    /// of `applied_block_height`, which is unchanged; the *accounting* of that
    /// height (most-recently-applied unique update, not a running min across
    /// distinct updates) is driven end-to-end by
    /// `confirmations_use_the_most_recently_applied_update` and
    /// `later_duplicate_does_not_raise_confirmations`.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:38,57.
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

        // Tip known, no applied update → confirmations 0: the spec's starting
        // value, and REQUIRED in the metadata, so it is emitted rather than
        // omitted.
        resolver.applied_block_height = None;
        assert_eq!(
            resolver.terminal_state().document_metadata.confirmations,
            Some(0)
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

        let ResolverState::Requests(next_state, _requests) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        let mut transactions: HashMap<BeaconType, Vec<Transaction>> = HashMap::new();
        transactions.insert(BeaconType::Singleton, vec![tx]);
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
    /// apply happens and the FSM asks for the next beacon round.
    fn answer_first_block_and_expect_next_round(
        next: Resolver<WaitingForBlockTimes>,
    ) -> Resolver<WaitingForResponses> {
        let mut mediantimes = HashMap::new();
        mediantimes.insert(zero_block_hash(), ts(HEADER_TIME - 3600));
        match next
            .process_block_times(mediantimes)
            .resolve()
            .expect("the first-round update applies once its block time is known")
        {
            ResolverState::Requests(next, _requests) => next,
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
        let next = answer_first_block_and_expect_next_round(next);

        let duplicate = confirmed_signal_tx_in_block(
            update.hash(),
            105,
            HEADER_TIME + 600,
            &"11".repeat(32),
            0xd2,
        );
        let mut transactions: HashMap<BeaconType, Vec<Transaction>> = HashMap::new();
        transactions.insert(BeaconType::Singleton, vec![duplicate]);
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
        let next = answer_first_block_and_expect_next_round(next);

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
        let mut transactions: HashMap<BeaconType, Vec<Transaction>> = HashMap::new();
        transactions.insert(BeaconType::Singleton, vec![duplicate, applicable]);
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

    /// Extract the beacon address from a `/address/{a}/txs` request path.
    ///
    /// The ADDRESS is the routing key, not the URI: the full URI embeds
    /// `rpc_host`, which differs between the capture endpoint and whatever the
    /// resolver was built with, so a URI match would miss on every fixture.
    /// Mirrors `chain_capture::record::address_from_txs_path` — including
    /// splitting any query string off first — so capture and replay key on the
    /// same string.
    fn address_from_txs_uri(uri: &esploda::http::Uri) -> &str {
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
    /// out of `ResolverState::Requests`, serve each one, merge the results into
    /// the `BeaconType` entry, feed them back. The ONE difference is where the
    /// bytes come from.
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

            let mut responses: HashMap<BeaconType, Vec<Transaction>> = HashMap::new();
            for (beacon_type, requests) in beacons {
                for req in requests {
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
                        .entry(beacon_type)
                        .or_default()
                        .extend(txs.iter().cloned());
                }
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
        let ResolverState::Requests(next_state, _requests) = resolver.resolve()? else {
            panic!("expected Requests from Init step");
        };
        let mut transactions: HashMap<BeaconType, Vec<Transaction>> = HashMap::new();
        transactions.insert(BeaconType::Singleton, txs);
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
                ResolverState::Requests(next, _requests) => {
                    let mut transactions: HashMap<BeaconType, Vec<Transaction>> = HashMap::new();
                    if let Some(txs) = first_round.take() {
                        transactions.insert(BeaconType::Singleton, txs);
                    }
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
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 4
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

        let ResolverState::Requests(next, _) = resolver.resolve().expect("Init step") else {
            panic!("expected Requests from Init step");
        };
        let mut transactions: HashMap<BeaconType, Vec<Transaction>> = HashMap::new();
        transactions.insert(BeaconType::Singleton, vec![tx]);
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
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 4,
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
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 4
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
    /// `versionTime` AFTER its block mediantime passes the step-4 gate and
    /// reaches the version-gap check, which raises LATE_PUBLISHING because
    /// v2 was never announced.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 4
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
    /// Spec: did-btcr2/src/operations/resolve.md "Process Next Update" step 4
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
    /// Spec: did-btcr2/src/operations/resolve.md:38,57.
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
    /// FIRST and becomes the confirmations height; the later h_high duplicate's
    /// defensive min is a no-op and does NOT raise it. With chain tip 300,
    /// confirmations = 300 - 100 + 1 = 201 (from h_low), never
    /// 300 - 200 + 1 = 101.
    ///
    /// This asserts the SORT-guaranteed lowest-height-first outcome, not a
    /// synthetic lower-than-applied duplicate (which cannot arise under the sort).
    ///
    /// Spec: did-btcr2/src/operations/resolve.md:57 footnote 2.
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
    /// steps 1, 2, 3 and 4 (resolve.md:163-171).
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
        // keeps a minted fixture from drifting into the number encoding the
        // upstream mutinynet vectors carry.
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

        // --- The mid-walk re-scan and the deactivation short-circuit, observed
        // --- by what WAS and was NOT asked -----------------------------------
        //
        // The v2 update adds a FOURTH beacon service. The beacon set is
        // re-checked after every applied update, so the walk asks for that
        // beacon's history right after v2 applies (round 2), before v3 is
        // taken. The deactivating v4 then resolves the document immediately:
        // no round follows it. Round 2's address is read off the capture — it
        // is the one captured key the genesis round did not ask for — so a
        // re-mint does not touch this test. A resolver that did not stop at
        // `deactivated` would issue a third round and be caught here.
        assert_eq!(
            rounds.len(),
            2,
            "{id}: the beacon v2 adds is scanned after v2 applies, and applying the \
             deactivating update must resolve immediately and process no further beacon \
             signals — rounds: {rounds:?}"
        );
        let mut requested = rounds[0].clone();
        requested.sort();
        let announced: Vec<String> = addresses.iter().map(|a| (*a).to_string()).collect();
        assert_eq!(
            requested, announced,
            "{id}: the first round must request exactly the genesis beacon addresses the \
             three updates were announced from"
        );
        let added: Vec<String> = f
            .addresses
            .keys()
            .filter(|address| !rounds[0].contains(address))
            .cloned()
            .collect();
        assert_eq!(
            added.len(),
            1,
            "{id}: the capture holds exactly one address beyond the genesis beacons — the \
             beacon v2 adds; captured keys: {:?}",
            f.addresses.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            rounds[1], added,
            "{id}: the second round must request exactly the beacon the v2 update added"
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
        if let Some(bound) = version_time_probe_bound(&f, id) {
            let (before, before_rounds) =
                drive_capture_rounds(resolver_for(None, Some(bound)), &f, id);
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
    /// Spec: did-btcr2/src/operations/resolve.md:189 (`LATE_PUBLISHING` MUST).
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
    /// Spec: did-btcr2/src/operations/resolve.md:55 (deactivated REQUIRED in metadata).
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
    /// Spec: did-btcr2/src/operations/resolve.md §"Process Next Update" step 2 (resolve.md:164-166)
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
        let Some(resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };

        let signal = NextSignal {
            beacon_type: BeaconType::Cas,
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
        let Some(resolver) = resolver_with(SidecarData::default(), None) else {
            return;
        };

        let signal = NextSignal {
            beacon_type: BeaconType::SparseMerkleTree,
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

    // ──────────────────────────────────────────────────────────────────────
    // Captured-chain replay: serving the resolver's OWN request URIs from the
    // bodies a capture recorded, keyed on the beacon address.
    // ──────────────────────────────────────────────────────────────────────

    /// A mutinynet address none of the three deterministically generated
    /// beacons uses, so a rotation onto it is observable as a NEW request in a
    /// SECOND round. Lifted from a committed mutinynet capture, so it is a real
    /// address of the right network rather than a hand-assembled string.
    const ROTATED_BEACON_ADDRESS: &str = "tb1q7mss0haz2pjzh6kry4ythrat3mpk4rj5hhgy4l";

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
        serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/service/-", "value": {
                "id": format!("{}#rotatedBeacon", did.encode()),
                "type": "SingletonBeacon",
                "serviceEndpoint": format!("bitcoin:{ROTATED_BEACON_ADDRESS}"),
            }}
        ]))
        .expect("the rotation patch is a valid RFC 6902 op array")
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
    /// resolve.md:40-46 runs Find Beacon Signals before EVERY Process Next
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
