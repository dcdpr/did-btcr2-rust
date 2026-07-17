//! Funding orchestration for beacon announcements.
//!
//! When the facade broadcasts an update/deactivate, it must fund the
//! singleton-beacon announcement transaction: discover the beacon address's own
//! UTXOs, select enough to cover the fee, and build a [`Prevout`] for each
//! selected output. This module hand-builds the two Esplora read endpoints the
//! funding step needs (`GET /address/{a}/utxo`, `GET /fee-estimates`), models the
//! caller's [`Fee`] choice, and resolves a rate-fee to an absolute fee via the
//! measured transaction vsize.
//!
//! Coin-selection target: the target is `needed = absolute_fee`
//! ONLY — NOT `fee + dust`. The core [`Update::build_unsigned`](did_btcr2::Update::build_unsigned)
//! folds sub-dust change into the fee, so a UTXO that covers exactly the fee
//! (leaving sub-dust change) is fundable and must not be rejected.

use std::collections::BTreeMap;

use did_btcr2::Prevout;
use esploda::bitcoin::{OutPoint, ScriptBuf, Txid};
use serde::Deserialize;

use crate::error::{Error, TransportError};
use crate::transport::BtcTransport;

/// The fee the caller wants the beacon announcement to pay.
///
/// `Absolute(n)` is `n` sats flat. `Rate(r)` is `r` sat/vB resolved to an
/// absolute fee from the built transaction's measured vsize; the rate
/// path is bounded to a single funding input (see
/// [`Error::MultiInputRateFeeUnsupported`]).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Fee {
    /// An absolute fee in satoshis.
    Absolute(u64),
    /// A fee rate in sat/vB, resolved to an absolute fee via the measured vsize.
    Rate(f64),
}

/// The default confirmation target (in blocks) used when the CLI does not
/// specify a fee: the fee becomes `Fee::Rate(estimates[DEFAULT_CONF_TARGET])`.
pub const DEFAULT_CONF_TARGET: u16 = 6;

/// A pessimistic provisional vsize (vB) for a 1-in / ≤2-out singleton announce
/// transaction, used to bootstrap the rate→absolute fee resolution before the
/// real transaction (and thus its real vsize) exists. Deliberately generous so
/// the provisional fee never under-selects; the second announce uses the
/// measured vsize, so the final fee is exact.
const PROVISIONAL_VSIZE: u64 = 200;

/// The maximum sat/vB fee rate accepted from an (untrusted) `/fee-estimates`
/// endpoint or CLI value, in sat/vB. Real mainnet congestion peaks at roughly
/// 1–2k sat/vB, so `10_000.0` sits comfortably above any legitimate rate while
/// still catching a hostile or malfunctioning endpoint returning an extreme
/// rate that would either overpay wildly or, via an unchecked `as u64` cast,
/// size a non-relayable fee. A rate above this ceiling is REJECTED, never
/// clamped (see [`resolve_fee`]).
const MAX_FEE_RATE_SAT_PER_VB: f64 = 10_000.0;

/// One entry from `GET /address/{addr}/utxo`.
///
/// The Esplora `/utxo` response OMITS the scriptPubKey: it is
/// derived from the beacon address by [`select`], never read from the response.
#[derive(Clone, Debug, Deserialize)]
pub struct EsploraUtxo {
    /// The funding transaction id (hex).
    pub txid: String,
    /// The output index within that transaction.
    pub vout: u32,
    /// The output value in satoshis.
    pub value: u64,
    /// Confirmation status.
    pub status: UtxoStatus,
}

/// The `status` object of a `/utxo` entry. Only `confirmed` is consulted by
/// selection (an unconfirmed UTXO is not spendable for a beacon announce).
#[derive(Clone, Debug, Deserialize)]
pub struct UtxoStatus {
    /// Whether the funding output is confirmed.
    pub confirmed: bool,
    /// The confirming block height, if any.
    #[serde(default)]
    pub block_height: Option<u32>,
}

/// Fetch the beacon address's UTXOs via `GET {base}/address/{addr}/utxo`.
///
/// `addr` is rendered with its `Display` (a Bitcoin address string). A non-2xx
/// status is mapped to [`TransportError::Status`]; the body is parsed as a JSON
/// array of [`EsploraUtxo`].
pub fn fetch_utxos<T: BtcTransport>(
    transport: &T,
    base_url: &str,
    addr: &esploda::bitcoin::Address,
) -> Result<Vec<EsploraUtxo>, Error> {
    let req = http::Request::get(format!("{base_url}/address/{addr}/utxo"))
        .body(Vec::new())
        .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;

    let resp = transport.execute(req)?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(Error::Transport(TransportError::Status {
            status,
            body: String::from_utf8_lossy(resp.body()).into_owned(),
        }));
    }
    let utxos: Vec<EsploraUtxo> = serde_json::from_slice(resp.body())?;
    Ok(utxos)
}

/// Fetch the fee-rate estimates via `GET {base}/fee-estimates`.
///
/// The Esplora response is a JSON object mapping stringified conf-targets (in
/// blocks) to sat/vB rates (f64). Parsed into a [`BTreeMap<u16, f64>`].
pub fn fetch_fee_estimates<T: BtcTransport>(
    transport: &T,
    base_url: &str,
) -> Result<BTreeMap<u16, f64>, Error> {
    let req = http::Request::get(format!("{base_url}/fee-estimates"))
        .body(Vec::new())
        .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;

    let resp = transport.execute(req)?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(Error::Transport(TransportError::Status {
            status,
            body: String::from_utf8_lossy(resp.body()).into_owned(),
        }));
    }
    // The wire keys are strings ("1", "6", "144", ...). Parse them into u16.
    let raw: BTreeMap<String, f64> = serde_json::from_slice(resp.body())?;
    let estimates = raw
        .into_iter()
        .filter_map(|(k, v)| k.parse::<u16>().ok().map(|t| (t, v)))
        .collect();
    Ok(estimates)
}

/// Look up the sat/vB rate for a conf-target, erroring if the target is absent
/// (A3 — error, do NOT silently low-ball with a default rate).
pub fn rate_from_estimates(estimates: &BTreeMap<u16, f64>, target: u16) -> Result<f64, Error> {
    estimates
        .get(&target)
        .copied()
        .ok_or(Error::FeeEstimateUnavailable { target })
}

/// Resolve a [`Fee`] to an absolute sats fee given a (measured or provisional)
/// vsize. `Absolute(n) => n`; `Rate(r) => ceil(r * vsize)`.
///
/// A `Rate` must be a positive, finite sat/vB value at or below
/// `MAX_FEE_RATE_SAT_PER_VB`, whose absolute fee (`ceil(r * vsize)`) is a
/// non-zero value representable in `u64`. Any rate that is negative, zero,
/// `NaN`, infinite, above the ceiling, or whose absolute fee is zero (e.g. a
/// zero `vsize`) or reaches the `2^64` boundary is rejected with
/// [`Error::InvalidFeeRate`] rather than being silently coerced, clamped, or
/// saturated by `as u64` (which would build a non-relayable or wildly
/// overpaying transaction). No path truncates, saturates, or wraps.
pub fn resolve_fee(fee: Fee, vsize: u64) -> Result<u64, Error> {
    match fee {
        Fee::Absolute(n) => Ok(n),
        Fee::Rate(r) => {
            if r <= 0.0 || !r.is_finite() {
                return Err(Error::InvalidFeeRate { rate: r });
            }
            // Top-end ceiling: an extreme rate from a hostile/malfunctioning
            // endpoint is rejected, never clamped.
            if r > MAX_FEE_RATE_SAT_PER_VB {
                return Err(Error::InvalidFeeRate { rate: r });
            }
            // u64-range overflow guard. The boundary is the power of two `2^64`,
            // NOT `u64::MAX as f64`: the latter rounds UP to `2^64`, so a guard
            // like `fee <= u64::MAX as f64` would let `fee == 2^64` pass and then
            // `fee as u64` would SATURATE to `u64::MAX` — the silent saturation
            // this reject forbids. Rejecting at `>= 2^64` keeps every accepted
            // `fee` strictly below the cast's saturating boundary.
            let fee = (r * vsize as f64).ceil();
            // Reject `<= 0.0`, not just `< 0.0`: a validated positive rate can
            // still yield a zero absolute fee when `vsize == 0`, and a 0-sat fee
            // is the exact non-relayable result this function's contract forbids.
            // (`vsize == 0` is the only way to reach 0 here, since `r > 0` makes
            // `ceil(r * vsize) >= 1` for every `vsize >= 1`.)
            if !fee.is_finite() || fee <= 0.0 || fee >= 2f64.powi(64) {
                return Err(Error::InvalidFeeRate { rate: r });
            }
            Ok(fee as u64)
        }
    }
}

/// The provisional vsize used to bootstrap rate-fee selection before the real
/// transaction exists (see [`PROVISIONAL_VSIZE`]).
pub fn provisional_vsize() -> u64 {
    PROVISIONAL_VSIZE
}

/// Sum of `value` over the confirmed UTXOs in `utxos` (the true confirmed
/// balance at the queried address). Single source of truth for the
/// `found_confirmed_sats` reported by [`Error::NoSpendableUtxo`].
pub fn confirmed_total(utxos: &[EsploraUtxo]) -> u64 {
    utxos
        .iter()
        .filter(|u| u.status.confirmed)
        .map(|u| u.value)
        .sum()
}

/// Select confirmed UTXOs covering `needed` (the absolute fee) and map each to a
/// [`Prevout`] locked to `beacon_spk`.
///
/// Target is `needed = absolute_fee` ONLY: the core folds
/// sub-dust change into the fee, so a UTXO covering exactly the fee is fundable.
/// Policy: prefer the largest single confirmed UTXO that covers `needed` (single
/// input). If no single confirmed UTXO covers `needed` but the confirmed total
/// does, fall back to largest-first multi-input selection (used only by the
/// absolute-fee path; the rate path pre-bounds to single-input upstream). If the
/// confirmed total is `< needed` (or there are no confirmed UTXOs), return
/// [`Error::NoSpendableUtxo`].
///
/// `address` is diagnostic-only — used solely to enrich the `NoSpendableUtxo`
/// error; selection stays keyed on `beacon_spk`.
///
/// `script_pubkey` is derived from the beacon address (`beacon_spk`), NEVER from
/// the `/utxo` response — every selected UTXO is locked to the
/// beacon address, so a forged scriptPubKey cannot be injected.
pub fn select(
    utxos: &[EsploraUtxo],
    beacon_spk: &ScriptBuf,
    needed: u64,
    address: &str,
) -> Result<Vec<Prevout>, Error> {
    // Confirmed UTXOs only, sorted largest-first (stable for determinism).
    let mut confirmed: Vec<&EsploraUtxo> = utxos.iter().filter(|u| u.status.confirmed).collect();
    confirmed.sort_by_key(|b| std::cmp::Reverse(b.value));

    if confirmed.is_empty() {
        return Err(Error::NoSpendableUtxo {
            address: address.to_string(),
            required_fee_sats: needed,
            found_confirmed_sats: 0,
        });
    }

    // Single-input preference: the largest UTXO that alone covers `needed`.
    if let Some(u) = confirmed.iter().find(|u| u.value >= needed) {
        return Ok(vec![to_prevout(u, beacon_spk)?]);
    }

    // Multi-input fallback (absolute-fee path only): largest-first until covered.
    let total: u64 = confirmed_total(utxos);
    if total < needed {
        return Err(Error::NoSpendableUtxo {
            address: address.to_string(),
            required_fee_sats: needed,
            found_confirmed_sats: total,
        });
    }
    let mut acc: u64 = 0;
    let mut chosen = Vec::new();
    for u in &confirmed {
        chosen.push(to_prevout(u, beacon_spk)?);
        acc += u.value;
        if acc >= needed {
            break;
        }
    }
    Ok(chosen)
}

/// Map a `/utxo` entry to a [`Prevout`], deriving the scriptPubKey from the
/// beacon address. The `txid` string is parsed at this single
/// JSON→typed boundary (newtype rule: raw bytes only at the boundary).
fn to_prevout(u: &EsploraUtxo, beacon_spk: &ScriptBuf) -> Result<Prevout, Error> {
    let txid: Txid = u.txid.parse().map_err(|_| Error::InvalidUtxoTxid {
        txid: u.txid.clone(),
    })?;
    Ok(Prevout {
        outpoint: OutPoint { txid, vout: u.vout },
        value: u.value,
        script_pubkey: beacon_spk.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use esploda::bitcoin::{Address, Network as BtcNetwork};
    use std::str::FromStr;

    /// A confirmed P2WPKH beacon address (deterministic) whose scriptPubKey the
    /// tests derive prevouts against.
    fn beacon_address() -> Address {
        // A well-formed signet/testnet P2WPKH address.
        Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
            .expect("valid bech32 address")
            .require_network(BtcNetwork::Testnet)
            .expect("address is testnet")
    }

    fn utxo(txid: &str, vout: u32, value: u64, confirmed: bool) -> EsploraUtxo {
        EsploraUtxo {
            txid: txid.to_string(),
            vout,
            value,
            status: UtxoStatus {
                confirmed,
                block_height: confirmed.then_some(100),
            },
        }
    }

    const TXID_A: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    /// The rendered beacon address string passed to `select` as the diagnostic-only
    /// `address` argument (matches [`beacon_address`]).
    const BEACON_ADDR: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    #[test]
    fn utxo_to_prevout_uses_beacon_script() {
        let spk = beacon_address().script_pubkey();
        let entry = utxo(TXID_A, 3, 5_000, true);
        let prevouts = select(&[entry], &spk, 1_000, BEACON_ADDR).expect("a covering UTXO selects");
        assert_eq!(prevouts.len(), 1);
        let p = &prevouts[0];
        // script_pubkey is derived from the beacon address, not the response.
        assert_eq!(
            p.script_pubkey, spk,
            "prevout spk derived from beacon address"
        );
        assert_eq!(p.value, 5_000, "value comes from the /utxo entry");
        assert_eq!(p.outpoint.vout, 3, "vout comes from the /utxo entry");
        assert_eq!(
            p.outpoint.txid.to_string(),
            TXID_A,
            "txid comes from the entry"
        );
    }

    #[test]
    fn select_errors_when_no_spendable_utxo() {
        let spk = beacon_address().script_pubkey();
        let err =
            select(&[], &spk, 1_000, BEACON_ADDR).expect_err("an empty UTXO set is not spendable");
        // Wrong-beacon shape: nothing confirmed at the queried address.
        match &err {
            Error::NoSpendableUtxo {
                address,
                required_fee_sats,
                found_confirmed_sats,
            } => {
                assert_eq!(address, BEACON_ADDR, "the queried address is reported");
                assert_eq!(*required_fee_sats, 1_000);
                assert_eq!(*found_confirmed_sats, 0, "an empty set has zero confirmed");
            }
            other => panic!("expected NoSpendableUtxo, got {other:?}"),
        }
        let rendered = err.to_string();
        assert!(
            rendered.contains(BEACON_ADDR),
            "message names the queried address: {rendered}"
        );
        assert!(
            rendered.contains("found 0 confirmed"),
            "message reports the wrong-beacon zero-balance shape: {rendered}"
        );
    }

    #[test]
    fn select_targets_absolute_fee_only() {
        let spk = beacon_address().script_pubkey();
        // value == fee + 1 (change would be sub-dust): target is `needed = fee`,
        // NOT `fee + dust`, so this SUCCEEDS.
        let entry = utxo(TXID_A, 0, 1_001, true);
        let prevouts = select(&[entry], &spk, 1_000, BEACON_ADDR).expect("fee-only target selects");
        assert_eq!(prevouts.len(), 1);
        assert_eq!(prevouts[0].value, 1_001);

        // A UTXO worth less than the fee is rejected (no spendable coverage).
        let small = utxo(TXID_A, 0, 999, true);
        let err =
            select(&[small], &spk, 1_000, BEACON_ADDR).expect_err("a below-fee UTXO is rejected");
        // Underfunded shape: some confirmed balance exists, but below the fee —
        // `0 < found < required`, distinct from the wrong-beacon `found == 0`.
        match &err {
            Error::NoSpendableUtxo {
                required_fee_sats,
                found_confirmed_sats,
                ..
            } => {
                assert!(
                    *found_confirmed_sats > 0 && *found_confirmed_sats < *required_fee_sats,
                    "underfunded: 0 < found ({found_confirmed_sats}) < required ({required_fee_sats})"
                );
                assert_eq!(
                    *found_confirmed_sats, 999,
                    "the true confirmed balance is reported"
                );
            }
            other => panic!("expected NoSpendableUtxo, got {other:?}"),
        }
    }

    #[test]
    fn select_skips_unconfirmed() {
        let spk = beacon_address().script_pubkey();
        let entry = utxo(TXID_A, 0, 5_000, false);
        let err = select(&[entry], &spk, 1_000, BEACON_ADDR)
            .expect_err("an unconfirmed UTXO is not spendable");
        assert!(matches!(err, Error::NoSpendableUtxo { .. }), "got {err:?}");
    }

    #[test]
    fn fee_rate_to_absolute() {
        // ceil(2.5 * 140) = 350.
        assert_eq!(
            resolve_fee(Fee::Rate(2.5), 140).expect("positive rate"),
            350
        );
        // ceil(1.0 * 200) = 200.
        assert_eq!(
            resolve_fee(Fee::Rate(1.0), 200).expect("positive rate"),
            200
        );
        // Absolute passes through unchanged (no rate validation).
        assert_eq!(
            resolve_fee(Fee::Absolute(1_234), 9_999).expect("absolute is always valid"),
            1_234
        );
    }

    #[test]
    fn fee_rate_rejects_non_positive_or_non_finite() {
        // A zero, negative, NaN, or infinite rate is a typed error, NOT a
        // 0-sat fee (which `as u64` would otherwise silently produce).
        for bad in [0.0_f64, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let err = resolve_fee(Fee::Rate(bad), 140)
                .expect_err("a non-positive/non-finite rate must be rejected");
            match err {
                Error::InvalidFeeRate { rate } => {
                    assert!(
                        rate == bad || (rate.is_nan() && bad.is_nan()),
                        "the error carries the offending rate"
                    );
                }
                other => panic!("expected InvalidFeeRate, got {other:?}"),
            }
        }
    }

    #[test]
    fn fee_rate_rejects_above_ceiling() {
        // A rate above MAX_FEE_RATE_SAT_PER_VB is rejected up front (the CEILING
        // branch) — not clamped, not truncated. vsize is small so only the
        // ceiling can be responsible for the rejection.
        let above = MAX_FEE_RATE_SAT_PER_VB + 1.0;
        let err = resolve_fee(Fee::Rate(above), 140)
            .expect_err("a rate above the ceiling must be rejected");
        match err {
            Error::InvalidFeeRate { rate } => assert_eq!(rate, above, "carries the offending rate"),
            other => panic!("expected InvalidFeeRate, got {other:?}"),
        }
        // Exactly at the ceiling is accepted (boundary is inclusive: reject `>`).
        assert_eq!(
            resolve_fee(Fee::Rate(MAX_FEE_RATE_SAT_PER_VB), 1).expect("at-ceiling rate resolves"),
            MAX_FEE_RATE_SAT_PER_VB as u64
        );
    }

    #[test]
    fn fee_rate_rejects_u64_overflow() {
        // r stays under MAX_FEE_RATE_SAT_PER_VB so the ceiling doesn't fire; the
        // huge vsize drives the u64-overflow branch. This test MUST exercise the
        // OVERFLOW guard, not the ceiling: 5_000 sat/vB * 1e16 vB = 5e19 sats,
        // which is above the 2^64 (~1.84e19) boundary, so ceil(r*vsize) >= 2^64.
        let r = 5_000.0_f64;
        assert!(r <= MAX_FEE_RATE_SAT_PER_VB, "rate is below the ceiling");
        let vsize = 10_000_000_000_000_000_u64; // 1e16
        let err = resolve_fee(Fee::Rate(r), vsize)
            .expect_err("an absolute fee reaching the 2^64 boundary must be rejected");
        match err {
            Error::InvalidFeeRate { rate } => assert_eq!(rate, r, "carries the offending rate"),
            other => panic!("expected InvalidFeeRate, got {other:?}"),
        }
    }

    #[test]
    fn fee_rate_rejects_zero_vsize() {
        // A valid positive rate against a zero vsize computes ceil(r * 0) == 0,
        // a non-relayable 0-sat fee. It must be a typed rejection, NOT Ok(0):
        // the `<= 0.0` guard (not `< 0.0`) is what catches this. A non-zero vsize
        // with the same rate still resolves, proving the rate itself is fine.
        let r = 5.0_f64;
        let err = resolve_fee(Fee::Rate(r), 0)
            .expect_err("a zero absolute fee (zero vsize) must be rejected");
        match err {
            Error::InvalidFeeRate { rate } => assert_eq!(rate, r, "carries the offending rate"),
            other => panic!("expected InvalidFeeRate, got {other:?}"),
        }
        assert_eq!(
            resolve_fee(Fee::Rate(r), 100).expect("same rate resolves with a real vsize"),
            500
        );
    }

    #[test]
    fn fee_estimate_unavailable_errors() {
        let mut estimates = BTreeMap::new();
        estimates.insert(1u16, 50.0);
        // The default conf-target (6) is absent → typed error, not a silent default.
        let err = rate_from_estimates(&estimates, DEFAULT_CONF_TARGET)
            .expect_err("a missing conf-target is an error");
        match err {
            Error::FeeEstimateUnavailable { target } => assert_eq!(target, DEFAULT_CONF_TARGET),
            other => panic!("expected FeeEstimateUnavailable, got {other:?}"),
        }
        // A present target resolves.
        assert_eq!(
            rate_from_estimates(&estimates, 1).expect("target 1 present"),
            50.0
        );
    }

    #[test]
    fn rate_fee_requires_single_input() {
        // The bounded single-input contract is enforced by Task 2's build path
        // (it calls `select` with the provisional fee and rejects a multi-input
        // result for a rate fee). Here we prove the precondition `select`
        // exposes: when no single confirmed UTXO covers `needed`, the SINGLE
        // largest UTXO does not satisfy the single-input find — the caller for a
        // rate fee must surface MultiInputRateFeeUnsupported.
        let spk = beacon_address().script_pubkey();
        let u1 = utxo(TXID_A, 0, 600, true);
        let u2 = utxo(TXID_A, 1, 600, true);
        // needed = 1_000: no single UTXO covers it, but the total (1_200) does.
        let prevouts = select(&[u1, u2], &spk, 1_000, BEACON_ADDR)
            .expect("multi-input covers for absolute fee");
        assert!(
            prevouts.len() > 1,
            "no single UTXO covers needed, so absolute-fee selection is multi-input"
        );
        // A rate-fee caller MUST reject this; the build path returns
        // Error::MultiInputRateFeeUnsupported. We assert the error variant exists
        // and is constructible (the bound is testable).
        let _ = Error::MultiInputRateFeeUnsupported;
    }
}
