//! The refuse-to-write gate: prove a captured body set is the right one before
//! any of it reaches the fixture tree.
//!
//! A bad capture must fail during capture, where the operator can retry against a
//! chain that is still standing — not later, as a confusing resolver-test failure
//! nobody can attribute. Telling "the capture is wrong" apart from "the resolver
//! is wrong" is the whole purpose of this module.

use crate::fixture::CapturedSignal;
use crate::targets::{CaptureSignals, VectorTarget};
use did_btcr2::Update;
use esploda::bitcoin::{opcodes::all::OP_RETURN, script::Instruction};
use esploda::esplora::{Status, Transaction};
use onlyerror::Error;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// Validation failures. Every message opens with the vector id and ends with the
/// operator's next action, because this gate runs during a capture session and
/// its output is the only thing standing between a bad capture and a fixture
/// nobody can debug later.
#[derive(Debug, Error)]
pub enum ValidateError {
    /// A recorded body is not an Esplora transaction list.
    #[error(
        "{vector}: the captured body for address {address} does not parse as an Esplora transaction list — check that the endpoint the capture ran against is an Esplora API and not a proxy or an error page"
    )]
    UnparseableBody {
        /// The vector being captured.
        vector: String,
        /// The beacon address whose body is unusable.
        address: String,
        /// The underlying parse failure.
        #[source]
        source: serde_json::Error,
    },

    /// The vector's sidecar does not carry the updates this gate checks for.
    #[error(
        "{vector}: the sidecar is unusable: {detail}. Every vector this tool captures announces at least one update, so an empty or malformed sidecar means the wrong one was loaded"
    )]
    UnusableSidecar {
        /// The vector being captured.
        vector: String,
        /// What is wrong with the sidecar.
        detail: String,
    },

    /// An announcement at a captured address confirmed above the set's
    /// `recordedTip`.
    #[error(
        "{vector}: transaction {txid} announces a signal in block {height}, above the recordedTip {recorded_tip} the set was recorded against — the chain moved past recordedTip, so capture before further beacon activity or report upstream"
    )]
    AnnouncementAboveRecordedTip {
        /// The set being captured.
        vector: String,
        /// The announcing transaction.
        txid: String,
        /// The block it confirmed in.
        height: u32,
        /// The set's `recordedTip`.
        recorded_tip: u32,
    },

    /// An announcement at a captured address is still in the mempool.
    #[error(
        "{vector}: transaction {txid} announces a signal but is unconfirmed, and the set's signals.json records only confirmed signals — the chain moved past recordedTip, so capture before further beacon activity or report upstream"
    )]
    UnconfirmedAnnouncement {
        /// The set being captured.
        vector: String,
        /// The unconfirmed transaction.
        txid: String,
    },

    /// A signals.json entry has no confirmed announcement in the capture.
    #[error(
        "{vector}: signals.json records transaction {txid}, but no captured transaction announces it — re-run the capture against the chain the set was recorded on"
    )]
    SignalNotOnChain {
        /// The set being captured.
        vector: String,
        /// The recorded transaction that was not found.
        txid: String,
    },

    /// A confirmed announcement that no signals.json entry records.
    #[error(
        "{vector}: transaction {txid} in block {height} announces a signal that signals.json does not record — re-run the capture against the chain the set was recorded on, or report the missing entry upstream"
    )]
    UnrecordedSignal {
        /// The set being captured.
        vector: String,
        /// The unrecorded announcement.
        txid: String,
        /// The block it confirmed in.
        height: u32,
    },

    /// An announcement and its signals.json entry disagree on one member.
    #[error(
        "{vector}: transaction {txid} disagrees with signals.json on {field}: recorded {recorded}, on chain {on_chain} — re-run the capture against the chain the set was recorded on"
    )]
    SignalMismatch {
        /// The set being captured.
        vector: String,
        /// The transaction whose record disagrees.
        txid: String,
        /// The member that disagrees: `blockHeight`, `blockHash`, `signalBytes`
        /// or `address`. For `address`, the on-chain side lists every captured
        /// address whose history carries the transaction.
        field: &'static str,
        /// What signals.json records.
        recorded: String,
        /// What the captured chain carries.
        on_chain: String,
    },
}

/// SHA-256 over the JCS canonical form of each signed update in the sidecar.
///
/// Re-implemented rather than called: the core crate's canonical-hash trait is
/// crate-private and `Update`'s fields are crate-private, so `Update::hash()` is
/// not reachable from here. The recipe is JCS, then SHA-256, over the FULL signed
/// update JSON with its proof included — exactly what the announcement
/// transaction pushes and what the resolver's update-lookup table keys on.
///
/// Each update is first parsed through the core crate's own `Update`, so a
/// sidecar entry the resolver would reject is rejected here too, and the bytes
/// hashed are exactly the JSON value the core would have stored. The minted
/// fixture emission calls this to find the announcements a minted session's own
/// updates must be matched by.
pub fn update_hashes(vector: &str, sidecar: &Value) -> Result<Vec<[u8; 32]>, ValidateError> {
    let unusable = |detail: String| ValidateError::UnusableSidecar {
        vector: vector.to_string(),
        detail,
    };

    let updates = sidecar["updates"]
        .as_array()
        .ok_or_else(|| unusable("no `updates` array".to_string()))?;
    if updates.is_empty() {
        return Err(unusable("`updates` is empty".to_string()));
    }

    updates
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            let update = Update::from_json_value(raw.clone()).map_err(|e| {
                unusable(format!(
                    "updates[{index}] is not a signed update the resolver would accept ({e})"
                ))
            })?;
            let jcs = serde_jcs::to_string(update.as_ref()).map_err(|e| {
                unusable(format!("updates[{index}] has no JCS canonical form ({e})"))
            })?;
            Ok(Sha256::digest(jcs.as_bytes()).into())
        })
        .collect()
}

/// An announcement found in a captured body, confirmed or not.
#[derive(Debug, Clone)]
struct ScannedSignal {
    /// The beacon address whose body carried the transaction.
    address: String,
    /// The transaction id.
    txid: String,
    /// The 32 pushed bytes.
    update_hash: [u8; 32],
    /// `Some((height, unix_time))` when the transaction is confirmed.
    confirmed: Option<(u32, i64)>,
}

/// Every CONFIRMED captured transaction whose LAST output announces one of
/// `wanted`.
///
/// LAST output only, and parsed with the same script instruction reader the
/// resolver uses: as a scriptpubkey the accepted shape is `6a20` followed by the
/// 32 pushed bytes and nothing else. A validator that scanned every output — or
/// that loosely matched a longer script — would bless a capture the resolver then
/// rejects, which is precisely the confusion this gate exists to prevent.
///
/// A body that does not parse as an Esplora transaction list contributes nothing
/// rather than failing, because a caller runs [`assert_bodies_parse`] first,
/// which reports the address; a caller using this function alone gets what
/// could be read.
pub fn scan_signals(
    addresses: &BTreeMap<String, Vec<Value>>,
    wanted: &[[u8; 32]],
) -> Vec<CapturedSignal> {
    scan_all(addresses, wanted)
        .into_iter()
        .filter_map(|signal| {
            let (block_height, block_time) = signal.confirmed?;
            Some(CapturedSignal {
                address: signal.address,
                txid: signal.txid,
                block_height,
                block_time,
                update_hash: hex::encode(signal.update_hash),
            })
        })
        .collect()
}

/// Every captured transaction whose last output announces one of `wanted`,
/// confirmed or not; [`scan_signals`] keeps the confirmed ones.
fn scan_all(addresses: &BTreeMap<String, Vec<Value>>, wanted: &[[u8; 32]]) -> Vec<ScannedSignal> {
    let mut found = Vec::new();
    for (address, body) in addresses {
        let Ok(txs) = parse_body(body) else {
            continue;
        };
        for tx in txs {
            let Some(update_hash) = announced_hash(&tx) else {
                continue;
            };
            if !wanted.contains(&update_hash) {
                continue;
            }
            let confirmed = match tx.status {
                Status::Confirmed {
                    block_height,
                    block_time,
                    ..
                } => Some((block_height, block_time.timestamp())),
                Status::Unconfirmed => None,
            };
            found.push(ScannedSignal {
                address: address.clone(),
                txid: tx.txid.to_string(),
                update_hash,
                confirmed,
            });
        }
    }
    found
}

/// The 32 bytes a transaction announces, or `None` if its LAST output is not an
/// `OP_RETURN <32 bytes>` push.
///
/// Mirrors the resolver: last output only, the whole script must parse cleanly,
/// and it must be exactly two instructions pushing exactly 32 bytes.
fn announced_hash(tx: &Transaction) -> Option<[u8; 32]> {
    let txout = tx.outputs.last()?;
    let ops = txout
        .script_pubkey
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let [Instruction::Op(OP_RETURN), Instruction::PushBytes(bytes)] = ops[..] else {
        return None;
    };
    <[u8; 32]>::try_from(bytes.as_bytes()).ok()
}

/// Deserialize one address's recorded body through the same serde path the
/// resolver takes: `Vec<esploda::esplora::Transaction>`, with the same status
/// and script types. A body this rejects is a body the resolver could not have
/// read either.
fn parse_body(body: &[Value]) -> Result<Vec<Transaction>, serde_json::Error> {
    serde_json::from_value(Value::Array(body.to_vec()))
}

/// Require every recorded body to be an Esplora transaction list, naming the
/// address of the first that is not.
///
/// The gate that has to run BEFORE anything scans for announcements. [`scan_all`]
/// skips a body it cannot parse, so without this an endpoint fault — a proxy
/// page, an error document, a shape serde will not take — contributes zero
/// signals and surfaces as "this update was never announced", pointing the
/// operator at the chain instead of at the endpoint.
///
/// Shared rather than restated because there are two paths that build a fixture
/// from captured bodies — the vendor capture and the minted emission — and a gate
/// that exists on only one of them is a gate that will be missing from whichever
/// path is read second.
pub fn assert_bodies_parse(
    vector: &str,
    addresses: &BTreeMap<String, Vec<Value>>,
) -> Result<(), ValidateError> {
    for (address, body) in addresses {
        parse_body(body).map_err(|source| ValidateError::UnparseableBody {
            vector: vector.to_string(),
            address: address.clone(),
            source,
        })?;
    }
    Ok(())
}

/// A confirmed announcement found in a captured body.
struct OnChainSignal {
    /// Every captured address whose body carries the transaction.
    addresses: Vec<String>,
    /// The confirming block's height.
    block_height: u32,
    /// The confirming block's hash, as the indexer renders it.
    block_hash: String,
    /// The confirming block's header time.
    block_time: i64,
    /// The 32 pushed bytes.
    bytes: [u8; 32],
}

/// Reject a capture of a set that carries `signals.json` unless the chain
/// matches that record exactly.
///
/// The upstream record is the oracle. Ordering rules derived from the sidecar
/// would refuse legitimate sets — a duplicate announcement above a later
/// update, an announcement deliberately below the current height — so this
/// gate reads nothing from the sidecar (a set may carry none, or withhold its
/// update on purpose).
///
/// Returns the proved announcements sorted by block height, then txid.
pub fn validate_signals(
    target: &VectorTarget,
    signals: &CaptureSignals,
    addresses: &BTreeMap<String, Vec<Value>>,
) -> Result<Vec<CapturedSignal>, ValidateError> {
    let vector = &target.id;

    // 1. Every recorded body is an Esplora transaction list.
    assert_bodies_parse(vector, addresses)?;

    // 2. Every announcement at a captured address — a transaction whose last
    //    output is `OP_RETURN <32 bytes>`, the resolver's own signal rule — is
    //    confirmed at or below recordedTip. Every other transaction is left in
    //    the recorded bodies and not judged, at any height: anyone can pay a
    //    beacon address on a public chain, refusing such a payment above the
    //    tip would make the set uncapturable for good, and replay never treats
    //    it as a signal. One transaction seen at two addresses is one
    //    announcement.
    let mut on_chain: BTreeMap<String, OnChainSignal> = BTreeMap::new();
    for (address, body) in addresses {
        let txs = parse_body(body).expect("assert_bodies_parse accepted every body");
        for tx in txs {
            let Some(bytes) = announced_hash(&tx) else {
                continue;
            };
            let txid = tx.txid.to_string();
            let Status::Confirmed {
                block_height,
                block_hash,
                block_time,
            } = tx.status
            else {
                return Err(ValidateError::UnconfirmedAnnouncement {
                    vector: vector.clone(),
                    txid,
                });
            };
            if block_height > signals.recorded_tip {
                return Err(ValidateError::AnnouncementAboveRecordedTip {
                    vector: vector.clone(),
                    txid,
                    height: block_height,
                    recorded_tip: signals.recorded_tip,
                });
            }
            on_chain
                .entry(txid)
                .or_insert_with(|| OnChainSignal {
                    addresses: Vec::new(),
                    block_height,
                    block_hash: block_hash.to_string(),
                    block_time: block_time.timestamp(),
                    bytes,
                })
                .addresses
                .push(address.clone());
        }
    }

    // 3. The confirmed announcements and the entries are the same multiset:
    //    each entry consumes the announcement with its txid, which must agree
    //    on height, block hash and bytes, and the entry must name an address
    //    whose captured history carries the transaction (a transaction that
    //    spends from that beacon and pays change to another is carried by
    //    both); an announcement no entry consumed is unrecorded.
    //
    // 4. There is no separate repeat check. Every announcement must match an
    //    entry, and the loader has already enforced the `update`-keyed
    //    duplicate rule on the entries; a byte-keyed repeat rule here would be
    //    a second, divergent key.
    let mut proved = Vec::with_capacity(signals.entries.len());
    for entry in &signals.entries {
        let Some(found) = on_chain.remove(&entry.txid) else {
            return Err(ValidateError::SignalNotOnChain {
                vector: vector.clone(),
                txid: entry.txid.clone(),
            });
        };
        let mismatch = |field: &'static str, recorded: String, on_chain: String| {
            ValidateError::SignalMismatch {
                vector: vector.clone(),
                txid: entry.txid.clone(),
                field,
                recorded,
                on_chain,
            }
        };
        if found.block_height != entry.block_height {
            return Err(mismatch(
                "blockHeight",
                entry.block_height.to_string(),
                found.block_height.to_string(),
            ));
        }
        if found.block_hash != entry.block_hash {
            return Err(mismatch(
                "blockHash",
                entry.block_hash.clone(),
                found.block_hash,
            ));
        }
        if found.bytes != entry.signal_bytes {
            return Err(mismatch(
                "signalBytes",
                hex::encode(entry.signal_bytes),
                hex::encode(found.bytes),
            ));
        }
        if !found.addresses.contains(&entry.address) {
            return Err(mismatch(
                "address",
                entry.address.clone(),
                found.addresses.join(", "),
            ));
        }
        proved.push(CapturedSignal {
            address: entry.address.clone(),
            txid: entry.txid.clone(),
            block_height: found.block_height,
            block_time: found.block_time,
            update_hash: hex::encode(found.bytes),
        });
    }
    if let Some((txid, found)) = on_chain.into_iter().next() {
        return Err(ValidateError::UnrecordedSignal {
            vector: vector.clone(),
            txid,
            height: found.block_height,
        });
    }

    // 5. Chain order.
    proved.sort_by(|a, b| (a.block_height, &a.txid).cmp(&(b.block_height, &b.txid)));
    Ok(proved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::{self, CaptureSignals, ExpectedOutcome, SignalRecord};
    use did_btcr2::identifier::{Did, Network};
    use serde_json::json;
    use std::str::FromStr as _;

    /// The DID of `regtest/k1/qgph7nre`, so the synthetic targets below carry a real
    /// identifier rather than one this test invented.
    const REGTEST_DID: &str =
        "did:btcr2:k1qgph7nrekhzerkmsktp8l7rdtpxh2mw45xp6e90sjvxszpz6au0grssegjx6z";

    /// A minimal signed update the core crate accepts, targeting `version`.
    ///
    /// Field order is deliberately NOT alphabetical: JCS has to reorder it, so a
    /// hash computed without canonicalization would differ.
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

    fn sidecar(updates: Vec<Value>) -> Value {
        json!({ "updates": updates })
    }

    /// A target that does not need the test-suite submodule to exist.
    fn target(sidecar: Value, expected_confirmations: Option<u64>) -> VectorTarget {
        VectorTarget {
            id: "regtest/k1/qgph7nre".to_string(),
            network_dir: "regtest".to_string(),
            network: Network::Regtest,
            did: Did::from_str(REGTEST_DID).expect("a vendor DID parses"),
            sidecar,
            expected: ExpectedOutcome::Resolved {
                document: json!({ "id": REGTEST_DID }),
                version_id: 2,
                deactivated: false,
                confirmations: expected_confirmations,
            },
            // The gate takes the record it checks as an argument; this one is
            // never read.
            signals: CaptureSignals {
                recorded_tip: 0,
                entries: Vec::new(),
            },
        }
    }

    /// `OP_RETURN <32 bytes>` as a scriptpubkey hex string.
    fn op_return(hash: [u8; 32]) -> String {
        format!("6a20{}", hex::encode(hash))
    }

    /// An Esplora transaction body in the shape the resolver deserializes, with
    /// `scripts` as its outputs in order.
    fn tx(scripts: &[String], txid_seed: u8, confirmed: Option<(u32, i64)>) -> Value {
        let status = match confirmed {
            Some((height, time)) => json!({
                "confirmed": true,
                "block_height": height,
                "block_hash": "00".repeat(32),
                "block_time": time,
            }),
            None => json!({
                "confirmed": false,
                "block_height": null,
                "block_hash": null,
                "block_time": null,
            }),
        };
        json!({
            "txid": format!("{txid_seed:02x}").repeat(32),
            "version": 2,
            "locktime": 0,
            "vin": [],
            "vout": scripts
                .iter()
                .map(|s| json!({ "scriptpubkey": s, "value": 0 }))
                .collect::<Vec<_>>(),
            "size": 0,
            "weight": 0,
            "fee": 0,
            "status": status,
        })
    }

    /// An Esplora transaction body with one output, confirmed in the named
    /// block. Unlike [`tx`], the txid and block hash are chosen by the caller,
    /// so a signals record can name them.
    fn tx_in_block(txid: &str, height: u32, block_hash: &str, script_hex: &str) -> Value {
        json!({
            "txid": txid,
            "version": 2,
            "locktime": 0,
            "vin": [],
            "vout": [
                { "scriptpubkey": "0014abababababababababababababababababababab", "value": 1000 },
                { "scriptpubkey": script_hex, "value": 0 },
            ],
            "size": 0,
            "weight": 0,
            "fee": 0,
            "status": {
                "confirmed": true,
                "block_height": height,
                "block_hash": block_hash,
                "block_time": 1_700_000_000i64 + i64::from(height),
            },
        })
    }

    fn bodies(entries: &[(&str, Vec<Value>)]) -> BTreeMap<String, Vec<Value>> {
        entries
            .iter()
            .map(|(a, txs)| ((*a).to_string(), txs.clone()))
            .collect()
    }

    #[test]
    fn update_hashes_are_sha256_over_the_jcs_canonical_form() {
        let one = update(2, "bitcoin:mmBCLTLMZqUFhiG4vhhaM7EbLRN6h7sCfG");
        let hashes = update_hashes("regtest/k1/qgph7nre", &sidecar(vec![one.clone()]))
            .expect("a well-formed sidecar hashes");
        assert_eq!(hashes.len(), 1);

        // Independently: canonicalize, then digest. `serde_jcs` reorders the
        // object's keys, so this also pins that the hash is over the CANONICAL
        // form and not over the sidecar's own byte order: `@context` sorts
        // first, and `patch` follows it directly, ahead of the `targetVersionId`
        // and `sourceHash` the helper wrote before it.
        let jcs = serde_jcs::to_string(&one).expect("a JSON value has a JCS form");
        let context = serde_json::to_string(&did_btcr2::UPDATE_CONTEXT)
            .expect("the pinned context array serializes");
        let sorted_prefix = format!(r#"{{"@context":{context},"patch":"#);
        assert!(
            jcs.starts_with(&sorted_prefix),
            "JCS sorts keys, so `@context` then `patch` come first: {jcs}"
        );
        let expected: [u8; 32] = Sha256::digest(jcs.as_bytes()).into();
        assert_eq!(hashes[0], expected);

        // The same update with its keys written in a different order hashes the
        // same — the property that makes the announced value reproducible.
        let reordered: Value =
            serde_json::from_str(&jcs).expect("the canonical form is itself JSON");
        let reordered_hashes = update_hashes("regtest/k1/qgph7nre", &sidecar(vec![reordered]))
            .expect("the reordered sidecar hashes");
        assert_eq!(reordered_hashes, hashes);
    }

    #[test]
    fn update_hashes_reads_a_real_vendor_sidecar() {
        if !targets::test_suite_present() {
            return;
        }
        let loaded = targets::load("regtest/k1/qgph7nre").expect("the vector loads");
        let hashes = update_hashes(&loaded.id, &loaded.sidecar).expect("its sidecar hashes");
        assert_eq!(hashes.len(), 1, "this vector announces one update");
    }

    #[test]
    fn a_sidecar_without_updates_is_refused() {
        let error = update_hashes("regtest/k1/qgph7nre", &json!({}))
            .expect_err("a sidecar with no updates must not hash to nothing");
        assert!(matches!(error, ValidateError::UnusableSidecar { .. }));
        assert!(error.to_string().contains("regtest/k1/qgph7nre"));

        let error = update_hashes("regtest/k1/qgph7nre", &sidecar(vec![]))
            .expect_err("an empty updates list must not pass vacuously");
        assert!(error.to_string().contains("empty"), "got: {error}");
    }

    #[test]
    fn scan_signals_finds_an_announcement_in_the_last_output() {
        let one = update(2, "a");
        let hashes = update_hashes("v", &sidecar(vec![one])).expect("hashes");
        let addresses = bodies(&[(
            "bcrt1qbeacon",
            vec![tx(
                &[
                    // A change output ahead of the announcement, as a real
                    // announcement transaction carries.
                    "0014abababababababababababababababababababab".to_string(),
                    op_return(hashes[0]),
                ],
                0xa1,
                Some((120, 1_700_000_000)),
            )],
        )]);

        let signals = scan_signals(&addresses, &hashes);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].address, "bcrt1qbeacon");
        assert_eq!(signals[0].txid, "a1".repeat(32));
        assert_eq!(signals[0].block_height, 120);
        assert_eq!(signals[0].block_time, 1_700_000_000);
        assert_eq!(signals[0].update_hash, hex::encode(hashes[0]));
    }

    #[test]
    fn scan_signals_ignores_an_announcement_that_is_not_the_last_output() {
        let hashes = update_hashes("v", &sidecar(vec![update(2, "a")])).expect("hashes");
        let addresses = bodies(&[(
            "bcrt1qbeacon",
            vec![tx(
                &[
                    op_return(hashes[0]),
                    "0014abababababababababababababababababababab".to_string(),
                ],
                0xa2,
                Some((120, 1_700_000_000)),
            )],
        )]);

        assert!(
            scan_signals(&addresses, &hashes).is_empty(),
            "the resolver reads only the last output, so neither may this"
        );
    }

    #[test]
    fn scan_signals_ignores_a_wrong_length_push_and_a_non_op_return_output() {
        let hashes = update_hashes("v", &sidecar(vec![update(2, "a")])).expect("hashes");
        let short_push = format!("6a1f{}", hex::encode(&hashes[0][..31]));
        let trailing_garbage = format!("{}51", op_return(hashes[0]));
        let addresses = bodies(&[
            (
                "bcrt1qshort",
                vec![tx(&[short_push], 0xb1, Some((120, 1_700_000_000)))],
            ),
            (
                "bcrt1qplain",
                vec![tx(
                    &["0014abababababababababababababababababababab".to_string()],
                    0xb2,
                    Some((120, 1_700_000_000)),
                )],
            ),
            (
                "bcrt1qtrailing",
                vec![tx(&[trailing_garbage], 0xb3, Some((120, 1_700_000_000)))],
            ),
        ]);

        assert!(
            scan_signals(&addresses, &hashes).is_empty(),
            "only an exact `6a20` + 32-byte push is an announcement"
        );
    }

    /// A 64-hex txid filled with `seed`.
    fn txid(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    /// A block hash derived from the height, so every block has its own.
    fn block_hash(height: u32) -> String {
        format!("{height:064x}")
    }

    /// One confirmed announcement of `bytes` in its own transaction.
    fn announce(seed: u8, height: u32, bytes: [u8; 32]) -> Value {
        tx_in_block(&txid(seed), height, &block_hash(height), &op_return(bytes))
    }

    /// The signals.json entry that records [`announce`]'s transaction.
    fn record(update: u64, seed: u8, height: u32, bytes: [u8; 32], tip: u32) -> SignalRecord {
        SignalRecord {
            update: Some(update),
            duplicate: false,
            address: "tb1qbeacon".to_string(),
            txid: txid(seed),
            block_height: height,
            block_hash: block_hash(height),
            signal_bytes: bytes,
            recorded_tip: tip,
            cohort: None,
        }
    }

    fn signals(recorded_tip: u32, entries: Vec<SignalRecord>) -> CaptureSignals {
        CaptureSignals {
            recorded_tip,
            entries,
        }
    }

    /// A set target whose sidecar the gate must not need.
    fn set_target() -> VectorTarget {
        let mut target = target(json!({}), Some(11));
        target.id = "signet/k1/qyp5h7kz".to_string();
        target
    }

    const U1: [u8; 32] = [0x11; 32];
    const U2: [u8; 32] = [0x22; 32];

    #[test]
    fn signals_gate_accepts_announcements_equal_to_the_record() {
        let record = signals(
            310,
            vec![record(1, 0xa1, 300, U1, 310), record(2, 0xa2, 305, U2, 310)],
        );
        // Listed newest first: the returned signals are in chain order anyway.
        let addresses = bodies(&[(
            "tb1qbeacon",
            vec![announce(0xa2, 305, U2), announce(0xa1, 300, U1)],
        )]);

        let proved = validate_signals(&set_target(), &record, &addresses)
            .expect("a capture equal to the record passes");
        assert_eq!(proved.len(), 2);
        assert_eq!(proved[0].txid, txid(0xa1));
        assert_eq!(proved[0].block_height, 300);
        assert_eq!(proved[0].block_time, 1_700_000_300);
        assert_eq!(proved[0].update_hash, hex::encode(U1));
        assert_eq!(proved[0].address, "tb1qbeacon");
        assert_eq!(proved[1].txid, txid(0xa2));
        assert_eq!(proved[1].block_height, 305);
    }

    #[test]
    fn signals_gate_accepts_a_flagged_duplicate_above_a_later_update() {
        let mut repeat = record(1, 0xa3, 326, U1, 330);
        repeat.duplicate = true;
        let record = signals(
            330,
            vec![
                record(1, 0xa1, 300, U1, 330),
                record(2, 0xa2, 305, U2, 330),
                repeat,
            ],
        );
        let addresses = bodies(&[(
            "tb1qbeacon",
            vec![
                announce(0xa1, 300, U1),
                announce(0xa2, 305, U2),
                announce(0xa3, 326, U1),
            ],
        )]);

        let proved = validate_signals(&set_target(), &record, &addresses)
            .expect("a repeat the record flags as a duplicate passes");
        assert_eq!(proved.len(), 3);
        assert_eq!(proved[2].block_height, 326);
    }

    #[test]
    fn signals_gate_refuses_a_repeat_the_record_lacks() {
        // The same chain as above, against a record without the flagged entry.
        // (An unflagged repeat inside signals.json never reaches this gate:
        // the loader refuses it.)
        let record = signals(
            330,
            vec![record(1, 0xa1, 300, U1, 330), record(2, 0xa2, 305, U2, 330)],
        );
        let addresses = bodies(&[(
            "tb1qbeacon",
            vec![
                announce(0xa1, 300, U1),
                announce(0xa2, 305, U2),
                announce(0xa3, 326, U1),
            ],
        )]);

        let error = validate_signals(&set_target(), &record, &addresses)
            .expect_err("an unrecorded repeat is refused");
        assert!(
            matches!(error, ValidateError::UnrecordedSignal { ref txid, height: 326, .. } if *txid == super::tests::txid(0xa3)),
            "got: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("signet/k1/qyp5h7kz") && message.contains(&txid(0xa3)),
            "names the set and the transaction: {message}"
        );
        assert!(message.contains("re-run the capture"), "{message}");
    }

    #[test]
    fn signals_gate_accepts_an_announcement_below_the_current_height() {
        // Update 2 is announced in block 299, below update 1's block 300: an
        // ordering rule derived from the sidecar would refuse it, the record
        // does not.
        let record = signals(
            310,
            vec![record(1, 0xa1, 300, U1, 310), record(2, 0xa2, 299, U2, 310)],
        );
        let addresses = bodies(&[(
            "tb1qbeacon",
            vec![announce(0xa1, 300, U1), announce(0xa2, 299, U2)],
        )]);

        let proved = validate_signals(&set_target(), &record, &addresses)
            .expect("the gate applies no ordering check");
        assert_eq!(proved[0].block_height, 299);
    }

    #[test]
    fn signals_gate_refuses_a_recorded_signal_missing_from_the_chain() {
        let record = signals(
            310,
            vec![record(1, 0xa1, 300, U1, 310), record(2, 0xa2, 305, U2, 310)],
        );
        let addresses = bodies(&[("tb1qbeacon", vec![announce(0xa1, 300, U1)])]);

        let error = validate_signals(&set_target(), &record, &addresses)
            .expect_err("a recorded signal the chain lacks is refused");
        assert!(
            matches!(error, ValidateError::SignalNotOnChain { ref txid, .. } if *txid == super::tests::txid(0xa2)),
            "got: {error}"
        );
        assert!(error.to_string().contains(&txid(0xa2)), "{error}");
    }

    #[test]
    fn signals_gate_refuses_a_different_block_hash() {
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let addresses = bodies(&[(
            "tb1qbeacon",
            vec![tx_in_block(
                &txid(0xa1),
                300,
                &block_hash(9_999),
                &op_return(U1),
            )],
        )]);

        let error = validate_signals(&set_target(), &record, &addresses)
            .expect_err("a reorganised block is refused");
        assert!(
            matches!(
                error,
                ValidateError::SignalMismatch {
                    field: "blockHash",
                    ..
                }
            ),
            "got: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("blockHash")
                && message.contains(&block_hash(300))
                && message.contains(&block_hash(9_999)),
            "names the member and both values: {message}"
        );
    }

    #[test]
    fn signals_gate_refuses_a_different_height_or_different_bytes() {
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let moved = bodies(&[(
            "tb1qbeacon",
            vec![tx_in_block(
                &txid(0xa1),
                301,
                &block_hash(300),
                &op_return(U1),
            )],
        )]);
        let error = validate_signals(&set_target(), &record, &moved)
            .expect_err("a different height is refused");
        assert!(
            matches!(
                error,
                ValidateError::SignalMismatch {
                    field: "blockHeight",
                    ..
                }
            ),
            "got: {error}"
        );

        let other_bytes = bodies(&[("tb1qbeacon", vec![announce(0xa1, 300, U2)])]);
        let error = validate_signals(&set_target(), &record, &other_bytes)
            .expect_err("different signal bytes are refused");
        assert!(
            matches!(
                error,
                ValidateError::SignalMismatch {
                    field: "signalBytes",
                    ..
                }
            ),
            "got: {error}"
        );
    }

    #[test]
    fn signals_gate_refuses_an_announcement_above_the_recorded_tip() {
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let addresses = bodies(&[(
            "tb1qbeacon",
            vec![announce(0xa1, 300, U1), announce(0xa2, 315, U2)],
        )]);

        let error = validate_signals(&set_target(), &record, &addresses)
            .expect_err("beacon activity past the recorded tip is refused");
        assert!(
            matches!(
                error,
                ValidateError::AnnouncementAboveRecordedTip { height: 315, recorded_tip: 310, ref txid, .. }
                    if *txid == super::tests::txid(0xa2)
            ),
            "got: {error}"
        );
        let message = error.to_string();
        for part in [
            txid(0xa2).as_str(),
            "315",
            "310",
            "capture before further beacon activity",
        ] {
            assert!(
                message.contains(part),
                "message must carry {part}: {message}"
            );
        }
    }

    #[test]
    fn signals_gate_accepts_dust_above_the_recorded_tip() {
        // Anyone can pay a public beacon address. A plain payment above the tip
        // is not an announcement: it stays in the recorded body and is not a
        // signal.
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let dust = json!({
            "txid": txid(0xd1),
            "version": 2,
            "locktime": 0,
            "vin": [],
            "vout": [{ "scriptpubkey": "0014cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "value": 546 }],
            "size": 0,
            "weight": 0,
            "fee": 0,
            "status": {
                "confirmed": true,
                "block_height": 315,
                "block_hash": block_hash(315),
                "block_time": 1_700_000_315i64,
            },
        });
        let addresses = bodies(&[("tb1qbeacon", vec![dust.clone(), announce(0xa1, 300, U1)])]);

        let proved = validate_signals(&set_target(), &record, &addresses)
            .expect("dust above the recorded tip does not block the capture");
        assert_eq!(proved.len(), 1, "the dust is not a signal");
        assert_eq!(proved[0].txid, txid(0xa1));
        assert_eq!(
            addresses["tb1qbeacon"][0], dust,
            "the dust body stays in the recording untouched"
        );
    }

    #[test]
    fn signals_gate_accepts_a_non_announcement_op_return_above_the_tip() {
        // OP_RETURN with a 31-byte push is not an announcement under the
        // resolver's rule, so it is not judged either.
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let short_push = format!("6a1f{}", hex::encode([0x33; 31]));
        let addresses = bodies(&[(
            "tb1qbeacon",
            vec![
                announce(0xa1, 300, U1),
                tx_in_block(&txid(0xe1), 320, &block_hash(320), &short_push),
            ],
        )]);

        let proved = validate_signals(&set_target(), &record, &addresses)
            .expect("a non-announcement above the tip is accepted");
        assert_eq!(proved.len(), 1);
    }

    #[test]
    fn signals_gate_refuses_an_unconfirmed_announcement() {
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let addresses = bodies(&[(
            "tb1qbeacon",
            vec![announce(0xa1, 300, U1), tx(&[op_return(U2)], 0xc9, None)],
        )]);

        let error = validate_signals(&set_target(), &record, &addresses)
            .expect_err("a mempool announcement is refused");
        assert!(
            matches!(error, ValidateError::UnconfirmedAnnouncement { ref txid, .. } if *txid == "c9".repeat(32)),
            "got: {error}"
        );
        assert!(error.to_string().contains("signet/k1/qyp5h7kz"), "{error}");
    }

    #[test]
    fn signals_gate_refuses_an_unparseable_body_first() {
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let addresses = bodies(&[("tb1qbeacon", vec![json!({ "not": "a transaction" })])]);

        let error = validate_signals(&set_target(), &record, &addresses)
            .expect_err("an unusable body is refused before anything is compared");
        assert!(
            matches!(error, ValidateError::UnparseableBody { ref address, .. } if address == "tb1qbeacon"),
            "got: {error}"
        );
    }

    #[test]
    fn signals_gate_runs_for_a_negative_set_without_updates() {
        // A withheld-update set: no `updates` in the sidecar, an expected error.
        // Hashing that sidecar is refused as unusable; the gate never reads it.
        let mut target = set_target();
        target.sidecar = json!({ "genesisDocument": { "id": REGTEST_DID } });
        target.expected = ExpectedOutcome::Error {
            code: "MISSING_UPDATE_DATA".to_string(),
        };
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let addresses = bodies(&[("tb1qbeacon", vec![announce(0xa1, 300, U1)])]);

        let proved = validate_signals(&target, &record, &addresses)
            .expect("the gate runs on the record alone");
        assert_eq!(proved.len(), 1);
        assert!(matches!(
            update_hashes(&target.id, &target.sidecar),
            Err(ValidateError::UnusableSidecar { .. })
        ));
    }

    #[test]
    fn signals_gate_counts_one_transaction_seen_at_two_addresses_once() {
        // A transaction spending from one beacon and paying change to another
        // appears in both address histories; it is still one announcement.
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let addresses = bodies(&[
            ("tb1qbeacon", vec![announce(0xa1, 300, U1)]),
            ("tb1qchange", vec![announce(0xa1, 300, U1)]),
        ]);

        let proved = validate_signals(&set_target(), &record, &addresses)
            .expect("one transaction, one entry");
        assert_eq!(proved.len(), 1);
        assert_eq!(
            proved[0].address, "tb1qbeacon",
            "the address the record names is kept"
        );
    }

    #[test]
    fn signals_gate_keeps_a_record_that_names_the_change_address() {
        // The same spend-with-change transaction, recorded under the beacon
        // that received the change: that history carries it too, so it matches.
        let mut entry = record(1, 0xa1, 300, U1, 310);
        entry.address = "tb1qchange".to_string();
        let record = signals(310, vec![entry]);
        let addresses = bodies(&[
            ("tb1qbeacon", vec![announce(0xa1, 300, U1)]),
            ("tb1qchange", vec![announce(0xa1, 300, U1)]),
        ]);

        let proved = validate_signals(&set_target(), &record, &addresses)
            .expect("the named address carries the transaction");
        assert_eq!(proved.len(), 1);
        assert_eq!(proved[0].address, "tb1qchange");
    }

    #[test]
    fn signals_gate_refuses_a_record_naming_an_address_that_does_not_carry_it() {
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let addresses = bodies(&[("tb1qother", vec![announce(0xa1, 300, U1)])]);

        let error = validate_signals(&set_target(), &record, &addresses)
            .expect_err("an address that does not carry the transaction is refused");
        assert!(
            matches!(
                error,
                ValidateError::SignalMismatch {
                    field: "address",
                    ..
                }
            ),
            "got: {error}"
        );
        let message = error.to_string();
        for part in ["address", "tb1qbeacon", "tb1qother", txid(0xa1).as_str()] {
            assert!(
                message.contains(part),
                "message must carry {part}: {message}"
            );
        }
    }

    #[test]
    fn signals_gate_address_refusal_lists_every_carrying_address() {
        let record = signals(310, vec![record(1, 0xa1, 300, U1, 310)]);
        let addresses = bodies(&[
            ("tb1qother", vec![announce(0xa1, 300, U1)]),
            ("tb1qthird", vec![announce(0xa1, 300, U1)]),
        ]);

        let error = validate_signals(&set_target(), &record, &addresses)
            .expect_err("neither carrying address is the recorded one");
        let ValidateError::SignalMismatch {
            field: "address",
            ref recorded,
            ref on_chain,
            ..
        } = error
        else {
            panic!("got: {error}");
        };
        assert_eq!(recorded, "tb1qbeacon");
        assert_eq!(on_chain, "tb1qother, tb1qthird");
    }
}
