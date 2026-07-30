//! The refuse-to-write gate: prove a captured body set is the right one before
//! any of it reaches the fixture tree.
//!
//! A bad capture must fail during capture, where the operator can retry against a
//! chain that is still standing — not later, as a confusing resolver-test failure
//! nobody can attribute. Telling "the capture is wrong" apart from "the resolver
//! is wrong" is the whole purpose of this module.

use crate::fixture::CapturedSignal;
use crate::targets::VectorTarget;
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

    /// A sidecar update was never announced in the captured transactions.
    #[error(
        "{vector}: no captured transaction announces update hash {update_hash_hex} — re-run the capture against a chain that carries this announcement, or check that the vector's sidecar is the one that was anchored"
    )]
    MissingSignal {
        /// The vector being captured.
        vector: String,
        /// Lowercase hex of the update hash that was not found.
        update_hash_hex: String,
    },

    /// A matching announcement is still in the mempool.
    #[error(
        "{vector}: the announcement in transaction {txid} is unconfirmed — wait for it to confirm and re-run the capture, because the resolver refuses an unconfirmed beacon transaction whose update it holds"
    )]
    UnconfirmedSignal {
        /// The vector being captured.
        vector: String,
        /// The transaction that has not confirmed.
        txid: String,
    },

    /// The captured chain does not reproduce the vector's stated confirmations.
    #[error(
        "{vector}: expected {expected} confirmations but the capture yields {got} (chain tip {tip}, announcement in block {height}) — the chain has moved since the vector was minted, so either re-mint the scenario or capture from a chain whose tip still reproduces it"
    )]
    ConfirmationsMismatch {
        /// The vector being captured.
        vector: String,
        /// The vector's stated confirmations.
        expected: u64,
        /// What the captured tip and block height produce.
        got: u64,
        /// The captured chain tip height.
        tip: u32,
        /// The height of the block carrying the applied announcement.
        height: u32,
    },
}

/// One signed update from a sidecar: the hash the chain announces, and the
/// version it targets.
#[derive(Debug, Clone, Copy)]
struct SidecarUpdate {
    /// SHA-256 over the JCS form of the full signed update.
    hash: [u8; 32],
    /// The update's `targetVersionId`.
    target_version_id: u64,
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
/// hashed are exactly the JSON value the core would have stored.
// The gate reaches the recipe through `sidecar_updates`, which also needs each
// update's target version; this projection is what the minted-fixture emission
// calls to find the announcements a minted session's own updates must be matched
// by.
pub fn update_hashes(vector: &str, sidecar: &Value) -> Result<Vec<[u8; 32]>, ValidateError> {
    Ok(sidecar_updates(vector, sidecar)?
        .into_iter()
        .map(|u| u.hash)
        .collect())
}

/// [`update_hashes`] plus each update's `targetVersionId`, which the
/// confirmations check needs to know which announcement is the applied one.
fn sidecar_updates(vector: &str, sidecar: &Value) -> Result<Vec<SidecarUpdate>, ValidateError> {
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
            let target_version_id = raw["targetVersionId"].as_u64().ok_or_else(|| {
                unusable(format!(
                    "updates[{index}] has no `targetVersionId` number (the spec carries it \
                     unquoted, and the core rejects the string form)"
                ))
            })?;
            let update = Update::from_json_value(raw.clone()).map_err(|e| {
                unusable(format!(
                    "updates[{index}] is not a signed update the resolver would accept ({e})"
                ))
            })?;
            let jcs = serde_jcs::to_string(update.as_ref()).map_err(|e| {
                unusable(format!("updates[{index}] has no JCS canonical form ({e})"))
            })?;
            let hash: [u8; 32] = Sha256::digest(jcs.as_bytes()).into();
            Ok(SidecarUpdate {
                hash,
                target_version_id,
            })
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
/// rather than failing, because [`validate`] runs the parse gate first and
/// reports the address; a caller using this function alone gets what could be
/// read.
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

/// [`scan_signals`] without the confirmed-only filter, so [`validate`] can tell
/// "never announced" apart from "announced but still in the mempool".
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

/// Reject a capture that must not be written.
///
/// Returns the announcements the capture proved, in the order they were found,
/// so the caller can put them straight into the fixture's provenance.
pub fn validate(
    target: &VectorTarget,
    tip_height: u32,
    addresses: &BTreeMap<String, Vec<Value>>,
) -> Result<Vec<CapturedSignal>, ValidateError> {
    // 1. Every recorded body is an Esplora transaction list. A body that does not
    //    parse here would silently contribute no signals below, turning a broken
    //    capture into a "missing announcement" error that points at the chain
    //    instead of at the endpoint.
    for (address, body) in addresses {
        parse_body(body).map_err(|source| ValidateError::UnparseableBody {
            vector: target.id.clone(),
            address: address.clone(),
            source,
        })?;
    }

    let updates = sidecar_updates(&target.id, &target.sidecar)?;
    let wanted: Vec<[u8; 32]> = updates.iter().map(|u| u.hash).collect();
    let scanned = scan_all(addresses, &wanted);

    // 2. Every sidecar update is announced somewhere in the capture.
    for update in &updates {
        if !scanned.iter().any(|s| s.update_hash == update.hash) {
            return Err(ValidateError::MissingSignal {
                vector: target.id.clone(),
                update_hash_hex: hex::encode(update.hash),
            });
        }
    }

    // 3. Every announcement that matched is confirmed. An unconfirmed one is a
    //    distinct fault with a distinct remedy — wait, do not re-mint.
    for signal in &scanned {
        if signal.confirmed.is_none() {
            return Err(ValidateError::UnconfirmedSignal {
                vector: target.id.clone(),
                txid: signal.txid.clone(),
            });
        }
    }

    // 4. The captured tip reproduces the vector's stated confirmations.
    //
    //    The tip is whatever the chain reported; it is never back-derived from
    //    the expected value, which would make this assertion circular and unable
    //    to fail. The four regtest vectors all measure against one frozen chain
    //    tip, so a single captured number has to reproduce four independent
    //    expectations — the strongest check available that a capture is sound,
    //    and the reason the minting path must not mine between those captures.
    if let Some(expected) = target.expected_confirmations {
        let applied =
            applied_signal(&updates, &scanned).ok_or_else(|| ValidateError::MissingSignal {
                vector: target.id.clone(),
                update_hash_hex: hex::encode(
                    updates
                        .iter()
                        .map(|u| u.hash)
                        .next_back()
                        .unwrap_or_default(),
                ),
            })?;
        let (height, _) = applied
            .confirmed
            .expect("step 3 rejected every unconfirmed announcement");
        let got = u64::from(tip_height.saturating_sub(height).saturating_add(1));
        if got != expected {
            return Err(ValidateError::ConfirmationsMismatch {
                vector: target.id.clone(),
                expected,
                got,
                tip: tip_height,
                height,
            });
        }
    }

    Ok(scan_signals(addresses, &wanted))
}

/// The announcement whose height the resolver's `confirmations` is measured
/// from: the one carrying the update with the highest `targetVersionId` and,
/// where that update was announced more than once, the LOWEST block height —
/// because the resolver folds a duplicate announcement to the minimum height.
fn applied_signal<'a>(
    updates: &[SidecarUpdate],
    scanned: &'a [ScannedSignal],
) -> Option<&'a ScannedSignal> {
    let last = updates.iter().max_by_key(|u| u.target_version_id)?;
    scanned
        .iter()
        .filter(|s| s.update_hash == last.hash)
        .min_by_key(|s| s.confirmed.map(|(height, _)| height))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets;
    use did_btcr2::identifier::{Did, Network};
    use serde_json::json;
    use std::str::FromStr as _;

    /// A DID from the vendor vectors, so the synthetic targets below carry a real
    /// identifier rather than one this test invented.
    const REGTEST_DID: &str =
        "did:btcr2:k1qgppexmyqqlce9netky3h4ur2j9dur83j7m7vva497kfhdgsq2t9nxgqj3x0s";

    /// A minimal signed update the core crate accepts, targeting `version`.
    ///
    /// Field order is deliberately NOT alphabetical: JCS has to reorder it, so a
    /// hash computed without canonicalization would differ.
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

    fn sidecar(updates: Vec<Value>) -> Value {
        json!({ "updates": updates })
    }

    /// A target that does not need the test-suite submodule to exist.
    fn target(sidecar: Value, expected_confirmations: Option<u64>) -> VectorTarget {
        VectorTarget {
            id: "regtest/k1/qgppexmy".to_string(),
            network_dir: "regtest".to_string(),
            network: Network::Regtest,
            did: Did::from_str(REGTEST_DID).expect("a vendor DID parses"),
            sidecar,
            expected_document: json!({ "id": REGTEST_DID }),
            expected_version_id: 2,
            expected_deactivated: false,
            expected_confirmations,
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

    fn bodies(entries: &[(&str, Vec<Value>)]) -> BTreeMap<String, Vec<Value>> {
        entries
            .iter()
            .map(|(a, txs)| ((*a).to_string(), txs.clone()))
            .collect()
    }

    #[test]
    fn update_hashes_are_sha256_over_the_jcs_canonical_form() {
        let one = update(2, "bitcoin:mmBCLTLMZqUFhiG4vhhaM7EbLRN6h7sCfG");
        let hashes = update_hashes("regtest/k1/qgppexmy", &sidecar(vec![one.clone()]))
            .expect("a well-formed sidecar hashes");
        assert_eq!(hashes.len(), 1);

        // Independently: canonicalize, then digest. `serde_jcs` reorders the
        // object's keys, so this also pins that the hash is over the CANONICAL
        // form and not over the sidecar's own byte order.
        let jcs = serde_jcs::to_string(&one).expect("a JSON value has a JCS form");
        assert!(
            jcs.starts_with(r#"{"patch":"#),
            "JCS sorts keys, so `patch` comes first: {jcs}"
        );
        let expected: [u8; 32] = Sha256::digest(jcs.as_bytes()).into();
        assert_eq!(hashes[0], expected);

        // The same update with its keys written in a different order hashes the
        // same — the property that makes the announced value reproducible.
        let reordered: Value =
            serde_json::from_str(&jcs).expect("the canonical form is itself JSON");
        let reordered_hashes = update_hashes("regtest/k1/qgppexmy", &sidecar(vec![reordered]))
            .expect("the reordered sidecar hashes");
        assert_eq!(reordered_hashes, hashes);
    }

    #[test]
    fn update_hashes_reads_a_real_vendor_sidecar() {
        if !targets::test_suite_root()
            .join("regtest/k1/qgppexmy/resolve/input.json")
            .exists()
        {
            eprintln!("SKIP: test-suite submodule absent");
            return;
        }
        let loaded = targets::load("regtest/k1/qgppexmy").expect("the vector loads");
        let hashes = update_hashes(&loaded.id, &loaded.sidecar).expect("its sidecar hashes");
        assert_eq!(hashes.len(), 1, "this vector announces one update");
    }

    #[test]
    fn a_sidecar_without_updates_is_refused() {
        let error = update_hashes("regtest/k1/qgppexmy", &json!({}))
            .expect_err("a sidecar with no updates must not hash to nothing");
        assert!(matches!(error, ValidateError::UnusableSidecar { .. }));
        assert!(error.to_string().contains("regtest/k1/qgppexmy"));

        let error = update_hashes("regtest/k1/qgppexmy", &sidecar(vec![]))
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

    #[test]
    fn validate_fails_when_no_capture_announces_an_update() {
        let target = target(sidecar(vec![update(2, "a")]), None);
        let other = update_hashes("v", &sidecar(vec![update(2, "different")])).expect("hashes");
        let addresses = bodies(&[(
            "bcrt1qbeacon",
            vec![tx(&[op_return(other[0])], 0xc1, Some((120, 1_700_000_000)))],
        )]);

        let error = validate(&target, 200, &addresses).expect_err("an unannounced update fails");
        let message = error.to_string();
        let expected_hex = hex::encode(update_hashes("v", &target.sidecar).expect("hashes")[0]);
        assert!(matches!(error, ValidateError::MissingSignal { .. }));
        assert!(
            message.contains("regtest/k1/qgppexmy"),
            "names the vector: {message}"
        );
        assert!(message.contains(&expected_hex), "names the hash: {message}");
        assert!(
            message.contains("re-run the capture"),
            "names the next action: {message}"
        );
    }

    #[test]
    fn validate_fails_when_the_announcement_is_unconfirmed() {
        let target = target(sidecar(vec![update(2, "a")]), None);
        let hashes = update_hashes("v", &target.sidecar).expect("hashes");
        let addresses = bodies(&[(
            "bcrt1qbeacon",
            vec![tx(&[op_return(hashes[0])], 0xc2, None)],
        )]);

        let error = validate(&target, 200, &addresses).expect_err("a mempool announcement fails");
        assert!(
            matches!(error, ValidateError::UnconfirmedSignal { ref txid, .. } if *txid == "c2".repeat(32)),
            "got: {error}"
        );
        assert!(error.to_string().contains("regtest/k1/qgppexmy"));
    }

    #[test]
    fn validate_fails_when_a_body_does_not_parse() {
        let target = target(sidecar(vec![update(2, "a")]), None);
        let addresses = bodies(&[("bcrt1qbeacon", vec![json!({ "not": "a transaction" })])]);

        let error = validate(&target, 200, &addresses).expect_err("an unusable body fails");
        let message = error.to_string();
        assert!(
            matches!(error, ValidateError::UnparseableBody { ref address, .. } if address == "bcrt1qbeacon"),
            "got: {error}"
        );
        assert!(
            message.contains("bcrt1qbeacon") && message.contains("regtest/k1/qgppexmy"),
            "names the address and the vector: {message}"
        );
    }

    #[test]
    fn validate_fails_when_the_confirmations_do_not_reproduce() {
        let target = target(sidecar(vec![update(2, "a")]), Some(93));
        let hashes = update_hashes("v", &target.sidecar).expect("hashes");
        let addresses = bodies(&[(
            "bcrt1qbeacon",
            vec![tx(
                &[op_return(hashes[0])],
                0xc3,
                Some((120, 1_700_000_000)),
            )],
        )]);

        // tip 300 - height 120 + 1 = 181, not the vector's 93.
        let error = validate(&target, 300, &addresses).expect_err("a moved tip fails");
        let message = error.to_string();
        assert!(
            matches!(
                error,
                ValidateError::ConfirmationsMismatch {
                    expected: 93,
                    got: 181,
                    tip: 300,
                    height: 120,
                    ..
                }
            ),
            "got: {error}"
        );
        for part in ["93", "181", "300", "120", "regtest/k1/qgppexmy"] {
            assert!(
                message.contains(part),
                "message must carry {part}: {message}"
            );
        }
    }

    #[test]
    fn validate_accepts_a_capture_that_reproduces_the_confirmations() {
        let target = target(sidecar(vec![update(2, "a")]), Some(93));
        let hashes = update_hashes("v", &target.sidecar).expect("hashes");
        let addresses = bodies(&[(
            "bcrt1qbeacon",
            vec![tx(
                &[op_return(hashes[0])],
                0xc4,
                Some((120, 1_700_000_000)),
            )],
        )]);

        // tip 212 - height 120 + 1 = 93.
        let signals = validate(&target, 212, &addresses).expect("a sound capture validates");
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].block_height, 120);
    }

    #[test]
    fn validate_measures_confirmations_from_the_lowest_height_of_a_repeated_announcement() {
        let target = target(sidecar(vec![update(2, "a")]), Some(93));
        let hashes = update_hashes("v", &target.sidecar).expect("hashes");
        // The same announcement mined twice: the resolver folds a duplicate to
        // the lower height, so the confirmations must be measured from 120, not
        // from 150.
        let addresses = bodies(&[(
            "bcrt1qbeacon",
            vec![
                tx(&[op_return(hashes[0])], 0xc5, Some((150, 1_700_000_900))),
                tx(&[op_return(hashes[0])], 0xc6, Some((120, 1_700_000_000))),
            ],
        )]);

        let signals =
            validate(&target, 212, &addresses).expect("the lower height is the applied one");
        assert_eq!(signals.len(), 2, "both announcements are still reported");
    }

    #[test]
    fn validate_skips_the_confirmations_check_when_the_vector_states_none() {
        // Every mutinynet vector states `confirmations: null`: the minted chain
        // asserts provenance, not a pinned number. The capture must still pass.
        let target = target(sidecar(vec![update(2, "a")]), None);
        let hashes = update_hashes("v", &target.sidecar).expect("hashes");
        let addresses = bodies(&[(
            "tb1qbeacon",
            vec![tx(
                &[op_return(hashes[0])],
                0xc7,
                Some((120, 1_700_000_000)),
            )],
        )]);

        // A tip that would fail any pinned expectation is fine here.
        let signals = validate(&target, 99_999, &addresses).expect("no confirmations to reproduce");
        assert_eq!(signals.len(), 1);
    }

    #[test]
    fn validate_requires_every_update_of_a_multi_update_sidecar() {
        let target = target(sidecar(vec![update(2, "a"), update(3, "b")]), None);
        let hashes = update_hashes("v", &target.sidecar).expect("hashes");
        let addresses = bodies(&[(
            "bcrt1qbeacon",
            vec![tx(
                &[op_return(hashes[0])],
                0xc8,
                Some((120, 1_700_000_000)),
            )],
        )]);

        let error =
            validate(&target, 200, &addresses).expect_err("a half-captured chain must not pass");
        assert!(
            error.to_string().contains(&hex::encode(hashes[1])),
            "the missing announcement is the second update: {error}"
        );
    }
}
