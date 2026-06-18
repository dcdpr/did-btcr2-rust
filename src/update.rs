#![warn(clippy::unwrap_used)]

use crate::zcap::proof::Proof;
use crate::{canonical_hash::CanonicalHash, error::Btc1Error, identifier::Sha256Hash, json_tools};
use json_patch::Patch;
use onlyerror::Error;
use serde_json::Value;
use std::{fs, num::NonZeroU64, path::Path};

#[derive(Debug, Error)]
pub enum Error {
    /// I/O error
    Io(#[from] std::io::Error),

    /// JSON parse error
    Json(#[from] serde_json::Error),

    /// JSON value parse error
    JsonValue(#[from] json_tools::JsonError),

    /// Invalid targetVersionId
    InvalidTargetVersionId,
}

#[derive(Clone, Debug)]
pub struct Update {
    pub(crate) source_hash: Sha256Hash,
    pub(crate) target_hash: Sha256Hash,
    pub(crate) target_version_id: NonZeroU64,
    pub(crate) proof: Proof,
    pub(crate) patch: Patch,

    pub(crate) json: Value,
}

impl Update {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let json = fs::read_to_string(path)?;

        Self::from_json_string(&json)
    }

    pub fn from_json_string(json: &str) -> Result<Self, Error> {
        let json = serde_json::from_str(json)?;

        Self::from_json_value(json)
    }

    pub fn from_json_value(json: Value) -> Result<Self, Error> {
        use json_tools::*;

        // TODO: Can we replace this with serde?
        let source_hash = hash_from_object(&json, "sourceHash")?;
        let target_hash = hash_from_object(&json, "targetHash")?;
        // `targetVersionId` is a JSON *number*, intentionally NOT the string form
        // used by the sibling `versionId` field in DocumentMetadata
        // (`version_id_serde`). The spec carries it unquoted
        // (did-btcr2/src/data-structures.md:105-106,
        // did-btcr2/src/example-data/btcr2-signed-update.json:29) and does integer
        // arithmetic/comparison on it during resolve
        // (did-btcr2/src/operations/resolve.md:160-176: `targetVersionId - 2`,
        // `== current_version_id + 1`). Do NOT "fix" this asymmetry by accepting a
        // string here — a string-form value must be rejected as UnexpectedJsonType.
        let target_version_id = u64::try_from(int_from_object(&json, "targetVersionId")?)
            .map_err(|_| Error::InvalidTargetVersionId)?
            .try_into()
            .map_err(|_| Error::InvalidTargetVersionId)?;
        // TODO: Check whether "proof" and "path" exists as a key.
        // TODO: Remove these clones
        let proof = serde_json::from_value(json["proof"].clone())?;
        let patch = serde_json::from_value(json["patch"].clone())?;

        Ok(Self {
            source_hash,
            target_hash,
            target_version_id,
            proof,
            patch,
            json,
        })
    }

    // Spec section 7.2.2.4
    pub(crate) fn confirm_duplicate(&self, hash_history: &[Sha256Hash]) -> Result<(), Btc1Error> {
        let update_hash = UnsecuredUpdate::from(self).hash();
        // target_version_id is u64; on 32-bit hosts a sufficiently long update
        // history would overflow usize. Legitimately fallible -> Result.
        // Btc1Error::InvalidDidUpdate is the closest existing variant; we do
        // not introduce a new error variant here.
        //
        // checked_sub(2) also defends against the prior u64 underflow when
        // target_version_id == 1 (NonZeroU64 enforces non-zero, not >= 2);
        // without checked_sub, 1u64 - 2 would wrap to 0xFFFF_FFFF_FFFF_FFFF in
        // release mode and the index would then go out of bounds on hash_history.
        let update_hash_index = u64::from(self.target_version_id)
            .checked_sub(2)
            .ok_or_else(|| {
                Btc1Error::InvalidDidUpdate(
                    "target_version_id must be >= 2 for duplicate-check; got 1".into(),
                )
            })?;
        let update_hash_index = usize::try_from(update_hash_index).map_err(|_| {
            Btc1Error::InvalidDidUpdate(
                "target_version_id overflows usize on this host (32-bit limit)".into(),
            )
        })?;
        let historical_update_hash = *hash_history.get(update_hash_index).ok_or_else(|| {
            Btc1Error::InvalidDidUpdate(
                "duplicate-check index past end of update hash history".into(),
            )
        })?;

        if historical_update_hash != update_hash {
            Err(Btc1Error::late_publishing(
                update_hash,
                historical_update_hash,
            ))
        } else {
            Ok(())
        }
    }

    /// Build a fully signed singleton-beacon announcement transaction.
    ///
    /// Sans-I/O primitive: given this signed update plus a singleton
    /// beacon's funding inputs and key material, produce a
    /// [`SignedBeaconTx`](crate::SignedBeaconTx) whose **last** output is
    /// `OP_RETURN <32-byte JSON Document Hash>` (the resolver reads only
    /// `outputs.last()`). The 32 signal bytes are `self.hash().0` — the same
    /// value the resolver's sidecar `update_lookup_table` keys on.
    ///
    /// All supplied `prevouts` are signed with the single `beacon_secret_key`
    /// (see the [`Prevout`](crate::Prevout) API contract). The signing scheme
    /// for each input is inferred from its `script_pubkey`:
    /// P2PKH (legacy ECDSA), P2WPKH (segwit-v0 ECDSA), or P2TR (key-path
    /// Schnorr/BIP340). Any other script type yields
    /// [`AnnounceError::UnsupportedScriptType`].
    ///
    /// Outputs are `[change?, op_return]`: a change output is emitted (before the
    /// OP_RETURN) only when `change > dust`; when `change <= dust` the remainder
    /// folds into the fee. `change = sum(prevouts) - fee` (the OP_RETURN output
    /// has value 0); an absolute `fee` is used with no vsize/feerate estimation
    /// Broadcasting the returned transaction is the caller's
    /// responsibility (sans-I/O purity).
    pub fn announce_singleton(
        &self,
        beacon_address: &esploda::bitcoin::Address,
        prevouts: &[crate::beacon::Prevout],
        fee: u64,
        change_address: &esploda::bitcoin::Address,
        beacon_secret_key: secp256k1::SecretKey,
    ) -> Result<crate::beacon::SignedBeaconTx, crate::beacon::AnnounceError> {
        use crate::beacon::{AnnounceError, SignedBeaconTx};
        use esploda::bitcoin::{
            PublicKey, ScriptBuf, Transaction, TxIn, TxOut, Witness,
            absolute::LockTime,
            blockdata::script::{Builder, PushBytesBuf},
            ecdsa,
            hashes::Hash,
            key::TapTweak,
            secp256k1::{KeyPair, Message, Secp256k1},
            sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType},
            taproot,
        };

        // The beacon_address is part of the announce contract (the signal is
        // broadcast from a beacon-controlled tx). It is the caller's funding
        // concern which UTXOs back it; this sans-I/O primitive does not bind
        // outputs to it. Touch it so the parameter is part of the signature
        // without implying a (currently absent) on-chain cross-check.
        let _ = beacon_address;

        // Guard: a zero-input transaction is consensus-invalid even at fee == 0.
        if prevouts.is_empty() {
            return Err(AnnounceError::NoPrevouts);
        }

        // 1. The 32 signal bytes = JCS-SHA256 of the full signed update (the
        //    sidecar key the resolver matches on).
        let signal: [u8; 32] = self.hash().0;

        // 2. Build the OP_RETURN signal output (value 0).
        let pb = PushBytesBuf::from(signal);
        let op_return_spk: ScriptBuf = Builder::new()
            .push_opcode(esploda::bitcoin::blockdata::opcodes::all::OP_RETURN)
            .push_slice(&pb)
            .into_script();
        let op_return = TxOut {
            value: 0,
            script_pubkey: op_return_spk,
        };

        // 3. change = sum(inputs) - fee; reject underflow.
        let inputs_total: u64 = prevouts.iter().map(|p| p.value).sum();
        if inputs_total < fee {
            return Err(AnnounceError::InsufficientFunds {
                inputs: inputs_total,
                fee,
            });
        }
        let change = inputs_total - fee;
        let change_spk = change_address.script_pubkey();
        let dust: u64 = change_spk.dust_value().to_sat();

        // 4. Output order: [change?, op_return]. OP_RETURN is ALWAYS LAST.
        let mut output = Vec::with_capacity(2);
        if change > dust {
            output.push(TxOut {
                value: change,
                script_pubkey: change_spk,
            });
        }
        output.push(op_return);

        // 5. Assemble the unsigned transaction (empty script_sig/witness).
        let input: Vec<TxIn> = prevouts
            .iter()
            .map(|p| TxIn {
                previous_output: p.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: esploda::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();
        let mut tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input,
            output,
        };

        // The P2TR sighash commits to ALL spent outputs, so build them up front
        // in input order.
        let all_txouts: Vec<TxOut> = prevouts
            .iter()
            .map(|p| TxOut {
                value: p.value,
                script_pubkey: p.script_pubkey.clone(),
            })
            .collect();

        let secp = Secp256k1::new();
        let bitcoin_pubkey = PublicKey::new(beacon_secret_key.public_key(&secp));

        // 6. Sign each input by scheme inferred from its scriptPubKey.
        for (idx, prevout) in prevouts.iter().enumerate() {
            let spk = &prevout.script_pubkey;
            let value = prevout.value;

            if spk.is_p2pkh() {
                let sighash = SighashCache::new(&tx)
                    .legacy_signature_hash(idx, spk, EcdsaSighashType::All as u32)
                    .map_err(|e| AnnounceError::Signing(e.to_string()))?;
                let msg = Message::from_slice(sighash.as_byte_array())
                    .map_err(|e| AnnounceError::Signing(e.to_string()))?;
                let sig = ecdsa::Signature {
                    sig: secp.sign_ecdsa(&msg, &beacon_secret_key),
                    hash_ty: EcdsaSighashType::All,
                };
                let sig_bytes = sig.to_vec();
                let sig_push =
                    <&esploda::bitcoin::script::PushBytes>::try_from(sig_bytes.as_slice())
                        .map_err(|e| AnnounceError::Signing(e.to_string()))?;
                tx.input[idx].script_sig = Builder::new()
                    .push_slice(sig_push)
                    .push_key(&bitcoin_pubkey)
                    .into_script();
            } else if spk.is_v0_p2wpkh() {
                let script_code = spk
                    .p2wpkh_script_code()
                    .ok_or(AnnounceError::UnsupportedScriptType)?;
                let sighash = SighashCache::new(&tx)
                    .segwit_signature_hash(idx, &script_code, value, EcdsaSighashType::All)
                    .map_err(|e| AnnounceError::Signing(e.to_string()))?;
                let msg = Message::from_slice(sighash.as_byte_array())
                    .map_err(|e| AnnounceError::Signing(e.to_string()))?;
                let sig = ecdsa::Signature {
                    sig: secp.sign_ecdsa(&msg, &beacon_secret_key),
                    hash_ty: EcdsaSighashType::All,
                };
                let mut w = Witness::new();
                w.push(sig.to_vec());
                w.push(bitcoin_pubkey.to_bytes());
                tx.input[idx].witness = w;
            } else if spk.is_v1_p2tr() {
                let sighash = SighashCache::new(&tx)
                    .taproot_key_spend_signature_hash(
                        idx,
                        &Prevouts::All(&all_txouts),
                        TapSighashType::Default,
                    )
                    .map_err(|e| AnnounceError::Signing(e.to_string()))?;
                let msg = Message::from_slice(sighash.as_byte_array())
                    .map_err(|e| AnnounceError::Signing(e.to_string()))?;
                // BIP341 key-path tweak: sign with the tweaked key, not the
                // internal key (an untweaked sig fails Script::verify).
                let untweaked = KeyPair::from_secret_key(&secp, &beacon_secret_key);
                let tweaked = untweaked.tap_tweak(&secp, None);
                let schnorr = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_inner());
                let sig = taproot::Signature {
                    sig: schnorr,
                    hash_ty: TapSighashType::Default,
                };
                let mut w = Witness::new();
                w.push(sig.to_vec());
                tx.input[idx].witness = w;
            } else {
                return Err(AnnounceError::UnsupportedScriptType);
            }
        }

        // 7. Internal infallible producer — the tx was built valid here.
        Ok(SignedBeaconTx(tx))
    }
}

impl AsRef<Value> for Update {
    fn as_ref(&self) -> &Value {
        &self.json
    }
}

impl CanonicalHash for Update {}

#[derive(Clone, Debug)]
pub(crate) struct UnsecuredUpdate {
    pub(crate) json: Value,
}

impl UnsecuredUpdate {
    /// Build an unsigned BTCR2 update directly from its inputs (the spec's
    /// "Construct BTCR2 Unsigned Update" step), independent of signing.
    ///
    /// Assembles the canonical unsigned-update JSON: the four required
    /// `@context` URLs in spec order, the JSON Patch, the source/target hashes
    /// (emitted as base64url-no-pad strings via the `Sha256Hash` serializer),
    /// and the target version id. The resulting struct hashes identically to
    /// the same JSON produced by stripping the proof off a signed `Update`,
    /// so the signing/verify paths share one canonical shape.
    pub(crate) fn construct(
        patch: &Patch,
        source_hash: Sha256Hash,
        target_hash: Sha256Hash,
        target_version_id: NonZeroU64,
    ) -> Self {
        let json = serde_json::json!({
            "@context": [
                "https://w3id.org/security/v2",
                "https://w3id.org/zcap/v1",
                "https://w3id.org/json-ld-patch/v1",
                "https://btcr2.dev/context/v1"
            ],
            "patch": patch,
            "sourceHash": source_hash,
            "targetHash": target_hash,
            "targetVersionId": u64::from(target_version_id),
        });
        Self { json }
    }
}

impl From<&Update> for UnsecuredUpdate {
    fn from(update: &Update) -> Self {
        let mut json = update.json.clone();
        if let Value::Object(map) = &mut json {
            map.remove("proof");
        }

        Self { json }
    }
}

impl AsRef<Value> for UnsecuredUpdate {
    fn as_ref(&self) -> &Value {
        &self.json
    }
}

impl CanonicalHash for UnsecuredUpdate {}

#[cfg(test)]
mod tests {
    use super::*;

    /// `confirm_duplicate` must NOT panic when the
    /// caller-supplied sidecar drives a duplicate-check index past the end of the
    /// update hash history. With `target_version_id - 2 >= hash_history.len()` the
    /// old raw slice index by position panicked out-of-bounds; the fix
    /// uses `.get(idx).ok_or_else(InvalidDidUpdate)` so the resolve path returns a
    /// typed spec error instead.
    ///
    /// The first update in `sidecar-two-updates.json` carries
    /// `targetVersionId: 2` → index 0; an EMPTY `hash_history` makes `0 >= 0`, the
    /// out-of-range path. Must return `Err(Btc1Error::InvalidDidUpdate(_))`, never
    /// a panic and never `LatePublishingError` (which is only reachable once the
    /// index is in range).
    #[test]
    fn confirm_duplicate_index_past_end_returns_err() {
        let raw = include_str!("../fixtures/spec-form/sidecar-two-updates.json");
        let value: Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let first_update_json = value["updates"][0].clone();
        let update =
            Update::from_json_value(first_update_json).expect("first fixture update parses");
        assert_eq!(u64::from(update.target_version_id), 2);

        // Empty history → update_hash_index 0 is past the end (0 >= 0).
        let hash_history: Vec<Sha256Hash> = Vec::new();
        let err = update
            .confirm_duplicate(&hash_history)
            .expect_err("out-of-range index must error, not panic");

        match err {
            Btc1Error::InvalidDidUpdate(_) => {}
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// A small RFC 6902 patch used across the construct tests.
    fn sample_patch() -> Patch {
        serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/x", "value": 1}
        ]))
        .expect("sample patch is a valid RFC 6902 op array")
    }

    /// a constructed unsigned update carries exactly the four
    /// required `@context` URLs, in spec order. The verify path requires an
    /// exact `@context` match, so a wrong or short set would break interop
    /// This pins the canonical set at construction time.
    #[test]
    fn unsigned_update_has_four_contexts() {
        let patch = sample_patch();
        let src = Sha256Hash([0x11; 32]);
        let tgt = Sha256Hash([0x22; 32]);
        let ver = NonZeroU64::new(2).expect("2 is non-zero");

        let u = UnsecuredUpdate::construct(&patch, src, tgt, ver);

        assert_eq!(
            u.as_ref()["@context"],
            serde_json::json!([
                "https://w3id.org/security/v2",
                "https://w3id.org/zcap/v1",
                "https://w3id.org/json-ld-patch/v1",
                "https://btcr2.dev/context/v1"
            ])
        );
    }

    /// the constructed unsigned update carries the expected field
    /// set — `targetVersionId` as the numeric version, `patch` round-tripping
    /// back to the input, and the two hashes serialized as JSON strings.
    #[test]
    fn unsigned_update_field_set() {
        let patch = sample_patch();
        let src = Sha256Hash([0x11; 32]);
        let tgt = Sha256Hash([0x22; 32]);
        let ver = NonZeroU64::new(2).expect("2 is non-zero");

        let u = UnsecuredUpdate::construct(&patch, src, tgt, ver);
        let json = u.as_ref();

        assert_eq!(json["targetVersionId"], serde_json::json!(2));

        let round_tripped: Patch = serde_json::from_value(json["patch"].clone())
            .expect("patch field round-trips back to a Patch");
        assert_eq!(round_tripped, patch);

        assert!(
            json["sourceHash"].is_string(),
            "sourceHash must serialize as a JSON string"
        );
        assert!(
            json["targetHash"].is_string(),
            "targetHash must serialize as a JSON string"
        );
    }

    /// Wire form: the hash strings are base64url-no-pad — they contain
    /// none of the base64-standard `+`, `/`, or padding `=` characters. Pins
    /// that the `Sha256Hash` serializer's encoding is preserved through the
    /// constructor.
    #[test]
    fn unsigned_update_hashes_are_base64url_no_pad() {
        let patch = sample_patch();
        let src = Sha256Hash([0x11; 32]);
        let tgt = Sha256Hash([0x22; 32]);
        let ver = NonZeroU64::new(2).expect("2 is non-zero");

        let u = UnsecuredUpdate::construct(&patch, src, tgt, ver);
        let json = u.as_ref();

        let source_hash = json["sourceHash"]
            .as_str()
            .expect("sourceHash is a JSON string");
        assert!(
            !source_hash.contains(['+', '/', '=']),
            "sourceHash must be base64url-no-pad (no '+', '/', or '='): {source_hash}"
        );
    }

    // ---- announce_singleton tests -----------------

    use crate::beacon::{AnnounceError, Prevout};
    use esploda::bitcoin::{
        Address, Amount, Network as BtcNetwork, OutPoint, PublicKey, ScriptBuf, TxOut, Txid,
        consensus,
        hashes::Hash as _,
        secp256k1::{KeyPair, Secp256k1, SecretKey as BtcSecretKey},
    };

    /// A deterministic test secret key.
    fn test_secret_key() -> BtcSecretKey {
        BtcSecretKey::from_slice(&[0x07; 32]).expect("0x07.. is a valid secret key")
    }

    /// A signed Update to announce. The golden fixture is a real signed update;
    /// `announce_singleton` only consumes `self.hash()`, so any valid Update
    /// works as the signal source.
    fn sample_signed_update() -> Update {
        let raw = include_str!("../fixtures/spec-form/golden-signed-update.json");
        Update::from_json_string(raw).expect("golden signed update parses")
    }

    fn p2pkh_address(sk: &BtcSecretKey) -> Address {
        let secp = Secp256k1::new();
        let pk = PublicKey::new(sk.public_key(&secp));
        Address::p2pkh(&pk, BtcNetwork::Regtest)
    }

    fn p2wpkh_address(sk: &BtcSecretKey) -> Address {
        let secp = Secp256k1::new();
        let pk = PublicKey::new(sk.public_key(&secp));
        Address::p2wpkh(&pk, BtcNetwork::Regtest).expect("compressed key yields p2wpkh")
    }

    fn p2tr_address(sk: &BtcSecretKey) -> Address {
        let secp = Secp256k1::new();
        let kp = KeyPair::from_secret_key(&secp, sk);
        let (xonly, _) = kp.x_only_public_key();
        Address::p2tr(&secp, xonly, None, BtcNetwork::Regtest)
    }

    /// A change address distinct from the signing key (a fixed regtest P2WPKH).
    fn change_address() -> Address {
        let sk = BtcSecretKey::from_slice(&[0x09; 32]).expect("valid key");
        p2wpkh_address(&sk)
    }

    fn outpoint(n: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n as u8; 32]),
            vout: n,
        }
    }

    /// announce against a single P2PKH prevout → last output is the
    /// 32-byte OP_RETURN signal == update.hash().0, and the input verifies.
    #[test]
    fn announce_signed_tx_p2pkh() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2pkh_address(&sk);
        let value = 100_000u64;
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value,
            script_pubkey: addr.script_pubkey(),
        }];

        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let tx = signed.as_tx();

        let last = tx.output.last().expect("has outputs");
        assert!(last.script_pubkey.is_op_return());
        let ops: Vec<_> = last.script_pubkey.instructions().flatten().collect();
        let push = match &ops[1] {
            esploda::bitcoin::blockdata::script::Instruction::PushBytes(b) => b.as_bytes(),
            other => panic!("expected push, got {other:?}"),
        };
        assert_eq!(push, &update.hash().0);
    }

    #[test]
    fn announce_signed_tx_p2wpkh() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2wpkh_address(&sk);
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value: 100_000,
            script_pubkey: addr.script_pubkey(),
        }];

        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let last = signed.as_tx().output.last().expect("has outputs");
        assert!(last.script_pubkey.is_op_return());
        let ops: Vec<_> = last.script_pubkey.instructions().flatten().collect();
        let push = match &ops[1] {
            esploda::bitcoin::blockdata::script::Instruction::PushBytes(b) => b.as_bytes(),
            other => panic!("expected push, got {other:?}"),
        };
        assert_eq!(push, &update.hash().0);
    }

    #[test]
    fn announce_signed_tx_p2tr() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2tr_address(&sk);
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value: 100_000,
            script_pubkey: addr.script_pubkey(),
        }];

        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let last = signed.as_tx().output.last().expect("has outputs");
        assert!(last.script_pubkey.is_op_return());
        let ops: Vec<_> = last.script_pubkey.instructions().flatten().collect();
        let push = match &ops[1] {
            esploda::bitcoin::blockdata::script::Instruction::PushBytes(b) => b.as_bytes(),
            other => panic!("expected push, got {other:?}"),
        };
        assert_eq!(push, &update.hash().0);
    }

    // -- positive oracle: each produced input passes Script::verify -------

    #[test]
    fn announce_bitcoinconsensus_p2pkh() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2pkh_address(&sk);
        let value = 100_000u64;
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value,
            script_pubkey: addr.script_pubkey(),
        }];
        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let serialized = consensus::encode::serialize(signed.as_tx());
        addr.script_pubkey()
            .verify(0, Amount::from_sat(value), &serialized)
            .expect("P2PKH input must verify under bitcoinconsensus");
    }

    #[test]
    fn announce_bitcoinconsensus_p2wpkh() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2wpkh_address(&sk);
        let value = 100_000u64;
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value,
            script_pubkey: addr.script_pubkey(),
        }];
        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let serialized = consensus::encode::serialize(signed.as_tx());
        addr.script_pubkey()
            .verify(0, Amount::from_sat(value), &serialized)
            .expect("P2WPKH input must verify under bitcoinconsensus");
    }

    /// Verify a single P2TR key-path input's Schnorr signature directly against
    /// the tweaked output key.
    ///
    /// The workspace-pinned `bitcoinconsensus` (0.20.2-0.5.0, libbitcoinconsensus
    /// from a pre-taproot Bitcoin Core) has NO taproot script-verify support —
    /// not even under `VERIFY_ALL` — so `Script::verify` treats every witness-v1
    /// input as anyone-can-spend and accepts ANY (even tampered) signature. For
    /// the P2TR case the oracle MUST therefore be a direct BIP340 Schnorr verify
    /// of the key-spend sighash against the tweaked output key. This is a
    /// stronger, more specific proof than bitcoinconsensus could give for
    /// taproot, and the matching negative-control below shows it actually
    /// enforces.
    fn p2tr_sig_verifies(
        tx: &esploda::bitcoin::Transaction,
        idx: usize,
        all_txouts: &[TxOut],
    ) -> bool {
        use esploda::bitcoin::{
            key::TapTweak,
            secp256k1::{KeyPair, Message, Secp256k1, schnorr},
            sighash::{Prevouts, SighashCache, TapSighashType},
        };
        let secp = Secp256k1::new();
        let sighash = SighashCache::new(tx)
            .taproot_key_spend_signature_hash(
                idx,
                &Prevouts::All(all_txouts),
                TapSighashType::Default,
            )
            .expect("taproot sighash");
        let msg = Message::from_slice(sighash.as_byte_array()).expect("32-byte msg");
        // Derive the tweaked x-only output key the witness commits to.
        let sk = test_secret_key();
        let untweaked = KeyPair::from_secret_key(&secp, &sk);
        let tweaked = untweaked.tap_tweak(&secp, None);
        let (xonly, _) = tweaked.to_inner().x_only_public_key();
        let witness = tx.input[idx].witness.to_vec();
        let sig = schnorr::Signature::from_slice(&witness[0][..64]).expect("64-byte schnorr sig");
        secp.verify_schnorr(&sig, &msg, &xonly).is_ok()
    }

    fn txouts_of(prevouts: &[Prevout]) -> Vec<TxOut> {
        prevouts
            .iter()
            .map(|p| TxOut {
                value: p.value,
                script_pubkey: p.script_pubkey.clone(),
            })
            .collect()
    }

    #[test]
    fn announce_bitcoinconsensus_p2tr() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2tr_address(&sk);
        let value = 100_000u64;
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value,
            script_pubkey: addr.script_pubkey(),
        }];
        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let all_txouts = txouts_of(&prevouts);
        assert!(
            p2tr_sig_verifies(signed.as_tx(), 0, &all_txouts),
            "P2TR key-path signature must verify against the tweaked output key"
        );
    }

    // -- NEGATIVE controls: tamper one sig/witness byte → verify MUST Err ------
    // Proves the bitcoinconsensus oracle actually enforces (a witness-v1 P2TR
    // input could otherwise verify trivially as anyone-can-spend under an
    // incomplete flag set).

    #[test]
    fn announce_tamper_rejected_p2pkh() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2pkh_address(&sk);
        let value = 100_000u64;
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value,
            script_pubkey: addr.script_pubkey(),
        }];
        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let mut tx = signed.into_inner();
        // Flip a byte in the scriptSig (the signature push lives there for P2PKH).
        let mut bytes = tx.input[0].script_sig.to_bytes();
        bytes[5] ^= 0xff;
        tx.input[0].script_sig = ScriptBuf::from(bytes);
        let serialized = consensus::encode::serialize(&tx);
        assert!(
            addr.script_pubkey()
                .verify(0, Amount::from_sat(value), &serialized)
                .is_err(),
            "tampered P2PKH scriptSig must fail bitcoinconsensus verify"
        );
    }

    #[test]
    fn announce_tamper_rejected_p2wpkh() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2wpkh_address(&sk);
        let value = 100_000u64;
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value,
            script_pubkey: addr.script_pubkey(),
        }];
        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let mut tx = signed.into_inner();
        // Flip a byte in witness element 0 (the signature).
        let mut w = tx.input[0].witness.to_vec();
        w[0][5] ^= 0xff;
        let mut new_w = esploda::bitcoin::Witness::new();
        for e in &w {
            new_w.push(e);
        }
        tx.input[0].witness = new_w;
        let serialized = consensus::encode::serialize(&tx);
        assert!(
            addr.script_pubkey()
                .verify(0, Amount::from_sat(value), &serialized)
                .is_err(),
            "tampered P2WPKH witness must fail bitcoinconsensus verify"
        );
    }

    #[test]
    fn announce_tamper_rejected_p2tr() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2tr_address(&sk);
        let value = 100_000u64;
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value,
            script_pubkey: addr.script_pubkey(),
        }];
        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let mut tx = signed.into_inner();
        // Flip a byte in witness element 0 (the 64-byte Schnorr signature).
        let mut w = tx.input[0].witness.to_vec();
        w[0][5] ^= 0xff;
        let mut new_w = esploda::bitcoin::Witness::new();
        for e in &w {
            new_w.push(e);
        }
        tx.input[0].witness = new_w;
        // The pinned bitcoinconsensus cannot validate taproot (anyone-can-spend
        // for witness-v1), so the oracle is a direct Schnorr verify against the
        // tweaked output key — the load-bearing negative control proving the
        // oracle actually enforces.
        let all_txouts = txouts_of(&prevouts);
        assert!(
            !p2tr_sig_verifies(&tx, 0, &all_txouts),
            "tampered P2TR Schnorr signature must fail direct BIP340 verify"
        );
    }

    // -- multi-input fan-out: two inputs, OP_RETURN last, both verify ----------

    #[test]
    fn announce_multi_input() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        // One P2WPKH + one P2TR forces both the per-input borrow dance and the
        // taproot Prevouts::All(all_txouts) path.
        let wpkh = p2wpkh_address(&sk);
        let tr = p2tr_address(&sk);
        let v0 = 100_000u64;
        let v1 = 200_000u64;
        let prevouts = vec![
            Prevout {
                outpoint: outpoint(0),
                value: v0,
                script_pubkey: wpkh.script_pubkey(),
            },
            Prevout {
                outpoint: outpoint(1),
                value: v1,
                script_pubkey: tr.script_pubkey(),
            },
        ];
        let signed = update
            .announce_singleton(&tr, &prevouts, 1_000, &change_address(), sk)
            .expect("multi-input announce succeeds");
        let tx = signed.as_tx();
        assert_eq!(tx.input.len(), 2);
        assert!(tx.output.last().unwrap().script_pubkey.is_op_return());

        let serialized = consensus::encode::serialize(tx);
        wpkh.script_pubkey()
            .verify(0, Amount::from_sat(v0), &serialized)
            .expect("input 0 (P2WPKH) must verify under bitcoinconsensus");
        // The taproot input cannot be validated by the pinned bitcoinconsensus
        // (pre-taproot); verify its Schnorr sig directly against the tweaked key.
        let all_txouts = txouts_of(&prevouts);
        assert!(
            p2tr_sig_verifies(tx, 1, &all_txouts),
            "input 1 (P2TR) key-path signature must verify"
        );
    }

    // -- output ordering: OP_RETURN last with a change output present ----------

    #[test]
    fn op_return_is_last() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2wpkh_address(&sk);
        // Large input, small fee → change >> dust, so a change output is emitted.
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value: 1_000_000,
            script_pubkey: addr.script_pubkey(),
        }];
        let signed = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect("announce succeeds");
        let tx = signed.as_tx();
        assert_eq!(tx.output.len(), 2, "change output + OP_RETURN");
        assert!(
            tx.output.last().unwrap().script_pubkey.is_op_return(),
            "OP_RETURN must be the last output"
        );
        assert!(
            !tx.output[0].script_pubkey.is_op_return(),
            "the change output precedes the OP_RETURN"
        );
    }

    // -- dust logic: change > dust emits, change <= dust folds into fee --------

    #[test]
    fn dust_change_logic() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2wpkh_address(&sk);
        let change_addr = change_address();
        let dust = change_addr.script_pubkey().dust_value().to_sat();

        // Case A: change clearly above dust → change output present (2 outputs).
        let prevouts_big = vec![Prevout {
            outpoint: outpoint(0),
            value: dust + 50_000,
            script_pubkey: addr.script_pubkey(),
        }];
        let big = update
            .announce_singleton(&addr, &prevouts_big, 1_000, &change_addr, sk)
            .expect("announce succeeds");
        assert_eq!(big.as_tx().output.len(), 2, "change above dust is emitted");

        // Case B: change == fee makes change 0 (<= dust) → no change (1 output).
        let prevouts_small = vec![Prevout {
            outpoint: outpoint(0),
            value: 1_000,
            script_pubkey: addr.script_pubkey(),
        }];
        let small = update
            .announce_singleton(&addr, &prevouts_small, 1_000, &change_addr, sk)
            .expect("announce succeeds");
        assert_eq!(
            small.as_tx().output.len(),
            1,
            "change <= dust folds into the fee (only OP_RETURN remains)"
        );
        assert!(small.as_tx().output[0].script_pubkey.is_op_return());
    }

    // -- empty prevouts: rejected before any tx assembly ----------------------

    #[test]
    fn announce_empty_prevouts_rejected() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2wpkh_address(&sk);
        let err = update
            .announce_singleton(&addr, &[], 0, &change_address(), sk)
            .expect_err("empty prevouts must be rejected");
        assert!(matches!(err, AnnounceError::NoPrevouts));
    }

    // -- insufficient funds: sum(inputs) < fee → typed error, no underflow ----

    #[test]
    fn announce_insufficient_funds_rejected() {
        let update = sample_signed_update();
        let sk = test_secret_key();
        let addr = p2wpkh_address(&sk);
        let prevouts = vec![Prevout {
            outpoint: outpoint(0),
            value: 500,
            script_pubkey: addr.script_pubkey(),
        }];
        let err = update
            .announce_singleton(&addr, &prevouts, 1_000, &change_address(), sk)
            .expect_err("fee > inputs must be rejected");
        assert!(matches!(
            err,
            AnnounceError::InsufficientFunds {
                inputs: 500,
                fee: 1_000
            }
        ));
    }
}
