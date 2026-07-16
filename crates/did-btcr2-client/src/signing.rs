//! Beacon-transaction signing (the wallet half of the construct/sign split).
//!
//! The sans-I/O core ([`did_btcr2`]) builds an [`UnsignedBeaconTx`] and hands
//! back a per-input [`Sighash`](did_btcr2::Sighash); the beacon secret key never
//! enters the core. This module is where that key finally lives: [`sign_beacon_tx`]
//! signs each input's sighash with the beacon wallet key, running the
//! prevout-ownership guard (fail-closed) BEFORE signing and applying the BIP341
//! key-path tweak for P2TR — then the core [`finalize`](did_btcr2::UnsignedBeaconTx::finalize)
//! assembles the broadcastable [`SignedBeaconTx`](did_btcr2::SignedBeaconTx).
//!
//! [`sign_beacon_tx`] is a pure free fn — no [`Client`](crate::Client), no
//! transport, no I/O — so it is unit-testable on its own.

use did_btcr2::beacon::{BeaconInputScheme, Sig, beacon_taproot_tweak, check_prevout_ownership};
use did_btcr2::{AnnounceError, UnsignedBeaconTx};
use esploda::bitcoin::sighash::{EcdsaSighashType, TapSighashType};
use esploda::bitcoin::{PublicKey, ecdsa, taproot};
use secp256k1::{Message, Secp256k1, SecretKey};

/// Sign every input of an unsigned beacon-announcement transaction with the
/// beacon wallet key.
///
/// For each input this runs the prevout-ownership guard
/// ([`check_prevout_ownership`], the T1 mitigation) BEFORE signing, so a prevout
/// the beacon key does not control fails closed with
/// [`AnnounceError::KeyDoesNotOwnPrevout`] rather than being signed into a
/// silently invalid, fund-committing transaction. It then signs the input's
/// [`Sighash`](did_btcr2::Sighash): P2TR key-path with the BIP341-tweaked key
/// ([`beacon_taproot_tweak`]) as a [`Sig::Schnorr`], P2WPKH/P2PKH as a
/// [`Sig::Ecdsa`] carrying the beacon [`PublicKey`] so the core
/// [`finalize`](did_btcr2::UnsignedBeaconTx::finalize) can assemble the witness /
/// `script_sig` (the core no longer derives the pubkey from the secret).
///
/// Pure — makes NO network call and needs no [`Client`](crate::Client): the
/// sighashes are already finished on `unsigned`, so the wallet never touches
/// `Prevouts`/`SighashCache`. The returned `Vec<Sig>` is positional, one entry
/// per input in [`UnsignedBeaconTx::inputs`] order, ready for `finalize`.
pub fn sign_beacon_tx(
    unsigned: &UnsignedBeaconTx,
    beacon_sk: &SecretKey,
) -> Result<Vec<Sig>, AnnounceError> {
    let secp = Secp256k1::new();
    let bitcoin_pubkey = PublicKey::new(beacon_sk.public_key(&secp));
    let mut sigs = Vec::with_capacity(unsigned.inputs().len());

    for input in unsigned.inputs() {
        // Guard: the beacon key must control this prevout, checked at the signing
        // site (where the key lives) BEFORE any signature is produced.
        check_prevout_ownership(
            &secp,
            beacon_sk,
            input.input_index,
            input.scheme,
            &input.script_pubkey,
        )?;

        // The core precomputed this input's sighash (a `Sighash` newtype); sign
        // its raw 32 bytes.
        let msg = Message::from_slice(input.sighash.as_bytes())
            .map_err(|e| AnnounceError::Signing(e.to_string()))?;

        let sig = match input.scheme {
            BeaconInputScheme::P2tr => {
                // BIP341 key-path tweak (d' = d + H_TapTweak(P)): a P2TR key-path
                // input must be signed with the tweaked key, not the internal key.
                let tweaked = beacon_taproot_tweak(&secp, beacon_sk);
                let schnorr = secp.sign_schnorr_no_aux_rand(&msg, &tweaked);
                Sig::Schnorr(taproot::Signature {
                    sig: schnorr,
                    hash_ty: TapSighashType::Default,
                })
            }
            BeaconInputScheme::P2pkh | BeaconInputScheme::P2wpkh => {
                let ecdsa_sig = ecdsa::Signature {
                    sig: secp.sign_ecdsa(&msg, beacon_sk),
                    hash_ty: EcdsaSighashType::All,
                };
                Sig::Ecdsa {
                    sig: ecdsa_sig,
                    pubkey: bitcoin_pubkey,
                }
            }
        };
        sigs.push(sig);
    }

    Ok(sigs)
}

#[cfg(test)]
mod tests {
    use super::*;

    use did_btcr2::Prevout;
    use did_btcr2::document::{Document, InitialDocument, ResolutionOptions};
    use did_btcr2::identifier::{Did, DidComponents, DidVersion, IdType, Network};
    use esploda::bitcoin::{OutPoint, ScriptBuf, Txid};
    use json_patch::Patch;

    const BEACON_SK_BYTES: [u8; 32] = [0x07; 32];

    fn beacon_sk() -> SecretKey {
        SecretKey::from_slice(&BEACON_SK_BYTES).expect("[7u8; 32] is a valid secret key")
    }

    /// Build the created genesis document + its DID for the beacon key, using the
    /// pure core API (no `Client`, no transport).
    fn created_doc() -> (Document, Did) {
        let secp = Secp256k1::new();
        let pk = beacon_sk().public_key(&secp);
        let id_type = IdType::from(pk);
        let components =
            DidComponents::new(DidVersion::One, Network::Mutinynet, id_type).expect("components");
        let did = Did::try_from(components).expect("did");
        let initial =
            InitialDocument::from_did(&did, &ResolutionOptions::default()).expect("initial doc");
        (Document::from(initial), did)
    }

    /// A benign update patch (appends the vm id to `assertionMethod`).
    fn benign_patch(vm_id: &str) -> Patch {
        serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/assertionMethod/-", "value": vm_id}
        ]))
        .expect("benign patch is valid RFC-6902")
    }

    /// A signed `Update` against the created genesis document (version 1 → 2).
    fn signed_update(doc: &Document, did: &Did) -> did_btcr2::Update {
        let vm_id = format!("{}#initialKey", did.encode());
        let target = std::num::NonZeroU64::new(2).expect("2 is non-zero");
        let update_sk =
            did_btcr2::key::SecretKey::try_from(BEACON_SK_BYTES).expect("valid update secret key");
        doc.construct_signed_update(benign_patch(&vm_id), target, &vm_id, update_sk)
            .expect("a signed update constructs against the genesis document")
    }

    /// The address of the created document's beacon at `idx` (0=P2PKH, 1=P2WPKH,
    /// 2=P2TR), all derived from the beacon key so the key owns each prevout.
    fn beacon_address(doc: &Document, idx: usize) -> esploda::bitcoin::Address {
        doc.beacons()
            .nth(idx)
            .expect("the default key DID has three beacons")
            .address()
            .clone()
    }

    /// A confirmed funding prevout locked to `spk`, worth `value` sats.
    fn prevout(spk: &ScriptBuf, value: u64) -> Prevout {
        Prevout {
            outpoint: OutPoint {
                txid: "0000000000000000000000000000000000000000000000000000000000000001"
                    .parse::<Txid>()
                    .expect("valid txid"),
                vout: 0,
            },
            value,
            script_pubkey: spk.clone(),
        }
    }

    /// A one-input unsigned beacon tx funded from the beacon at `idx`.
    fn unsigned_over_beacon(idx: usize) -> UnsignedBeaconTx {
        let (doc, did) = created_doc();
        let signed = signed_update(&doc, &did);
        let addr = beacon_address(&doc, idx);
        let spk = addr.script_pubkey();
        let p = prevout(&spk, 100_000);
        signed
            .build_unsigned(&addr, &[p], 1_000, &addr)
            .expect("build_unsigned over an owned prevout")
    }

    #[test]
    fn sign_beacon_tx_p2tr_yields_one_schnorr_and_finalizes() {
        let unsigned = unsigned_over_beacon(2); // P2TR beacon
        let sigs = sign_beacon_tx(&unsigned, &beacon_sk()).expect("signing an owned P2TR prevout");
        assert_eq!(sigs.len(), 1, "one input → one signature");
        assert!(
            matches!(sigs[0], Sig::Schnorr(_)),
            "a P2TR key-path input is signed as Schnorr, got {:?}",
            sigs[0]
        );
        // The finalized tx assembles: the Schnorr sig matches the P2TR witness.
        let signed_tx = unsigned
            .finalize(&sigs)
            .expect("finalize yields a SignedBeaconTx");
        let last = signed_tx
            .as_tx()
            .output
            .last()
            .expect("the announce tx has an output");
        assert!(
            last.script_pubkey.is_op_return(),
            "last output is OP_RETURN"
        );
    }

    #[test]
    fn sign_beacon_tx_p2wpkh_yields_ecdsa_with_pubkey() {
        let unsigned = unsigned_over_beacon(1); // P2WPKH beacon
        let sigs =
            sign_beacon_tx(&unsigned, &beacon_sk()).expect("signing an owned P2WPKH prevout");
        assert_eq!(sigs.len(), 1);
        let secp = Secp256k1::new();
        let expected_pk = PublicKey::new(beacon_sk().public_key(&secp));
        match &sigs[0] {
            Sig::Ecdsa { pubkey, .. } => assert_eq!(
                *pubkey, expected_pk,
                "the ECDSA Sig carries the beacon public key"
            ),
            other => panic!("expected Sig::Ecdsa for a P2WPKH input, got {other:?}"),
        }
        unsigned
            .finalize(&sigs)
            .expect("finalize assembles the P2WPKH witness");
    }

    #[test]
    fn sign_beacon_tx_rejects_foreign_prevout() {
        // Build a one-input unsigned tx whose single prevout is a P2TR output
        // owned by a DIFFERENT key. build_unsigned is keyless (it only infers the
        // scheme), so the foreign prevout passes construction; the signing-site
        // ownership guard must then fail closed BEFORE producing any signature.
        let (doc, did) = created_doc();
        let signed = signed_update(&doc, &did);
        let addr = beacon_address(&doc, 2); // funding/change is our P2TR beacon
        let secp = Secp256k1::new();
        let foreign_sk = SecretKey::from_slice(&[0x09; 32]).expect("valid foreign key");
        let foreign_internal = foreign_sk.x_only_public_key(&secp).0;
        let foreign_spk = ScriptBuf::new_v1_p2tr(&secp, foreign_internal, None);
        let p = prevout(&foreign_spk, 100_000);
        let unsigned = signed
            .build_unsigned(&addr, &[p], 1_000, &addr)
            .expect("build_unsigned accepts the (keyless) foreign prevout");

        let err = sign_beacon_tx(&unsigned, &beacon_sk())
            .expect_err("a prevout the beacon key does not own must fail closed");
        assert!(
            matches!(err, AnnounceError::KeyDoesNotOwnPrevout { index: 0 }),
            "expected KeyDoesNotOwnPrevout at index 0, got {err:?}"
        );
    }
}
