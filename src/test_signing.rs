//! Test-only beacon signer. The core crate cannot depend on the downstream
//! did-btcr2-client (reverse dependency), so its own tests reconstruct the
//! sign+assemble step with secp256k1 directly to exercise `build_unsigned` end
//! to end. Mirrors — but is independent of — the production client
//! `sign_beacon_tx` + core `finalize` path.
#![cfg(test)]

use crate::beacon::{AnnounceError, BeaconInputScheme, SignedBeaconTx, UnsignedBeaconTx};
use esploda::bitcoin::{
    PublicKey, ScriptBuf, Witness,
    blockdata::script::Builder,
    ecdsa,
    key::TapTweak,
    script::PushBytes,
    secp256k1::{KeyPair, Message, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, TapSighashType},
    taproot,
};

/// Sign every input of `unsigned` with `beacon_sk`, cross-check ownership
/// (fail-closed `KeyDoesNotOwnPrevout`, mirroring the production signing-site
/// guard), assemble the per-scheme witness/`script_sig`, and re-wrap through the
/// `OP_RETURN <32>` invariant. No client dependency.
pub(crate) fn sign_and_finalize_for_test(
    unsigned: &UnsignedBeaconTx,
    beacon_sk: &SecretKey,
) -> Result<SignedBeaconTx, AnnounceError> {
    let secp = Secp256k1::new();
    let pubkey = PublicKey::new(beacon_sk.public_key(&secp));
    let mut tx = unsigned.as_tx().clone();
    for input in unsigned.inputs() {
        let idx = input.input_index;

        // Ownership cross-check: derive the script the beacon key actually
        // controls for this scheme and require it to match the prevout's
        // scriptPubKey, else fail closed rather than emit a silently invalid,
        // fund-committing transaction.
        let expected = match input.scheme {
            BeaconInputScheme::P2pkh => ScriptBuf::new_p2pkh(&pubkey.pubkey_hash()),
            BeaconInputScheme::P2wpkh => match pubkey.wpubkey_hash() {
                Some(w) => ScriptBuf::new_v0_p2wpkh(&w),
                None => return Err(AnnounceError::KeyDoesNotOwnPrevout { index: idx }),
            },
            BeaconInputScheme::P2tr => {
                // new_v1_p2tr applies the BIP341 key-path tweak internally, so
                // this compares the *tweaked* output key.
                let internal = beacon_sk.x_only_public_key(&secp).0;
                ScriptBuf::new_v1_p2tr(&secp, internal, None)
            }
        };
        if expected != input.script_pubkey {
            return Err(AnnounceError::KeyDoesNotOwnPrevout { index: idx });
        }

        let msg = Message::from_slice(input.sighash.as_bytes())
            .map_err(|e| AnnounceError::Signing(e.to_string()))?;
        match input.scheme {
            BeaconInputScheme::P2tr => {
                // BIP341 key-path tweak: sign with the tweaked key, not the
                // internal key (an untweaked sig fails Script::verify).
                let tweaked = KeyPair::from_secret_key(&secp, beacon_sk).tap_tweak(&secp, None);
                let schnorr = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_inner());
                let sig = taproot::Signature {
                    sig: schnorr,
                    hash_ty: TapSighashType::Default,
                };
                let mut w = Witness::new();
                w.push(sig.to_vec());
                tx.input[idx].witness = w;
            }
            BeaconInputScheme::P2wpkh => {
                let sig = ecdsa::Signature {
                    sig: secp.sign_ecdsa(&msg, beacon_sk),
                    hash_ty: EcdsaSighashType::All,
                };
                let mut w = Witness::new();
                w.push(sig.to_vec());
                w.push(pubkey.to_bytes());
                tx.input[idx].witness = w;
            }
            BeaconInputScheme::P2pkh => {
                let sig = ecdsa::Signature {
                    sig: secp.sign_ecdsa(&msg, beacon_sk),
                    hash_ty: EcdsaSighashType::All,
                };
                let bytes = sig.to_vec();
                let push = <&PushBytes>::try_from(bytes.as_slice())
                    .map_err(|e| AnnounceError::Signing(e.to_string()))?;
                tx.input[idx].script_sig = Builder::new()
                    .push_slice(push)
                    .push_key(&pubkey)
                    .into_script();
            }
        }
    }
    SignedBeaconTx::try_from(tx)
}
