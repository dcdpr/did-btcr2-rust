#![allow(dead_code)] // todo
#![warn(clippy::unwrap_used)]

//! BIP340 cryptosuite implementation.
//!
//! Panic-sweep policy: test code is exempted via clippy.toml.

use crate::update::{UnsecuredUpdate, Update};
use crate::zcap::proof::{Proof, ProofInner, ProofPurpose, ProofValue};
use crate::{error::Btcr2Error, identifier::Sha256Hash, key::PublicKey};
use multibase::{Base, decode, encode};
use secp256k1::schnorr::Signature;
use secp256k1::{KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) struct CryptoSuite;

impl CryptoSuite {
    // bip340 cryptosuite spec Section 3.3.1
    pub(crate) fn create_proof(
        &self,
        unsecured_update: &UnsecuredUpdate,
        mut inner: ProofInner,
        secret_key: SecretKey,
    ) -> Result<Proof, Btcr2Error> {
        // Add document context to proof if present
        if let Some(context) = unsecured_update.as_ref()["@context"].as_array() {
            inner.context = context
                .iter()
                .flat_map(|e| e.as_str())
                .map(|e| e.to_string())
                .collect();
        }

        // Create proof config
        let proof_config =
            self.configure_proof(&serde_json::to_value(&inner).expect("JSON is always valid JCS"));

        // Transform document
        let transformed_data = self.transform(unsecured_update);

        // Hash the data
        let hash_data = self.hash(&transformed_data, &proof_config);

        // Generate proof value
        let proof_bytes = self.serialize_proof(hash_data, secret_key)?;

        // Encode proof value with Multibase
        let proof_value = multibase_encode(proof_bytes);

        // Create final proof
        let proof = Proof::from_inner(inner, proof_value);

        Ok(proof)
    }

    // This is defined by https://www.w3.org/TR/vc-data-integrity/#verify-proof
    // And it calls Self::verify_proof()
    pub(crate) fn data_integrity_verify_proof(
        &self,
        public_key: PublicKey,
        update: &Update,
        expected_proof_purpose: &ProofPurpose,
    ) -> Result<(), Btcr2Error> {
        // Step 5
        if &update.proof.inner.proof_purpose != expected_proof_purpose {
            return Err(Btcr2Error::ProofVerification(format!(
                "Proof purpose was expected to be {expected_proof_purpose}"
            )));
        }

        // Step 8
        self.verify_proof(public_key, update)
    }

    // bip340 cryptosuite spec Section 3.3.2
    fn verify_proof(&self, public_key: PublicKey, update: &Update) -> Result<(), Btcr2Error> {
        // Compare @context FIRST (before any expensive crypto). Per VC Data
        // Integrity, the proof's @context MUST exactly match the secured
        // document's @context — both length and elementwise. The previous
        // `.zip().all(...)` truncated at the shorter iterator and accepted a
        // proof whose @context was a strict prefix of the update's;
        // symmetrically, the absent-@context branch silently accepted proofs
        // carrying a non-empty context. Both were context-binding bypasses
        // Performing this check before multibase_decode
        // is also defense-in-depth: cheap structural checks fail fast before
        // expensive crypto.
        match update.as_ref()["@context"].as_array() {
            Some(context) => {
                if context.len() != update.proof.inner.context.len() {
                    return Err(Btcr2Error::InvalidUpdateProof(
                        "Proof context length does not match update context length".into(),
                    ));
                }
                let contexts_are_equal = context.iter().zip(update.proof.inner.context.iter()).all(
                    |(update_context_entry, proof_context_entry)| {
                        update_context_entry
                            .as_str()
                            .map(|update_context_entry| update_context_entry == proof_context_entry)
                            .unwrap_or_default()
                    },
                );

                if !contexts_are_equal {
                    return Err(Btcr2Error::InvalidUpdateProof(
                        "Proof context does not match update context".into(),
                    ));
                }
            }
            None => {
                if !update.proof.inner.context.is_empty() {
                    return Err(Btcr2Error::InvalidUpdateProof(
                        "Update has no @context but proof carries a non-empty @context".into(),
                    ));
                }
            }
        }

        // Remove proof from update document
        let unsecured_update = UnsecuredUpdate::from(update);

        // Decode proof value
        let proof_bytes = multibase_decode(&update.proof.proof_value)?;

        // Transform document
        let transformed_data = self.transform(&unsecured_update);

        // Configure proof
        let proof_options =
            serde_json::to_value(&update.proof.inner).expect("JSON is always valid JCS");
        let proof_config = self.configure_proof(&proof_options);

        // Hash data
        let hash_data = self.hash(&transformed_data, &proof_config);

        // Verify proof
        self.proof_verify(hash_data, proof_bytes, public_key)
    }

    // bip340 cryptosuite spec Section 3.3.3
    fn transform(&self, unsecured_update: &UnsecuredUpdate) -> String {
        serde_jcs::to_string(unsecured_update.as_ref()).expect("JSON is always valid JCS")
    }

    // bip340 cryptosuite spec Section 3.3.4
    fn hash(&self, transformed_data: &str, proof_config: &str) -> Sha256Hash {
        let mut hasher = Sha256::new();

        // Hash and concatenate proof config and transformed data
        hasher.update(Sha256::digest(proof_config));
        hasher.update(Sha256::digest(transformed_data));

        Sha256Hash(hasher.finalize().into())
    }

    // bip340 cryptosuite spec Section 3.3.5
    fn configure_proof(&self, options: &Value) -> String {
        serde_jcs::to_string(options).expect("JSON is always valid JCS")
    }

    // bip340 cryptosuite spec Section 3.3.6
    //
    // The proof config is already folded into `hash_data` by `hash()`, so the
    // proof options do not separately influence the signed bytes; this function
    // signs exactly the precomputed `hash_data`. (The verify side is not
    // symmetric — `proof_verify` takes a real `proof_bytes` input.)
    fn serialize_proof(
        &self,
        hash_data: Sha256Hash,
        secret_key: SecretKey,
    ) -> Result<Signature, Btcr2Error> {
        bip340_sign(hash_data, secret_key)
    }

    // bip340 cryptosuite spec Section 3.3.7
    fn proof_verify(
        &self,
        hash_data: Sha256Hash,
        proof_bytes: Signature,
        public_key: PublicKey,
    ) -> Result<(), Btcr2Error> {
        // Verify signature
        bip340_verify(hash_data, proof_bytes, &public_key.x_only_public_key().0)
    }
}

/// Sign data using BIP340 Schnorr signatures
fn bip340_sign(message_hash: Sha256Hash, secret_key: SecretKey) -> Result<Signature, Btcr2Error> {
    let secp = Secp256k1::new();

    // Create message object from hash
    let message = Message::from_slice(&message_hash.0)
        .expect("Sha256Hash is exactly 32 bytes; Message::from_slice requires 32");

    // Sign with BIP340 Schnorr
    let keypair = KeyPair::from_secret_key(&secp, &secret_key);

    // Deterministic signing (no fresh auxiliary randomness): the signature is a
    // pure function of (secret key, message), so a given signed update is
    // byte-reproducible. This is chosen deliberately to enable pinned,
    // reproducible reference vectors for signed updates. The accepted trade-off
    // is weaker side-channel hardening than fresh-aux-rand signing; that is an
    // acceptable risk for a sans-I/O reference library.
    Ok(secp.sign_schnorr_no_aux_rand(&message, &keypair))
}

/// Verify a BIP340 Schnorr signature
fn bip340_verify(
    message_hash: Sha256Hash,
    signature: Signature,
    public_key: &XOnlyPublicKey,
) -> Result<(), Btcr2Error> {
    let secp = Secp256k1::new();

    // Create message object from hash
    let message = Message::from_slice(&message_hash.0)
        .expect("Sha256Hash is exactly 32 bytes; Message::from_slice requires 32");

    // Verify signature
    secp.verify_schnorr(&signature, &message, public_key)
        .map_err(|_| Btcr2Error::InvalidUpdateProof("Verification failed".into()))
}

/// Encode binary data using Multibase (base58-btc)
fn multibase_encode(signature: Signature) -> ProofValue {
    ProofValue(encode(Base::Base58Btc, signature.as_ref()))
}

/// Decode multibase encoded string
fn multibase_decode(proof_value: &ProofValue) -> Result<Signature, Btcr2Error> {
    // The producer pins `proofValue` to base58-btc (`multibase_encode`), and the
    // cryptosuite (data-structures.md) requires base58-btc. `multibase::decode`
    // accepts *any* multibase prefix, so we must reject a signature re-encoded in
    // a different base (e.g. base64url `u…`, base16 `f…`); accepting those would
    // weaken canonicalization of the signed artifact.
    let (base, decoded) = decode(&proof_value.0)
        .map_err(|_| Btcr2Error::ProofVerification("Invalid proofValue encoding".into()))?;

    if base != Base::Base58Btc {
        return Err(Btcr2Error::ProofVerification(
            "proofValue must be base58-btc multibase".into(),
        ));
    }

    Signature::from_slice(&decoded)
        .map_err(|_| Btcr2Error::ProofVerification("Invalid proofValue encoding".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Construct a deterministic PublicKey for tests where the signature path
    // is never reached (the context-binding check fires first, before
    // multibase_decode). `PublicKey` is re-exported from secp256k1 (see
    // crate::key: `pub use secp256k1::{PublicKey, SecretKey}`), so
    // sk.public_key(&secp) returns exactly the type verify_proof expects.
    fn dummy_public_key() -> secp256k1::PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32])
            .expect("[1u8; 32] is a valid secp256k1 secret key");
        sk.public_key(&secp)
    }

    // Build an Update from inline JSON. The signature inside
    // `proof.proofValue` is bogus; we never reach multibase_decode because
    // verify_proof now runs the context-binding check first.
    fn make_update(json: serde_json::Value) -> Update {
        Update::from_json_value(json).expect("test fixture is valid Update JSON")
    }

    // Common base: a minimal Update JSON with valid sourceHash/targetHash
    // (base64url-no-pad of 32 bytes), targetVersionId, empty patch, and a
    // proof object. Caller mutates `@context` and `proof.@context`.
    fn base_update_json() -> serde_json::Value {
        // 32 zero-bytes base64url-no-pad-encoded is 43 'A's.
        let zero_hash = "A".repeat(43);
        serde_json::json!({
            "@context": [],
            "sourceHash": zero_hash,
            "targetHash": zero_hash,
            "targetVersionId": 2,
            "patch": [],
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "bip340-jcs-2025",
                "verificationMethod": "did:example:test#key",
                "proofPurpose": "capabilityInvocation",
                "capability": "urn:zcap:root:did%3Aexample%3Atest",
                "capabilityAction": "Write",
                "@context": [],
                "proofValue": "z11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
            }
        })
    }

    use crate::update::UnsecuredUpdate;
    use crate::zcap::proof::{CryptoSuiteName, ProofInner, ProofPurpose, ProofType};

    // A SecretKey derived from a non-constant, valid byte array. NOT a zero key.
    fn test_secret_key() -> SecretKey {
        SecretKey::from_slice(&[1u8; 32]).expect("[1u8; 32] is a valid secp256k1 secret key")
    }

    // A minimal unsigned update (four contexts) to sign over.
    fn unsigned_update() -> UnsecuredUpdate {
        UnsecuredUpdate {
            json: serde_json::json!({
                "@context": [],
                "patch": [],
                "targetVersionId": 2,
            }),
        }
    }

    // A valid ProofInner for capabilityInvocation.
    fn proof_inner() -> ProofInner {
        ProofInner {
            id: None,
            proof_type: ProofType::DataIntegrityProof,
            proof_purpose: ProofPurpose::CapabilityInvocation,
            verification_method: "did:example:test#key".to_string(),
            cryptosuite: CryptoSuiteName::Jcs,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            previous_proof: None,
            nonce: None,
            context: vec![],
            capability: "urn:zcap:root:did%3Aexample%3Atest".to_string(),
            capability_action: "Write".to_string(),
            invocation_target: None,
        }
    }

    #[test]
    fn sign_produces_base58btc_64byte() {
        // a produced proofValue is a base58-btc multibase string
        // ('z' prefix) whose decoded body is exactly the 64-byte detached
        // Schnorr signature.
        let suite = CryptoSuite;
        let proof = suite
            .create_proof(&unsigned_update(), proof_inner(), test_secret_key())
            .expect("signing with a valid key must succeed");

        assert!(
            proof.proof_value.0.starts_with('z'),
            "proofValue must be base58-btc multibase (prefix 'z'), got: {}",
            proof.proof_value.0
        );

        let (_base, decoded) =
            multibase::decode(&proof.proof_value.0).expect("proofValue must be valid multibase");
        assert_eq!(
            decoded.len(),
            64,
            "a BIP340 detached Schnorr signature is exactly 64 bytes"
        );
    }

    #[test]
    fn sign_is_deterministic() {
        // Determinism prerequisite for a pinned golden signed-update vector:
        // sign_schnorr_no_aux_rand is a pure function of (key, message), so
        // signing the same update twice yields byte-identical proofValues.
        let suite = CryptoSuite;
        let first = suite
            .create_proof(&unsigned_update(), proof_inner(), test_secret_key())
            .expect("first signing must succeed");
        let second = suite
            .create_proof(&unsigned_update(), proof_inner(), test_secret_key())
            .expect("second signing must succeed");

        assert_eq!(
            first.proof_value.0, second.proof_value.0,
            "deterministic signing must produce byte-identical proofValues"
        );
    }

    #[test]
    fn no_zero_key_stub_in_tree() {
        // Pins the removal of the hardcoded zero-key signing stub: a future
        // reintroduction of the constant zero secret-key byte array in this
        // source file fails at unit-test time.
        let src = include_str!("cryptosuite.rs");
        // Assemble the needle at runtime from two separate literals so this
        // guard does not match its own source text (include_str! pulls in this
        // very file).
        let needle = ["0u8; SECRET", "_KEY_SIZE"].concat();
        assert!(
            !src.contains(&needle),
            "zero-key signing stub must not be reintroduced into cryptosuite.rs"
        );
    }

    #[test]
    fn verify_proof_rejects_prefix_context_forgery() {
        // a proof whose @context is a strict prefix of the
        // update's @context must NOT pass verification. The previous
        // `.zip().all(...)` truncated at length 2 and accepted this.
        let mut json = base_update_json();
        json["@context"] = serde_json::json!(["A", "B", "C"]);
        json["proof"]["@context"] = serde_json::json!(["A", "B"]);
        let update = make_update(json);

        let suite = CryptoSuite;
        let err = suite
            .verify_proof(dummy_public_key(), &update)
            .expect_err("prefix-context forgery must be rejected");
        match err {
            Btcr2Error::InvalidUpdateProof(msg) => {
                assert!(
                    msg.contains("length"),
                    "expected length-mismatch message, got: {msg}"
                );
            }
            other => panic!("expected InvalidUpdateProof, got {other:?}"),
        }
    }

    #[test]
    fn multibase_decode_rejects_non_base58btc() {
        // the producer pins proofValue to base58-btc and the spec
        // requires it. A 64-byte signature re-encoded in any other multibase
        // (here base64url, prefix 'u') must be rejected even though
        // multibase::decode would happily decode it.
        let sig_bytes = [0x42u8; 64];
        let base58 = multibase::encode(Base::Base58Btc, sig_bytes);
        assert!(
            base58.starts_with('z'),
            "sanity: base58-btc multibase prefix is 'z'"
        );
        let base64url = multibase::encode(Base::Base64Url, sig_bytes);
        assert!(
            base64url.starts_with('u'),
            "sanity: base64url multibase prefix is 'u'"
        );

        // base58-btc form of a 64-byte body decodes to a Signature object
        // (from_slice only checks length, not curve validity), so the base check
        // passes and we get Ok back.
        multibase_decode(&ProofValue(base58))
            .expect("a 64-byte base58-btc body must decode to a Signature");

        // base64url form must be rejected at the base check.
        let err_base64 = multibase_decode(&ProofValue(base64url))
            .expect_err("non-base58-btc multibase must be rejected");
        match err_base64 {
            Btcr2Error::ProofVerification(msg) => assert!(
                msg.contains("base58-btc"),
                "expected base58-btc requirement message, got: {msg}"
            ),
            other => panic!("expected ProofVerification, got {other:?}"),
        }
    }

    #[test]
    fn verify_proof_rejects_non_base58btc_proof_value() {
        // End-to-end through verify_proof: a proof whose @context matches
        // the update's (both empty) reaches multibase_decode; a proofValue in a
        // non-base58-btc multibase must be rejected rather than verified.
        let sig_bytes = [0x42u8; 64];
        let base64url = multibase::encode(Base::Base64Url, sig_bytes);

        let mut json = base_update_json();
        json["proof"]["proofValue"] = serde_json::json!(base64url);
        let update = make_update(json);

        let suite = CryptoSuite;
        let err = suite
            .verify_proof(dummy_public_key(), &update)
            .expect_err("non-base58-btc proofValue must be rejected");
        match err {
            Btcr2Error::ProofVerification(msg) => assert!(
                msg.contains("base58-btc"),
                "expected base58-btc requirement message, got: {msg}"
            ),
            other => panic!("expected ProofVerification, got {other:?}"),
        }
    }

    #[test]
    fn verify_proof_rejects_proof_context_when_update_has_none() {
        // an update with no @context but a proof with a
        // non-empty @context must NOT pass. The previous else-branch was a
        // no-op.
        let mut json = base_update_json();
        // Remove @context entirely from the update (the None-branch path).
        json.as_object_mut()
            .expect("base_update_json builds an object at the top level")
            .remove("@context");
        json["proof"]["@context"] = serde_json::json!(["A"]);
        let update = make_update(json);

        let suite = CryptoSuite;
        let err = suite
            .verify_proof(dummy_public_key(), &update)
            .expect_err("proof with @context but update without must be rejected");
        assert!(matches!(err, Btcr2Error::InvalidUpdateProof(_)));
    }
}
