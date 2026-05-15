#![allow(dead_code)] // todo
#![warn(clippy::unwrap_used)]

//! BIP340 cryptosuite implementation.
//!
//! Panic-sweep policy: test code is exempted via clippy.toml.

use crate::update::{UnsecuredUpdate, Update};
use crate::zcap::proof::{Proof, ProofInner, ProofPurpose, ProofValue};
use crate::{error::Btc1Error, identifier::Sha256Hash, key::PublicKey};
use multibase::{Base, decode, encode};
use secp256k1::schnorr::Signature;
use secp256k1::{KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) struct CryptoSuite;

impl CryptoSuite {
    // bip340 cryptosuite spec Section 3.3.1
    fn create_proof(
        &self,
        unsecured_update: &UnsecuredUpdate,
        mut inner: ProofInner,
    ) -> Result<Proof, Btc1Error> {
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
        let proof_bytes = self.serialize_proof(hash_data, &inner)?;

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
    ) -> Result<(), Btc1Error> {
        // Step 5
        if &update.proof.inner.proof_purpose != expected_proof_purpose {
            return Err(Btc1Error::ProofVerification(format!(
                "Proof purpose was expected to be {expected_proof_purpose}"
            )));
        }

        // Step 8
        self.verify_proof(public_key, update)
    }

    // bip340 cryptosuite spec Section 3.3.2
    fn verify_proof(&self, public_key: PublicKey, update: &Update) -> Result<(), Btc1Error> {
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
                    return Err(Btc1Error::InvalidUpdateProof(
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
                    return Err(Btc1Error::InvalidUpdateProof(
                        "Proof context does not match update context".into(),
                    ));
                }
            }
            None => {
                if !update.proof.inner.context.is_empty() {
                    return Err(Btc1Error::InvalidUpdateProof(
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
    fn serialize_proof(
        &self,
        _hash_data: Sha256Hash,
        _proof: &ProofInner,
    ) -> Result<Signature, Btc1Error> {
        // BIP340 signing requires verification_method-keyed
        // secret-key retrieval. The previous implementation used a hardcoded
        // zero-key stub (a "hidden half-implementation" per PROJECT.md). Per
        // The panic-sweep policy converts hidden stubs to visible
        // `todo!()` so contributors cannot accidentally exercise them.
        todo!("BIP340 signing — verification_method-keyed secret-key retrieval")
    }

    // bip340 cryptosuite spec Section 3.3.7
    fn proof_verify(
        &self,
        hash_data: Sha256Hash,
        proof_bytes: Signature,
        public_key: PublicKey,
    ) -> Result<(), Btc1Error> {
        // Verify signature
        bip340_verify(hash_data, proof_bytes, &public_key.x_only_public_key().0)
    }
}

/// Sign data using BIP340 Schnorr signatures
fn bip340_sign(message_hash: Sha256Hash, secret_key: SecretKey) -> Result<Signature, Btc1Error> {
    let secp = Secp256k1::new();

    // Create message object from hash
    let message = Message::from_slice(&message_hash.0)
        .expect("Sha256Hash is exactly 32 bytes; Message::from_slice requires 32");

    // Sign with BIP340 Schnorr
    let keypair = KeyPair::from_secret_key(&secp, &secret_key);

    Ok(secp.sign_schnorr_no_aux_rand(&message, &keypair))
}

/// Verify a BIP340 Schnorr signature
fn bip340_verify(
    message_hash: Sha256Hash,
    signature: Signature,
    public_key: &XOnlyPublicKey,
) -> Result<(), Btc1Error> {
    let secp = Secp256k1::new();

    // Create message object from hash
    let message = Message::from_slice(&message_hash.0)
        .expect("Sha256Hash is exactly 32 bytes; Message::from_slice requires 32");

    // Verify signature
    secp.verify_schnorr(&signature, &message, public_key)
        .map_err(|_| Btc1Error::InvalidUpdateProof("Verification failed".into()))
}

/// Encode binary data using Multibase (base58-btc)
fn multibase_encode(signature: Signature) -> ProofValue {
    ProofValue(encode(Base::Base58Btc, signature.as_ref()))
}

/// Decode multibase encoded string
fn multibase_decode(proof_value: &ProofValue) -> Result<Signature, Btc1Error> {
    let decoded = decode(&proof_value.0)
        .map(|(_, decoded)| decoded)
        .map_err(|_| Btc1Error::ProofVerification("Invalid proofValue encoding".into()))?;

    Signature::from_slice(&decoded)
        .map_err(|_| Btc1Error::ProofVerification("Invalid proofValue encoding".into()))
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
            Btc1Error::InvalidUpdateProof(msg) => {
                assert!(
                    msg.contains("length"),
                    "expected length-mismatch message, got: {msg}"
                );
            }
            other => panic!("expected InvalidUpdateProof, got {other:?}"),
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
        assert!(matches!(err, Btc1Error::InvalidUpdateProof(_)));
    }
}
