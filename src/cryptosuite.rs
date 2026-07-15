#![allow(dead_code)] // todo
#![warn(clippy::unwrap_used)]

//! BIP340 cryptosuite implementation.
//!
//! Panic-sweep policy: test code is exempted via clippy.toml.

use crate::update::{UnsecuredUpdate, Update};
use crate::zcap::proof::{Proof, ProofInner, ProofPurpose, ProofValue};
use crate::{
    error::Btcr2Error,
    identifier::Sha256Hash,
    key::{PublicKey, SecretKey},
};
use multibase::{Base, decode, encode};
use secp256k1::schnorr::Signature;
use secp256k1::{KeyPair, Message, Secp256k1, XOnlyPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) struct CryptoSuite;

impl CryptoSuite {
    // bip340 cryptosuite spec Section 3.3.1
    pub(crate) fn create_proof(
        &self,
        unsecured_update: &UnsecuredUpdate,
        mut inner: ProofInner,
        secret_key: &SecretKey,
    ) -> Result<Proof, Btcr2Error> {
        // Add document context to proof if present.
        //
        // Construction-side only: the spec's update `@context` entries are all
        // string URLs (data-structures.md, BTCR2 Unsigned Update), so a non-string
        // entry here is a malformed update — reject it with a typed error rather
        // than silently drop it (the old `flat_map(as_str)` vanished non-string
        // entries, letting the signed proof config diverge from the update's
        // declared context). This is NOT a general JSON-LD validator; the
        // verifier's exact-match-vs-prefix @context semantics remain deferred
        // (QUESTIONS item 11) and are untouched here.
        if let Some(context) = unsecured_update.as_ref()["@context"].as_array() {
            inner.context = context
                .iter()
                .map(|e| {
                    e.as_str().map(str::to_string).ok_or_else(|| {
                        Btcr2Error::InvalidDidUpdate("@context entries must be strings".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
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

        // Configure proof.
        //
        // proofOptions = securedDocument.proof minus proofValue, taken from the
        // ORIGINAL proof JSON (Cryptosuite §3.3.2 step 2), NOT a re-serialisation
        // of the typed `ProofInner`. The typed path normalises `.000Z` created
        // datetimes (chrono re-emits `...Z`) and drops unknown extension
        // properties (ProofInner has no `#[serde(flatten)]` catch-all); either
        // divergence changes the JCS bytes and falsely rejects a conformant
        // foreign signature. Reading the original JSON here mirrors the @context
        // handling above (`update.as_ref()["@context"]`).
        let mut proof_options = update.as_ref()["proof"].clone();
        // Fail loud if `proof` is absent/not an object: indexing a missing key
        // yields Value::Null, and silently hashing `null` would swap a clean
        // typed rejection for an opaque signature mismatch and drop the invariant
        // announcement the old `.expect("JSON is always valid JCS")` gave. A
        // malformed update must be reported, not smuggled through.
        let serde_json::Value::Object(map) = &mut proof_options else {
            return Err(Btcr2Error::InvalidUpdateProof(
                "update proof is absent or not a JSON object".into(),
            ));
        };
        map.remove("proofValue");
        // Extension-property authentication boundary: a property INSIDE this
        // `proof` object IS JCS-canonicalised into the signed proofOptions hash
        // below, so it IS covered by the BIP340 signature (authenticated). Only
        // properties OUTSIDE `proof` (elsewhere in the update) ride along
        // unauthenticated; the crate never reads those.
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

        let digest: [u8; 32] = hasher.finalize().into();
        Sha256Hash::from(digest)
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
        secret_key: &SecretKey,
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
fn bip340_sign(message_hash: Sha256Hash, secret_key: &SecretKey) -> Result<Signature, Btcr2Error> {
    let secp = Secp256k1::new();

    // Create message object from hash
    let message = Message::from_slice(message_hash.as_bytes())
        .expect("Sha256Hash is exactly 32 bytes; Message::from_slice requires 32");

    // Sign with BIP340 Schnorr. This is the ONLY place the inner secp key is
    // unwrapped (the final point of use). `KeyPair` here is secp256k1's own
    // type, unrelated to crate::key::KeyPair.
    let keypair = KeyPair::from_secret_key(&secp, secret_key.as_inner());

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
    let message = Message::from_slice(message_hash.as_bytes())
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
    // crate::key: `pub use secp256k1::PublicKey`), so sk.public_key(&secp)
    // returns exactly the type verify_proof expects.
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
        SecretKey::try_from([1u8; 32]).expect("[1u8; 32] is a valid secp256k1 secret key")
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
            .create_proof(&unsigned_update(), proof_inner(), &test_secret_key())
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
            .create_proof(&unsigned_update(), proof_inner(), &test_secret_key())
            .expect("first signing must succeed");
        let second = suite
            .create_proof(&unsigned_update(), proof_inner(), &test_secret_key())
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
    fn create_proof_rejects_non_string_context_entry() {
        // A non-string `@context` entry (here a number) is a malformed
        // update payload and must produce a typed `Btcr2Error::InvalidDidUpdate`
        // at proof construction — NOT be silently dropped (the old
        // `flat_map(as_str)` vanished it, so the signed proof config could diverge
        // from the update's declared context).
        let update = UnsecuredUpdate {
            json: serde_json::json!({
                "@context": ["https://w3id.org/security/v2", 42],
                "patch": [],
                "targetVersionId": 2,
            }),
        };
        let suite = CryptoSuite;
        let err = suite
            .create_proof(&update, proof_inner(), &test_secret_key())
            .expect_err("a non-string @context entry must be rejected");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => {
                assert!(
                    msg.contains("@context"),
                    "message should name @context, got: {msg}"
                );
            }
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    #[test]
    fn create_proof_accepts_all_string_context() {
        // Happy path: an all-string `@context` still signs and the proof carries
        // the contexts verbatim (the fallible map is order- and
        // content-preserving for well-formed input).
        let update = UnsecuredUpdate {
            json: serde_json::json!({
                "@context": ["https://w3id.org/security/v2", "https://w3id.org/zcap/v1"],
                "patch": [],
                "targetVersionId": 2,
            }),
        };
        let suite = CryptoSuite;
        let proof = suite
            .create_proof(&update, proof_inner(), &test_secret_key())
            .expect("an all-string @context must sign successfully");
        assert_eq!(
            proof.inner.context,
            vec![
                "https://w3id.org/security/v2".to_string(),
                "https://w3id.org/zcap/v1".to_string(),
            ],
            "the proof config carries the update's string contexts verbatim"
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

    // The BIP340 sign/verify core. `bip340_sign`/`bip340_verify` are
    // private, so these test them directly via `super::`. proofValue is
    // attacker-influenceable, so a mutated signature must not verify.

    #[test]
    fn test_bip340_sign_verify_round_trip() {
        // A signature produced by bip340_sign over a message verifies against the
        // signer's x-only public key.
        let sk = test_secret_key();
        let secp = Secp256k1::new();
        let xonly = sk.as_inner().public_key(&secp).x_only_public_key().0;
        let msg = Sha256Hash::from([0x11u8; 32]);

        let sig = bip340_sign(msg, &sk).expect("signing with a valid key must succeed");
        bip340_verify(msg, sig, &xonly).expect("a fresh signature must verify");
    }

    #[test]
    fn test_bip340_verify_rejects_flipped_signature_byte() {
        // Flipping one byte of the 64-byte signature must fail verification. Byte
        // index 32 is in the `s` scalar half; the mutation still parses through
        // Signature::from_slice (length is unchanged) but fails the Schnorr check
        // — so this is a VERIFY rejection, not a parse rejection.
        //
        // NOTE (deviation from plan): bip340_verify returns the CONCRETE variant
        // Btcr2Error::InvalidUpdateProof on verify failure (cryptosuite.rs:228),
        // not ProofVerification as the plan text stated. The behavior (rejection)
        // is what matters; we assert the variant the code actually returns.
        let sk = test_secret_key();
        let secp = Secp256k1::new();
        let xonly = sk.as_inner().public_key(&secp).x_only_public_key().0;
        let msg = Sha256Hash::from([0x11u8; 32]);

        let sig = bip340_sign(msg, &sk).expect("signing with a valid key must succeed");
        let mut bytes: [u8; 64] = *sig.as_ref();
        bytes[32] ^= 0x01;
        let bad = Signature::from_slice(&bytes)
            .expect("a length-preserving byte flip still parses as a Signature");

        let err = bip340_verify(msg, bad, &xonly)
            .expect_err("a flipped signature byte must fail verification");
        match err {
            Btcr2Error::InvalidUpdateProof(_) => {}
            other => panic!("expected InvalidUpdateProof, got {other:?}"),
        }
    }

    // The length half: a valid base58-btc encoding
    // of a NON-64-byte buffer passes the base check but must fail closed at
    // Signature::from_slice's length check with ProofVerification — never yield a
    // bogus Signature. The base-mismatch half is covered by
    // multibase_decode_rejects_non_base58btc; the from_bip21 network-mismatch
    // half of this rule lives in beacon.rs.
    #[test]
    fn test_multibase_decode_rejects_wrong_length() {
        // 32 bytes, correctly base58-btc-encoded: right base, wrong length.
        let short = [0x42u8; 32];
        let base58 = multibase::encode(Base::Base58Btc, short);
        assert!(
            base58.starts_with('z'),
            "sanity: base58-btc multibase prefix is 'z'"
        );

        let err = multibase_decode(&ProofValue(base58))
            .expect_err("a non-64-byte base58-btc body must be rejected");
        match err {
            Btcr2Error::ProofVerification(_) => {}
            other => panic!("expected ProofVerification, got {other:?}"),
        }
    }

    // The highest-value interop fix: verify_proof must build the
    // proofOptions bytes from the ORIGINAL proof JSON (`update.json["proof"]`
    // minus proofValue), not a re-serialisation of the lossy typed ProofInner.
    // The helper below hand-forges a foreign proof over the SAME original-JSON
    // proofOptions the fixed verify path uses, so the two lossy-field positives
    // exercise exactly the divergence a typed re-emission would introduce.

    // The secp256k1 public key matching `test_secret_key()`. `verify_proof`
    // takes `crate::key::PublicKey` (== `secp256k1::PublicKey`) and derives its
    // own x-only key, matching what `bip340_sign` signs under.
    fn test_public_key() -> secp256k1::PublicKey {
        let secp = Secp256k1::new();
        test_secret_key().as_inner().public_key(&secp)
    }

    // Hand-forge a valid `proofValue` over `update_json` (which carries a `proof`
    // object; any existing proofValue is ignored) using the ORIGINAL-JSON
    // proofOptions path the fixed `verify_proof` uses:
    //   proofOptions = proof minus proofValue
    //   transformed  = update minus proof
    //   hash         = Sha256(Sha256(proofOptions) || Sha256(transformed))   [hash(), 151-159]
    // then BIP340-signs that hash with `test_secret_key()` and inserts the
    // base58-btc proofValue. Because it drives the SAME private
    // configure_proof/transform/hash chain, a NO-lossy-field control forged this
    // way verifies on any tree — proving the composition is faithful — while a
    // lossy-field variant only verifies once Task 1 stops discarding those bytes.
    fn forge_signed_update(mut update_json: serde_json::Value) -> Update {
        let suite = CryptoSuite;

        // proofOptions = proof minus proofValue (from the ORIGINAL JSON).
        let mut proof_options = update_json["proof"].clone();
        proof_options
            .as_object_mut()
            .expect("proof is a JSON object")
            .remove("proofValue");
        let proof_config = suite.configure_proof(&proof_options);

        // transformed = update minus proof.
        let mut unsecured_json = update_json.clone();
        unsecured_json
            .as_object_mut()
            .expect("update json is a JSON object")
            .remove("proof");
        let unsecured = UnsecuredUpdate {
            json: unsecured_json,
        };
        let transformed = suite.transform(&unsecured);

        // hash = Sha256(Sha256(proof_config) || Sha256(transformed)).
        let hash = suite.hash(&transformed, &proof_config);
        let sig =
            bip340_sign(hash, &test_secret_key()).expect("signing with a valid key must succeed");
        let proof_value = multibase_encode(sig);

        update_json["proof"]["proofValue"] = serde_json::json!(proof_value.0);
        make_update(update_json)
    }

    #[test]
    fn verify_accepts_foreign_created_with_millis() {
        let suite = CryptoSuite;

        // CONTROL (composition gate, asserted FIRST): a proof whose `created` is a
        // plain `"...Z"` (no lossy field). The typed round-trip re-emits this
        // byte-identically, so it verifies on ANY tree — proving our hand-rolled
        // Sha256(proof_config) || Sha256(transformed) + BIP340 path faithfully
        // reproduces hash(). Only after this passes do we trust the lossy positive.
        let mut control = base_update_json();
        control["proof"]["created"] = serde_json::json!("2024-01-01T00:00:00Z");
        let control_update = forge_signed_update(control);
        suite.verify_proof(test_public_key(), &control_update).expect(
            "control: plain '...Z' created (no lossy field) must verify — composition is faithful",
        );

        // LOSSY POSITIVE: same proof but `created` carries JS-style millis
        // `"...00.000Z"`. The typed ProofInner round-trip normalises this to
        // `"...00Z"` (different JCS bytes); building proofOptions from the ORIGINAL
        // proof JSON (Task 1) preserves the millis, so the foreign signature
        // verifies. Reverting Task 1 makes THIS assertion fail (typed path drops
        // the `.000`) while the control above would still pass — so the test is
        // non-vacuous and exercises exactly the created-millis divergence.
        let mut lossy = base_update_json();
        lossy["proof"]["created"] = serde_json::json!("2024-01-01T00:00:00.000Z");
        let lossy_update = forge_signed_update(lossy);
        suite.verify_proof(test_public_key(), &lossy_update).expect(
            "foreign proof with '.000Z' created must verify (millis preserved by original-JSON proofOptions)",
        );
    }

    #[test]
    fn verify_accepts_unknown_extension_property() {
        let suite = CryptoSuite;

        // CONTROL (composition gate, asserted FIRST): no extension property. Same
        // faithful-composition guarantee as above — verifies on any tree.
        let control = base_update_json();
        let control_update = forge_signed_update(control);
        suite
            .verify_proof(test_public_key(), &control_update)
            .expect("control: no extension property must verify — composition is faithful");

        // LOSSY POSITIVE: an unknown extension property INSIDE `proof`. ProofInner
        // has no `#[serde(flatten)]` catch-all, so the typed round-trip DROPS this
        // key (different JCS bytes). Original-JSON proofOptions (Task 1) retains
        // it, so the foreign proof verifies — and the property, being inside the
        // signed proofOptions, is authenticated. Reverting Task 1 makes THIS
        // assertion fail (typed path drops the key) while the control still
        // passes — non-vacuous, exercising the extension-property divergence.
        let mut lossy = base_update_json();
        lossy["proof"]["foreignExtension"] = serde_json::json!("interop");
        let lossy_update = forge_signed_update(lossy);
        suite
            .verify_proof(test_public_key(), &lossy_update)
            .expect("foreign proof carrying an unknown extension property must verify");
    }

    #[test]
    fn verify_proof_round_trips_locally_signed() {
        // A3 lock: a LOCALLY self-signed update (create_proof -> assemble Update
        // JSON exactly as construct_signed_update does) must still verify through
        // the fixed original-JSON proofOptions path. For a locally-built proof
        // (`created: None`, no extension props) the original JSON minus proofValue
        // is byte-identical to the old typed serialisation, so this positive holds
        // — the fix does not regress the sign->verify round-trip.
        let suite = CryptoSuite;

        // Unsigned document with valid sourceHash/targetHash (base_update_json
        // with the proof removed) so the assembled Update parses.
        let mut unsigned_json = base_update_json();
        unsigned_json
            .as_object_mut()
            .expect("base_update_json is a JSON object")
            .remove("proof");
        let unsigned = UnsecuredUpdate {
            json: unsigned_json,
        };

        let proof = suite
            .create_proof(&unsigned, proof_inner(), &test_secret_key())
            .expect("signing with a valid key must succeed");

        // Assemble the signed Update JSON exactly as construct_signed_update does
        // (document.rs:774-782): the unsigned JSON with "proof" inserted.
        let mut signed_json = unsigned.json;
        signed_json
            .as_object_mut()
            .expect("unsigned update is a JSON object")
            .insert(
                "proof".to_string(),
                serde_json::to_value(&proof).expect("proof serializes to JSON"),
            );

        let update =
            Update::from_json_value(signed_json).expect("locally signed update must parse");

        suite.verify_proof(test_public_key(), &update).expect(
            "a locally self-signed update must still verify through the original-JSON proofOptions path",
        );
    }
}
