//! Verification methods: the public keys a DID document authorizes for
//! signing updates.

use crate::key::{PublicKey, PublicKeyExt as _};
use std::{cmp::PartialEq, str::FromStr};

/// Verification method ID
///
/// These look like DIDs with a `#fragment`. Used to identify [`VerificationMethod`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethodId(pub(crate) String);

impl FromStr for VerificationMethodId {
    type Err = std::convert::Infallible;

    fn from_str(method_id: &str) -> Result<Self, Self::Err> {
        Ok(Self(method_id.to_string()))
    }
}

/// One entry of the top-level `verificationMethod` array.
///
/// Entries are retained as opaque DID Core 1.1 §5.2 objects: any controller
/// DID, any key encoding. A document may carry an Ed25519 Multikey with a
/// `did:key` controller or a JWK with no `publicKeyMultibase` next to its
/// secp256k1 key, and it still parses. The one parse-time rule is that an
/// entry carrying `publicKeyMultibase` declares `type` `Multikey`, this
/// crate's reading of resolve.md's DID Core conformance check rather than a
/// rule the spec names (see `DocumentFields` parsing). Nothing is decoded here
/// because did-btcr2/src/operations/resolve.md
/// ("Check `update.proof`") reads `publicKeyMultibase` only from the entry a
/// proof invokes; the key is decoded at that point
/// (`DocumentFields<Did>::invoking_public_key`), never at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethod {
    /// Identifier for the verification method
    pub id: VerificationMethodId,

    /// Type of verification method, carried as the raw parsed `type` string
    /// (e.g. `"Multikey"`). Document parsing requires `"Multikey"` when
    /// `public_key_multibase` is present; beyond that it does not select a
    /// key: the resolve path reads `publicKeyMultibase` from the invoked
    /// entry and verifies with the BIP340 cryptosuite.
    pub type_: String,

    /// The controller DID, verbatim; not parsed as a did:btcr2 identifier (a
    /// foreign method may name a `did:key`).
    pub controller: String,

    /// The object's `publicKeyMultibase`, verbatim, when it has one.
    pub public_key_multibase: Option<String>,
}

/// A verification method object carried inside a relationship array
/// (DID Core 1.1 §5.3.1). Any DID Core verification method may appear
/// here — any `type`, any `controller`, any key encoding — so the
/// object is retained by its `id` and its raw `publicKeyMultibase`, if
/// present. Only the entry that a proof invokes is read as a key, and
/// it is decoded at that point (did-btcr2/src/operations/resolve.md,
/// "Check update.proof").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedVerificationMethod {
    /// The object's `id`; may be a relative DID URL.
    pub id: VerificationMethodId,
    /// The object's `publicKeyMultibase`, verbatim, when it has one.
    pub public_key_multibase: Option<String>,
}

/// One entry of a verification-relationship array (`authentication`,
/// `assertionMethod`, `capabilityInvocation`, `capabilityDelegation`):
/// either a reference to an entry of `verificationMethod`, or a
/// verification method embedded in place (DID Core 1.1 §5.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationRelationship {
    /// A DID URL naming an entry of `verificationMethod`; may be relative to
    /// the document `id`.
    Reference(VerificationMethodId),
    /// A verification method carried in the relationship array itself.
    Embedded(EmbeddedVerificationMethod),
}

impl VerificationMethod {
    /// Create a new Multikey verification method for a secp256k1 key.
    ///
    /// Sets `type_` to `"Multikey"` — the only type this crate signs with —
    /// and `public_key_multibase` to the key's Multikey encoding. To carry
    /// an entry parsed from a document (which may be of any type and key
    /// encoding), use [`Self::with_type`].
    pub fn new(id: VerificationMethodId, controller: String, public_key: PublicKey) -> Self {
        Self::with_type(
            id,
            controller,
            Some(public_key.to_multikey()),
            "Multikey".to_string(),
        )
    }

    /// Create a verification method from its parsed fields, verbatim.
    ///
    /// Used by the document parser to retain an entry's declared type,
    /// controller and `publicKeyMultibase` as they appear. The type string
    /// does not affect whether the key is used.
    pub fn with_type(
        id: VerificationMethodId,
        controller: String,
        public_key_multibase: Option<String>,
        type_: String,
    ) -> Self {
        Self {
            id,
            type_,
            controller,
            public_key_multibase,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;

    /// `with_type` carries the declared type, controller and
    /// `publicKeyMultibase` verbatim — a foreign method with a `did:key`
    /// controller is retained as-is — and `new` defaults the type to
    /// `"Multikey"` with the secp256k1 key's Multikey encoding.
    #[test]
    fn with_type_keeps_the_declared_type_string() {
        let id = VerificationMethodId("did:btcr2:x1abc#key-0".to_string());
        let ed25519 = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        let vm = VerificationMethod::with_type(
            id.clone(),
            format!("did:key:{ed25519}"),
            Some(ed25519.to_string()),
            "Ed25519VerificationKey2020".to_string(),
        );
        assert_eq!(vm.type_, "Ed25519VerificationKey2020");
        assert_eq!(vm.controller, format!("did:key:{ed25519}"));
        assert_eq!(vm.public_key_multibase.as_deref(), Some(ed25519));

        let keyless = VerificationMethod::with_type(
            id.clone(),
            "did:example:other".to_string(),
            None,
            "JsonWebKey2020".to_string(),
        );
        assert_eq!(keyless.public_key_multibase, None);

        let public_key = KeyPair::generate().public_key;
        let via_new = VerificationMethod::new(id, "did:btcr2:x1abc".to_string(), public_key);
        assert_eq!(via_new.type_, "Multikey");
        assert_eq!(via_new.controller, "did:btcr2:x1abc");
        assert_eq!(via_new.public_key_multibase, Some(public_key.to_multikey()));
    }
}
