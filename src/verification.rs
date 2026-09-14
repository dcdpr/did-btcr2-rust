//! Verification methods: the public keys a DID document authorizes for
//! signing updates.

use crate::key::PublicKey;
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

/// Represents a verification method for cryptographic proofs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethod<T> {
    /// Identifier for the verification method
    pub id: VerificationMethodId,

    /// Type of verification method, carried as the raw parsed `type` string
    /// (e.g. `"Multikey"`). It is not used to select or reject a key: the
    /// resolve path reads `publicKeyMultibase` and verifies with the BIP340
    /// cryptosuite regardless of the declared type.
    pub type_: String,

    /// The controller of this verification method
    pub controller: T,

    /// Public key
    pub public_key: PublicKey,
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

impl<T> VerificationMethod<T> {
    /// Create a new Multikey verification method.
    ///
    /// Sets `type_` to `"Multikey"` — the only type this crate signs with.
    /// To carry a type parsed from a foreign document (which may be
    /// non-Multikey), use [`Self::with_type`].
    pub fn new(id: VerificationMethodId, controller: T, public_key: PublicKey) -> Self {
        Self::with_type(id, controller, public_key, "Multikey".to_string())
    }

    /// Create a verification method carrying its parsed `type` string.
    ///
    /// Used by the document parser to retain a method's declared type
    /// verbatim. The type string does not affect whether the key is used.
    pub fn with_type(
        id: VerificationMethodId,
        controller: T,
        public_key: PublicKey,
        type_: String,
    ) -> Self {
        Self {
            id,
            type_,
            controller,
            public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;

    /// `with_type` carries the declared type string verbatim and `new`
    /// defaults it to `"Multikey"`; the key is reachable either way.
    #[test]
    fn with_type_keeps_the_declared_type_string() {
        let id = VerificationMethodId("did:btcr2:x1abc#key-0".to_string());
        let controller = "did:btcr2:x1abc".to_string();
        let public_key = KeyPair::generate().public_key;

        let vm = VerificationMethod::with_type(
            id.clone(),
            controller.clone(),
            public_key,
            "Ed25519VerificationKey2020".to_string(),
        );
        assert_eq!(vm.type_, "Ed25519VerificationKey2020");
        assert_eq!(vm.public_key, public_key);

        let via_new = VerificationMethod::new(id, controller, public_key);
        assert_eq!(via_new.type_, "Multikey");
        assert_eq!(via_new.public_key, public_key);
    }
}
