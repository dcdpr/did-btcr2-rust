//! Verification methods: the public keys a DID document authorizes for
//! signing updates.

use crate::key::PublicKey;
use onlyerror::Error;
use std::{cmp::PartialEq, str::FromStr};

/// Errors arising while parsing or resolving a verification method.
#[derive(Error, Debug)]
pub enum Error {
    /// Unsupported verification method type
    UnsupportedVerificationMethod,
}

/// Verification method ID
///
/// These look like DIDs with a `#fragment`. Used to identify [`VerificationMethod`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethodId(pub(crate) String);

impl FromStr for VerificationMethodId {
    type Err = Error;

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
    /// (e.g. `"Multikey"`). The two-tier leniency policy keeps a non-Multikey
    /// method in the parsed document (lenient envelope) but rejects it at key
    /// extraction (strict crypto-trust boundary); see [`Self::public_key`].
    pub type_: String,

    /// The controller of this verification method
    pub controller: T,

    /// Public key
    pub public_key: PublicKey,
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
    /// Used by the document parser to retain a method's declared type verbatim
    /// (lenient envelope). A non-Multikey type is retained here but rejected at
    /// [`Self::public_key`] (strict crypto-trust boundary).
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

    /// Get the public key from this verification method.
    ///
    /// Fails with [`Error::UnsupportedVerificationMethod`] unless the method's
    /// declared `type` is exactly `"Multikey"` — the strict side of the
    /// two-tier leniency policy: a non-Multikey method may be retained in the
    /// parsed document, but its key MUST NOT be used to verify a proof.
    pub fn public_key(&self) -> Result<&PublicKey, Error> {
        if self.type_ != "Multikey" {
            return Err(Error::UnsupportedVerificationMethod);
        }

        Ok(&self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;

    fn vm_with_type(type_: &str) -> VerificationMethod<String> {
        VerificationMethod::with_type(
            VerificationMethodId("did:btcr2:x1abc#key-0".to_string()),
            "did:btcr2:x1abc".to_string(),
            KeyPair::generate().public_key,
            type_.to_string(),
        )
    }

    /// Strict crypto-trust boundary: a retained non-Multikey verification
    /// method fails at key extraction rather than silently coercing to Multikey.
    #[test]
    fn public_key_rejects_non_multikey_type() {
        let vm = vm_with_type("Ed25519VerificationKey2020");
        assert!(matches!(
            vm.public_key(),
            Err(Error::UnsupportedVerificationMethod)
        ));
    }

    /// Happy path: a Multikey verification method yields its key.
    #[test]
    fn public_key_returns_key_for_multikey_type() {
        let vm = vm_with_type("Multikey");
        let pk = vm.public_key().expect("Multikey extraction succeeds");
        assert_eq!(pk, &vm.public_key);
    }

    /// `new` preserves the Multikey default for in-crate constructions.
    #[test]
    fn new_defaults_to_multikey() {
        let vm = VerificationMethod::with_type(
            VerificationMethodId("did:btcr2:x1abc#key-0".to_string()),
            "did:btcr2:x1abc".to_string(),
            KeyPair::generate().public_key,
            "Multikey".to_string(),
        );
        let via_new = VerificationMethod::new(vm.id.clone(), vm.controller.clone(), vm.public_key);
        assert_eq!(via_new.type_, "Multikey");
        assert!(via_new.public_key().is_ok());
    }
}
