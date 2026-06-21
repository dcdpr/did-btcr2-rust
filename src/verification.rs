//! Verification methods: the public keys a DID document authorizes for
//! signing updates, and the trait for resolving them by id.

use crate::{identifier::Did, key::PublicKey};
use onlyerror::Error;
use std::{cmp::PartialEq, str::FromStr};

/// Errors arising while parsing or resolving a verification method.
#[derive(Error, Debug)]
pub enum Error {
    /// Unsupported verification method type
    UnsupportedVerificationMethod,
}

/// Verification method types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationMethodType {
    /// Multikey verification method
    Multikey,

    /// Other types
    Other,
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

    /// Type of verification method
    pub type_: VerificationMethodType,

    /// The controller of this verification method
    pub controller: T,

    /// Public key
    pub public_key: PublicKey,
}

impl<T> VerificationMethod<T> {
    /// Create a new verification method
    pub fn new(id: VerificationMethodId, controller: T, public_key: PublicKey) -> Self {
        Self {
            id,
            type_: VerificationMethodType::Multikey,
            controller,
            public_key,
        }
    }

    /// Get the public key from this verification method
    pub fn public_key(&self) -> Result<&PublicKey, Error> {
        if self.type_ != VerificationMethodType::Multikey {
            return Err(Error::UnsupportedVerificationMethod);
        }

        Ok(&self.public_key)
    }
}

/// Mock verification method resolver for testing
#[derive(Debug, Default)]
pub struct MockVerificationMethodResolver {
    methods: Vec<VerificationMethod<Did>>,
}

impl MockVerificationMethodResolver {
    /// Create a new empty resolver
    pub fn new() -> Self {
        Self {
            methods: Vec::new(),
        }
    }

    /// Add a verification method to the resolver
    pub fn add_method(&mut self, method: VerificationMethod<Did>) {
        self.methods.push(method);
    }

    /// Resolve a verification method by ID
    pub fn resolve(&self, id: VerificationMethodId) -> Option<&VerificationMethod<Did>> {
        self.methods.iter().find(|m| m.id == id)
    }
}

/// Trait for resolving verification methods
pub trait VerificationMethodResolver {
    /// Resolve a verification method by ID
    fn resolve(&self, id: &str) -> Result<VerificationMethod<Did>, Error>;
}
