//! A Rust implementation of the **did:btcr2** Bitcoin DID method.
//!
//! `did:btcr2` is a censorship-resistant DID method anchored to the Bitcoin
//! blockchain. This crate provides the spec-conformant `create`, `resolve`,
//! `update`, and `deactivate` operations over a **sans-I/O** core: the
//! [`resolver`] drives a state machine that asks the caller to fetch
//! blockchain data and feeds the responses back, so the library performs no
//! network or disk I/O itself. I/O-bearing composition lives in the separate
//! `did-btcr2-client` facade.
//!
//! The current scope is the **Singleton beacon** path (a single Bitcoin
//! address announcing updates for one DID); CAS and Sparse Merkle Tree beacons
//! are planned for future milestones. Canonicalization is JCS (JSON
//! Canonicalization Scheme) with SHA-256, and update proofs use the BIP340
//! Schnorr Data Integrity cryptosuite.
//!
//! Key entry points: [`Document`] for DID documents, [`identifier::Did`] for
//! parsed identifiers, and [`Resolver`](resolver::Resolver) for resolution.
#![deny(missing_docs)]

pub mod beacon;
pub mod document;
pub mod error;
pub mod identifier;
pub mod key;
pub mod resolver;
pub mod verification;

mod canonical_hash;
mod cryptosuite;
mod json_tools;
mod update;
mod zcap;

#[cfg(test)]
mod test_signing;

// Re-exports of key components
pub use beacon::{
    AnnounceError, BeaconInput, BeaconInputScheme, Prevout, Sig, Sighash, SignedBeaconTx,
    UnsignedBeaconTx,
};
pub use document::{
    Document, DocumentMetadata, ResolutionMetadata, ResolutionOptions, ResolutionResult,
};
pub use key::{KeyPair, PublicKey, SecretKey};
pub use update::Update;
