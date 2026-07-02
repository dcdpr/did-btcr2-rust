//! Error types and W3C DID Resolution Problem Details mapping for did:btcr2
//! operations.

use crate::identifier::Sha256Hash;
use onlyerror::Error;
use serde_json::{Value, json};

/// Legacy top-level error type. Retained only for ZCAP errors pending the full
/// error-vocabulary reconciliation; new spec errors live in [`Btcr2Error`].
// TODO: Remove this
#[derive(Error, Debug)]
pub enum Error {
    /// ZCAP (Authorization Capabilities) related errors
    #[error("ZCAP error: {0}")]
    Zcap(String),
}

/// Maps an error to a W3C DID Resolution Problem Details JSON-LD object, as
/// returned in `didResolutionMetadata` when a resolution operation fails.
pub trait ProblemDetails {
    /// The Problem Details JSON-LD object for this error, or `None` when the
    /// error carries no spec-defined detail body.
    fn details(&self) -> Option<Value> {
        None
    }
}

/// Errors defined by the did:btcr2 specification and the related W3C DID
/// Resolution and Data Integrity specifications.
#[derive(Error, Debug)]
pub enum Btcr2Error {
    // Errors from DID Resolution Spec
    //
    /// An invalid DID was detected during DID Resolution.
    InvalidDid(String),

    /// The DID document was malformed.
    InvalidDidDocument(String),

    // Errors from DID BTCR2 Spec
    //
    /// Sidecar data was invalid
    InvalidSidecarData(String),

    /// Update payload was published late
    LatePublishingError(String),

    /// Update payload could not be located in either the supplied sidecar
    /// data nor in CAS (spec MISSING_UPDATE_DATA).
    ///
    /// Spec: did-btcr2/src/errors.md:21-23. Added for exactly this variant.
    /// Other non-spec error variants (ProofTransformation, ProofGeneration,
    /// Zcap) remain deferred to a later error-vocabulary cleanup.
    MissingUpdateData {
        /// JSON Document Hash of the update payload that could not be located.
        update_hash: Sha256Hash,
    },

    /// Invalid Update Proof
    InvalidUpdateProof(String),

    /// ZCAP (Authorization Capabilities) related errors
    Zcap(String),

    /// Problems when creating or applying a DID Update
    InvalidDidUpdate(String),

    // Errors from Verifiable Credentials Data Integrity Spec
    //
    /// Proof verification error
    ProofVerification(String),

    /// Proof transformation error
    ProofTransformation(String),

    /// Proof generation error
    ProofGeneration(String),

    /// A subject-controlled beacon/CAS path reached an arm not yet implemented
    /// (CAS Map / Sparse Merkle Tree / genesis-CAS retrieval). Returned instead
    /// of panicking the resolver, so a remote-published DID reaching these arms
    /// yields a typed resolution error rather than crashing the process.
    ///
    /// PROVISIONAL problem-details code — subject to the deferred error-
    /// vocabulary audit, which replaces these arms with real implementations
    /// and may keep or rename this variant and its code.
    Unsupported(String),
}

impl Btcr2Error {
    pub(crate) fn late_publishing(found_hash: Sha256Hash, expected_hash: Sha256Hash) -> Self {
        Self::LatePublishingError(format!(
            "Found hash `{}`, expected `{}`",
            hex::encode(found_hash.0),
            hex::encode(expected_hash.0),
        ))
    }
}

impl ProblemDetails for Btcr2Error {
    fn details(&self) -> Option<Value> {
        let prefix = match self {
            Self::InvalidDid(_) | Self::InvalidDidDocument(_) => "https://www.w3.org/ns/did",
            // TODO: Is this the right error namespace?
            // From: https://github.com/dcdpr/did-btcr2/issues/71#issuecomment-3179550385
            Self::InvalidSidecarData(_)
            | Self::LatePublishingError(_)
            | Self::MissingUpdateData { .. }
            | Self::InvalidUpdateProof(_)
            | Self::Zcap(_)
            | Self::InvalidDidUpdate(_)
            | Self::ProofVerification(_)
            | Self::ProofTransformation(_)
            | Self::ProofGeneration(_)
            | Self::Unsupported(_) => "https://btc1.dev/context/v1",
        };

        let name = match self {
            Self::InvalidDid(_) => "INVALID_DID",
            Self::InvalidDidDocument(_) => "INVALID_DID_DOCUMENT",
            Self::InvalidSidecarData(_) => "INVALID_SIDECAR_DATA",
            Self::LatePublishingError(_) => "LATE_PUBLISHING_ERROR",
            Self::MissingUpdateData { .. } => "MISSING_UPDATE_DATA",
            Self::InvalidUpdateProof(_) => "INVALID_UPDATE_PROOF",
            Self::Zcap(_) => "ZCAP",
            Self::InvalidDidUpdate(_) => "INVALID_DID_UPDATE",
            Self::ProofVerification(_) => "PROOF_VERIFICATION_ERROR",
            Self::ProofTransformation(_) => "PROOF_TRANSFORMATION_ERROR",
            Self::ProofGeneration(_) => "PROOF_GENERATION_ERROR",
            // PROVISIONAL — no spec "unsupported" code exists (errors.md); this
            // btcr2-namespaced code is subject to the deferred error-vocabulary
            // audit, which may rename it.
            Self::Unsupported(_) => "UNSUPPORTED_BEACON",
        };

        Some(json!({
            "type": format!("{prefix}#{name}"),
            "title": self.to_string(),
            "detail": match self {
                Self::InvalidDid(detail) => detail.clone(),
                Self::InvalidDidDocument(detail) => detail.clone(),
                Self::InvalidSidecarData(detail) => detail.clone(),
                Self::LatePublishingError(detail) => detail.clone(),
                Self::MissingUpdateData { update_hash } => {
                    format!("update_hash={}", hex::encode(update_hash.0))
                }
                Self::InvalidUpdateProof(detail) => detail.clone(),
                Self::Zcap(detail) => detail.clone(),
                Self::InvalidDidUpdate(detail) => detail.clone(),
                Self::ProofVerification(detail) => detail.clone(),
                Self::ProofTransformation(detail) => detail.clone(),
                Self::ProofGeneration(detail) => detail.clone(),
                Self::Unsupported(detail) => detail.clone(),
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared `Unsupported` variant is fully wired into `problem_details`:
    /// the `type` carries the provisional `UNSUPPORTED_BEACON` code and the
    /// `detail` is the arm-naming message. Proves all three match arms (prefix,
    /// name, detail) are present.
    #[test]
    fn unsupported_problem_details_carries_provisional_code_and_detail() {
        let message = "CAS Map beacon resolution is not yet implemented";
        let err = Btcr2Error::Unsupported(message.into());
        let details = err.details().expect("Unsupported yields problem details");

        assert_eq!(
            details["type"],
            "https://btc1.dev/context/v1#UNSUPPORTED_BEACON",
        );
        assert_eq!(details["detail"], message);
    }

    /// `InvalidDid` carries the W3C `did` namespace prefix, the `INVALID_DID`
    /// code, a Display-wired `title`, and the plain carried detail string.
    #[test]
    fn invalid_did_problem_details_shape() {
        let err = Btcr2Error::InvalidDid("bad did".into());
        let d = err.details().expect("InvalidDid yields problem details");
        assert_eq!(d["type"], "https://www.w3.org/ns/did#INVALID_DID");
        assert_eq!(d["title"], err.to_string());
        assert_eq!(d["detail"], "bad did");
    }

    /// `InvalidDidDocument` is the second variant on the W3C `did` prefix; its
    /// code is `INVALID_DID_DOCUMENT`.
    #[test]
    fn invalid_did_document_problem_details_shape() {
        let err = Btcr2Error::InvalidDidDocument("bad doc".into());
        let d = err
            .details()
            .expect("InvalidDidDocument yields problem details");
        assert_eq!(d["type"], "https://www.w3.org/ns/did#INVALID_DID_DOCUMENT");
        assert_eq!(d["title"], err.to_string());
        assert_eq!(d["detail"], "bad doc");
    }

    /// `MissingUpdateData` covers the second namespace prefix (btc1.dev) and the
    /// non-trivial formatted-detail arm (hex of the 32-byte update hash).
    #[test]
    fn missing_update_data_problem_details_shape() {
        let err = Btcr2Error::MissingUpdateData {
            update_hash: Sha256Hash([0u8; 32]),
        };
        let d = err
            .details()
            .expect("MissingUpdateData yields problem details");
        // NOTE: this pins the current `btc1.dev` namespace prefix. The
        // btc1.dev -> btcr2.dev namespace rename is still outstanding; this
        // assertion is a deliberate re-bless site and MUST be updated to
        // `btcr2.dev` when that rename lands.
        assert_eq!(d["type"], "https://btc1.dev/context/v1#MISSING_UPDATE_DATA");
        assert_eq!(d["title"], err.to_string());
        // detail is the formatted hex of the 32-byte hash (all-zero here).
        assert_eq!(
            d["detail"],
            format!("update_hash={}", hex::encode([0u8; 32]))
        );
    }
}
