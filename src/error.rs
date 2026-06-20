use crate::identifier::Sha256Hash;
use onlyerror::Error;
use serde_json::{Value, json};

// TODO: Remove this
#[derive(Error, Debug)]
pub enum Error {
    /// ZCAP (Authorization Capabilities) related errors
    #[error("ZCAP error: {0}")]
    Zcap(String),
}

// Errors defined by the DID:BTCR2 specification and other related specifications.
pub trait ProblemDetails {
    fn details(&self) -> Option<Value> {
        None
    }
}

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
    MissingUpdateData { update_hash: Sha256Hash },

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
            | Self::ProofGeneration(_) => "https://btc1.dev/context/v1",
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
            },
        }))
    }
}
