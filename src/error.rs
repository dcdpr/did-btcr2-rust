//! Error types and W3C DID Resolution Problem Details mapping for did:btcr2
//! operations.

use crate::identifier::Sha256Hash;
use onlyerror::Error;
use serde_json::{Value, json};

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
    //
    // Spec reference: did-btcr2/src/errors.md:21-23. Added for exactly this
    // variant; the other non-spec error variants are handled separately.
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

    /// A subject-controlled beacon/CAS path (CAS Map / Sparse Merkle Tree /
    /// genesis-CAS retrieval) reached an arm that is not yet implemented.
    //
    // Returned instead of panicking the resolver, so a remote-published DID
    // reaching these arms yields a typed resolution error rather than crashing
    // the process.
    //
    // The problem-details code is provisional and subject to a later
    // error-vocabulary audit, which replaces these arms with real
    // implementations and may keep or rename this variant and its code.
    Unsupported(String),
}

impl Btcr2Error {
    pub(crate) fn late_publishing(found_hash: Sha256Hash, expected_hash: Sha256Hash) -> Self {
        Self::LatePublishingError(format!(
            "Found hash `{}`, expected `{}`",
            hex::encode(found_hash.as_bytes()),
            hex::encode(expected_hash.as_bytes()),
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
            Self::LatePublishingError(_) => "LATE_PUBLISHING",
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
                    format!("update_hash={}", hex::encode(update_hash.as_bytes()))
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
            update_hash: Sha256Hash::from([0u8; 32]),
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

    /// Pins the wire `type` (prefix + `#NAME`) emitted by `ProblemDetails::details`
    /// for the three `did:btcr2` method errors in the spec error registry plus
    /// the empty-service-genesis `InvalidDidDocument`. Asserting the FULL string
    /// tripwires both a wrong namespace prefix AND a drifted code name — in
    /// particular this is what fails if `LATE_PUBLISHING` ever regresses to the
    /// old `LATE_PUBLISHING_ERROR` string. (The `btc1.dev` prefix is a tracked
    /// future rename; these assertions must be re-blessed to `btcr2.dev` then.)
    #[test]
    fn error_wire_codes_match_spec_registry() {
        let cases: [(Btcr2Error, &str); 4] = [
            (
                Btcr2Error::InvalidDidUpdate("bad update".into()),
                "https://btc1.dev/context/v1#INVALID_DID_UPDATE",
            ),
            (
                Btcr2Error::LatePublishingError("late".into()),
                "https://btc1.dev/context/v1#LATE_PUBLISHING",
            ),
            (
                Btcr2Error::MissingUpdateData {
                    update_hash: Sha256Hash::from([0u8; 32]),
                },
                "https://btc1.dev/context/v1#MISSING_UPDATE_DATA",
            ),
            (
                Btcr2Error::InvalidDidDocument("bad genesis".into()),
                "https://www.w3.org/ns/did#INVALID_DID_DOCUMENT",
            ),
        ];

        for (err, expected_type) in cases {
            let d = err
                .details()
                .expect("registry error yields problem details");
            assert_eq!(d["type"], expected_type, "wire type mismatch for {err:?}");
        }
    }

    /// The swept `MissingUpdateData` / `Unsupported` variants render a single
    /// concise user-facing `Display` (the problem-details `title`) with no
    /// internal dev commentary: no spec `file:line` refs, no provisional /
    /// milestone / deferral notes, and no sibling-variant names.
    #[test]
    fn swept_variants_display_is_clean() {
        let missing = Btcr2Error::MissingUpdateData {
            update_hash: Sha256Hash::from([0u8; 32]),
        }
        .to_string();
        for banned in [
            "Spec:",
            "errors.md",
            "deferred",
            "PROVISIONAL",
            "ProofTransformation",
            "ProofGeneration",
            "Zcap",
        ] {
            assert!(
                !missing.contains(banned),
                "MissingUpdateData Display leaked `{banned}`: {missing:?}",
            );
        }
        assert!(!missing.is_empty(), "MissingUpdateData Display is empty");
        assert!(
            !missing.contains('\n'),
            "MissingUpdateData Display should be a single line: {missing:?}",
        );

        let unsupported = Btcr2Error::Unsupported("x".into()).to_string();
        for banned in ["PROVISIONAL", "M2", "deferred"] {
            assert!(
                !unsupported.contains(banned),
                "Unsupported Display leaked `{banned}`: {unsupported:?}",
            );
        }
        assert!(!unsupported.is_empty(), "Unsupported Display is empty");
        assert!(
            !unsupported.contains('\n'),
            "Unsupported Display should be a single line: {unsupported:?}",
        );
    }
}
