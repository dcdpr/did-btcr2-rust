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
    #[error("An invalid DID was detected during DID Resolution: {0}")]
    InvalidDid(String),

    /// The DID document was malformed.
    #[error("The DID document was malformed: {0}")]
    InvalidDidDocument(String),

    /// The DID document was not found: the genesis document could not be
    /// retrieved, or the requested `versionId` lies past the end of the DID's
    /// history. The occurrence-specific reason is the payload (problem-details
    /// `detail`).
    #[error("The DID document was not found: {0}")]
    NotFound(String),

    /// One or more resolution options are invalid: `versionId` and
    /// `versionTime` supplied together (DID Resolution defines them as
    /// mutually exclusive), or a caller-supplied option that cannot be used
    /// as given.
    #[error("One or more resolution options are invalid: {0}")]
    InvalidOptions(String),

    // Errors from DID BTCR2 Spec
    //
    /// Sidecar data was invalid
    #[error("Sidecar data was invalid: {0}")]
    InvalidSidecarData(String),

    /// Update payload was published late
    #[error("Update payload was published late: {0}")]
    LatePublishingError(String),

    /// Update payload could not be located in either the supplied sidecar
    /// data nor in CAS (spec MISSING_UPDATE_DATA).
    //
    // Spec reference: did-btcr2/src/errors.md:21-23. Added for exactly this
    // variant; the other non-spec error variants are handled separately.
    #[error(
        "Update payload could not be located in the sidecar data or CAS: update_hash={update_hash:?}"
    )]
    MissingUpdateData {
        /// JSON Document Hash of the update payload that could not be located.
        update_hash: Sha256Hash,
    },

    /// Invalid Update Proof
    #[error("Invalid Update Proof: {0}")]
    InvalidUpdateProof(String),

    /// Problems when creating or applying a DID Update
    #[error("Problems when creating or applying a DID Update: {0}")]
    InvalidDidUpdate(String),

    // Errors from Verifiable Credentials Data Integrity Spec
    //
    /// Proof verification error
    #[error("Proof verification error: {0}")]
    ProofVerification(String),

    /// Proof transformation error
    #[error("Proof transformation error: {0}")]
    ProofTransformation(String),

    /// Proof generation error
    #[error("Proof generation error: {0}")]
    ProofGeneration(String),

    /// A subject-controlled beacon/CAS path (CAS Map / Sparse Merkle Tree)
    /// reached an arm that is not yet implemented.
    //
    // Returned instead of panicking the resolver, so a remote-published DID
    // reaching these arms yields a typed resolution error rather than crashing
    // the process.
    //
    // The problem-details code is provisional and subject to a later
    // error-vocabulary audit, which replaces these arms with real
    // implementations and may keep or rename this variant and its code.
    #[error("Not yet implemented: {0}")]
    Unsupported(String),
}

impl Btcr2Error {
    /// The fixed, per-variant summary: the problem-details `title` (RFC 9457
    /// — the same for every occurrence of a type) and the leading clause of
    /// `Display`, which appends the occurrence's detail after a colon.
    pub fn title(&self) -> &'static str {
        match self {
            Self::InvalidDid(_) => "An invalid DID was detected during DID Resolution",
            Self::InvalidDidDocument(_) => "The DID document was malformed",
            Self::NotFound(_) => "The DID document was not found",
            Self::InvalidOptions(_) => "One or more resolution options are invalid",
            Self::InvalidSidecarData(_) => "Sidecar data was invalid",
            Self::LatePublishingError(_) => "Update payload was published late",
            Self::MissingUpdateData { .. } => {
                "Update payload could not be located in the sidecar data or CAS"
            }
            Self::InvalidUpdateProof(_) => "Invalid Update Proof",
            Self::InvalidDidUpdate(_) => "Problems when creating or applying a DID Update",
            Self::ProofVerification(_) => "Proof verification error",
            Self::ProofTransformation(_) => "Proof transformation error",
            Self::ProofGeneration(_) => "Proof generation error",
            Self::Unsupported(_) => "Not yet implemented",
        }
    }

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
            Self::InvalidDid(_)
            | Self::InvalidDidDocument(_)
            | Self::NotFound(_)
            | Self::InvalidOptions(_) => "https://www.w3.org/ns/did",
            // The method's own namespace, the same one the document
            // `@context` uses (`https://btcr2.dev/context/v1`). The spec's
            // error registry (did-btcr2/src/errors.md) names the codes but
            // defines no `type` URI for them; this is the crate's choice
            // until it does, and is raised with the spec editors.
            Self::InvalidSidecarData(_)
            | Self::LatePublishingError(_)
            | Self::MissingUpdateData { .. }
            | Self::InvalidUpdateProof(_)
            | Self::InvalidDidUpdate(_)
            | Self::ProofVerification(_)
            | Self::ProofTransformation(_)
            | Self::ProofGeneration(_)
            | Self::Unsupported(_) => "https://btcr2.dev/context/v1",
        };

        let name = match self {
            Self::InvalidDid(_) => "INVALID_DID",
            Self::InvalidDidDocument(_) => "INVALID_DID_DOCUMENT",
            Self::NotFound(_) => "NOT_FOUND",
            Self::InvalidOptions(_) => "INVALID_OPTIONS",
            Self::InvalidSidecarData(_) => "INVALID_SIDECAR_DATA",
            Self::LatePublishingError(_) => "LATE_PUBLISHING",
            Self::MissingUpdateData { .. } => "MISSING_UPDATE_DATA",
            Self::InvalidUpdateProof(_) => "INVALID_UPDATE_PROOF",
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
            "title": self.title(),
            "detail": match self {
                Self::InvalidDid(detail) => detail.clone(),
                Self::InvalidDidDocument(detail) => detail.clone(),
                Self::NotFound(detail) => detail.clone(),
                Self::InvalidOptions(detail) => detail.clone(),
                Self::InvalidSidecarData(detail) => detail.clone(),
                Self::LatePublishingError(detail) => detail.clone(),
                Self::MissingUpdateData { update_hash } => {
                    format!("update_hash={}", hex::encode(update_hash.as_bytes()))
                }
                Self::InvalidUpdateProof(detail) => detail.clone(),
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
            "https://btcr2.dev/context/v1#UNSUPPORTED_BEACON",
        );
        assert_eq!(details["detail"], message);
    }

    /// `NotFound` is the DID Resolution `NOT_FOUND` error: its `type` is the
    /// standard `https://www.w3.org/ns/did#NOT_FOUND` identifier (not a
    /// method-namespaced URI), the `title` is the generic fixed sentence, and
    /// the `detail` is the reason the producer raised it with. Proves all
    /// three match arms (prefix, name, detail) are present, and that the title
    /// is the same whichever producer raised the error: a missing genesis
    /// document and an unreachable `versionId` differ only in `detail`.
    #[test]
    fn not_found_problem_details_shape() {
        let message =
            "no sidecar genesisDocument was supplied and this resolver has no CAS fetcher";
        let err = Btcr2Error::NotFound(message.into());
        let details = err.details().expect("NotFound yields problem details");
        assert_eq!(details["type"], "https://www.w3.org/ns/did#NOT_FOUND");
        assert_eq!(details["detail"], message);
        assert_eq!(details["title"], "The DID document was not found");
        assert_eq!(
            err.to_string(),
            format!("The DID document was not found: {message}"),
            "Display carries the occurrence detail after the fixed title"
        );

        let message = "versionId 5 was requested but the DID's history ends at version 3";
        let err = Btcr2Error::NotFound(message.into());
        let details = err.details().expect("NotFound yields problem details");
        assert_eq!(details["type"], "https://www.w3.org/ns/did#NOT_FOUND");
        assert_eq!(details["detail"], message);
        assert_eq!(
            details["title"], "The DID document was not found",
            "the title does not name the genesis document: it is the same for every producer"
        );
        assert_eq!(err.title(), "The DID document was not found");
        assert_eq!(
            err.to_string(),
            format!("The DID document was not found: {message}")
        );
    }

    /// Every variant's `Display` opens with its fixed `title()` and carries
    /// the occurrence's detail after it: an error chain printed with
    /// `Display` names what went wrong, not only which kind of thing did.
    /// The problem-details `title` stays the fixed summary (RFC 9457), never
    /// the occurrence text.
    #[test]
    fn display_is_title_then_detail_for_every_variant() {
        let detail = "the specific thing that went wrong";
        let variants = [
            Btcr2Error::InvalidDid(detail.into()),
            Btcr2Error::InvalidDidDocument(detail.into()),
            Btcr2Error::NotFound(detail.into()),
            Btcr2Error::InvalidOptions(detail.into()),
            Btcr2Error::InvalidSidecarData(detail.into()),
            Btcr2Error::LatePublishingError(detail.into()),
            Btcr2Error::InvalidUpdateProof(detail.into()),
            Btcr2Error::InvalidDidUpdate(detail.into()),
            Btcr2Error::ProofVerification(detail.into()),
            Btcr2Error::ProofTransformation(detail.into()),
            Btcr2Error::ProofGeneration(detail.into()),
            Btcr2Error::Unsupported(detail.into()),
        ];
        for err in &variants {
            assert_eq!(
                err.to_string(),
                format!("{}: {detail}", err.title()),
                "{err:?}"
            );
            let d = err.details().expect("every variant yields problem details");
            assert_eq!(d["title"], err.title(), "{err:?}");
            assert_eq!(d["detail"], detail, "{err:?}");
        }
        let err = Btcr2Error::MissingUpdateData {
            update_hash: Sha256Hash::from([0u8; 32]),
        };
        assert!(
            err.to_string().starts_with(&format!("{}: ", err.title())),
            "{err}"
        );
        assert_eq!(err.details().expect("details")["title"], err.title());
    }

    /// `InvalidDid` carries the W3C `did` namespace prefix, the `INVALID_DID`
    /// code, a fixed `title`, and the plain carried detail string.
    #[test]
    fn invalid_did_problem_details_shape() {
        let err = Btcr2Error::InvalidDid("bad did".into());
        let d = err.details().expect("InvalidDid yields problem details");
        assert_eq!(d["type"], "https://www.w3.org/ns/did#INVALID_DID");
        assert_eq!(d["title"], err.title());
        assert_eq!(d["detail"], "bad did");
    }

    /// `InvalidOptions` is the DID Resolution `INVALID_OPTIONS` error: the
    /// standard `https://www.w3.org/ns/did#INVALID_OPTIONS` type, a
    /// Display-wired `title`, and the carried detail.
    #[test]
    fn invalid_options_problem_details_shape() {
        let err = Btcr2Error::InvalidOptions("versionId and versionTime together".into());
        let d = err
            .details()
            .expect("InvalidOptions yields problem details");
        assert_eq!(d["type"], "https://www.w3.org/ns/did#INVALID_OPTIONS");
        assert_eq!(d["title"], err.title());
        assert_eq!(d["detail"], "versionId and versionTime together");
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
        assert_eq!(d["title"], err.title());
        assert_eq!(d["detail"], "bad doc");
    }

    /// `MissingUpdateData` covers the method namespace prefix (btcr2.dev) and
    /// the non-trivial formatted-detail arm (hex of the 32-byte update hash).
    #[test]
    fn missing_update_data_problem_details_shape() {
        let err = Btcr2Error::MissingUpdateData {
            update_hash: Sha256Hash::from([0u8; 32]),
        };
        let d = err
            .details()
            .expect("MissingUpdateData yields problem details");
        // Pins the method namespace: the same host the document `@context`
        // uses, so nothing on the wire still says `btc1`.
        assert_eq!(
            d["type"],
            "https://btcr2.dev/context/v1#MISSING_UPDATE_DATA"
        );
        assert_eq!(d["title"], err.title());
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
    /// old `LATE_PUBLISHING_ERROR` string, or if any method code slips back to
    /// the retired `btc1.dev` host.
    #[test]
    fn error_wire_codes_match_spec_registry() {
        let cases: [(Btcr2Error, &str); 4] = [
            (
                Btcr2Error::InvalidDidUpdate("bad update".into()),
                "https://btcr2.dev/context/v1#INVALID_DID_UPDATE",
            ),
            (
                Btcr2Error::LatePublishingError("late".into()),
                "https://btcr2.dev/context/v1#LATE_PUBLISHING",
            ),
            (
                Btcr2Error::MissingUpdateData {
                    update_hash: Sha256Hash::from([0u8; 32]),
                },
                "https://btcr2.dev/context/v1#MISSING_UPDATE_DATA",
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

    /// No variant's `type` names the retired `btc1.dev` host: every method
    /// code is on `btcr2.dev`, every DID Resolution code on `www.w3.org`.
    #[test]
    fn no_problem_details_type_names_the_retired_host() {
        let all = [
            Btcr2Error::InvalidDid("x".into()),
            Btcr2Error::InvalidDidDocument("x".into()),
            Btcr2Error::NotFound("x".into()),
            Btcr2Error::InvalidOptions("x".into()),
            Btcr2Error::InvalidSidecarData("x".into()),
            Btcr2Error::LatePublishingError("x".into()),
            Btcr2Error::MissingUpdateData {
                update_hash: Sha256Hash::from([0u8; 32]),
            },
            Btcr2Error::InvalidUpdateProof("x".into()),
            Btcr2Error::InvalidDidUpdate("x".into()),
            Btcr2Error::ProofVerification("x".into()),
            Btcr2Error::ProofTransformation("x".into()),
            Btcr2Error::ProofGeneration("x".into()),
            Btcr2Error::Unsupported("x".into()),
        ];
        for err in all {
            let ty = err.details().expect("every variant has a body")["type"]
                .as_str()
                .expect("type is a string")
                .to_string();
            assert!(
                ty.starts_with("https://btcr2.dev/context/v1#")
                    || ty.starts_with("https://www.w3.org/ns/did#"),
                "{err:?} emits {ty}"
            );
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
