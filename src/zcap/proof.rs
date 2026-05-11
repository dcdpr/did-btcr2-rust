use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Types of proofs supported by the library
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ProofType {
    /// General Data Integrity Proof
    #[default]
    DataIntegrityProof,
}

impl fmt::Display for ProofType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataIntegrityProof")
    }
}

/// Purposes for cryptographic proofs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProofPurpose {
    /// Authentication of entity identified by a DID
    Authentication,
    /// Assertion method for making verifiable claims
    AssertionMethod,
    /// Capability invocation
    CapabilityInvocation,
    /// Capability delegation
    CapabilityDelegation,
    /// Other purposes
    #[serde(untagged)]
    Other(String),
}

impl fmt::Display for ProofPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofPurpose::Authentication => f.write_str("authentication"),
            ProofPurpose::AssertionMethod => f.write_str("assertionMethod"),
            ProofPurpose::CapabilityInvocation => f.write_str("capabilityInvocation"),
            ProofPurpose::CapabilityDelegation => f.write_str("capabilityDelegation"),
            ProofPurpose::Other(s) => f.write_str(s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProofValue(pub(crate) String);

/// Represents a cryptographic proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(flatten)]
    pub(crate) inner: ProofInner,

    /// Proof value (encoded binary data)
    pub(crate) proof_value: ProofValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofInner {
    /// Optional identifier for the proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Type of proof
    #[serde(rename = "type")]
    pub proof_type: ProofType,

    /// Purpose of the proof
    pub proof_purpose: ProofPurpose,

    /// Verification method that can be used to verify the proof
    pub verification_method: String,

    /// Cryptographic suite used for the proof
    pub cryptosuite: CryptoSuiteName,

    /// When the proof was created (ISO8601 dateTime)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,

    /// When the proof expires (ISO8601 dateTime)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,

    /// Security domain for the proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Challenge to prevent replay attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// Previous proof ID or array of IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<Value>,

    /// Random value to increase privacy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Optional JSON-LD context
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// ZCAP: Capability being invoked (for capabilityInvocation proof purpose)
    pub capability: String,

    /// ZCAP: Action being performed with the capability
    pub capability_action: String,

    // TODO: What is this? Our spec looks wrong...?
    // See example in https://dcdpr.github.io/did-btc1/#dereference-root-capability-identifier
    // `invocationTarget` is used in an ephemeral object (never serialized) named "root capability",
    // but also appears in ZCAP delegated capability OUTSIDE of `proof`:
    // https://w3c-ccg.github.io/zcap-spec/#delegated-capability
    //
    /// ZCAP: Target of the capability invocation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_target: Option<String>,
}

impl Proof {
    pub(crate) fn from_inner(inner: ProofInner, proof_value: ProofValue) -> Self {
        Self { inner, proof_value }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum CryptoSuiteName {
    #[default]
    #[serde(rename = "bip340-jcs-2025")]
    Jcs,
}

impl fmt::Display for CryptoSuiteName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jcs => f.write_str("bip340-jcs-2025"),
        }
    }
}
