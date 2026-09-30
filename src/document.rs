#![warn(clippy::unwrap_used)]
//! Panic-sweep policy: legitimately fallible sites use Result;
//! type-system-guaranteed sites use `.expect("<invariant>")` with a structural
//! justification. Test code is exempted via clippy.toml's `allow-unwrap-in-tests`.

use crate::beacon::{AddressExt as _, Beacon, BeaconType};
use crate::canonical_hash::CanonicalHash;
use crate::cryptosuite::CryptoSuite;
use crate::error::{Btcr2Error, ProblemDetails};
use crate::identifier::{Did, DidComponents, DidVersion, IdType, Network, Sha256Hash};
use crate::key::{PublicKey, PublicKeyExt as _};
use crate::verification::{
    EmbeddedVerificationMethod, VerificationMethod, VerificationMethodId, VerificationRelationship,
};
use crate::zcap::proof::{CryptoSuiteName, ProofInner, ProofType};
use crate::zcap::{derive_root_capability, proof::ProofPurpose};
use crate::{
    identifier::TryNetworkExt,
    json_tools,
    resolver::Resolver,
    update::{UnsecuredUpdate, Update},
};
use chrono::{DateTime, Utc};
use esploda::bitcoin::Address;
use json_patch::Patch;
use nonempty::NonEmpty;
use onlyerror::Error;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    num::{NonZeroU32, NonZeroU64},
    path::Path,
    str::FromStr,
};

const DID_CORE_V1_1_CONTEXT: &str = "https://www.w3.org/ns/did/v1.1";
const DID_BTC1_CONTEXT: &str = "https://btcr2.dev/context/v1";

// The genesis-document placeholder DID. Externally-prepared intermediate
// documents are authored with this placeholder in every `id` position; binding
// to a real DID substitutes it for the encoded `did:btcr2:…` string. Spec:
// did-btcr2/src/data-structures.md:56-57, terminology.md:148-149.
const DID_PLACEHOLDER: &str = "did:btcr2:_";

mod version_id_serde {
    //! Custom serde for `NonZeroU64` ↔ ASCII string.
    //!
    //! Spec: did-btcr2/src/data-structures.md:363 — versionId is an
    //! "ASCII string representation of the version".
    //!
    //! Pattern: matches the `Sha256Hash` manual-serde precedent for
    //! `Sha256Hash` at identifier.rs:286-312.
    //!
    //! Paired round-trip test asserts that BOTH
    //! `serde_json::to_string` AND `serde_jcs::to_string` produce `"5"`
    //! (JSON string), not `5` (JSON number).

    use serde::{Deserialize, Deserializer, Serializer};
    use std::num::NonZeroU64;

    pub fn serialize<S: Serializer>(v: &NonZeroU64, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<NonZeroU64, D::Error> {
        let s = String::deserialize(de)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Errors arising while reading, parsing, generating, or updating a DID
/// document.
#[derive(Error, Debug)]
pub enum Error {
    /// Error during document I/O operations
    DocumentIO(#[from] std::io::Error),

    /// Error parsing JSON document
    JsonParse(#[from] serde_json::Error),

    /// Error parsing JSON value
    JsonValue(#[from] json_tools::JsonError),

    /// DID Encoding error
    DidEncoding(#[from] crate::identifier::Error),

    /// DID:BTCR2 error
    Btcr2Error(#[from] Btcr2Error),

    /// This should not happen: Only needed to satisfy `String: FromStr` trait bound
    Infallible(#[from] std::convert::Infallible),

    /// Bitcoin address parse error
    AddressParse(#[from] esploda::bitcoin::address::Error),

    /// Unexpected DID
    #[error("Expected `{0}` but found `{1}`")]
    UnexpectedDid(String, String),

    /// A key-based DID unexpectedly yielded no genesis public key.
    ///
    /// Structurally unreachable — the key-based generation paths are only
    /// entered for `IdType::Key` DIDs via [`InitialDocument::from_did`] — but modeled as a
    /// typed error rather than a panic so hostile input can never trigger an
    /// abort on the generation path.
    #[error("key-based DID has no genesis public key")]
    MissingGenesisKey,
}

impl ProblemDetails for Error {
    fn details(&self) -> Option<Value> {
        match self {
            Self::Btcr2Error(err) => err.details(),
            _ => None,
        }
    }
}

/// The reason a document failed to parse, for an update rejection message.
///
/// The spec-level reason is the useful part: a `Btcr2Error` wrapped by this
/// enum displays only as the wrapper's summary, so it is unwrapped, and any
/// other variant is rendered with its source chain.
fn conformance_cause(err: &Error) -> String {
    match err {
        Error::Btcr2Error(inner) => inner.to_string(),
        other => std::iter::successors(Some(other as &(dyn std::error::Error + 'static)), |e| {
            e.source()
        })
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": "),
    }
}

/// Rejects an update whose patch changes the DID document `id`.
///
/// The DID document identifier is immutable across an update (update.md
/// identifier immutability), and on resolve the post-patch `id` MUST equal the
/// DID (resolve.md:222). The comparison is on the raw JSON values, before any
/// typed parse: the typed parse decodes `id` as a did:btcr2 identifier, so an
/// `id` rewritten to a DID-Core-valid but non-bech32 value would otherwise
/// surface as an encoding error instead of the id change it is.
fn check_id_unchanged(before: &Value, after: &Value) -> Result<(), Btcr2Error> {
    if after.get("id") != before.get("id") {
        return Err(Btcr2Error::InvalidDidUpdate(
            "update may not change the DID document id".into(),
        ));
    }
    Ok(())
}

/// Sealed marker trait that selects the sequence type for fields constrained
/// by the spec's "updatable document" invariant (≥1 capabilityInvocation and
/// ≥1 service for resolved DIDs; unconstrained for intermediate placeholder-DID
/// documents).
///
/// See:
///   - did-btcr2/src/data-structures.md §did-document
///
/// The resolved-DID variant is non-empty at compile time (intermediates keep
/// `Vec<_>`); `TryFrom` converts at the parse boundary using `nonempty` 0.12.
mod document_mode {
    pub trait Sealed {}
    impl Sealed for crate::identifier::Did {}
    impl Sealed for String {}
}

/// Selects the sequence type used for fields constrained by the spec's
/// "updatable document" invariant.
///
/// For `T = Did` (resolved DID variant), `Sequence<U>` resolves to
/// `NonEmpty<U>` — compile-time non-emptiness. For `T = String`
/// (intermediate / placeholder-DID variant), `Sequence<U>` resolves to
/// `Vec<U>` — unconstrained.
///
/// The supertraits are what `Sequence<U>` demands of its element type, so a
/// relationship entry (`VerificationRelationship`) can itself be a sequence
/// element.
pub(crate) trait DocumentMode:
    document_mode::Sealed + Clone + std::fmt::Debug + PartialEq + Eq
{
    type Sequence<U>: Clone + std::fmt::Debug + PartialEq + Eq
    where
        U: Clone + std::fmt::Debug + PartialEq + Eq;
}

impl DocumentMode for crate::identifier::Did {
    type Sequence<U>
        = NonEmpty<U>
    where
        U: Clone + std::fmt::Debug + PartialEq + Eq;
}

impl DocumentMode for String {
    type Sequence<U>
        = Vec<U>
    where
        U: Clone + std::fmt::Debug + PartialEq + Eq;
}

/// Convert a parsed `Vec<U>` into the variant-specific `Sequence<U>`,
/// returning `Err` on empty input for the resolved-DID variant: `TryFrom`
/// converts at the parse boundary.
pub(crate) trait SequenceFromVec<U>: DocumentMode
where
    U: Clone + std::fmt::Debug + PartialEq + Eq,
{
    fn sequence_from_vec(
        items: Vec<U>,
        field_name: &'static str,
    ) -> Result<Self::Sequence<U>, Btcr2Error>;
}

impl<U> SequenceFromVec<U> for crate::identifier::Did
where
    U: Clone + std::fmt::Debug + PartialEq + Eq,
{
    fn sequence_from_vec(
        items: Vec<U>,
        field_name: &'static str,
    ) -> Result<NonEmpty<U>, Btcr2Error> {
        NonEmpty::from_vec(items).ok_or_else(|| {
            Btcr2Error::InvalidDidDocument(format!(
                "updatable DID document must contain at least one {field_name}"
            ))
        })
    }
}

impl<U> SequenceFromVec<U> for String
where
    U: Clone + std::fmt::Debug + PartialEq + Eq,
{
    fn sequence_from_vec(items: Vec<U>, _field_name: &'static str) -> Result<Vec<U>, Btcr2Error> {
        // Intermediate (placeholder-DID) documents are unconstrained.
        Ok(items)
    }
}

/// Fully parsed and validated DID document fields.
///
/// The DID identifier can be either [`Did`] or [`String`]. This specifically allows parsing
/// intermediate DID documents with the "xxx" DID placeholders.
///
/// For `T = Did` (resolved-DID variant), the `capability_invocation` and
/// `service` fields are statically non-empty (`NonEmpty<_>`). For
/// `T = String` (intermediate / placeholder-DID variant), both fields stay
/// `Vec<_>` (unconstrained).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DocumentFields<T: DocumentMode> {
    /// DID identifier
    pub(crate) id: T,

    /// Document context
    pub(crate) context: Vec<String>,

    /// Document controller (DID Core 1.1 §5.1.2): a string or a set of
    /// strings, each a DID of any method — not only `did:btcr2` — kept as
    /// text because nothing in resolution reads it. Parsed by
    /// `json_tools::controllers_from_object`.
    controller: Vec<String>,

    pub(crate) verification_method: Vec<VerificationMethod>,

    // The four verification-relationship arrays. Each entry is either a
    // reference into `verification_method` or an embedded verification method
    // (DID Core 1.1 §5.3.1); only `capability_invocation` is consulted when an
    // update proof is checked, see `DocumentFields<Did>::invoking_public_key`.
    authentication: Vec<VerificationRelationship>,
    assertion_method: Vec<VerificationRelationship>,
    capability_invocation: <T as DocumentMode>::Sequence<VerificationRelationship>,
    capability_delegation: Vec<VerificationRelationship>,

    pub(crate) service: <T as DocumentMode>::Sequence<Beacon>,

    /// Whether the DID has been deactivated.
    ///
    /// Spec: did-btcr2/src/operations/deactivate.md — set by the JSON Patch
    /// `{"op":"add","path":"/deactivated","value":true}` via the normal
    /// `apply_update` path (no special case). Initial documents do not
    /// carry the field; deserialization defaults it to `false` (the manual
    /// `TryFrom` `.unwrap_or(false)` is this codebase's `#[serde(default)]`
    /// equivalent). Uniform `bool` across both `T = Did` and `T = String`
    /// modes — the GAT `Sequence<U>` selector only governs `service` and
    /// `capability_invocation`.
    pub(crate) deactivated: bool,
}

// TODO: Can we replace this with serde?
impl<T> TryFrom<(&Value, Option<Network>)> for DocumentFields<T>
where
    T: FromStr
        + TryNetworkExt
        + DocumentMode
        + SequenceFromVec<VerificationRelationship>
        + SequenceFromVec<Beacon>,
    Error: From<<T as FromStr>::Err>,
    json_tools::JsonError: From<<T as FromStr>::Err> + From<<VerificationMethodId as FromStr>::Err>,
{
    type Error = Error;

    fn try_from((value, network): (&Value, Option<Network>)) -> Result<Self, Self::Error> {
        use json_tools::*;

        let id: T = string_from_object(value, "id")?.parse()?;
        let network = id.try_network().or(network).ok_or_else(|| {
            Btcr2Error::InvalidDid("no network derivable from id and none provided".into())
        })?;

        // TODO: Might want to abstract this null-check for required keys.
        if value["@context"].is_null() {
            return Err(JsonError::JsonMissingKey("@context".into()).into());
        }
        let context = vec_from_object(value, "@context", |id| {
            string_from_value(id).map(ToString::to_string)
        })?;

        let controller = controllers_from_object(value)?;
        let verification_method =
            vec_from_object(value, "verificationMethod", verification_method_from_value)?;
        // An entry that carries `publicKeyMultibase` must declare type
        // `Multikey`; this crate reads that into resolve.md's "conforms to
        // DID Core" check (the spec does not name the rule), so any other
        // type fails the parse, and an update producing it is
        // INVALID_DID_UPDATE. Entries without `publicKeyMultibase` keep their
        // own type. See `verification_method_from_value`.
        if let Some(method) = verification_method
            .iter()
            .find(|method| method.public_key_multibase.is_some() && method.type_ != "Multikey")
        {
            return Err(Btcr2Error::InvalidDidDocument(format!(
                "verification method {} carries publicKeyMultibase but declares type {}, not Multikey",
                method.id.0, method.type_
            ))
            .into());
        }
        let authentication = vec_from_object(value, "authentication", |entry| {
            relationship_from_value(entry, "authentication")
        })?;
        let assertion_method = vec_from_object(value, "assertionMethod", |entry| {
            relationship_from_value(entry, "assertionMethod")
        })?;
        let capability_invocation_vec = vec_from_object(value, "capabilityInvocation", |entry| {
            relationship_from_value(entry, "capabilityInvocation")
        })?;
        let capability_delegation = vec_from_object(value, "capabilityDelegation", |entry| {
            relationship_from_value(entry, "capabilityDelegation")
        })?;
        // Two-tier leniency, pulls in upstream fix for
        // https://github.com/dcdpr/did-btcr2/issues/170:
        // a service whose `type` does not name a beacon type (e.g.
        // `LinkedDomains`) is retain-and-ignore — kept in `json_data` (the raw
        // envelope) but excluded from the typed beacon vec, so a single
        // non-beacon service can no longer fail the whole document. This
        // leniency covers unknown-but-PRESENT types only: a service missing
        // `type` entirely is malformed and still errors (the `?` below
        // propagates the missing-key error), as does a real beacon with a
        // malformed `serviceEndpoint`.
        let service_array = &value["service"];
        let mut service_vec: Vec<Beacon> = Vec::new();
        if !service_array.is_null() {
            let services = service_array.as_array().ok_or_else(|| {
                JsonError::UnexpectedJsonType("service".into(), ExpectedType::Array)
            })?;
            for service in services {
                let ty = match string_from_object(service, "type")?.parse::<BeaconType>() {
                    Ok(ty) => ty,
                    // Non-beacon service: retained in json_data, skipped here.
                    Err(crate::beacon::Error::InvalidBeaconType) => continue,
                    // `BeaconType::from_str` only yields `InvalidBeaconType`;
                    // any other beacon error is a real parse fault — propagate.
                    Err(e) => return Err(JsonError::from(e).into()),
                };
                let id = string_from_object(service, "id")?.to_string();
                let descriptor =
                    Address::from_bip21(string_from_object(service, "serviceEndpoint")?, network)
                        .map_err(JsonError::from)?;

                service_vec.push(Beacon::new(id, ty, descriptor));
            }
        }

        // parse-boundary conversion. For T = Did this enforces
        // NonEmpty (returning Btcr2Error::InvalidDidDocument on empty);
        // for T = String this is a no-op pass-through.
        let capability_invocation =
            <T as SequenceFromVec<VerificationRelationship>>::sequence_from_vec(
                capability_invocation_vec,
                "capabilityInvocation",
            )?;
        let service =
            <T as SequenceFromVec<Beacon>>::sequence_from_vec(service_vec, "beacon service")?;

        // an absent field defaults to false for initial documents (which
        // never carry it); the deactivate JSON Patch flips it to true via the
        // normal apply_update re-parse path — no special case here. A present
        // field MUST be a JSON boolean (data-structures.md:361): a
        // present-but-non-boolean value (e.g. `"true"`, `1`, `null`) is rejected
        // rather than silently coerced to false (active), which would let a
        // crafted `deactivated` mask a deactivated DID as active.
        let deactivated = match value.get("deactivated") {
            None => false,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(_) => {
                return Err(
                    Btcr2Error::InvalidDidDocument("deactivated must be a boolean".into()).into(),
                );
            }
        };

        Ok(DocumentFields {
            id,
            context,
            controller,
            verification_method,
            authentication,
            assertion_method,
            capability_invocation,
            capability_delegation,
            service,
            deactivated,
        })
    }
}

/// Parse one entry of the top-level `verificationMethod` array (`id`, `type`,
/// `controller`, `publicKeyMultibase`).
///
/// Entries are retained opaque: DID Core 1.1 §5.2 allows verification
/// methods that are not secp256k1 keys there — an Ed25519 Multikey with a
/// `did:key` controller, a JWK with no `publicKeyMultibase` — and
/// did-btcr2/src/operations/resolve.md ("Check `update.proof`") reads
/// `publicKeyMultibase` only from the entry a proof invokes. So `id`, `type`
/// and `controller` must be strings, `publicKeyMultibase` is kept verbatim
/// when present (a present value must be a JSON string), and nothing is
/// decoded until `DocumentFields<Did>::invoking_public_key` reads the invoked
/// entry.
///
/// One rule applies to the array, checked by the caller once the entries are
/// parsed: an entry carrying `publicKeyMultibase` must declare `type`
/// `Multikey`. This is this crate's reading of resolve.md's check that the
/// resolved document conforms to DID Core, not a rule the spec names: DID
/// Core itself does not constrain which `type` may carry
/// `publicKeyMultibase` (the DID Specification Registries pair
/// `Ed25519VerificationKey2020` with it too). The Controlled Identifiers
/// `Multikey` type is the one this method's documents use with
/// `publicKeyMultibase`, so any other type is read as non-conformant: the
/// parse fails, and resolve.md turns an update producing such a document into
/// INVALID_DID_UPDATE. Whether the spec means this is an open question to the
/// spec authors. The rule does not look at the key's curve or the controller.
///
/// It deliberately does not apply to the relationship arrays either, although
/// an embedded method there is a verification method too (DID Core 1.1
/// §5.3.1): a `capabilityInvocation` object typed `JsonWebKey2020` that
/// carries a secp256k1 `publicKeyMultibase` parses, and an update can sign
/// with it. The asymmetry is intentional. No spec rule names either shape,
/// and the test-suite vector that motivates the rule exercises only the
/// top-level one, so the narrowest reading that meets it stands until the
/// spec authors answer the open question; see `relationship_from_value`.
fn verification_method_from_value(
    method: &Value,
) -> Result<VerificationMethod, json_tools::JsonError> {
    use json_tools::string_from_object;

    Ok(VerificationMethod::with_type(
        string_from_object(method, "id")?.parse()?,
        string_from_object(method, "controller")?.to_string(),
        optional_multibase_from_object(method, "verificationMethod")?,
        string_from_object(method, "type")?.to_string(),
    ))
}

/// Read an entry's `publicKeyMultibase` verbatim: absent or `null` is
/// `None`, a string is `Some`, anything else is a typed error naming
/// `{field}.publicKeyMultibase`.
fn optional_multibase_from_object(
    entry: &Value,
    field: &str,
) -> Result<Option<String>, json_tools::JsonError> {
    use json_tools::{ExpectedType, JsonError};

    match entry.get("publicKeyMultibase") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(JsonError::UnexpectedJsonType(
            format!("{field}.publicKeyMultibase"),
            ExpectedType::String,
        )),
    }
}

/// Parse one entry of a verification-relationship array: a JSON string is a
/// reference (possibly a relative DID URL), a JSON object is an embedded
/// verification method (DID Core 1.1 §5.3.1). Any other JSON type is a typed
/// error naming `field`, never a panic.
///
/// An embedded object is retained by its `id` and its raw `publicKeyMultibase`
/// only: DID Core allows any verification method type there (an Ed25519 key,
/// a `publicKeyJwk` with no multibase form, a foreign controller), and none
/// of that is inspected unless a proof invokes the entry — see
/// `DocumentFields<Did>::invoking_public_key`. In particular the top-level
/// `Multikey` type rule of `verification_method_from_value` is not applied
/// here, on purpose, pending the same open question to the spec authors. The
/// `id` must be a JSON string and a present `publicKeyMultibase` must be one
/// too; both errors name the array (`{field}.id`,
/// `{field}.publicKeyMultibase`).
fn relationship_from_value(
    entry: &Value,
    field: &str,
) -> Result<VerificationRelationship, json_tools::JsonError> {
    use json_tools::{ExpectedType, JsonError};

    match entry {
        Value::String(reference) => Ok(VerificationRelationship::Reference(reference.parse()?)),
        Value::Object(_) => {
            let id = match entry.get("id") {
                None | Some(Value::Null) => {
                    return Err(JsonError::JsonMissingKey(format!("{field}.id")));
                }
                Some(Value::String(s)) => s.parse()?,
                Some(_) => {
                    return Err(JsonError::UnexpectedJsonType(
                        format!("{field}.id"),
                        ExpectedType::String,
                    ));
                }
            };
            Ok(VerificationRelationship::Embedded(
                EmbeddedVerificationMethod {
                    id,
                    public_key_multibase: optional_multibase_from_object(entry, field)?,
                },
            ))
        }
        _ => Err(JsonError::UnexpectedJsonType(
            field.into(),
            ExpectedType::StringOrObject,
        )),
    }
}

/// DID document resolution options.
#[derive(Debug, Default)]
pub struct ResolutionOptions {
    /// The Media Type of the caller's preferred representation of the DID document
    pub accept: Option<String>,

    /// Flag which instructs a DID resolver to expand relative DID URLs
    pub expand_relative_urls: bool,

    /// The version of the identifier and/or DID document
    pub version_id: Option<NonZeroU64>,

    /// A timestamp used during resolution as a bound for when to stop resolving
    pub version_time: Option<DateTime<Utc>>,

    /// Data necessary for resolving a DID such as DID Update Payloads and SMT proofs
    pub sidecar_data: Option<SidecarData>,

    /// Chain tip height, the basis for every confirmation count: the
    /// `minConf` gate on each beacon signal (`tip - height + 1` against
    /// [`ResolutionOptions::min_conf`]) and `DocumentMetadata.confirmations`.
    /// `None` means the caller did not supply the tip: a walk that meets no
    /// confirmed signal still resolves (with `confirmations: None`, fail-closed
    /// rather than misleadingly `0`), but the first confirmed signal is a
    /// typed [`resolver::Error::MissingChainTip`](crate::resolver::Error::MissingChainTip),
    /// because its confirmations cannot be counted.
    ///
    /// Sans-I/O: the resolver does NOT fetch the tip. The
    /// did-btcr2-client crate owns the `/blocks/tip/height` call.
    pub chain_tip_height: Option<u32>,

    /// `resolutionOptions.minConf`: the confirmations a beacon signal's
    /// transaction must have before the resolver processes it; `6` when not
    /// provided ([`ResolutionOptions::DEFAULT_MIN_CONF`]). A signal with fewer
    /// is skipped, whether or not the sidecar holds its update — the same
    /// rule as an unconfirmed transaction. Lowering it trades reorganisation
    /// exposure for latency; the returned `confirmations` lets a consumer
    /// judge the result.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Find Beacon Signals" and
    /// data-structures.md (resolution options).
    pub min_conf: Option<NonZeroU32>,

    /// Esplora base URL the resolver formats every request from
    /// (`{base}/address/{descriptor}/txs`, `{base}/block/{hash}`). REQUIRED
    /// for resolution: `None` is `INVALID_OPTIONS` from [`Document::resolve`],
    /// because the resolver has no default endpoint — the right one depends
    /// on the DID's network, and a silent fallback would resolve a DID of
    /// another chain to its genesis document with no error. Must be an
    /// absolute HTTP(S) URI with no query string; a trailing slash is
    /// dropped. Sans-I/O caller-injected config, same category as
    /// `chain_tip_height`; the `did-btcr2-client` crate fills it from the
    /// network name.
    pub esplora_url: Option<String>,
}

impl ResolutionOptions {
    /// The `minConf` in force when the option is not provided: six, the
    /// industry threshold for treating a Bitcoin transaction as settled
    /// (resolve.md "Find Beacon Signals", footnote 3).
    pub const DEFAULT_MIN_CONF: NonZeroU32 = match NonZeroU32::new(6) {
        Some(n) => n,
        None => unreachable!(),
    };
}

/// Spec triple per did-btcr2/src/operations/resolve.md:16-17:
/// `(didResolutionMetadata, didDocument, didDocumentMetadata)`.
///
/// Named struct — positional tuples invite swap bugs; most callers
/// want only one or two of the three fields. The clean-break choice
/// accepts that the crate is not yet published.
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    /// The `didResolutionMetadata` describing the resolution process.
    pub resolution_metadata: ResolutionMetadata,
    /// The resolved DID document.
    pub document: Document,
    /// The `didDocumentMetadata` describing the resolved document.
    pub document_metadata: DocumentMetadata,
}

/// `didResolutionMetadata` per resolve.md:51 and data-structures.md
/// "DID Resolution Metadata". `#[non_exhaustive]` lets later work add the
/// error JSON-LD fields without a breaking change; outside the crate, build
/// it with `Default::default()` and assign fields.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct ResolutionMetadata {
    /// Media type of the resolved DID document — `contentType` on the wire
    /// (data-structures.md "DID Resolution Metadata", MUST): the value of
    /// `resolutionOptions.accept`, or `application/did` (the default
    /// representation) when the caller supplied none. `None` only for a
    /// value built outside the resolver via `Default`.
    pub content_type: Option<String>,
}

/// `didDocumentMetadata` per adrs/0004-did-document-metadata-shape.md
/// UNION resolution:
/// - `version_id`: REQUIRED per resolve.md:53-54 and
///   data-structures.md:363. Always emitted.
/// - `confirmations`: REQUIRED per resolve.md:55 and
///   data-structures.md:360. `0` when the tip is known and no update was
///   applied (the spec's starting value); `None` only when the caller did
///   not supply `chain_tip_height` (fail-closed).
/// - `deactivated`: REQUIRED per both sources.
/// - `updated`: OPTIONAL per data-structures.md; ABSENT in resolve.md.
///   Always emitted as a UNION.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DocumentMetadata {
    /// Spec wire shape: ASCII string per data-structures.md:363.
    /// Custom serde — `5` (number) would silently break interop.
    #[serde(rename = "versionId", with = "version_id_serde")]
    pub version_id: std::num::NonZeroU64,

    /// Confirmations of the block holding the most recently applied unique
    /// update; `0` when none was applied. `None` (omitted on the wire) only
    /// when the caller did not supply `ResolutionOptions::chain_tip_height`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub confirmations: Option<u32>,

    /// Sourced from `contemporary_doc.fields.deactivated` after the
    /// resolver's final apply_update.
    // Always emitted (no skip_serializing_if): REQUIRED by both resolve.md:56 and data-structures.md.
    pub deactivated: bool,

    /// ISO-8601 timestamp of the most recent applied update (UNION).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub updated: Option<chrono::DateTime<chrono::Utc>>,
}

/// Serde adapter for [`SidecarData::updates`].
///
/// `Update` is parsed via the hand-rolled `Update::from_json_value`
/// (update.rs) rather than a `Deserialize` derive, so this bridges serde's
/// `Deserialize` to that parser: each element is deserialized as a raw
/// [`Value`] and then handed to `Update::from_json_value`.
fn deserialize_updates<'de, D>(deserializer: D) -> Result<Vec<Update>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Vec<Value> = Vec::deserialize(deserializer)?;
    raw.into_iter()
        .map(|value| Update::from_json_value(value).map_err(serde::de::Error::custom))
        .collect()
}

/// Spec-form sidecar data per did-btcr2/src/data-structures.md §sidecar-data
/// (lines 215-227). Keyed by JSON Document Hash, NOT by Txid.
///
/// The hot-path lookup is `update_lookup_table.get(&signal_bytes)`; the table
/// is built eagerly at the parse boundary via [`SidecarData::new`] /
/// [`SidecarData::from_json_value`] (a public
/// constructor). A sidecar produced by another conformant implementation is
/// consumed without translation.
///
/// `Deserialize` is implemented manually via a private wire type so
/// `update_lookup_table` is rebuilt on every serde path and can never be left
/// stale; wire fields are `pub(crate)` as defense-in-depth.
#[derive(Debug, Default)]
pub struct SidecarData {
    /// Spec wire-form `genesisDocument` field: the intermediate (placeholder-DID)
    /// document for an external (`x`-HRP) DID. Consumed by `resolve_external`,
    /// which bridges it into an initial document (substituting the DID and
    /// validating against the External `genesisBytes`) when no in-memory
    /// `initial_document` is supplied.
    pub(crate) genesis_document: Option<Value>,

    /// DID Update Payloads, in spec wire form. The lookup table is built from
    /// these eagerly at the parse boundary.
    pub(crate) updates: Vec<Update>,

    /// Opaque for forward-compat. a future change replaces `Vec<Value>` with a
    /// typed CAS Announcement; the value is carried without parsing it.
    /// `#[allow(dead_code)]` for the same pub→pub(crate) demotion reason as
    /// `genesis_document` (consumed once that path lands).
    #[allow(dead_code)]
    pub(crate) cas_updates: Option<Vec<Value>>,

    /// Opaque for forward-compat. a future change replaces `Vec<Value>` with a
    /// typed SMT Proof; the value is carried without parsing it.
    /// `#[allow(dead_code)]` for the same pub→pub(crate) demotion reason as
    /// `genesis_document` (consumed once that path lands).
    #[allow(dead_code)]
    pub(crate) smt_proofs: Option<Vec<Value>>,

    /// Built eagerly at the parse boundary; NOT part of the wire form.
    /// O(1) lookup on the resolver hot path (`update_lookup_table.get(&hash)`);
    /// built once per resolution. Keyed by `Update::hash()` (JCS + SHA-256 of
    /// the full signed update — canonical_hash.rs / update.rs).
    pub(crate) update_lookup_table: HashMap<Sha256Hash, Update>,

    /// Legacy in-memory initial document used by the `x`-HRP
    /// `resolve_external` path. Not populated from the spec wire form (that is
    /// `genesis_document`); set programmatically by callers/tests. To be
    /// removed once `resolve_external` consumes `genesis_document`.
    pub(crate) initial_document: Option<InitialDocument>,
}

/// Private wire representation of [`SidecarData`]. Owns the derived
/// `Deserialize` plus all wire-field serde attributes (reusing the
/// [`deserialize_updates`] adapter for `updates`). [`SidecarData`]'s manual
/// `Deserialize` funnels through this struct and finishes via
/// [`SidecarData::new`], which always builds `update_lookup_table` — so NO
/// serde path can produce a populated-`updates` / empty-table `SidecarData`
#[derive(Deserialize)]
struct SidecarDataWire {
    #[serde(rename = "genesisDocument", default)]
    genesis_document: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_updates")]
    updates: Vec<Update>,
    #[serde(rename = "casUpdates", default)]
    cas_updates: Option<Vec<Value>>,
    #[serde(rename = "smtProofs", default)]
    smt_proofs: Option<Vec<Value>>,
}

impl<'de> Deserialize<'de> for SidecarData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SidecarDataWire::deserialize(deserializer)?;
        // SidecarData::new builds update_lookup_table from updates eagerly, so a
        // SidecarData obtained through ANY serde path (from_value/from_str) has a
        // table consistent with its updates — never empty when updates are present
        // Equivalent to calling rebuild_lookup_table on a finish step.
        Ok(SidecarData::new(
            wire.genesis_document,
            wire.updates,
            wire.cas_updates,
            wire.smt_proofs,
        ))
    }
}

/// Private borrowing wire-ref mirror of [`SidecarDataWire`], driving the manual
/// `Serialize` for [`SidecarData`]. The read side ([`SidecarDataWire`]) and this
/// emit side carry the SAME four spec wire fields in the same order, so the
/// serialize/deserialize contract stays visibly paired: `genesisDocument`,
/// `updates`, `casUpdates`, `smtProofs`. The two non-wire fields
/// (`update_lookup_table`, `initial_document`) are simply absent here, so they
/// can never leak onto the wire.
///
/// Borrowing shape note: the Option fields are `Option<&'a T>` (populated via
/// `.as_ref()`), NOT `&'a Option<T>`. With the latter, serde's
/// `skip_serializing_if = "Option::is_none"` would hand `Option::is_none` a
/// `&&Option<T>` and fail to compile.
#[derive(Serialize)]
struct SidecarDataWireRef<'a> {
    #[serde(rename = "genesisDocument", skip_serializing_if = "Option::is_none")]
    genesis_document: Option<&'a Value>,
    /// Each element is the corresponding `Update`'s stored signed wire JSON
    /// (`&update.json`) surfaced verbatim — NOT re-encoded from typed fields, so
    /// the spec-fixed shapes (e.g. `targetVersionId` as an unquoted number)
    /// survive unchanged.
    updates: Vec<&'a Value>,
    #[serde(rename = "casUpdates", skip_serializing_if = "Option::is_none")]
    cas_updates: Option<&'a Vec<Value>>,
    #[serde(rename = "smtProofs", skip_serializing_if = "Option::is_none")]
    smt_proofs: Option<&'a Vec<Value>>,
}

impl Serialize for SidecarData {
    /// Emit exactly the four spec wire fields the manual `Deserialize` reads
    /// back — surfacing each `Update`'s stored wire JSON rather than
    /// re-serializing typed fields. `None` Options are omitted (never `null`);
    /// `update_lookup_table` and `initial_document` never appear.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SidecarDataWireRef {
            genesis_document: self.genesis_document.as_ref(),
            updates: self.updates.iter().map(|u| &u.json).collect(),
            cas_updates: self.cas_updates.as_ref(),
            smt_proofs: self.smt_proofs.as_ref(),
        }
        .serialize(serializer)
    }
}

impl SidecarData {
    /// Construct from wire-form parts and build `update_lookup_table` eagerly
    pub fn new(
        genesis_document: Option<Value>,
        updates: Vec<Update>,
        cas_updates: Option<Vec<Value>>,
        smt_proofs: Option<Vec<Value>>,
    ) -> Self {
        let update_lookup_table = updates.iter().map(|u| (u.hash(), u.clone())).collect();
        Self {
            genesis_document,
            updates,
            cas_updates,
            smt_proofs,
            update_lookup_table,
            initial_document: None,
        }
    }

    /// Deserialize from a JSON [`Value`] and build the `update_lookup_table`.
    ///
    /// The manual `Deserialize` (via the private wire type → [`SidecarData::new`])
    /// already builds the table on the serde path, so the trailing
    /// `rebuild_lookup_table()` is a harmless no-op kept to document intent and
    /// to satisfy the table-rebuild key-link.
    pub fn from_json_value(value: Value) -> Result<Self, serde_json::Error> {
        let mut data: Self = serde_json::from_value(value)?;
        data.rebuild_lookup_table();
        Ok(data)
    }

    /// Rebuild the lookup table from `self.updates`. Call after constructing via
    /// `serde_json::from_value::<SidecarData>` directly (which skips the table).
    pub fn rebuild_lookup_table(&mut self) {
        self.update_lookup_table = self.updates.iter().map(|u| (u.hash(), u.clone())).collect();
    }

    /// Append a signed update to the sidecar and rebuild the lookup table.
    ///
    /// This method is dedup-on-hash by design: it skips the append if an update
    /// with the same `Update::hash()` is already present (the resolver
    /// collapses dupes, but a clean file is preferred). It preserves
    /// `genesis_document` (and the other wire fields) untouched, so the CLI — a
    /// separate crate that cannot reach the `pub(crate)` wire fields — can
    /// accumulate the update chain without dropping an external DID's genesis.
    pub fn push_update(&mut self, update: Update) {
        if self.updates.iter().any(|u| u.hash() == update.hash()) {
            return;
        }
        self.updates.push(update);
        self.rebuild_lookup_table();
    }
}

impl DocumentFields<Did> {
    /// The single definition of the capabilityInvocation lookup, shared by both
    /// the construction primitive (`Document::construct_signed_update`) and the
    /// resolve path (`InitialDocument::apply_update`) so the spec rule has one
    /// home and cannot drift between the two sides.
    ///
    /// Finds the entry of this document's `capabilityInvocation` set that
    /// identifies `verification_method` (a proof's `verificationMethod`, or the
    /// id a caller wants to sign with) and returns the public key that entry
    /// carries — only a key the document authorized to invoke its root
    /// capability may sign an update. A reference entry identifies it when the
    /// two DID URLs are equal; an embedded verification method object
    /// identifies it when the object's `id` is equal. Every DID URL is resolved
    /// against the document `id` (`absolutize_did_url`) before comparison, so
    /// a relative reference such as `#key-0` on either side compares equal to
    /// its absolute form. The first entry in `capabilityInvocation` order that
    /// identifies the id wins, and the key is read from that entry only.
    ///
    /// The key is decoded from the invoking entry's `publicKeyMultibase`
    /// here, at the point of use (`decode_invoking_multikey`): for an
    /// embedded object from the object itself, for a reference from the
    /// `verificationMethod` entry whose (absolutized) `id` equals the
    /// reference. So a method of another key type — or with no
    /// `publicKeyMultibase` — anywhere in the document never blocks parsing
    /// and is rejected as `INVALID_DID_UPDATE` only when a proof invokes it.
    /// The declared `type` is not consulted (resolve.md reads
    /// `publicKeyMultibase`).
    ///
    /// Rejected with the spec-literal INVALID_DID_UPDATE
    /// (`Btcr2Error::InvalidDidUpdate`) when no entry identifies the id, or
    /// when the referenced verification method does not exist — matching
    /// did-btcr2/src/operations/update.md (construction) and
    /// did-btcr2/src/operations/resolve.md (resolution), the same code on both
    /// sides, so no interop-visible divergence ships.
    pub(crate) fn invoking_public_key(
        &self,
        verification_method: &str,
    ) -> Result<PublicKey, Btcr2Error> {
        let target = absolutize_did_url(verification_method, &self.id);

        let entry = self
            .capability_invocation
            .iter()
            .find(|entry| {
                let id = match entry {
                    VerificationRelationship::Reference(reference) => &reference.0,
                    VerificationRelationship::Embedded(method) => &method.id.0,
                };
                absolutize_did_url(id, &self.id) == target
            })
            .ok_or_else(|| {
                Btcr2Error::InvalidDidUpdate(
                    "verificationMethod id not present in the capabilityInvocation set".into(),
                )
            })?;

        match entry {
            VerificationRelationship::Embedded(method) => {
                decode_invoking_multikey(method.public_key_multibase.as_deref())
            }
            VerificationRelationship::Reference(_) => self
                .verification_method
                .iter()
                .find(|method| absolutize_did_url(&method.id.0, &self.id) == target)
                .ok_or_else(|| {
                    Btcr2Error::InvalidDidUpdate(
                        "capabilityInvocation references a verificationMethod id that is not \
                         present in the document"
                            .into(),
                    )
                })
                .and_then(|method| {
                    decode_invoking_multikey(method.public_key_multibase.as_deref())
                }),
        }
    }
}

/// Decode the `publicKeyMultibase` of the verification method a proof
/// invokes as a secp256k1 Multikey — the one place a document's key material
/// is read (resolve.md "Check `update.proof`": "Read `publicKeyMultibase`
/// from that verification method"). An absent value, or one that is not a
/// secp256k1 Multikey, is INVALID_DID_UPDATE.
fn decode_invoking_multikey(public_key_multibase: Option<&str>) -> Result<PublicKey, Btcr2Error> {
    let multikey = public_key_multibase.ok_or_else(|| {
        Btcr2Error::InvalidDidUpdate(
            "the invoking verification method has no publicKeyMultibase".into(),
        )
    })?;
    PublicKey::from_multikey(multikey).map_err(|e| {
        Btcr2Error::InvalidDidUpdate(format!(
            "the invoking verification method's publicKeyMultibase is not a secp256k1 \
             Multikey: {e}"
        ))
    })
}

/// Represents a JSON or JSON-LD document
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// All structural Document fields
    pub(crate) fields: DocumentFields<Did>,
    /// The document data as a JSON Value
    json_data: Value,
}

impl Document {
    /// Build the DID from its parsed components and begin resolution, returning
    /// the [`Did`] and a [`Resolver`] primed to drive the sans-I/O resolution
    /// FSM (did:btcr2 spec section 7.1.1).
    pub fn from_did_components(
        did_components: DidComponents,
        resolution_options: ResolutionOptions,
    ) -> Result<(Did, Resolver), Error> {
        let did = Did::try_from(did_components)?;
        let resolver = Self::resolve(&did, resolution_options)?;

        Ok((did, resolver))
    }

    // Spec section 7.2
    //
    // TODO: Sans-I/O: This needs to not bake any I/O into the implementation. Instead, this should
    // return a finite state machine that represents the protocol described in the spec. This allows
    // the caller to do their own I/O and drive the state machine forward to `Document` resolution.
    /// Resolve a `did:btcr2` identifier, returning the sans-I/O [`Resolver`]
    /// FSM the caller drives to completion.
    ///
    /// Named to match the spec verb (`fn resolve(did, resolutionOptions)`,
    /// did-btcr2/src/operations/resolve.md:16-17). The
    /// `Document::<verb>` convention now matches every other operation.
    pub fn resolve(did: &Did, resolution_options: ResolutionOptions) -> Result<Resolver, Error> {
        let initial_document = InitialDocument::from_did(did, &resolution_options)?;

        Ok(Resolver::new(initial_document, resolution_options)?)
    }

    /// Build the unsigned BTCR2 update for `patch` against this document,
    /// returning it together with the source and target document hashes.
    ///
    /// `sourceHash` is the JCS-SHA256 of this document; `targetHash` is the
    /// JCS-SHA256 of the patched document. The patch is applied to a *clone*
    /// of the document JSON — this method never mutates `self`. The patched
    /// document is re-validated for conformance and rejected if it would
    /// change the DID document `id` (the spec requires the identifier to be
    /// immutable across an update).
    ///
    /// Spec: did-btcr2/src/operations/update.md — "Construct BTCR2 Unsigned
    /// Update" and the identifier-immutability requirement.
    pub(crate) fn construct_unsigned_update(
        &self,
        patch: &Patch,
        target_version_id: NonZeroU64,
    ) -> Result<(UnsecuredUpdate, Sha256Hash, Sha256Hash), Btcr2Error> {
        let source_hash = self.hash();

        // Apply the patch to a clone so `self` is left untouched. The resolver's
        // apply_update applies the identical call to its own json_data, so the
        // two target documents canonicalize to the same JCS bytes.
        let mut target_value = self.json_data.clone();
        json_patch::patch(&mut target_value, patch).map_err(|e| {
            Btcr2Error::InvalidDidUpdate(format!("Unable to apply JSON Patch: {e}"))
        })?;

        check_id_unchanged(&self.json_data, &target_value)?;

        // Re-validate conformance (mirrors apply_update's DocumentFields check)
        // and hash the patched document for the targetHash.
        let target_hash = Document::from_json_value(target_value)
            .map_err(|e| {
                Btcr2Error::InvalidDidUpdate(format!(
                    "patched document is non-conformant: {}",
                    conformance_cause(&e)
                ))
            })?
            .hash();

        let unsigned =
            UnsecuredUpdate::construct(patch, source_hash, target_hash, target_version_id);

        Ok((unsigned, source_hash, target_hash))
    }

    /// Construct a signed BTCR2 update from `patch` against this document.
    ///
    /// This is the spec's Update operation up to — but not including —
    /// announcing the update on a beacon. It does not mutate `self`; it
    /// returns the signed [`Update`] for the caller (or a beacon) to announce.
    ///
    /// Before any signing, two guards run:
    ///   1. an entry of this document's capabilityInvocation set must identify
    ///      `verification_method_id` — a reference equal to it, or an embedded
    ///      verification method whose `id` equals it — and, for a reference,
    ///      the referenced verification method must exist (relative DID URLs
    ///      are resolved against the document `id` first), and
    ///   2. the public key derived from `secret_key` must equal the public key
    ///      that entry carries.
    ///
    /// The first is a spec requirement (raising `INVALID_DID_UPDATE` on
    /// failure, via the lookup shared with the resolve path); the second is a
    /// project correctness guard that prevents emitting a signed update nobody
    /// could verify (see adrs/0006).
    ///
    /// The proof's `verificationMethod` is the id resolved against the
    /// document `id` (an absolute DID URL), whatever form the caller passed,
    /// so any verifier — literal-comparing or resolving — identifies the same
    /// entry.
    ///
    /// Spec: did-btcr2/src/operations/update.md — the capabilityInvocation
    /// lookup and the Data Integrity Config shape.
    pub fn construct_signed_update(
        &self,
        patch: Patch,
        target_version_id: NonZeroU64,
        verification_method_id: &str,
        secret_key: crate::key::SecretKey,
    ) -> Result<Update, Btcr2Error> {
        // Guard 0: a deactivated DID is terminal and MUST NOT accept further
        // updates (spec: did-btcr2/src/operations/deactivate.md). The resolver
        // FSM short-circuits on deactivation, but the construction primitive must
        // also refuse so it cannot mint a post-deactivation update on its own.
        if self.fields.deactivated {
            return Err(Btcr2Error::InvalidDidUpdate(
                "cannot update a deactivated DID document".into(),
            ));
        }

        // Guard 1: an entry of the capabilityInvocation set must identify the id
        // and yield its public key (shared with apply_update via the single
        // lookup helper).
        let public_key = self.fields.invoking_public_key(verification_method_id)?;

        // Guard 2: the caller key must match that public key, so the produced
        // signature will verify against this document.
        let derived = secret_key
            .as_inner()
            .public_key(&secp256k1::Secp256k1::new());
        if derived != public_key {
            return Err(Btcr2Error::InvalidDidUpdate(
                "secret key does not match the verificationMethod public key".into(),
            ));
        }

        // Build the unsigned update (also enforces id-immutability + conformance).
        let (unsigned, _source_hash, _target_hash) =
            self.construct_unsigned_update(&patch, target_version_id)?;

        // Data Integrity Config: the capability is this DID's root capability,
        // the proof authorizes a capabilityInvocation Write, and `created` is
        // left unset so the produced update is byte-reproducible.
        let capability = derive_root_capability(self.fields.id.clone());
        let inner = ProofInner {
            id: None,
            proof_type: ProofType::DataIntegrityProof,
            proof_purpose: ProofPurpose::CapabilityInvocation,
            verification_method: absolutize_did_url(verification_method_id, &self.fields.id),
            cryptosuite: CryptoSuiteName::Jcs,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            previous_proof: None,
            nonce: None,
            context: vec![],
            capability,
            capability_action: "Write".to_string(),
            invocation_target: None,
        };

        // Sign over the unsigned update with the caller's key. Pass by shared
        // borrow: this method owns `secret_key` and drops (scrubs) it on return,
        // so the signing chain never needs to consume or duplicate the secret.
        let proof = CryptoSuite.create_proof(&unsigned, inner, &secret_key)?;

        // Assemble the signed update: the unsigned JSON with "proof" inserted.
        // Parsing it back through Update::from_json_value yields exactly the
        // Update a verifier would see on the wire.
        let mut signed_json = unsigned.as_ref().clone();
        if let Value::Object(map) = &mut signed_json {
            map.insert(
                "proof".to_string(),
                serde_json::to_value(&proof).map_err(|_| {
                    Btcr2Error::InvalidDidUpdate("failed to serialize proof".into())
                })?,
            );
        }

        Update::from_json_value(signed_json).map_err(|_| {
            Btcr2Error::InvalidDidUpdate("constructed signed update failed to parse".into())
        })
    }

    /// Construct a signed deactivation update for this DID document.
    ///
    /// Deactivation (spec: did-btcr2/src/operations/deactivate.md) is the
    /// one-op JSON Patch `[{"op":"add","path":"/deactivated","value":true}]`
    /// applied through the ordinary signed-update path: this is a thin wrapper
    /// over [`Document::construct_signed_update`]. The deactivated-document
    /// guard (Guard 0 in `construct_signed_update`) is inherited for free, so
    /// deactivating an already-deactivated document returns a typed
    /// `Btcr2Error::InvalidDidUpdate` before any signing.
    ///
    /// `target_version_id` is taken explicitly (mirroring
    /// `construct_signed_update`): a sans-I/O method has no resolver state from
    /// which to derive the current version.
    pub fn deactivate(
        &self,
        verification_method_id: &str,
        secret_key: crate::key::SecretKey,
        target_version_id: NonZeroU64,
    ) -> Result<Update, Btcr2Error> {
        let patch: Patch = serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/deactivated", "value": true}
        ]))
        .expect("the static deactivate patch is always valid RFC-6902");
        self.construct_signed_update(patch, target_version_id, verification_method_id, secret_key)
    }
}

impl Document {
    /// Load a document from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        Self::from_json_string(&content)
    }

    /// Create a document from a JSON string
    pub fn from_json_string(json: &str) -> Result<Self, Error> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_json_value(value)
    }

    /// Create a document from a JSON Value
    pub fn from_json_value(json_data: Value) -> Result<Self, Error> {
        let fields = DocumentFields::try_from((&json_data, None))?;

        Ok(Self { fields, json_data })
    }

    /// Save the document to a file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let json = self.to_json_string()?;
        fs::write(path, json)?;

        Ok(())
    }

    /// Convert the document to a JSON string
    pub fn to_json_string(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(&self.json_data)?)
    }

    /// Iterate the beacon services declared on this document.
    ///
    /// Read-only borrow over the document's beacon services; an out-of-crate
    /// caller pairs this with [`Beacon::address`](crate::beacon::Beacon::address)
    /// to read each beacon's Bitcoin address. No I/O is performed.
    pub fn beacons(&self) -> impl Iterator<Item = &Beacon> {
        self.fields.service.iter()
    }
}

impl From<InitialDocument> for Document {
    fn from(doc: InitialDocument) -> Self {
        Self {
            fields: doc.fields,
            json_data: doc.json_data,
        }
    }
}

impl AsRef<Value> for Document {
    fn as_ref(&self) -> &Value {
        &self.json_data
    }
}

impl CanonicalHash for Document {}

/// Representation of initial DID document, according to did::btcr2 specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialDocument {
    pub(crate) fields: DocumentFields<Did>,
    json_data: Value,
}

/// The Bitcoin block that confirmed the beacon signal announcing an update.
/// The resolve path checks a proof's `created` against the header
/// `timestamp` and its `expires` against the block `mediantime`
/// (did-btcr2/src/operations/resolve.md, "Check update.proof").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AnnouncingBlock {
    /// `time` from the block header (Esplora `status.block_time`).
    pub(crate) timestamp: DateTime<Utc>,
    /// The block's `mediantime`; `None` when the caller has not obtained it.
    /// A proof carrying `expires` cannot be checked without it and is rejected.
    pub(crate) mediantime: Option<DateTime<Utc>>,
}

#[cfg(test)]
impl AnnouncingBlock {
    /// A fixed block for tests: header time 1_700_000_000, mediantime one
    /// hour earlier (the mainnet-typical gap the spec footnote describes).
    pub(crate) fn fixed() -> Self {
        Self {
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).expect("in range"),
            mediantime: Some(DateTime::from_timestamp(1_699_996_400, 0).expect("in range")),
        }
    }
}

impl InitialDocument {
    /// Load an initial document from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        Self::from_json_string(&content)
    }

    /// Create an initial document from a JSON string
    pub fn from_json_string(json: &str) -> Result<Self, Error> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_json_value(value)
    }

    /// Create an initial document from a JSON Value
    pub fn from_json_value(value: Value) -> Result<Self, Error> {
        let doc = Document::from_json_value(value)?;

        Ok(Self {
            fields: doc.fields,
            json_data: doc.json_data,
        })
    }

    // Spec section 7.1.2
    /// Create a document from an external intermediate DID Document that has been prepared
    /// externally.
    pub fn from_external_intermediate(
        doc: IntermediateDocument,
        version: Option<DidVersion>,
        network: Option<Network>,
    ) -> Result<(Did, Self), Error> {
        let hash = doc.hash();

        let id_type = IdType::External(hash);

        // The DID encode is a genuine structural invariant: default DidVersion,
        // default Network, and a 32-byte External hash payload always encode to a
        // valid did:btcr2 string, so `.expect()` is correct here.
        let did: Did = DidComponents::new(
            version.unwrap_or_default(),
            network.unwrap_or_default(),
            id_type,
        )?
        .try_into()
        .expect("default DidVersion + default Network + 32-byte External hash payload always encode to a valid did:btcr2 string");

        // An externally-authored intermediate document can be structurally valid
        // as an intermediate document while violating the non-empty
        // `service`/`capabilityInvocation` invariant of an initial document.
        // `from_json_value` does not enforce those invariants, so a nonconforming
        // genesis document (e.g. an empty `service` array) must surface as a typed
        // error here rather than panic.
        let initial_document = doc.into_initial(&did)?;

        // Step 9 is unimplemented (this is the caller's responsibility)
        // Optionally store canonicalBytes on a Content Addressable Storage (CAS) system like the
        // InterPlanetary File System (IPFS).

        Ok((did, initial_document))
    }

    // Spec section 7.2.1
    /// Create an initial document from an existing DID.
    pub fn from_did(did: &Did, resolution_options: &ResolutionOptions) -> Result<Self, Error> {
        match did.components().id_type() {
            IdType::Key(_) => Self::deterministically_generate(did, resolution_options),
            IdType::External(hash) => Self::resolve_external(did, hash, resolution_options),
        }
    }

    // Spec section 7.2.1.1
    fn deterministically_generate(
        did: &Did,
        resolution_options: &ResolutionOptions,
    ) -> Result<Self, Error> {
        let verification_method_id = format!("{}#initialKey", did.encode());
        let verification_method_ids = json!([verification_method_id]);
        let beacon = generate_beacons(did, resolution_options)?;

        Self::from_json_value(json!({
            "id": did.encode(),
            "@context": [DID_CORE_V1_1_CONTEXT, DID_BTC1_CONTEXT],
            "verificationMethod": [{
                "id": verification_method_id,
                "type": "Multikey",
                "controller": did.encode(),
                "publicKeyMultibase": did.public_key().ok_or(Error::MissingGenesisKey)?.to_multikey(),
            }],
            "authentication": verification_method_ids,
            "assertionMethod": verification_method_ids,
            "capabilityInvocation": verification_method_ids,
            "capabilityDelegation": verification_method_ids,
            "service": beacon.into_iter().map(Beacon::into_json).collect::<Vec<_>>(),
        }))
    }

    // Spec section 7.2.1.2
    fn resolve_external(
        did: &Did,
        hash: Sha256Hash,
        resolution_options: &ResolutionOptions,
    ) -> Result<Self, Error> {
        let sidecar = resolution_options.sidecar_data.as_ref();

        // Step 1: obtain the initial document. Precedence:
        //   1. an in-memory `initial_document` supplied programmatically (legacy /
        //      test-harness path), OR
        //   2. the spec wire-form `genesisDocument` — the intermediate
        //      (placeholder-DID) document — bridged into an initial document by
        //      substituting this DID's own identifier and validated against the
        //      External `genesisBytes`. This is the production sidecar path a CLI
        //      `resolve --sidecar <file>` deserializes (`initial_document: None`,
        //      `genesis_document: Some(..)`).
        // If neither is present (no sidecar, or both fields None) the Genesis
        // Document cannot be retrieved: this crate has no CAS fetcher, and the
        // resolve algorithm names that outcome NOT_FOUND
        // (did-btcr2/src/operations/resolve.md, Process Sidecar Data).
        let initial_document = if let Some(doc) =
            sidecar.and_then(|data| data.initial_document.as_ref())
        {
            doc.sidecar_initial_validation(hash)?
        } else if let Some(genesis) = sidecar.and_then(|data| data.genesis_document.as_ref()) {
            // resolve.md "Process Sidecar Data": hash `sidecar.genesisDocument`
            // AS SHIPPED and compare it to `genesis_bytes` — before any
            // substitution, so a genesis document that legitimately spells
            // its own full DID somewhere is judged on the bytes the
            // identifier committed to, not on a reverse-substituted copy.
            // Structural errors in the genesis document propagate as typed
            // errors (no unwrap); the network is this DID's own.
            let intermediate =
                IntermediateDocument::from_json_value(genesis.clone(), did.components().network())?;
            if intermediate.hash() != hash {
                return Err(Btcr2Error::InvalidDid(
                    "sidecar genesisDocument does not match the DID's genesis hash: the \
                     document's JCS SHA-256 differs from the hash committed in the identifier"
                        .to_string(),
                )
                .into());
            }
            // Then "Establish current_document": the placeholder replaced
            // with the DID by a simple string replacement.
            intermediate.into_initial(did)?
        } else {
            return Err(Btcr2Error::NotFound(
                "no sidecar genesisDocument was supplied and this resolver has no CAS fetcher; \
                 the Genesis Document cannot be retrieved"
                    .into(),
            ))?;
        };

        // Step 3: Validate conformant DID document according to the DID Core 1.1 specification

        // todo: Add a function to validate DID document conformance

        Ok(initial_document)
    }

    /// The in-memory `initial_document` sidecar shortcut's check: recover the
    /// genesis document by reversing the placeholder substitution and require
    /// its hash to be the DID's genesis bytes. The spec-form `genesisDocument`
    /// path hashes the shipped document itself in `resolve_external`.
    fn sidecar_initial_validation(&self, hash: Sha256Hash) -> Result<Self, Error> {
        let intermediate_doc = IntermediateDocument::from_initial(self)?;

        // Canonicalize the JSON doc to get a hash
        let hash_bytes = intermediate_doc.hash();

        if hash_bytes != hash {
            Err(Btcr2Error::InvalidDid(
                "sidecar initial DID document does not match the DID's genesis hash: \
                 the intermediate document's JCS SHA-256 differs from the hash committed \
                 in the identifier"
                    .to_string(),
            ))?
        } else {
            Ok(self.clone())
        }
    }

    /// Apply a signed update to this document on the resolve path
    /// (did-btcr2/src/operations/resolve.md, "Check update.proof" and
    /// "Apply update"). In order: refuse if deactivated; require the update's
    /// and its proof's `@context` to be the pinned array; the proof's
    /// `proofPurpose` must be `capabilityInvocation`, its `capabilityAction`
    /// must be `Write`, and its `capability` must equal this DID's root
    /// capability URN; the proof's `verificationMethod` must be identified by
    /// a `capabilityInvocation` entry; the proof's `created` must not be after
    /// the announcing block's header timestamp, its `expires` must not be
    /// before the block's `mediantime`, and `expires` must not be before
    /// `created`; the entry's key must verify the proof; apply the patch to a
    /// clone; re-parse; the id must be unchanged and the result must hash to
    /// `targetHash`. Every rejection is `INVALID_DID_UPDATE`. The document is
    /// replaced only after every check passes; a rejected update leaves it
    /// unchanged.
    pub(crate) fn apply_update(
        &mut self,
        update: &Update,
        announcing_block: &AnnouncingBlock,
    ) -> Result<(), Btcr2Error> {
        // A deactivated DID is terminal and MUST NOT accept further updates
        // (spec: did-btcr2/src/operations/deactivate.md). The resolver FSM
        // short-circuits on deactivation, but the application primitive must also
        // refuse so a post-deactivation update cannot be applied directly.
        if self.fields.deactivated {
            return Err(Btcr2Error::InvalidDidUpdate(
                "cannot apply an update to a deactivated DID document".into(),
            ));
        }

        // The update's @context, and its proof's, must be the spec's pinned
        // array before any proof work (resolve.md, "Check update.proof").
        // verify_proof's proof-equals-update comparison below is the second
        // line; this one fixes what both must equal.
        update.ensure_pinned_context()?;

        // The three Data Integrity Config equalities (resolve.md, "Check
        // update.proof"), checked before any signature work. The capability
        // is compared by string equality against the URN derived for this
        // DID: the spec says the value equals the URN the config specifies.
        let proof = &update.proof.inner;
        if proof.proof_purpose != ProofPurpose::CapabilityInvocation {
            return Err(Btcr2Error::InvalidDidUpdate(
                "proof proofPurpose is not capabilityInvocation".into(),
            ));
        }
        if proof.capability_action != "Write" {
            return Err(Btcr2Error::InvalidDidUpdate(
                "proof capabilityAction is not \"Write\"".into(),
            ));
        }
        let expected_capability = derive_root_capability(self.fields.id.clone());
        if proof.capability != expected_capability {
            return Err(Btcr2Error::InvalidDidUpdate(
                "proof capability is not the root capability URN of this DID".into(),
            ));
        }

        // The proof's verificationMethod MUST be identified by an entry of this
        // document's capabilityInvocation set, and the key is read from that
        // entry (resolve.md, "Check update.proof"). Shared with
        // construct_signed_update via the single lookup helper; a missing entry
        // or a dangling reference is the spec-literal INVALID_DID_UPDATE.
        let public_key = self
            .fields
            .invoking_public_key(&proof.verification_method)?;

        // Proof time bounds against the block that confirmed the announcing
        // beacon signal (resolve.md, "Check update.proof", footnote 6):
        // `created` against the header timestamp, `expires` against
        // `mediantime`. Strict comparisons: an equal timestamp passes. A proof
        // carrying `expires` is rejected when the mediantime is unavailable —
        // the spec makes the check unconditional, so it cannot be skipped.
        if let Some(created) = proof.created
            && created > announcing_block.timestamp
        {
            return Err(Btcr2Error::InvalidDidUpdate(
                "proof created is after the announcing block's header timestamp".into(),
            ));
        }
        if let Some(expires) = proof.expires {
            match announcing_block.mediantime {
                Some(mediantime) if expires < mediantime => {
                    return Err(Btcr2Error::InvalidDidUpdate(
                        "proof expires is before the announcing block's mediantime".into(),
                    ));
                }
                Some(_) => {}
                None => {
                    return Err(Btcr2Error::InvalidDidUpdate(
                        "proof expires cannot be checked: the announcing block's mediantime is not available".into(),
                    ));
                }
            }
        }
        if let (Some(created), Some(expires)) = (proof.created, proof.expires)
            && expires < created
        {
            return Err(Btcr2Error::InvalidDidUpdate(
                "proof expires is before proof created".into(),
            ));
        }

        // Resolve-path apply site: a proof-verification failure MUST surface as
        // INVALID_DID_UPDATE (resolve.md:257), not the granular ProofVerification
        // code. Every other error apply_update raises is already InvalidDidUpdate,
        // so the whole apply step is spec-uniform. Find-refs confirms apply_update
        // has one production caller — the resolver resolve path — so this collapse
        // is resolve-path-only (no construction caller loses a granular variant).
        CryptoSuite
            .data_integrity_verify_proof(public_key, update, &ProofPurpose::CapabilityInvocation)
            .map_err(|e| {
                Btcr2Error::InvalidDidUpdate(format!("update proof failed verification: {e}"))
            })?;

        // Apply the patch to a clone and commit only after every check below
        // passes, so a rejected update never leaves a half-mutated document
        // behind for the resolver to keep iterating with.
        let mut patched = self.json_data.clone();
        json_patch::patch(&mut patched, &update.patch).map_err(|e| {
            Btcr2Error::InvalidDidUpdate(format!("Unable to apply JSON Patch: {e}"))
        })?;

        // The post-patch document id MUST still equal this DID (resolve.md:222).
        // Checked on the raw JSON before the typed parse, so an id change is
        // reported as such even when the new id is not a did:btcr2 identifier.
        check_id_unchanged(&self.json_data, &patched)?;

        // No typed `fields.id != self.fields.id` check follows: `fields.id` is
        // parsed from the same raw `id` string just compared equal to this
        // document's, which itself parsed to `self.fields.id`, so it cannot differ.
        let fields = DocumentFields::try_from((&patched, None)).map_err(|e| {
            Btcr2Error::InvalidDidUpdate(format!(
                "Updated DID document is non-conformant: {}",
                conformance_cause(&e)
            ))
        })?;

        let candidate = InitialDocument {
            fields,
            json_data: patched,
        };
        if candidate.hash() != update.target_hash {
            return Err(Btcr2Error::InvalidDidUpdate(
                "Hash of updated document does not match target hash".into(),
            ));
        }

        *self = candidate;
        Ok(())
    }
}

impl AsRef<Value> for InitialDocument {
    fn as_ref(&self) -> &Value {
        &self.json_data
    }
}

impl CanonicalHash for InitialDocument {}

/// Representation of intermediate DID document, according to did::btcr2 specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntermediateDocument {
    // Intermediate (placeholder-DID) documents stay unconstrained;
    // the type-level NonEmpty invariant only applies to `DocumentFields<Did>`.
    pub(crate) service: Vec<Beacon>,
    json_data: Value,
}

impl AsRef<Value> for IntermediateDocument {
    fn as_ref(&self) -> &Value {
        &self.json_data
    }
}

impl CanonicalHash for IntermediateDocument {}

impl IntermediateDocument {
    /// Load an intermediate document from a file
    pub fn from_file<P: AsRef<Path>>(path: P, network: Network) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        Self::from_json_string(&content, network)
    }

    /// Create an intermediate document from a JSON string
    pub fn from_json_string(json: &str, network: Network) -> Result<Self, Error> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_json_value(value, network)
    }

    /// Create an intermediate document from a JSON Value
    pub fn from_json_value(value: Value, network: Network) -> Result<Self, Error> {
        // validate structural integrity
        let fields = DocumentFields::<String>::try_from((&value, Some(network)))?;

        Ok(Self {
            service: fields.service,
            json_data: value,
        })
    }

    /// Build the Initial DID Document from this genesis (intermediate)
    /// document by replacing every `did:btcr2:_` placeholder with `did`
    /// (`did-btcr2/src/operations/resolve.md`, "Establish current_document":
    /// "A simple string replacement is sufficient").
    ///
    /// Literal, on the serialized document: every occurrence of the
    /// placeholder text is replaced — as a whole value, as a `#fragment`
    /// prefix, inside a longer string such as a service endpoint URL, and in
    /// an object key alike — because that is what every other implementation
    /// does, and the first update's `sourceHash` is the hash of the result.
    /// A narrower substitution would yield a different initial document, a
    /// different `sourceHash`, and an `INVALID_DID_UPDATE` here for an update
    /// that applies everywhere else.
    ///
    /// This substitution is where an external DID's `sourceHash` is anchored.
    /// The first update's `sourceHash` is the JCS-then-SHA-256 hash of the
    /// document AFTER this substitution — never of the sidecar
    /// `genesisDocument` bytes as shipped. The as-shipped bytes hash to the
    /// DID's genesis bytes (the `x1` identifier payload) instead, so a reader
    /// who hashes the sidecar genesis document directly and compares it to
    /// `sourceHash` will see a mismatch that is not a defect. Pinned over every
    /// external vector with updates by
    /// `external_source_hash_is_the_initial_document_after_placeholder_substitution`.
    pub(crate) fn into_initial(self, did: &Did) -> Result<InitialDocument, Btcr2Error> {
        let json_data = replace_text(&self.json_data, DID_PLACEHOLDER, did.encode())?;

        // A nonconforming genesis (e.g. empty service/capabilityInvocation on an
        // x1 sidecar) is structurally invalid as an initial document — surface a
        // typed error, never panic on attacker-supplied sidecar data.
        InitialDocument::from_json_value(json_data)
            .map_err(|e| Btcr2Error::InvalidDidDocument(e.to_string()))
    }

    /// The inverse of [`IntermediateDocument::into_initial`]: every occurrence
    /// of the document's DID replaced with the `did:btcr2:_` placeholder, by
    /// the same literal text replacement. Used by the in-memory
    /// `initial_document` sidecar shortcut to recover the genesis document it
    /// was bound from; the spec-form `genesisDocument` path hashes the
    /// shipped document directly and never needs this.
    pub(crate) fn from_initial(initial_doc: &InitialDocument) -> Result<Self, Btcr2Error> {
        let did = &initial_doc.fields.id;
        let json_data = replace_text(&initial_doc.json_data, did.encode(), DID_PLACEHOLDER)?;

        // `DocumentFields<Did>::service` is `NonEmpty<Beacon>`; the
        // intermediate-document field stays `Vec<Beacon>`.
        let service: Vec<Beacon> = initial_doc.fields.service.iter().cloned().collect();

        Ok(Self { service, json_data })
    }
}

/// The spec's "simple string replacement": serialize `value`, replace every
/// occurrence of `from` with `to` in the text, and parse the result back.
/// Neither a DID nor the placeholder contains a character JSON escapes, so
/// the text form is the document itself and the result re-parses; a failure
/// to would mean the replacement produced a document that is not JSON, which
/// is reported rather than assumed away.
fn replace_text(value: &Value, from: &str, to: &str) -> Result<Value, Btcr2Error> {
    let text = serde_json::to_string(value)
        .map_err(|e| Btcr2Error::InvalidDidDocument(format!("document does not serialize: {e}")))?;
    serde_json::from_str(&text.replace(from, to)).map_err(|e| {
        Btcr2Error::InvalidDidDocument(format!(
            "document is not JSON after replacing `{from}` with `{to}`: {e}"
        ))
    })
}

/// Resolve a DID URL reference against the document's DID.
///
/// DID Core 1.1 §3.2.1 applies RFC 3986 §5.2 with the DID as the base URI:
/// scheme `did`, authority `method:method-specific-id`, empty path. An
/// absolute reference (one starting with `did:`) is returned unchanged. A
/// relative one is re-composed onto the DID: `#f` and `?q` append; a path
/// merges as `/` + path (§5.2.3, base has an authority and an empty path)
/// and is dot-normalised (§5.2.4), so `key-1`, `./key-1` and `../key-1`
/// all resolve to `<did>/key-1` and no reference can climb above the DID.
/// Implementations MUST resolve a relative DID URL against the document
/// id before they compare (did-btcr2/src/data-structures.md).
///
/// The base is always the document's own `id`, never a DID taken from the
/// proof or the capability, so an update cannot choose what a relative
/// reference resolves against.
pub(crate) fn absolutize_did_url(reference: &str, base: &Did) -> String {
    if reference.starts_with("did:") {
        return reference.to_owned();
    }
    let (before_fragment, fragment) = match reference.split_once('#') {
        Some((rest, fragment)) => (rest, Some(fragment)),
        None => (reference, None),
    };
    let (path, query) = match before_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (before_fragment, None),
    };
    let mut target = base.encode().to_owned();
    if !path.is_empty() {
        let merged = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        target.push_str(&remove_dot_segments(&merged));
    }
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    if let Some(fragment) = fragment {
        target.push('#');
        target.push_str(fragment);
    }
    target
}

/// RFC 3986 §5.2.4 `remove_dot_segments`, rule for rule (A–E).
pub(crate) fn remove_dot_segments(path: &str) -> String {
    let mut input = path.to_owned();
    let mut output = String::new();
    while !input.is_empty() {
        if let Some(rest) = input
            .strip_prefix("../")
            .or_else(|| input.strip_prefix("./"))
        {
            // A: a leading "../" or "./" is dropped
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("/./") {
            // B: "/./" becomes "/"
            input = format!("/{rest}");
        } else if input == "/." {
            // B: a trailing "/." becomes "/"
            input = "/".to_owned();
        } else if let Some(rest) = input.strip_prefix("/../") {
            // C: "/../" becomes "/" and the last output segment goes
            input = format!("/{rest}");
            pop_last_segment(&mut output);
        } else if input == "/.." {
            // C: a trailing "/.." becomes "/" and the last output segment goes
            input = "/".to_owned();
            pop_last_segment(&mut output);
        } else if input == "." || input == ".." {
            // D: a bare "." or ".." is dropped
            input.clear();
        } else {
            // E: move the first path segment (with its leading "/", if any,
            // up to but not including the next "/") from input to output
            let start = usize::from(input.starts_with('/'));
            let end = input[start..].find('/').map_or(input.len(), |i| i + start);
            output.push_str(&input[..end]);
            input = input[end..].to_owned();
        }
    }
    output
}

/// Drop the last `/segment` of `output` (RFC 3986 §5.2.4 rule C).
fn pop_last_segment(output: &mut String) {
    match output.rfind('/') {
        Some(i) => output.truncate(i),
        None => output.clear(),
    }
}

// Spec section 7.2.1.1.1
fn generate_beacons(
    did: &Did,
    _resolution_options: &ResolutionOptions,
) -> Result<Vec<Beacon>, Error> {
    let secp = secp256k1::Secp256k1::verification_only();
    let network = did.components().network().try_into()?;
    // TODO: After the `bitcoin` crate is updated, we can remove this extra public key constructor.
    let public_key =
        esploda::bitcoin::PublicKey::new(did.public_key().ok_or(Error::MissingGenesisKey)?);

    let p2pkh_id = format!("{}#initialP2PKH", did.encode());
    let p2wpkh_id = format!("{}#initialP2WPKH", did.encode());
    let p2tr_id = format!("{}#initialP2TR", did.encode());

    let p2pkh_beacon = Address::p2pkh(&public_key, network);
    let p2wpkh_beacon = Address::p2wpkh(&public_key, network)?;
    let p2tr_beacon = Address::p2tr(&secp, public_key.inner.into(), None, network);

    // TODO: Allow overriding the default minimum confirmations required in `ResolutionOptions`?
    Ok(vec![
        Beacon::new(p2pkh_id, BeaconType::Singleton, p2pkh_beacon),
        Beacon::new(p2wpkh_id, BeaconType::Singleton, p2wpkh_beacon),
        Beacon::new(p2tr_id, BeaconType::Singleton, p2tr_beacon),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zcap::dereference_root_capability;
    // ResolverState is only used by test_document_from_did_components, which is
    // feature-gated under `old-spec-fixtures`. Gate the import to match.
    #[cfg(feature = "old-spec-fixtures")]
    use crate::resolver::ResolverState;
    use crate::test_vectors::read_vendor_copy;

    impl Did {
        fn hash_unchecked(&self) -> Sha256Hash {
            match self.components().id_type() {
                IdType::Key(_) => unreachable!(), // todo: parse don't validate
                IdType::External(hash) => hash,
            }
        }
    }

    /// The spec's "simple string replacement": every occurrence of the
    /// placeholder text is rewritten — a whole value, a `#fragment` id, a
    /// `/path` or `?query` DID URL, text inside a longer string such as a
    /// service endpoint URL, an array element, and an object key — and the
    /// result is a document again. Nothing is left for a narrower rule to
    /// miss, because the first update's `sourceHash` is the hash of exactly
    /// this document.
    #[test]
    fn replace_text_rewrites_every_occurrence_of_the_placeholder() {
        let v = json!({
            "id": "did:btcr2:_",
            "vm": "did:btcr2:_#key-0",
            "path": "did:btcr2:_/path",
            "query": "did:btcr2:_?service=x",
            "endpoint": "https://hub.example/did:btcr2:_",
            "note": "see did:btcr2:_ in the log",
            "list": ["did:btcr2:_", "did:btcr2:_#svc"],
            "did:btcr2:_": "a key",
            "untouched": "did:btcr2:x1other",
        });
        let out = replace_text(&v, "did:btcr2:_", "did:btcr2:x1abc").expect("replaces");
        assert_eq!(out["id"], "did:btcr2:x1abc");
        assert_eq!(out["vm"], "did:btcr2:x1abc#key-0");
        assert_eq!(out["path"], "did:btcr2:x1abc/path");
        assert_eq!(out["query"], "did:btcr2:x1abc?service=x");
        assert_eq!(out["endpoint"], "https://hub.example/did:btcr2:x1abc");
        assert_eq!(out["note"], "see did:btcr2:x1abc in the log");
        assert_eq!(out["list"][0], "did:btcr2:x1abc");
        assert_eq!(out["list"][1], "did:btcr2:x1abc#svc");
        assert_eq!(out["did:btcr2:x1abc"], "a key");
        assert_eq!(out["untouched"], "did:btcr2:x1other");

        // And the reverse replacement is the exact inverse on this document.
        let back = replace_text(&out, "did:btcr2:x1abc", "did:btcr2:_").expect("replaces");
        assert_eq!(back, v);
    }

    /// DID Core 1.1 §3.2.1 / RFC 3986 §5.2 with the DID as the base: fragment
    /// and query references append; path references (with or without a
    /// leading `/`, `./` or `../`) become `<did>/` + the dot-normalised path,
    /// so no reference can climb above the DID; an absolute `did:` reference
    /// is returned unchanged (and is never parsed, so a foreign DID passes
    /// through as-is).
    #[test]
    fn absolutize_did_url_resolves_relative_references_against_the_document_id() {
        let (base, _vm_id, _initial, _document) = source_documents();
        let did = base.encode().to_owned();
        let foreign = "did:btcr2:x1qother#key-0".to_owned();
        let table: Vec<(String, String)> = vec![
            ("#key-0".into(), format!("{did}#key-0")),
            ("?versionId=2".into(), format!("{did}?versionId=2")),
            ("/path".into(), format!("{did}/path")),
            ("key-1".into(), format!("{did}/key-1")),
            ("./key-1".into(), format!("{did}/key-1")),
            ("../key-1".into(), format!("{did}/key-1")),
            ("../../key-1".into(), format!("{did}/key-1")),
            ("a/./b/../c?x=1#f".into(), format!("{did}/a/c?x=1#f")),
            ("".into(), did.clone()),
            (format!("{did}#key-0"), format!("{did}#key-0")),
            (foreign.clone(), foreign),
        ];
        for (reference, expected) in table {
            assert_eq!(
                absolutize_did_url(&reference, &base),
                expected,
                "{reference:?}"
            );
        }
    }

    /// RFC 3986 §5.4.2's two worked examples for `remove_dot_segments`, plus
    /// the two shapes that matter for a DID base: a leading `/../` cannot pop
    /// below the root, and a trailing `/..` leaves the trailing slash.
    #[test]
    fn remove_dot_segments_matches_rfc_3986_examples() {
        assert_eq!(remove_dot_segments("/a/b/c/./../../g"), "/a/g");
        assert_eq!(remove_dot_segments("mid/content=5/../6"), "mid/6");
        assert_eq!(remove_dot_segments("/../key-1"), "/key-1");
        assert_eq!(remove_dot_segments("/a/b/.."), "/a/");
    }

    // This helper reads the legacy fixture `resolutionOptions.json`, which keys
    // its `signalsMetadata` by txid. The spec-form resolver keys its
    // sidecar lookup by the JSON Document Hash of each update (`Update::hash()`),
    // which equals the OP_RETURN beacon-signal bytes — so the txid key is
    // discarded here and the update payloads are collected into a
    // `SidecarData` whose `update_lookup_table` is built by `SidecarData::new`.
    //
    // Feature-gated to match its only remaining caller — the
    // `old-spec-fixtures`-gated legacy test `test_document_from_did_components`.
    // The default-build re-homed tests
    // build their `ResolutionOptions` directly from the regtest operation
    // vectors via the operation-vector adapter, so this legacy
    // signalsMetadata-by-txid reader is no longer on the default path.
    #[cfg(feature = "old-spec-fixtures")]
    impl ResolutionOptions {
        pub(crate) fn from_json_string(json: &str) -> Self {
            let json = serde_json::from_str::<Value>(json).unwrap();

            let updates: Vec<Update> = json["sidecarData"]["signalsMetadata"]
                .as_object()
                .unwrap()
                .values()
                .filter_map(|metadata| {
                    Update::from_json_value(metadata["updatePayload"].clone()).ok()
                })
                .collect();

            ResolutionOptions {
                sidecar_data: Some(SidecarData::new(None, updates, None, None)),
                ..Default::default()
            }
        }
    }

    #[test]
    fn test_document_parse() {
        // Re-homed onto the regtest k1 qgpakaw4 resolved DID document
        // (resolve/output.json.didDocument). Its shape — 3 SingletonBeacon
        // services + 1 Multikey verificationMethod — is the regtest-vector
        // re-derivation of the asserted counts (was the now-deleted mutinynet
        // fixture, same 3/1 shape).
        let resolve_output = read_vendor_copy("regtest/k1/qgpakaw4/resolve/output.json");
        let did_document = resolve_output["didDocument"].to_string();
        let doc = Document::from_json_string(&did_document).unwrap();

        assert_eq!(doc.fields.service.len(), 3);
        assert_eq!(doc.fields.verification_method.len(), 1);
    }

    /// A document carrying a non-beacon `service`
    /// (`LinkedDomains`) alongside its beacons parses successfully — the
    /// non-beacon service is retain-and-ignored (excluded from the typed beacon
    /// vec / `beacons()`, but retained in `json_data`) rather than failing the
    /// whole document.
    #[test]
    fn non_beacon_service_is_retained_not_fatal() {
        let resolve_output = read_vendor_copy("regtest/k1/qgpakaw4/resolve/output.json");
        let mut did_document = resolve_output["didDocument"].clone();

        let did_id = did_document["id"].as_str().unwrap().to_string();
        did_document["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{did_id}#linked-domain"),
            "type": "LinkedDomains",
            "serviceEndpoint": "https://example.com"
        }));

        let doc = Document::from_json_value(did_document.clone()).expect("parse must succeed");

        // The LinkedDomains service is excluded from beacon logic ...
        assert_eq!(doc.beacons().count(), 3);
        assert_eq!(doc.fields.service.len(), 3);
        // ... but survives in the retained raw envelope (json_data).
        assert_eq!(doc.as_ref()["service"].as_array().unwrap().len(), 4);
    }

    /// Boundary of the leniency policy: a service object with NO `type` field is
    /// malformed and still fails the whole document (the `?` on
    /// `string_from_object(service, "type")` propagates the missing-key error) —
    /// retain-and-ignore covers unknown-but-present types, not absent required
    /// fields.
    #[test]
    fn service_missing_type_still_errors() {
        let resolve_output = read_vendor_copy("regtest/k1/qgpakaw4/resolve/output.json");
        let mut did_document = resolve_output["didDocument"].clone();

        let service = &mut did_document["service"].as_array_mut().unwrap()[0];
        service.as_object_mut().unwrap().remove("type");

        assert!(Document::from_json_value(did_document).is_err());
    }

    // Drives the EXTERNAL x1 q26jeds9 vector. The vector's
    // `other.json.genesisDocument` is authored with the spec-form `did:btcr2:_`
    // genesis placeholder; `into_initial` substitutes it for the real DID, and
    // `sidecar_initial_validation` confirms the rebuilt intermediate hash matches
    // the External `genesisBytes`. (The old flat regtest/x1qgcs.../initialDidDoc.json
    // was deleted by the upstream restructure; this read is homed on the surviving
    // q26jeds9 path.)
    #[test]
    fn test_sidecar_initial_validation() {
        let other = read_vendor_copy("regtest/x1/q26jeds9/other.json");

        let did: Did = "did:btcr2:x1q26jeds9at48fu5jvpya5s88eqpzne77sp6zlrr9v5dtg7jppa08uhacp3f"
            .parse()
            .unwrap();

        let intermediate = IntermediateDocument::from_json_value(
            other["genesisDocument"].clone(),
            Network::Regtest,
        )
        .unwrap();
        let initial_doc = intermediate.into_initial(&did).unwrap();

        let resolution_options = ResolutionOptions {
            sidecar_data: Some(SidecarData {
                initial_document: Some(initial_doc),
                ..Default::default()
            }),
            ..Default::default()
        };

        let hash = did.hash_unchecked();
        let initial_doc =
            InitialDocument::resolve_external(&did, hash, &resolution_options).unwrap();
        assert_eq!(initial_doc.fields.id, did);
    }

    // Production sidecar path: a `SidecarData` deserialized from the spec wire form
    // `{"genesisDocument": <intermediate placeholder doc>}` carries
    // `initial_document: None` and `genesis_document: Some(..)`. `resolve_external`
    // must bridge the genesis document into the initial document (substituting the
    // DID and using the DID's OWN network) and pass `sidecar_initial_validation`.
    // This exercises the serde/CLI path — NOT the in-code struct-literal
    // `initial_document` shortcut used by `test_sidecar_initial_validation`.
    #[test]
    fn resolve_external_bridges_genesis_document_from_serde_path() {
        let other = read_vendor_copy("regtest/x1/q26jeds9/other.json");

        let did: Did = "did:btcr2:x1q26jeds9at48fu5jvpya5s88eqpzne77sp6zlrr9v5dtg7jppa08uhacp3f"
            .parse()
            .unwrap();

        // Deserialize the sidecar from the wire form. This is the exact shape a CLI
        // `--sidecar-out` writes and `resolve --sidecar` reads back: the serde path
        // leaves `initial_document` None and only fills `genesis_document`.
        let sidecar = SidecarData::from_json_value(json!({
            "genesisDocument": other["genesisDocument"].clone(),
        }))
        .unwrap();
        assert!(
            sidecar.initial_document.is_none(),
            "serde path must leave initial_document None; the bridge must build it from genesis_document"
        );
        assert!(sidecar.genesis_document.is_some());

        let resolution_options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..Default::default()
        };

        let hash = did.hash_unchecked();
        let initial_doc =
            InitialDocument::resolve_external(&did, hash, &resolution_options).unwrap();
        assert_eq!(initial_doc.fields.id, did);
    }

    /// A self-contained external (placeholder-DID) genesis document with the
    /// placeholder in every position the literal replacement must reach: the
    /// id, a `#fragment` id, a controller, and INSIDE a non-beacon service's
    /// endpoint URL.
    fn genesis_with_placeholder_in_an_endpoint() -> Value {
        json!({
            "id": "did:btcr2:_",
            "@context": [
                "https://www.w3.org/ns/did/v1.1",
                "https://btcr2.dev/context/v1"
            ],
            "verificationMethod": [{
                "id": "did:btcr2:_#key-0",
                "type": "Multikey",
                "controller": "did:btcr2:_",
                "publicKeyMultibase": "zQ3shTHn9hZ1BHtoZayz4VmPAZT97p2v8swmuPEUwBKHCanTL"
            }],
            "authentication": ["did:btcr2:_#key-0"],
            "assertionMethod": ["did:btcr2:_#key-0"],
            "capabilityInvocation": ["did:btcr2:_#key-0"],
            "capabilityDelegation": ["did:btcr2:_#key-0"],
            "service": [
                {
                    "id": "did:btcr2:_#service-0",
                    "serviceEndpoint": "bitcoin:mnDXvNsFTf9cs4hWigPkENCBDp9eJpfyxF",
                    "type": "SingletonBeacon"
                },
                {
                    "id": "did:btcr2:_#hub",
                    "type": "LinkedDomains",
                    "serviceEndpoint": "https://hub.example/did:btcr2:_"
                }
            ]
        })
    }

    /// The spec-form path judges `sidecar.genesisDocument` AS SHIPPED — its
    /// hash is the DID's genesis bytes — and then builds the initial document
    /// by the literal replacement, so a placeholder INSIDE a service endpoint
    /// URL is rewritten too. The create path (`from_external_intermediate`)
    /// and the resolve path (`resolve_external`) produce the same initial
    /// document, which is what anchors the first update's `sourceHash`.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md "Process Sidecar Data" and
    /// "Establish current_document" ("A simple string replacement is
    /// sufficient").
    #[test]
    fn resolve_external_hashes_the_shipped_genesis_and_replaces_every_placeholder() {
        let genesis = genesis_with_placeholder_in_an_endpoint();
        let intermediate = IntermediateDocument::from_json_value(genesis.clone(), Network::Regtest)
            .expect("the genesis document is structurally valid");
        let shipped_hash = intermediate.hash();
        let (did, created) =
            InitialDocument::from_external_intermediate(intermediate, None, Some(Network::Regtest))
                .expect("the genesis document mints an x1 DID");
        assert_eq!(
            did.hash_unchecked(),
            shipped_hash,
            "the DID commits to the hash of the genesis document as shipped"
        );

        let sidecar = SidecarData::from_json_value(json!({ "genesisDocument": genesis }))
            .expect("the sidecar deserializes");
        let resolution_options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..Default::default()
        };
        let resolved =
            InitialDocument::resolve_external(&did, did.hash_unchecked(), &resolution_options)
                .expect("the shipped genesis document hashes to the DID's genesis bytes");

        assert_eq!(resolved.fields.id, did);
        assert_eq!(
            resolved.as_ref()["service"][1]["serviceEndpoint"],
            format!("https://hub.example/{}", did.encode()),
            "the placeholder inside the endpoint URL is replaced too"
        );
        assert_eq!(
            resolved.as_ref()["service"][1]["id"],
            format!("{}#hub", did.encode())
        );
        assert_eq!(
            resolved, created,
            "create and resolve build the same initial document from one genesis document"
        );
        assert_ne!(
            resolved.hash(),
            shipped_hash,
            "the initial document is not the genesis document: its hash is what the first \
             update's sourceHash names"
        );
    }

    /// A `genesisDocument` whose content is not what the DID committed to is
    /// `INVALID_DID`, judged before any substitution: here the endpoint URL
    /// differs by one character.
    #[test]
    fn resolve_external_rejects_a_genesis_document_the_did_did_not_commit_to() {
        let genesis = genesis_with_placeholder_in_an_endpoint();
        let intermediate = IntermediateDocument::from_json_value(genesis.clone(), Network::Regtest)
            .expect("the genesis document is structurally valid");
        let (did, _) =
            InitialDocument::from_external_intermediate(intermediate, None, Some(Network::Regtest))
                .expect("the genesis document mints an x1 DID");

        let mut tampered = genesis;
        tampered["service"][1]["serviceEndpoint"] = json!("https://hub.example/did:btcr2:_/x");
        let sidecar = SidecarData::from_json_value(json!({ "genesisDocument": tampered }))
            .expect("the sidecar deserializes");
        let resolution_options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..Default::default()
        };
        let result =
            InitialDocument::resolve_external(&did, did.hash_unchecked(), &resolution_options);
        let Err(Error::Btcr2Error(Btcr2Error::InvalidDid(detail))) = result else {
            panic!(
                "a genesis document the DID did not commit to must be InvalidDid, got {result:?}"
            );
        };
        assert!(
            detail.contains("genesisDocument"),
            "the detail names the sidecar field: {detail}"
        );
    }

    // `sidecar_initial_validation` recomputes the intermediate-document hash from
    // the supplied initial document and rejects it when that hash does not equal
    // the External `genesisBytes`. Here the bound initial document is correct; the
    // only divergence is a deliberately corrupted hash argument (one byte flipped
    // in the External genesisBytes), so the failure is isolated to the hash check
    // and the error must be `InvalidDid`.
    #[test]
    fn test_sidecar_initial_validation_hash_mismatch() {
        let other = read_vendor_copy("regtest/x1/q26jeds9/other.json");

        let did: Did = "did:btcr2:x1q26jeds9at48fu5jvpya5s88eqpzne77sp6zlrr9v5dtg7jppa08uhacp3f"
            .parse()
            .unwrap();

        let intermediate = IntermediateDocument::from_json_value(
            other["genesisDocument"].clone(),
            Network::Regtest,
        )
        .unwrap();
        let initial_doc = intermediate.into_initial(&did).unwrap();

        // Flip one byte of the genuine External genesisBytes so the only thing
        // wrong is the hash passed to validation.
        let mut wrong_bytes = *did.hash_unchecked().as_bytes();
        wrong_bytes[0] ^= 0xff;
        let wrong = Sha256Hash::from(wrong_bytes);

        let result = initial_doc.sidecar_initial_validation(wrong);
        assert!(
            matches!(result, Err(Error::Btcr2Error(Btcr2Error::InvalidDid(_)))),
            "hash mismatch must error InvalidDid, got: {result:?}"
        );
    }

    // The sidecar hash-mismatch detail surfaced into
    // `didResolutionMetadata` must be a real, human-readable string — never the
    // shipped `TODO` placeholder. This test is fixture-free (it builds the initial
    // document deterministically via `source_documents`) so the content assertion
    // always runs, and it drives the same `hash_bytes != hash` branch by passing a
    // deliberately corrupted hash. It asserts the variant is unchanged
    // (`InvalidDid`) and the detail is non-empty and contains no `TODO`.
    #[test]
    fn sidecar_initial_validation_mismatch_detail_is_real_and_todo_free() {
        let (_did, _vm_id, initial, _document) = source_documents();

        // The genuine intermediate hash of `initial`; flip one byte so the only
        // divergence is the hash argument and the mismatch branch is exercised.
        let mut wrong_bytes = *IntermediateDocument::from_initial(&initial)
            .expect("the initial document reverses to its genesis document")
            .hash()
            .as_bytes();
        wrong_bytes[0] ^= 0xff;
        let wrong = Sha256Hash::from(wrong_bytes);

        let result = initial.sidecar_initial_validation(wrong);
        let Err(Error::Btcr2Error(Btcr2Error::InvalidDid(detail))) = result else {
            panic!("hash mismatch must error InvalidDid, got: {result:?}");
        };
        assert!(
            !detail.is_empty(),
            "the sidecar mismatch detail must be non-empty"
        );
        assert!(
            !detail.contains("TODO"),
            "the sidecar mismatch detail must not contain the TODO placeholder, got: {detail:?}"
        );
    }

    /// An external vector's first-update `sourceHash` is the hash of the
    /// initial document after `did:btcr2:_` placeholder substitution, not of
    /// the sidecar genesis document as shipped. Both halves are asserted: the
    /// as-shipped genesis hashes to the DID's genesis bytes, and the
    /// substituted initial document hashes to the vector's `sourceHash`.
    /// Iterates the external vectors of the test-suite at `19f8d424` that
    /// carry an update, read from their in-repository copies, so it never
    /// skips and a copy that breaks the recipe fails here by name.
    #[test]
    fn external_source_hash_is_the_initial_document_after_placeholder_substitution() {
        const EXTERNAL_WITH_UPDATES: &[&str] = &[
            "mutinynet/x1/q425c5wf",
            "mutinynet/x1/q550pp4e",
            "mutinynet/x1/q5cfewep",
            "mutinynet/x1/q5ugrf3w",
            "mutinynet/x1/qkrrp544",
            "regtest/x1/q26jeds9",
            "regtest/x1/qfl7se8f",
        ];
        for id in EXTERNAL_WITH_UPDATES {
            let input = read_vendor_copy(&format!("{id}/resolve/input.json"));
            let did: Did = input["did"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: `did` is a string"))
                .parse()
                .unwrap_or_else(|e| panic!("{id}: `did` parses: {e}"));
            let sidecar = &input["resolutionOptions"]["sidecar"];
            let genesis = sidecar["genesisDocument"].clone();
            assert!(
                genesis.is_object(),
                "{id}: sidecar carries a genesisDocument object"
            );
            let first_update = Update::from_json_value(sidecar["updates"][0].clone())
                .unwrap_or_else(|e| panic!("{id}: first sidecar update parses: {e}"));

            let intermediate =
                IntermediateDocument::from_json_value(genesis, did.components().network())
                    .unwrap_or_else(|e| panic!("{id}: genesisDocument parses: {e}"));
            assert_eq!(
                intermediate.hash(),
                did.hash_unchecked(),
                "{id}: as-shipped genesis hashes to the DID's genesis bytes"
            );
            assert_ne!(
                intermediate.hash(),
                first_update.source_hash,
                "{id}: sourceHash is NOT the hash of the as-shipped genesis document"
            );

            let initial = intermediate
                .into_initial(&did)
                .unwrap_or_else(|e| panic!("{id}: into_initial succeeds: {e}"));
            assert_eq!(
                initial.hash(),
                first_update.source_hash,
                "{id}: sourceHash is the hash AFTER did:btcr2:_ -> DID substitution"
            );
        }
    }

    // When `resolve_external` is given no sidecar genesis source at all, the
    // Genesis Document cannot be retrieved (this crate has no CAS fetcher) and
    // the resolve algorithm names that outcome NOT_FOUND. It must return the
    // typed `Btcr2Error::NotFound` rather than panicking — a remote-published
    // External DID with no sidecar genesis cannot crash the resolver.
    #[test]
    fn external_genesis_without_sidecar_is_not_found() {
        let did: Did = "did:btcr2:x1q26jeds9at48fu5jvpya5s88eqpzne77sp6zlrr9v5dtg7jppa08uhacp3f"
            .parse()
            .unwrap();

        // No sidecar genesis document supplied → the `.and_then` chain yields
        // None and the not-found branch fires.
        let resolution_options = ResolutionOptions::default();

        let hash = did.hash_unchecked();
        let result = InitialDocument::resolve_external(&did, hash, &resolution_options);
        assert!(
            matches!(result, Err(Error::Btcr2Error(Btcr2Error::NotFound(_)))),
            "an x1 DID with no genesis source must error NOT_FOUND, got: {result:?}"
        );
    }

    // A hostile x1 sidecar whose genesisDocument carries an empty
    // `service` array is a valid INTERMEDIATE document (DocumentFields<String>
    // leaves `service`/`capabilityInvocation` unconstrained) but violates the
    // NonEmpty invariant of an INITIAL document (DocumentFields<Did>). Before the
    // fix, `into_initial` `.expect()`ed that fallible parse — so this input reached
    // a reachable PANIC (a DoS on attacker-supplied sidecar data). It must now
    // surface a typed `Btcr2Error::InvalidDidDocument` propagated through
    // `resolve_external`, never a panic.
    #[test]
    fn resolve_external_empty_service_genesis_returns_typed_error_not_panic() {
        let raw = include_str!("../fixtures/spec-form/sidecar-empty-service-genesis.json");
        let value: Value = serde_json::from_str(raw).unwrap();

        // Fold-in 9 staging check: the empty-service genesis MUST parse as an
        // intermediate document, so the failure below is isolated to `into_initial`
        // (the panic site) — NOT an earlier, wrong-stage parse rejection. If this
        // parse ever failed, the resolve assertion could pass vacuously.
        let intermediate = IntermediateDocument::from_json_value(
            value["genesisDocument"].clone(),
            Network::Regtest,
        );
        assert!(
            intermediate.is_ok(),
            "empty-service genesis must parse as an intermediate document so the test \
             reaches into_initial, got: {intermediate:?}"
        );
        // The DID that commits to THIS genesis document, so the shipped-hash
        // check `resolve_external` runs first passes and the failure below is
        // isolated to the initial-document invariant.
        let did: Did = DidComponents::new(
            DidVersion::One,
            Network::Regtest,
            IdType::External(intermediate.expect("parsed above").hash()),
        )
        .expect("regtest is a valid network")
        .try_into()
        .expect("an external id type encodes to a valid DID");

        // Drive the production serde/CLI sidecar path: a `SidecarData` deserialized
        // from the wire form leaves `initial_document` None and fills
        // `genesis_document`, so `resolve_external` bridges it via `into_initial`.
        let sidecar = SidecarData::from_json_value(value).unwrap();
        assert!(sidecar.genesis_document.is_some());
        let resolution_options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            ..Default::default()
        };

        let hash = did.hash_unchecked();
        let result = InitialDocument::resolve_external(&did, hash, &resolution_options);
        assert!(
            matches!(
                result,
                Err(Error::Btcr2Error(Btcr2Error::InvalidDidDocument(_)))
            ),
            "empty-service genesis must surface a typed InvalidDidDocument (no panic), got: {result:?}"
        );
    }

    // The `create --external` path shares the same into_initial bridge as the
    // resolve/sidecar path above. An externally-authored intermediate document
    // whose `service` array is empty is a valid INTERMEDIATE document
    // (DocumentFields<String> leaves `service`/`capabilityInvocation`
    // unconstrained) but violates the NonEmpty invariant of an INITIAL document
    // (DocumentFields<Did>). `from_external_intermediate` must surface that as a
    // typed error, NOT panic. (Anti-vacuity: on the pre-fix tree this input hits
    // the `.expect()` on into_initial and panics the process, so this test would
    // abort rather than return an Err.)
    #[test]
    fn from_external_intermediate_empty_service_genesis_returns_typed_error_not_panic() {
        let raw = include_str!("../fixtures/spec-form/sidecar-empty-service-genesis.json");
        let value: Value = serde_json::from_str(raw).unwrap();

        // The empty-service genesis MUST parse as an intermediate document, so the
        // failure below is isolated to the into_initial site reached by
        // `from_external_intermediate` — not an earlier, wrong-stage rejection.
        let intermediate = IntermediateDocument::from_json_value(
            value["genesisDocument"].clone(),
            Network::Regtest,
        );
        assert!(
            intermediate.is_ok(),
            "empty-service genesis must parse as an intermediate document so the test \
             reaches into_initial, got: {intermediate:?}"
        );
        let intermediate = intermediate.unwrap();

        let result =
            InitialDocument::from_external_intermediate(intermediate, None, Some(Network::Regtest));
        assert!(
            matches!(
                result,
                Err(Error::Btcr2Error(Btcr2Error::InvalidDidDocument(_)))
            ),
            "empty-service genesis must surface a typed InvalidDidDocument (no panic), got: {:?}",
            result.map(|(did, _)| did)
        );
    }

    /// `controller` per DID Core 1.1 §5.1.2 on a resolved (`T = Did`)
    /// document: a single string, an array, and a foreign-method DID all
    /// parse; a string that is not a DID and a non-string entry are typed
    /// errors. On the resolve path this is what decides whether an update
    /// that sets `controller` applies or is rejected as non-conformant.
    #[test]
    fn controller_accepts_a_string_or_a_set_of_any_method_dids() {
        let (did, _vm_id, _initial, document) = source_documents();
        let with_controller = |controller: Value| {
            let mut json = document.as_ref().clone();
            json["controller"] = controller;
            Document::from_json_value(json)
        };

        with_controller(json!(did.encode())).expect("a string-form did:btcr2 controller parses");
        with_controller(json!([did.encode()])).expect("an array-form controller parses");
        with_controller(json!([
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ]))
        .expect("a foreign-method controller parses");
        with_controller(json!("did:web:example.com:alice"))
            .expect("a string-form foreign-method controller parses");

        let err = with_controller(json!("alice")).expect_err("not a DID");
        assert!(
            matches!(&err, Error::JsonValue(json_tools::JsonError::InvalidControllerDid(s)) if s == "alice"),
            "got {err:?}"
        );
        let err = with_controller(json!([did.encode(), 7])).expect_err("not a string");
        assert!(
            matches!(&err, Error::JsonValue(json_tools::JsonError::UnexpectedJsonType(f, _)) if f == "controller"),
            "got {err:?}"
        );
    }

    /// An update that sets a string-form or foreign-method `controller`
    /// applies on the resolve path (`apply_update` re-parses the patched
    /// document with the same rule), rather than failing as a non-conformant
    /// document.
    #[test]
    fn apply_update_accepts_a_controller_patch() {
        let (_did, vm_id, initial, document) = source_documents();
        for controller in [
            json!("did:web:example.com:alice"),
            json!(["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]),
        ] {
            let patch: Patch = serde_json::from_value(json!([
                { "op": "add", "path": "/controller", "value": controller }
            ]))
            .expect("a valid patch");
            let update = document
                .construct_signed_update(
                    patch,
                    NonZeroU64::new(2).expect("2 is non-zero"),
                    &vm_id,
                    source_secret_key(),
                )
                .expect("the controller patch constructs");
            let mut target = initial.clone();
            target
                .apply_update(&update, &AnnouncingBlock::fixed())
                .expect("the controller patch applies on the resolve path");
            assert_eq!(target.as_ref()["controller"], controller);
        }
    }

    /// `@context` stays an array: data-structures.md requires the array form
    /// for a did:btcr2 document, and the method spec wins over DID Core's
    /// allowance of a bare string.
    #[test]
    fn context_as_a_bare_string_is_still_rejected() {
        let (_did, _vm_id, _initial, document) = source_documents();
        let mut json = document.as_ref().clone();
        json["@context"] = json!("https://www.w3.org/ns/did/v1.1");
        let err = Document::from_json_value(json).expect_err("a string @context is rejected");
        assert!(
            matches!(&err, Error::JsonValue(json_tools::JsonError::UnexpectedJsonType(f, _)) if f == "@context"),
            "got {err:?}"
        );
    }

    #[test]
    fn test_document_validation_missing_elements() {
        let path = "./fixtures/initialDidDoc-missing-verificationMethod-id.json";
        assert!(matches!(
            InitialDocument::from_file(path),
            Err(Error::JsonValue(json_tools::JsonError::JsonMissingKey(key))) if key == "id"
        ));
    }

    // this legacy test drives a full multi-block FSM traversal
    // over the OLD flat signet fixture layout (txid-keyed signalsMetadata with
    // Base58 `sourceHash`/`targetHash`, plus a hardcoded `targetDocument.json` and
    // testnet beacon-address URLs). That flat layout was DELETED upstream; its
    // behavioural coverage (descriptor→DID, beacon-request generation, FSM
    // resolution, target-doc hash match) is now provided against REAL spec
    // vectors by the operation-vector adapter (`op_vectors_resolve_matches_output`
    // + `op_vectors_update_signs_to_expected_hashes`). It additionally decodes
    // under the OLD nibble layout (version=high/network=low), which is
    // spec-owned.
    //
    // It is RETAINED, gated + `#[ignore]`'d, only as legacy scaffolding: the
    // `include_str!` reads are re-pointed to a SURVIVING regtest vector file so
    // `--all-features` still COMPILES (a gated read of a vanished path would
    // not). It is never executed (its hardcoded testnet URLs/hashes do not match
    // the regtest file), so the path mismatch cannot assert. Un-gate / delete
    // once the nibble-layout change is resolved upstream.
    #[cfg(feature = "old-spec-fixtures")]
    #[ignore = "2026-06-22 nibble-layout-pending (spec-owned): legacy flat-layout \
                FSM traversal superseded by the operation-vector adapter; reads re-pointed to a \
                surviving regtest fixture so --all-features compiles. Un-gate when the layout lands."]
    #[test]
    fn test_document_from_did_components() {
        let id_type = IdType::from(
            PublicKey::from_slice(
                &hex::decode("03da2c07d2443fbf228aa773e5f685562158d39ee675b586b3ebdb897e7f1e56f5")
                    .unwrap(),
            )
            .unwrap(),
        );
        let did_components = DidComponents::new(DidVersion::One, Network::Signet, id_type).unwrap();

        // Re-pointed to a surviving regtest vector so the gated build compiles
        // (test is #[ignore]'d; this read is never asserted against).
        let resolution_options = ResolutionOptions::from_json_string(include_str!(
            "../test-suite/regtest/k1/qgph7nre/resolve/input.json"
        ));

        let (did, fsm) = Document::from_did_components(did_components, resolution_options).unwrap();
        let ResolverState::Requests(next_state, requests) = fsm.resolve().unwrap() else {
            unreachable!()
        };

        let request_urls = requests[&BeaconType::Singleton]
            .iter()
            .map(|req| req.uri().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            request_urls,
            [
                "https://blockstream.info/testnet/api/address/mtA1SshFsJtD2Di1KBSTmyuD23eBqUekQ3/txs",
                "https://blockstream.info/testnet/api/address/tb1q323c0l0fapjeg4ux9ayumnpqh8xzqgk3wg82dy/txs",
                "https://blockstream.info/testnet/api/address/tb1pecc8w64wdvn6x2np8yr8qvsz2pclydkd9t5jde2gf0hy0musfxxsn23q20/txs",
            ],
        );

        let json: serde_json::Value = serde_json::from_str(include_str!(
            "../fixtures/k1qypa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dagl0mgs4-transactions.json"
        ))
        .unwrap();
        let txs: Vec<esploda::esplora::Transaction> =
            serde_json::from_value(json["SingletonBeacon"].clone()).unwrap();
        let transactions = crate::resolver::history_under_first_request(&requests, txs);
        let fsm = next_state.process_responses(transactions);

        let ResolverState::Resolved(result) = fsm.resolve().unwrap() else {
            unreachable!()
        };
        assert_eq!(result.document.fields.id.encode(), did.encode());

        // Re-pointed to a surviving regtest vector so the gated build compiles.
        let target_doc = Document::from_json_string(include_str!(
            "../test-suite/regtest/k1/qgph7nre/update/input.json"
        ))
        .unwrap();
        assert_eq!(result.document.hash(), target_doc.hash());
    }

    // ──────────────────────────────────────────────────────────────────────
    // acceptance tests.
    //
    // The four tests below codify the type-level NonEmpty invariant on
    // `DocumentFields<Did>::capability_invocation` and `::service`, plus the
    // Carve-out that the intermediate `DocumentFields<String>`
    // variant stays unconstrained.
    // ──────────────────────────────────────────────────────────────────────

    /// Minimum valid resolved-DID JSON document. Used as a base by the
    /// acceptance tests; the failing-case tests overwrite the field
    /// they want to test with an empty array before running TryFrom.
    ///
    /// Re-homed onto the regtest k1 qgpakaw4 resolved didDocument (≥1
    /// capabilityInvocation + 3 SingletonBeacon services, so the NonEmpty
    /// invariant holds), read from the in-repository copy of that vendor file
    /// at `19f8d424`, so it never skips.
    fn valid_resolved_doc_json() -> Value {
        read_vendor_copy("regtest/k1/qgpakaw4/resolve/output.json")["didDocument"].clone()
    }

    #[test]
    fn empty_capability_invocation_rejected() {
        // a resolved DID document must contain ≥1
        // capabilityInvocation entry. Spec: did-btcr2/src/data-structures.md
        // §did-document. Type-level guarantee via DocumentMode::Sequence<U> = NonEmpty<U>.
        //
        // The error must surface as Btcr2Error::InvalidDidDocument with the
        // field name in the detail string (the outer Error variant prints
        // only "DID:BTCR2 error" — Btcr2Error doc comments are the Display form
        // so the test pattern-matches the inner variant directly).
        let mut json = valid_resolved_doc_json();
        json["capabilityInvocation"] = serde_json::json!([]);
        let result = DocumentFields::<Did>::try_from((&json, None));
        match result {
            Err(Error::Btcr2Error(Btcr2Error::InvalidDidDocument(detail))) => {
                assert!(
                    detail.contains("capabilityInvocation"),
                    "expected detail mentioning capabilityInvocation, got: {detail}"
                );
            }
            Err(other) => panic!("expected Btcr2Error::InvalidDidDocument, got: {other:?}"),
            Ok(_) => panic!("expected Err for empty capabilityInvocation, got Ok"),
        }
    }

    #[test]
    fn empty_service_rejected() {
        // a resolved DID document must contain ≥1
        // beacon service. Spec: did-btcr2/src/data-structures.md §did-document.
        let mut json = valid_resolved_doc_json();
        json["service"] = serde_json::json!([]);
        let result = DocumentFields::<Did>::try_from((&json, None));
        match result {
            Err(Error::Btcr2Error(Btcr2Error::InvalidDidDocument(detail))) => {
                assert!(
                    detail.contains("beacon") || detail.contains("service"),
                    "expected detail mentioning beacon/service, got: {detail}"
                );
            }
            Err(other) => panic!("expected Btcr2Error::InvalidDidDocument, got: {other:?}"),
            Ok(_) => panic!("expected Err for empty service, got Ok"),
        }
    }

    #[test]
    fn valid_doc_passes() {
        // Happy path: a fully populated resolved-DID document parses
        // into `DocumentFields<Did>` successfully and the NonEmpty fields
        // carry the populated entries.
        let json = valid_resolved_doc_json();
        let fields = DocumentFields::<Did>::try_from((&json, None))
            .expect("fully populated resolved-DID document must parse");
        assert_eq!(fields.capability_invocation.len(), 1);
        assert_eq!(fields.service.len(), 3);
    }

    #[test]
    fn intermediate_doc_allows_empty() {
        // Intermediate `DocumentFields<String>` (placeholder
        // DID) is unconstrained — `Sequence<U> = Vec<U>` for T = String, so
        // empty capabilityInvocation / service must parse to Ok(_).
        //
        // Re-homed onto the x1 q26jeds9 vector's `other.json.genesisDocument`
        // (the external intermediate/placeholder-DID shape, id `did:btcr2:_`).
        // The old flat regtest/x1qgcs.../intermediateDidDoc.json was deleted.
        let other = read_vendor_copy("regtest/x1/q26jeds9/other.json");
        let mut json = other["genesisDocument"].clone();
        json["capabilityInvocation"] = serde_json::json!([]);
        json["service"] = serde_json::json!([]);
        let result = DocumentFields::<String>::try_from((&json, Some(Network::Regtest)));
        assert!(
            result.is_ok(),
            "intermediate doc should be unconstrained, got: {:?}",
            result.err()
        );
    }

    // Drives the x1 q26jeds9 vector. The vector's `other.json.genesisDocument`
    // is the external intermediate document; its hash IS the External
    // `genesisBytes`, so `from_external_intermediate` re-derives the q26jeds9 DID.
    // Because the genesis document is authored with the spec-form `did:btcr2:_`
    // placeholder, `into_initial` substitutes it for the real DID, producing the
    // bound genesis (version-1) document. The re-derived DID must equal the
    // create output, and reversing the binding (`from_initial`) and re-hashing the
    // intermediate must reproduce the External `genesisBytes` — the round-trip the
    // External `did:btcr2` identity is built on. (The old flat
    // regtest/x1qgcs.../{intermediateDidDoc.json,did.txt,initialDidDoc.json} were
    // deleted upstream; this read is homed on the surviving q26jeds9 path.)
    #[test]
    fn test_from_external_intermediate() {
        let other = read_vendor_copy("regtest/x1/q26jeds9/other.json");
        let create_output = read_vendor_copy("regtest/x1/q26jeds9/create/output.json");

        let intermediate_doc = IntermediateDocument::from_json_value(
            other["genesisDocument"].clone(),
            Network::Regtest,
        )
        .unwrap();
        let (did, initial_doc) = InitialDocument::from_external_intermediate(
            intermediate_doc,
            None,
            Some(Network::Regtest),
        )
        .unwrap();

        // The re-derived DID must equal create/output.json.did.
        assert_eq!(did.encode(), create_output["did"].as_str().unwrap());

        // The bound initial document must carry the real DID (placeholder
        // substituted), not the genesis placeholder.
        assert_eq!(initial_doc.fields.id, did);

        // Reversing the binding and re-hashing the intermediate must reproduce the
        // External genesisBytes encoded in the DID — the identity round-trip.
        let rebuilt = IntermediateDocument::from_initial(&initial_doc)
            .expect("the initial document reverses to its genesis document");
        assert_eq!(rebuilt.hash(), did.hash_unchecked());
    }

    /// Smoke: the empty spec-form fixture deserializes into
    /// `SidecarData` with zero updates and an empty lookup table.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md §Process Sidecar Data
    /// lines 62-67. Fixture lives at `fixtures/spec-form/`, re-homed from
    /// `test-suite/spec-form/` because that path is a teammate-shared
    /// nested submodule.
    #[test]
    fn sidecar_data_empty_fixture_deserializes() {
        let raw = include_str!("../fixtures/spec-form/sidecar-empty.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let data = super::SidecarData::from_json_value(value)
            .expect("empty fixture deserializes into SidecarData");
        assert!(data.updates.is_empty());
        assert!(data.update_lookup_table.is_empty());
        assert!(data.cas_updates.is_none());
        assert!(data.smt_proofs.is_none());
    }

    /// the PUBLIC serde path (`serde_json::from_value::<SidecarData>`)
    /// must yield a `SidecarData` whose `update_lookup_table` is fully populated
    /// and correctly keyed — WITHOUT a follow-up `from_json_value` /
    /// `rebuild_lookup_table` call. Before the manual `Deserialize`, the derived
    /// impl left the table empty, so a caller deserializing directly got
    /// populated `updates` with an empty table and every beacon-signal lookup
    /// then raised a spurious `MISSING_UPDATE_DATA`.
    ///
    /// Spec: did-btcr2/src/operations/resolve.md §Process Sidecar Data
    /// lines 62-67 (build a hash → update map).
    #[test]
    fn sidecar_data_deserialize_populates_lookup_table() {
        let raw = include_str!("../fixtures/spec-form/sidecar-two-updates.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");

        // The PUBLIC derived/serde path — NOT from_json_value.
        let data: super::SidecarData =
            serde_json::from_value(value).expect("public serde path deserializes");

        assert_eq!(data.updates.len(), 2);
        assert_eq!(
            data.update_lookup_table.len(),
            data.updates.len(),
            "lookup table must have one entry per update on the public serde path"
        );

        // Keys are exactly { update.hash() } and a known-update lookup hits
        // (would NOT raise MISSING_UPDATE_DATA).
        for update in &data.updates {
            assert!(
                data.update_lookup_table.contains_key(&update.hash()),
                "table must be keyed by Update::hash()"
            );
        }
        assert!(
            data.update_lookup_table
                .contains_key(&data.updates[0].hash()),
            "a beacon-signal lookup on a supplied update must hit"
        );
    }

    /// Forward-compat: populated `casUpdates` / `smtProofs` arrays
    /// deserialize cleanly without breaking the resolver path. The resolver
    /// treats both as opaque; typed parsing arrives later.
    ///
    /// Fixture: `fixtures/spec-form/sidecar-forward-compat.json`.
    #[test]
    fn sidecar_data_forward_compat_fixture_ignores_cas_and_smt() {
        let raw = include_str!("../fixtures/spec-form/sidecar-forward-compat.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let data = super::SidecarData::from_json_value(value)
            .expect("forward-compat fixture deserializes");
        assert!(data.cas_updates.is_some());
        assert!(data.smt_proofs.is_some());
        assert!(data.update_lookup_table.is_empty());
    }

    /// Load the two distinct valid signed updates from the shared
    /// `sidecar-two-updates.json` fixture (real BIP340 proofs, spec-form
    /// `targetVersionId` numbers), returning them as `(u1, u2)`. Reused by the
    /// emit-side round-trip tests so no proof is hand-fabricated.
    fn two_fixture_updates() -> (Update, Update) {
        let raw = include_str!("../fixtures/spec-form/sidecar-two-updates.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let updates = value["updates"].as_array().expect("updates array");
        assert_eq!(updates.len(), 2, "fixture must carry exactly two updates");
        let u1 = Update::from_json_value(updates[0].clone()).expect("update 0 parses");
        let u2 = Update::from_json_value(updates[1].clone()).expect("update 1 parses");
        (u1, u2)
    }

    /// The emit half of the round-trip (roadmap criterion #5, core half): a
    /// `SidecarData` built in memory serializes to spec wire JSON and re-parses
    /// equal. Updates match by [`Update::hash()`] (they have no `PartialEq`).
    /// Also pins that `targetVersionId` stays an unquoted JSON *number* (D-7a) —
    /// so a future "clean up to typed serialize" refactor cannot silently quote
    /// it — and that no non-wire field ever leaks.
    #[test]
    fn sidecar_serialize_roundtrip() {
        let (update, _) = two_fixture_updates();
        let sc = SidecarData::new(None, vec![update.clone()], None, None);

        let v = serde_json::to_value(&sc).expect("SidecarData serializes");
        let obj = v
            .as_object()
            .expect("serialized SidecarData is a JSON object");

        // Exactly the `updates` wire field is present; no genesis / CAS / SMT
        // (all None), and NEITHER internal field ever emits.
        assert_eq!(v["updates"].as_array().expect("updates array").len(), 1);
        assert!(!obj.contains_key("genesisDocument"));
        assert!(!obj.contains_key("casUpdates"));
        assert!(!obj.contains_key("smtProofs"));
        assert!(!obj.contains_key("update_lookup_table"));
        assert!(!obj.contains_key("initial_document"));

        // Each emitted update equals the Update's stored wire JSON verbatim.
        assert_eq!(v["updates"][0], update.json);

        // targetVersionId number pin (D-7a).
        let u0 = v["updates"][0]
            .as_object()
            .expect("emitted update is an object");
        let tvid = u0
            .get("targetVersionId")
            .expect("fixture update carries targetVersionId");
        assert!(tvid.is_number(), "targetVersionId must stay a JSON number");
        assert!(
            !tvid.is_string(),
            "targetVersionId must NOT be quoted as a string"
        );

        // serialize -> deserialize identity: the update survives by hash and the
        // lookup table is rebuilt on the parse boundary.
        let back = SidecarData::from_json_value(v).expect("emitted wire re-parses");
        assert_eq!(back.updates.len(), 1);
        assert_eq!(back.updates[0].hash(), update.hash());
        assert!(back.update_lookup_table.contains_key(&update.hash()));
    }

    /// `push_update` preserves an existing `genesisDocument` while appending an
    /// update (the merge invariant), and the merged `SidecarData` emits the
    /// genesis + both updates and re-parses equal. Genesis is a plain `Value`
    /// (compared by `==`); updates compare by [`Update::hash()`].
    #[test]
    fn push_update_preserves_genesis() {
        let (u1, u2) = two_fixture_updates();
        let genesis_value = json!({
            "id": "did:btcr2:_",
            "@context": ["https://www.w3.org/ns/did/v1.1"],
        });

        let mut sc = SidecarData::new(Some(genesis_value.clone()), vec![u1.clone()], None, None);
        sc.push_update(u2.clone());

        // Append kept genesis and produced [u1, u2].
        assert_eq!(sc.updates.len(), 2);
        assert_eq!(sc.genesis_document, Some(genesis_value.clone()));
        assert_eq!(sc.updates[0].hash(), u1.hash());
        assert_eq!(sc.updates[1].hash(), u2.hash());

        // Dedup-on-hash: re-pushing an already-present update is a no-op.
        sc.push_update(u1.clone());
        assert_eq!(
            sc.updates.len(),
            2,
            "push_update must dedup on Update::hash()"
        );

        // Emit carries the genesis and both updates.
        let v = serde_json::to_value(&sc).expect("merged SidecarData serializes");
        assert_eq!(
            v.get("genesisDocument"),
            Some(&genesis_value),
            "genesisDocument must survive the merge and emit unchanged"
        );
        assert_eq!(v["updates"].as_array().expect("updates array").len(), 2);

        // serialize -> deserialize identity through the merged form.
        let back = SidecarData::from_json_value(v).expect("merged wire re-parses");
        assert_eq!(back.updates.len(), 2);
        assert_eq!(back.genesis_document, Some(genesis_value));
        assert!(back.update_lookup_table.contains_key(&u1.hash()));
        assert!(back.update_lookup_table.contains_key(&u2.hash()));
    }

    /// DocumentMetadata.version_id round-trips
    /// through serde_json::to_string AND serde_jcs::to_string as the spec ASCII
    /// string form (`"5"`), NOT as a JSON number (`5`).
    ///
    /// Spec: did-btcr2/src/data-structures.md:363.
    ///
    /// This test pins the contract that the version_id_serde module emits a
    /// JSON string. A regression where the custom serde is replaced with a
    /// default `#[derive(Serialize)]` would emit `5` (number) and silently
    /// break cross-implementation interop.
    #[test]
    fn document_metadata_version_id_round_trips_as_ascii_string() {
        use std::num::NonZeroU64;
        let meta = super::DocumentMetadata {
            version_id: NonZeroU64::new(5).expect("5 is non-zero"),
            confirmations: None,
            deactivated: false,
            updated: None,
        };
        let json = serde_json::to_string(&meta).expect("serde_json serialize");
        assert!(
            json.contains(r#""versionId":"5""#),
            "expected ASCII string `\"5\"`, got: {json}"
        );
        let jcs = serde_jcs::to_string(&meta).expect("serde_jcs serialize");
        assert!(
            jcs.contains(r#""versionId":"5""#),
            "expected ASCII string `\"5\"`, got: {jcs}"
        );

        // Round-trip back to NonZeroU64
        let decoded: super::DocumentMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.version_id.get(), 5);

        // Negative check: a malformed JSON with version_id as number must fail to deserialize.
        let bad = r#"{"versionId":5,"deactivated":false}"#;
        let result: Result<super::DocumentMetadata, _> = serde_json::from_str(bad);
        assert!(
            result.is_err(),
            "expected deserialization failure for numeric versionId, got: {result:?}"
        );
    }

    /// A deterministically-generated key-based document exposes its three
    /// default singleton beacons via the read-only public accessors
    /// (`Document::beacons()` + `Beacon::id()`/`beacon_type()`/`address()`)
    /// without any caller reaching into `pub(crate)` internals.
    #[test]
    fn beacons_accessor() {
        use crate::beacon::BeaconType;

        let (did, _vm_id, _initial, document) = source_documents();
        let network = did.components().network();

        // `beacons()` borrows the document — it must not consume or clone it.
        let beacons: Vec<&crate::beacon::Beacon> = document.beacons().collect();
        assert_eq!(
            beacons.len(),
            3,
            "generate_beacons emits exactly the 3 default singletons"
        );

        // The document is still usable after iterating — proving `beacons()`
        // is a borrow, not a move.
        let _still_borrowable = document.beacons().count();

        let suffixes = ["initialP2PKH", "initialP2WPKH", "initialP2TR"];
        for (beacon, suffix) in beacons.iter().zip(suffixes) {
            assert!(!beacon.id().is_empty(), "beacon id must be non-empty");
            assert!(
                beacon.id().ends_with(suffix),
                "beacon id {:?} must end with {suffix}",
                beacon.id()
            );
            assert_eq!(
                beacon.beacon_type(),
                BeaconType::Singleton,
                "default beacons are Singletons"
            );

            // The address borrowed out re-parses as a valid Bitcoin address
            // for the DID's network (round-trip through its string form).
            let addr_str = beacon.address().to_string();
            assert!(!addr_str.is_empty(), "beacon address renders non-empty");
            let reparsed = addr_str
                .parse::<esploda::bitcoin::Address<_>>()
                .expect("beacon address string is a valid Bitcoin address")
                .require_network(
                    network
                        .try_into()
                        .expect("DID network maps to a bitcoin network"),
                );
            assert!(
                reparsed.is_ok(),
                "beacon address must be valid for the DID's network: {addr_str}"
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Signed-update construction (Document::construct_signed_update).
    //
    // These cover: the round-trip through apply_update (the keystone), the
    // three pre-sign guards + id-immutability rejection, the Data Integrity
    // Config shape, the proofValue encoding, no-self-mutation, a wrong version
    // failing the resolver dedup, and a pinned deterministic golden vector.
    //
    // Source spec lines are cited inline (e.g. update.md:86) rather than the
    // project's internal requirement ids.
    // ──────────────────────────────────────────────────────────────────────

    use crate::key::SecretKey;
    use crate::update::UPDATE_CONTEXT;
    use secp256k1::Secp256k1;

    /// Fixed secret key for the construction tests. Any fixed valid secp256k1
    /// key works; `[7u8; 32]` is chosen for reproducibility (its public key
    /// derives the source DID below, so the key-match guard's happy path and
    /// the round-trip both have a key that matches the document's method).
    const SOURCE_SECRET_KEY_BYTES: [u8; 32] = [7u8; 32];

    fn source_secret_key() -> SecretKey {
        SecretKey::try_from(SOURCE_SECRET_KEY_BYTES)
            .expect("[7u8; 32] is a valid secp256k1 secret key")
    }

    /// The same key material as [`source_secret_key`] but as the raw
    /// `secp256k1::SecretKey` the Bitcoin beacon-signing path
    /// (`sign_and_finalize_for_test`) expects — that path signs the on-chain
    /// transaction and is deliberately NOT the crate-owned newtype.
    fn source_beacon_secret_key() -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&SOURCE_SECRET_KEY_BYTES)
            .expect("[7u8; 32] is a valid secp256k1 secret key")
    }

    /// Build a key-based source DID whose single verificationMethod public key
    /// is derived from `SOURCE_SECRET_KEY_BYTES`, then deterministically
    /// generate its initial DID document. Returns the DID, the verification
    /// method id, the `InitialDocument` (the apply_update target), and the
    /// equivalent `Document` (the construct_signed_update receiver). Both wrap
    /// the same JSON and hash identically.
    fn source_documents() -> (Did, String, InitialDocument, Document) {
        let secp = Secp256k1::new();
        let public_key = source_secret_key().as_inner().public_key(&secp);
        let id_type = IdType::from(public_key);
        let did: Did = DidComponents::new(DidVersion::One, Network::Mutinynet, id_type)
            .expect("mutinynet is a valid network")
            .try_into()
            .expect("default version + mutinynet + key id type encode to a valid did");

        let resolution_options = ResolutionOptions::default();
        let initial = InitialDocument::from_did(&did, &resolution_options)
            .expect("key-based DID deterministically generates its initial document");
        let document = Document::from(initial.clone());

        let vm_id = format!("{}#initialKey", did.encode());
        (did, vm_id, initial, document)
    }

    /// A benign patch that keeps the document conformant and does not touch
    /// `id`: it appends the existing verification-method id to `assertionMethod`
    /// (a list of verification-method ids). It leaves capabilityInvocation and
    /// service non-empty, so the patched document still parses.
    fn benign_patch(vm_id: &str) -> Patch {
        serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/assertionMethod/-", "value": vm_id}
        ]))
        .expect("benign patch is a valid RFC 6902 op array")
    }

    /// KEYSTONE: a produced signed update applied to the prior document returns
    /// Ok and the applied document's hash equals the constructed targetHash.
    /// The produced update carries the pinned `@context` on both the update
    /// and its proof, which is what lets `apply_update`'s context check pass.
    ///
    /// Spec: did-btcr2/src/operations/update.md (Construct Signed Update) +
    /// the verify path the resolver runs in apply_update.
    #[test]
    fn construct_signed_update_round_trips() {
        let (_did, vm_id, initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("a valid (patch, version, vm_id, key) must produce a signed update");
        assert_eq!(
            update.as_ref()["@context"],
            serde_json::json!(UPDATE_CONTEXT)
        );
        assert_eq!(
            update.as_ref()["proof"]["@context"],
            serde_json::json!(UPDATE_CONTEXT)
        );

        let mut applied = initial.clone();
        applied
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect("the produced update must apply cleanly to the prior document");
        assert_eq!(
            applied.hash(),
            update.target_hash,
            "the applied document hash must equal the constructed targetHash"
        );
    }

    /// `Document::deactivate` produces a signed update
    /// whose patch is exactly `[{"op":"add","path":"/deactivated","value":true}]`,
    /// whose proof verifies, and which applies to the source document producing a
    /// target with `deactivated == true`. Mirrors `construct_signed_update_round_trips`.
    ///
    /// Spec: did-btcr2/src/operations/deactivate.md (the deactivate JSON Patch) +
    /// the verify/apply path the resolver runs in apply_update.
    #[test]
    fn deactivate_update_round_trip() {
        let (_did, vm_id, initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let update = document
            .deactivate(&vm_id, source_secret_key(), version)
            .expect("a valid (vm_id, key, version) must produce a signed deactivate update");

        // The patch is exactly the one-op add /deactivated true.
        let expected_patch: Patch = serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/deactivated", "value": true}
        ]))
        .expect("the expected deactivate patch is valid RFC-6902");
        assert_eq!(
            update.patch, expected_patch,
            "deactivate must carry the one-op add /deactivated true patch"
        );

        // Round-trip: applying the produced update yields a deactivated target
        // whose hash matches the constructed targetHash.
        let mut applied = initial.clone();
        applied
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect("the produced deactivate update must apply cleanly to the prior document");
        assert!(
            applied.fields.deactivated,
            "applying the deactivate update must set deactivated == true"
        );
        assert_eq!(
            applied.hash(),
            update.target_hash,
            "the applied document hash must equal the constructed targetHash"
        );
    }

    /// Criterion 3a (deactivate-path twin of `construct_rejects_deactivated_document`):
    /// calling `Document::deactivate` on an already-deactivated document returns
    /// `Btcr2Error::InvalidDidUpdate` whose message mentions "deactivated" BEFORE
    /// any signing — the construct-time Guard 0 is inherited for free (the
    /// typed error originates at construct time, not the resolver).
    ///
    /// Spec: did-btcr2/src/operations/deactivate.md.
    #[test]
    fn deactivate_then_construct_rejected() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        json.as_object_mut()
            .expect("document_json builds an object")
            .insert("deactivated".to_string(), serde_json::json!(true));
        let document =
            Document::from_json_value(json).expect("a deactivated document is still conformant");

        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let err = document
            .deactivate(&vm_id, source_secret_key(), version)
            .expect_err("a deactivated document must not produce a deactivate update");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("deactivated"),
                "expected a deactivated-document message, got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Round-trip + integration tests.
    //
    // These prove the announce primitive feeds the resolver's signal
    // extraction end-to-end, and that a create -> update -> deactivate ->
    // re-resolve flow terminates with deactivated == true.
    // ──────────────────────────────────────────────────────────────────────

    /// Test bridge: turn a [`SignedBeaconTx`] into an
    /// `esploda::esplora::Transaction` with a synthetic `Status::Confirmed`.
    ///
    /// The resolver reads only the LAST output's `script_pubkey`, the `status`,
    /// and the `txid`, so only those carry real data. The esplora `value`/`fee`
    /// fields are BTC `Decimal` in memory but sats-on-the-wire (serde adapters
    /// convert at the JSON boundary), so we build the whole struct via JSON and
    /// `serde_json::from_value` rather than stuffing sats into a Decimal field
    fn bridge_to_esplora(
        signed: &crate::beacon::SignedBeaconTx,
        block_height: u32,
        block_time: i64,
    ) -> esploda::esplora::Transaction {
        let tx = signed.as_tx();
        let txid = tx.txid();
        let vout: Vec<serde_json::Value> = tx
            .output
            .iter()
            .map(|o| {
                serde_json::json!({
                    "scriptpubkey": o.script_pubkey.to_hex_string(),
                    "value": o.value,
                })
            })
            .collect();
        let json = serde_json::json!({
            "txid": txid.to_string(),
            "version": tx.version,
            "locktime": 0,
            "vin": [],
            "vout": vout,
            "size": 0,
            "weight": 0,
            "fee": 0,
            "status": {
                "confirmed": true,
                "block_height": block_height,
                // A synthetic, structurally-valid block hash (all-zero is a valid
                // 32-byte BlockHash for the resolver, which never inspects it).
                "block_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "block_time": block_time,
            },
        });
        serde_json::from_value(json).expect("the bridged esplora transaction JSON deserializes")
    }

    /// The first default beacon (in `generate_beacons` order) whose descriptor
    /// matches `pred`, returned as a `(beacon_address, prevout)` pair. The
    /// prevout is funded at `value` sats from a synthetic outpoint and locked to
    /// the beacon's own scriptPubKey — for a key-based DID the beacon address
    /// derives from the DID key, so the DID secret key spends it.
    fn beacon_prevout(
        initial: &InitialDocument,
        pred: impl Fn(&Address) -> bool,
        value: u64,
    ) -> (Address, crate::beacon::Prevout) {
        use esploda::bitcoin::{OutPoint, Txid, hashes::Hash};
        let beacon = initial
            .fields
            .service
            .iter()
            .find(|b| pred(&b.descriptor))
            .expect("a default beacon of the requested address type exists");
        let address = beacon.descriptor.clone();
        let script_pubkey = address.script_pubkey();
        let prevout = crate::beacon::Prevout {
            // A synthetic funding outpoint; the sans-I/O signer does not check it
            // exists on-chain (UTXO existence is the caller's I/O concern).
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            value,
            script_pubkey,
        };
        (address, prevout)
    }

    /// Criterion 2: a produced beacon transaction round-trips through the
    /// resolver. We build a signed update, announce it as a Singleton-beacon tx,
    /// bridge that tx to a confirmed `esplora::Transaction`, feed it through the
    /// public resolver FSM, and assert the resolver applies the update (resolving
    /// to the UPDATED document, not the genesis one).
    ///
    /// SELF-REFERENTIAL INTEROP CAVEAT: both the produced OP_RETURN push and the
    /// sidecar `update_lookup_table` key derive from the SAME `Update::hash()`,
    /// so this proves INTERNAL consistency of the JSON-Document-Hash plumbing —
    /// it does NOT exercise any foreign/external test vector and therefore does
    /// NOT prove cross-implementation interop of the "JSON Document Hash"
    /// definition.
    #[test]
    fn announce_round_trip() {
        use crate::resolver::{Resolver, ResolverState};
        use std::collections::HashMap;

        let (did, vm_id, initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        // Build a real signed update against the genesis document.
        let patch = benign_patch(&vm_id);
        let update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("a valid signed update is produced against the genesis document");

        // Announce it from the P2WPKH default beacon (its key is the DID key).
        let (beacon_address, prevout) =
            beacon_prevout(&initial, |a| a.script_pubkey().is_v0_p2wpkh(), 10_000);
        let unsigned = update
            .build_unsigned(&beacon_address, &[prevout], 1_000, &beacon_address)
            .expect("build_unsigned");
        let signed =
            crate::test_signing::sign_and_finalize_for_test(&unsigned, &source_beacon_secret_key())
                .expect("sign produces a signed beacon tx");

        // The OP_RETURN signal bytes equal the update hash (the sidecar key).
        let bridged = bridge_to_esplora(&signed, 100, 1_700_000_000);

        // Sidecar holds the update; its lookup table is keyed by update.hash().
        let sidecar = SidecarData::new(None, vec![update.clone()], None, None);
        let resolution_options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            esplora_url: Some("http://esplora.test/api".into()),
            chain_tip_height: Some(1_000),
            ..Default::default()
        };
        let resolver =
            Resolver::new(initial.clone(), resolution_options).expect("the options are valid");

        // Drive the FSM: Init -> feed the bridged tx as the history of a
        // declared beacon -> resolve. Which genesis beacon is immaterial here;
        // the bridged tx is served under the first one requested.
        let ResolverState::Requests(next_state, requests) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        let transactions = crate::resolver::history_under_first_request(&requests, vec![bridged]);
        let fsm = next_state.process_responses(transactions);

        // The resolver may need additional empty-signal steps to terminate.
        let mut state = fsm
            .resolve()
            .expect("processing the beacon signal resolves a step");
        let result = loop {
            match state {
                ResolverState::Resolved(result) => break result,
                ResolverState::Requests(next, _requests) => {
                    state = next
                        .process_responses(HashMap::new())
                        .resolve()
                        .expect("empty-signal step resolves");
                }
                ResolverState::BlockRequests(..) => {
                    panic!("unexpected block request: no update in this test carries proof.expires")
                }
            }
        };

        // The update was applied: the resolved document is the UPDATED one
        // (version 2), not the genesis (version 1). (Resolving to the genesis
        // doc is the warning sign.)
        assert_eq!(result.document.fields.id.encode(), did.encode());
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            2,
            "the produced beacon tx must drive the resolver to the updated document"
        );
    }

    /// True DUPLICATE beacon signals (already-applied updates announced twice)
    /// must NOT raise a false LATE_PUBLISHING — the resolver must still resolve
    /// to the latest updated document. Regression for the spurious DOCUMENT-hash
    /// push in the duplicate-update branch (resolver step 10.1): pushing the
    /// contemporary document hash before `confirm_duplicate` grows the update-hash
    /// history out from under `confirm_duplicate`, which indexes it at
    /// `[targetVersionId - 2]`. A duplicate of an EARLIER version shifts a later
    /// version's index onto the spurious document hash, so the later duplicate's
    /// in-range comparison mismatches and raises a false late-publishing.
    ///
    /// Drive: two real updates (v2 then v3), each announced and delivered on the
    /// beacon TWICE in a single batch. With the bug, the v2 duplicate's spurious
    /// push displaces the v3 entry so the v3 duplicate reads a document hash and
    /// errors; without it, both duplicates confirm-as-duplicate and resolution
    /// reaches version 3.
    #[test]
    fn duplicate_signals_do_not_raise_false_late_publishing() {
        use crate::resolver::{Resolver, ResolverState};
        use std::collections::HashMap;

        let (did, vm_id, genesis, genesis_doc) = source_documents();

        // Update #1 (v2) against the genesis document.
        let v2 = NonZeroU64::new(2).expect("2 is non-zero");
        let update1 = genesis_doc
            .construct_signed_update(benign_patch(&vm_id), v2, &vm_id, source_secret_key())
            .expect("update #1 constructs against the genesis document");

        // Apply #1 to get the contemporary document for update #2.
        let mut after_update1 = genesis.clone();
        after_update1
            .apply_update(&update1, &AnnouncingBlock::fixed())
            .expect("update #1 applies to the genesis document");
        let doc_after_update1 = Document::from(after_update1);

        // Update #2 (v3) against the post-update-1 document (another benign patch).
        let v3 = NonZeroU64::new(3).expect("3 is non-zero");
        let update2 = doc_after_update1
            .construct_signed_update(benign_patch(&vm_id), v3, &vm_id, source_secret_key())
            .expect("update #2 constructs against the post-update-1 document");

        // Announce both from the P2WPKH default beacon and bridge each twice
        // (the duplicate confirmation carries the identical update / signal hash).
        let (beacon_address, prevout1) =
            beacon_prevout(&genesis, |a| a.script_pubkey().is_v0_p2wpkh(), 10_000);
        let unsigned1 = update1
            .build_unsigned(&beacon_address, &[prevout1], 1_000, &beacon_address)
            .expect("build_unsigned update #1");
        let signed1 = crate::test_signing::sign_and_finalize_for_test(
            &unsigned1,
            &source_beacon_secret_key(),
        )
        .expect("announce update #1");
        let (_addr2, prevout2) =
            beacon_prevout(&genesis, |a| a.script_pubkey().is_v0_p2wpkh(), 10_000);
        let unsigned2 = update2
            .build_unsigned(&beacon_address, &[prevout2], 1_000, &beacon_address)
            .expect("build_unsigned update #2");
        let signed2 = crate::test_signing::sign_and_finalize_for_test(
            &unsigned2,
            &source_beacon_secret_key(),
        )
        .expect("announce update #2");
        let b1 = bridge_to_esplora(&signed1, 100, 1_700_000_000);
        let b1_dup = bridge_to_esplora(&signed1, 100, 1_700_000_000);
        let b2 = bridge_to_esplora(&signed2, 101, 1_700_000_100);
        let b2_dup = bridge_to_esplora(&signed2, 101, 1_700_000_100);

        let sidecar = SidecarData::new(None, vec![update1.clone(), update2.clone()], None, None);
        let resolution_options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            esplora_url: Some("http://esplora.test/api".into()),
            chain_tip_height: Some(1_000),
            ..Default::default()
        };
        let resolver =
            Resolver::new(genesis.clone(), resolution_options).expect("the options are valid");

        let ResolverState::Requests(next_state, requests) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        // Each update arrives TWICE on the first genesis beacon: the dups must
        // not trip a false late-publishing.
        let transactions =
            crate::resolver::history_under_first_request(&requests, vec![b1, b1_dup, b2, b2_dup]);
        let fsm = next_state.process_responses(transactions);

        let mut state = fsm.resolve().expect(
            "processing the duplicate beacon signals resolves a step without late-publishing",
        );
        let result = loop {
            match state {
                ResolverState::Resolved(result) => break result,
                ResolverState::Requests(next, _requests) => {
                    state = next
                        .process_responses(HashMap::new())
                        .resolve()
                        .expect("empty-signal step resolves without a false late-publishing");
                }
                ResolverState::BlockRequests(..) => {
                    panic!("unexpected block request: no update in this test carries proof.expires")
                }
            }
        };

        // The duplicate signals did not derail resolution: it reached version 3.
        assert_eq!(result.document.fields.id.encode(), did.encode());
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            3,
            "duplicate beacon signals must not derail resolution to a false LATE_PUBLISHING"
        );
    }

    /// Criterion 4: create a key-based DID, apply one update and then a
    /// deactivate update, and re-resolve — the terminal state has
    /// `deactivated == true` and `version_id == 3` (genesis 1 -> update 2 ->
    /// deactivate 3), with the FSM short-circuiting on deactivation (
    /// no signal past the deactivation mutates the document).
    #[test]
    fn create_update_deactivate_reresolve() {
        use crate::resolver::{Resolver, ResolverState};
        use std::collections::HashMap;

        // Create: key-based DID -> deterministic genesis document.
        let (_did, vm_id, genesis, genesis_doc) = source_documents();

        // Update #1: a benign patch targeting version 2, constructed against the
        // genesis document (so source_hash == genesis.hash()).
        let v2 = NonZeroU64::new(2).expect("2 is non-zero");
        let update1 = genesis_doc
            .construct_signed_update(benign_patch(&vm_id), v2, &vm_id, source_secret_key())
            .expect("update #1 constructs against the genesis document");

        // Apply update #1 to obtain the contemporary document for update #2.
        let mut after_update1 = genesis.clone();
        after_update1
            .apply_update(&update1, &AnnouncingBlock::fixed())
            .expect("update #1 applies to the genesis document");
        let doc_after_update1 = Document::from(after_update1);

        // Deactivate update: targets version 3, constructed against the
        // post-update-1 document (so source_hash == doc_after_update1.hash()).
        let v3 = NonZeroU64::new(3).expect("3 is non-zero");
        let deactivate = doc_after_update1
            .deactivate(&vm_id, source_secret_key(), v3)
            .expect("the deactivate update constructs against the post-update-1 document");

        // Announce both updates from the P2WPKH default beacon and bridge each to
        // a confirmed esplora tx.
        let (beacon_address, prevout1) =
            beacon_prevout(&genesis, |a| a.script_pubkey().is_v0_p2wpkh(), 10_000);
        let unsigned1 = update1
            .build_unsigned(&beacon_address, &[prevout1], 1_000, &beacon_address)
            .expect("build_unsigned update #1");
        let signed1 = crate::test_signing::sign_and_finalize_for_test(
            &unsigned1,
            &source_beacon_secret_key(),
        )
        .expect("announce update #1");
        let (_addr2, prevout2) =
            beacon_prevout(&genesis, |a| a.script_pubkey().is_v0_p2wpkh(), 10_000);
        let unsigned2 = deactivate
            .build_unsigned(&beacon_address, &[prevout2], 1_000, &beacon_address)
            .expect("build_unsigned the deactivate update");
        let signed2 = crate::test_signing::sign_and_finalize_for_test(
            &unsigned2,
            &source_beacon_secret_key(),
        )
        .expect("announce the deactivate update");
        let bridged1 = bridge_to_esplora(&signed1, 100, 1_700_000_000);
        let bridged2 = bridge_to_esplora(&signed2, 101, 1_700_000_100);

        // Sidecar carries both updates (keyed by hash()); re-resolve from genesis.
        let sidecar = SidecarData::new(None, vec![update1.clone(), deactivate.clone()], None, None);
        let resolution_options = ResolutionOptions {
            sidecar_data: Some(sidecar),
            esplora_url: Some("http://esplora.test/api".into()),
            chain_tip_height: Some(1_000),
            ..Default::default()
        };
        let resolver =
            Resolver::new(genesis.clone(), resolution_options).expect("the options are valid");

        let ResolverState::Requests(next_state, requests) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        let transactions =
            crate::resolver::history_under_first_request(&requests, vec![bridged1, bridged2]);
        let fsm = next_state.process_responses(transactions);

        let mut state = fsm
            .resolve()
            .expect("processing the beacon signals resolves a step");
        let result = loop {
            match state {
                ResolverState::Resolved(result) => break result,
                ResolverState::Requests(next, _requests) => {
                    state = next
                        .process_responses(HashMap::new())
                        .resolve()
                        .expect("empty-signal step resolves");
                }
                ResolverState::BlockRequests(..) => {
                    panic!("unexpected block request: no update in this test carries proof.expires")
                }
            }
        };

        // Terminal state: deactivated, version 3 (1 -> 2 -> 3), FSM short-circuit
        // (no signal past the deactivation mutates the document).
        assert!(
            result.document_metadata.deactivated,
            "the re-resolved document must be deactivated"
        );
        assert_eq!(
            u64::from(result.document_metadata.version_id),
            3,
            "genesis 1 -> update 2 -> deactivate 3"
        );
        assert!(
            result.document.fields.deactivated,
            "the resolved document itself carries deactivated == true"
        );
    }

    /// update.md — a vm_id that no capabilityInvocation entry identifies (and
    /// that names no verification method at all) is rejected before any
    /// signing.
    #[test]
    fn update_rejects_unknown_vm() {
        let (did, _vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&format!("{}#initialKey", did.encode()));
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let unknown = format!("{}#does-not-exist", did.encode());
        let err = document
            .construct_signed_update(patch, version, &unknown, source_secret_key())
            .expect_err("an unknown verificationMethod id must be rejected");
        assert!(matches!(err, Btcr2Error::InvalidDidUpdate(_)));
    }

    /// update.md — an `INVALID_DID_UPDATE` error MUST be raised if the JSON
    /// Patch fails to apply. RFC 6902 evaluates operations in order and a
    /// failed `test` operation fails the whole patch; a `remove` of a missing
    /// path fails the same way. Neither produces an update.
    #[test]
    fn construct_signed_update_rejects_failing_patch() {
        let (_did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let failing_test: Patch = serde_json::from_value(serde_json::json!([
            {"op": "test", "path": "/id", "value": "did:btcr2:not-this-document"},
            {"op": "add", "path": "/service/-", "value": {
                "id": "#extra", "type": "SingletonBeacon",
                "serviceEndpoint": "bitcoin:tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
            }}
        ]))
        .expect("a failing `test` op is a well-formed RFC 6902 patch");
        let err = document
            .construct_signed_update(failing_test, version, &vm_id, source_secret_key())
            .expect_err("a patch whose `test` op fails must be rejected");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref m) if m.contains("JSON Patch")),
            "got {err:?}"
        );

        let missing_path: Patch = serde_json::from_value(serde_json::json!([
            {"op": "remove", "path": "/service/99"}
        ]))
        .expect("a remove of a missing path is a well-formed RFC 6902 patch");
        let err = document
            .construct_signed_update(missing_path, version, &vm_id, source_secret_key())
            .expect_err("a patch that removes a missing path must be rejected");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref m) if m.contains("JSON Patch")),
            "got {err:?}"
        );
    }

    /// resolve.md:245 — apply_update MUST reject an update whose proof
    /// verificationMethod is NOT a member of the document's capabilityInvocation
    /// set (an update signed by a key the document never authorized to invoke its
    /// root capability). The same membership rule the construction side enforces
    /// is enforced on the resolve path via a shared helper, mapped to the
    /// spec-literal INVALID_DID_UPDATE (`Btcr2Error::InvalidDidUpdate`).
    #[test]
    fn apply_update_rejects_vm_not_in_capability_invocation() {
        let (did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        // A valid signed update against the conformant genesis document (its
        // capabilityInvocation DOES contain vm_id, so construction succeeds).
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("a valid signed update is produced");

        // Build the apply target: same id and same verificationMethod (so the
        // proof's VM resolves to a public key and the signature still verifies),
        // but capabilityInvocation references a DIFFERENT method id — so the
        // proof's VM is NOT an authorized invoker.
        let secp = Secp256k1::new();
        let other_key = SecretKey::generate().as_inner().public_key(&secp);
        let other_vm_id = format!("{}#otherKey", did.encode());
        let mut json = document_json(&did, &vm_id);
        json["verificationMethod"]
            .as_array_mut()
            .expect("verificationMethod is an array")
            .push(serde_json::json!({
                "id": other_vm_id,
                "type": "Multikey",
                "controller": did.encode(),
                "publicKeyMultibase": other_key.to_multikey(),
            }));
        json["capabilityInvocation"] = serde_json::json!([other_vm_id]);
        json["capabilityDelegation"] = serde_json::json!([other_vm_id]);

        let mut target = InitialDocument::from_json_value(json)
            .expect("the apply target is a conformant document");
        let err = target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("a proof VM absent from capabilityInvocation must be rejected on apply");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("capabilityInvocation"),
                "rejection must be the capabilityInvocation-membership check, not an \
                 incidental hash/parse failure; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// Signs an update over `patch` with the genesis key, bypassing the
    /// construction primitive (which refuses an id-changing patch), so the
    /// resolve-path checks can be exercised against it. The caller supplies
    /// `target_hash` because a re-identified document may not parse.
    fn sign_update_by_hand(
        initial: &InitialDocument,
        vm_id: &str,
        patch: &Patch,
        target_hash: Sha256Hash,
    ) -> Update {
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let unsigned = UnsecuredUpdate::construct(patch, initial.hash(), target_hash, version);

        let capability = derive_root_capability(initial.fields.id.clone());
        let inner = ProofInner {
            id: None,
            proof_type: ProofType::DataIntegrityProof,
            proof_purpose: ProofPurpose::CapabilityInvocation,
            verification_method: vm_id.to_string(),
            cryptosuite: CryptoSuiteName::Jcs,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            previous_proof: None,
            nonce: None,
            context: vec![],
            capability,
            capability_action: "Write".to_string(),
            invocation_target: None,
        };
        let proof = CryptoSuite
            .create_proof(&unsigned, inner, &source_secret_key())
            .expect("the hand-built update signs");
        let mut signed_json = unsigned.as_ref().clone();
        if let Value::Object(map) = &mut signed_json {
            map.insert(
                "proof".to_string(),
                serde_json::to_value(&proof).expect("proof serializes"),
            );
        }
        Update::from_json_value(signed_json).expect("the hand-signed update parses")
    }

    /// Extracts the detail of an `InvalidDidUpdate`, failing on any other variant.
    fn invalid_did_update_detail(err: Btcr2Error) -> String {
        match err {
            Btcr2Error::InvalidDidUpdate(detail) => detail,
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// resolve.md:222 — apply_update MUST reject an update whose patch changes the
    /// document `id` (a post-patch `id != did`): a patch cannot re-point the
    /// document identity. Mapped to the spec-literal INVALID_DID_UPDATE
    /// (`Btcr2Error::InvalidDidUpdate`).
    ///
    /// The update is signed by hand against the genesis VM; its targetHash is
    /// the hash of the re-identified document, so the id check is the gate. A
    /// rejected update leaves the document untouched.
    #[test]
    fn apply_update_rejects_post_patch_id_change() {
        let (did, vm_id, initial, _document) = source_documents();

        // A DIFFERENT, valid key-based DID string to re-point `id` at.
        let secp = Secp256k1::new();
        let other_public_key = SecretKey::try_from([5u8; 32])
            .expect("[5u8; 32] is a valid secp256k1 secret key")
            .as_inner()
            .public_key(&secp);
        let other_did: Did = DidComponents::new(
            DidVersion::One,
            Network::Mutinynet,
            IdType::from(other_public_key),
        )
        .expect("mutinynet is a valid network")
        .try_into()
        .expect("a second key-based did encodes");
        assert_ne!(other_did.encode(), did.encode());

        // An id-changing patch (replaces the document id). The vm/controller ids
        // are left referencing the ORIGINAL did so the document still parses.
        let id_change_patch: Patch = serde_json::from_value(serde_json::json!([
            {"op": "replace", "path": "/id", "value": other_did.encode()}
        ]))
        .expect("id-change patch is a valid RFC 6902 op array");

        let mut target_value = initial.as_ref().clone();
        json_patch::patch(&mut target_value, &id_change_patch)
            .expect("the id-change patch applies to the genesis json");
        let target_hash = Document::from_json_value(target_value)
            .expect("the re-identified document still parses as conformant")
            .hash();
        let update = sign_update_by_hand(&initial, &vm_id, &id_change_patch, target_hash);

        let mut target = initial.clone();
        let before = target.hash();
        let err = target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("a patch that changes the document id must be rejected on apply");
        let detail = invalid_did_update_detail(err);
        assert!(
            detail.contains("may not change the DID document id"),
            "unexpected detail: {detail}"
        );
        assert_eq!(target.hash(), before, "a rejected update must not mutate");
    }

    /// resolve.md:222 — an id rewritten to a DID-Core-valid but non-bech32
    /// did:btcr2 string is reported as the id change it is, not as an encoding
    /// error from parsing the new id.
    #[test]
    fn apply_update_reports_an_id_change_to_a_non_btcr2_id_as_an_id_change() {
        let (_did, vm_id, initial, _document) = source_documents();
        let id_change_patch: Patch = serde_json::from_value(serde_json::json!([
            {"op": "replace", "path": "/id", "value": "did:btcr2:k1qexample"}
        ]))
        .expect("id-change patch is a valid RFC 6902 op array");

        // The re-identified document does not parse, so there is no real target
        // hash; the id check runs before the target-hash check, so any hash will do.
        let update = sign_update_by_hand(&initial, &vm_id, &id_change_patch, initial.hash());

        let mut target = initial.clone();
        let before = target.hash();
        let err = target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("a patch that changes the document id must be rejected on apply");
        let detail = invalid_did_update_detail(err);
        assert!(
            detail.contains("may not change the DID document id"),
            "unexpected detail: {detail}"
        );
        assert!(!detail.contains("Bech32"), "unexpected detail: {detail}");
        assert!(
            !detail.contains("non-conformant"),
            "unexpected detail: {detail}"
        );
        assert_eq!(target.hash(), before, "a rejected update must not mutate");
    }

    /// update.md:86 — a vm_id present in verificationMethod but absent from
    /// capabilityInvocation is rejected before signing.
    #[test]
    fn update_rejects_vm_not_in_capability_invocation() {
        let (did, vm_id, _initial, _document) = source_documents();

        // Build a document whose method id is in verificationMethod but NOT in
        // capabilityInvocation (capabilityInvocation references a different,
        // still-present method id so the document stays conformant). The patch
        // and key are valid for `vm_id`; only the capabilityInvocation
        // membership fails.
        let secp = Secp256k1::new();
        let other_key = SecretKey::generate().as_inner().public_key(&secp);
        let other_vm_id = format!("{}#otherKey", did.encode());

        let mut json = document_json(&did, &vm_id);
        json["verificationMethod"]
            .as_array_mut()
            .expect("verificationMethod is an array")
            .push(serde_json::json!({
                "id": other_vm_id,
                "type": "Multikey",
                "controller": did.encode(),
                "publicKeyMultibase": other_key.to_multikey(),
            }));
        // capabilityInvocation references only the OTHER method id.
        json["capabilityInvocation"] = serde_json::json!([other_vm_id]);

        let document = Document::from_json_value(json).expect("document is conformant");
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let err = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect_err("a vm_id absent from capabilityInvocation must be rejected");
        assert!(matches!(err, Btcr2Error::InvalidDidUpdate(_)));
    }

    /// A verification method object carrying a freshly generated key, for
    /// embedding in a relationship array under `id`.
    fn embedded_method_json(did: &Did, id: &str) -> Value {
        let secp = Secp256k1::new();
        let key = SecretKey::generate().as_inner().public_key(&secp);
        serde_json::json!({
            "id": id,
            "type": "Multikey",
            "controller": did.encode(),
            "publicKeyMultibase": key.to_multikey(),
        })
    }

    /// The signing key's verification method object (the key
    /// `source_secret_key` derives), for embedding in `capabilityInvocation`
    /// so an update can be verified with no `verificationMethod` entry at all.
    fn embedded_source_method_json(did: &Did, id: &str) -> Value {
        let secp = Secp256k1::new();
        let key = source_secret_key().as_inner().public_key(&secp);
        serde_json::json!({
            "id": id,
            "type": "Multikey",
            "controller": did.encode(),
            "publicKeyMultibase": key.to_multikey(),
        })
    }

    const RELATIONSHIP_FIELDS: [&str; 4] = [
        "authentication",
        "assertionMethod",
        "capabilityInvocation",
        "capabilityDelegation",
    ];

    /// DID Core 1.1 §5.3.1 / data-structures.md: every relationship array
    /// accepts a mix of references and embedded verification method objects,
    /// and the parsed entries keep their shape and the embedded object's id.
    #[test]
    fn relationship_arrays_accept_embedded_objects() {
        let (did, vm_id, _initial, _document) = source_documents();
        let embedded_id = format!("{}#embedded", did.encode());
        let mut json = document_json(&did, &vm_id);
        for field in RELATIONSHIP_FIELDS {
            json[field] = serde_json::json!([vm_id, embedded_method_json(&did, &embedded_id)]);
        }

        let parsed = InitialDocument::from_json_value(json)
            .expect("a document with embedded relationship entries parses");
        let arrays: [&[VerificationRelationship]; 4] = [
            &parsed.fields.authentication,
            &parsed.fields.assertion_method,
            &parsed
                .fields
                .capability_invocation
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            &parsed.fields.capability_delegation,
        ];
        for (field, entries) in RELATIONSHIP_FIELDS.iter().zip(arrays) {
            assert_eq!(entries.len(), 2, "{field}");
            assert!(
                matches!(entries[0], VerificationRelationship::Reference(_)),
                "{field}[0]"
            );
            match &entries[1] {
                VerificationRelationship::Embedded(method) => {
                    assert_eq!(method.id.0, embedded_id, "{field}[1]");
                }
                other => panic!("{field}[1]: expected Embedded, got {other:?}"),
            }
        }
    }

    /// A relationship entry that is neither a string nor an object is a typed
    /// JSON error naming the field (no panic on odd JSON), for both a
    /// plain `Vec` array and the `NonEmpty` `capabilityInvocation` array.
    #[test]
    fn relationship_entry_rejects_non_string_non_object() {
        let (did, vm_id, _initial, _document) = source_documents();

        let mut json = document_json(&did, &vm_id);
        json["authentication"] = serde_json::json!([42]);
        let err = InitialDocument::from_json_value(json)
            .expect_err("a numeric relationship entry must be rejected");
        match err {
            Error::JsonValue(json_tools::JsonError::UnexpectedJsonType(
                field,
                json_tools::ExpectedType::StringOrObject,
            )) => assert_eq!(field, "authentication"),
            other => panic!("expected UnexpectedJsonType(_, StringOrObject), got {other:?}"),
        }

        let mut json = document_json(&did, &vm_id);
        json["capabilityInvocation"] = serde_json::json!([true]);
        let err = InitialDocument::from_json_value(json)
            .expect_err("a boolean relationship entry must be rejected");
        match err {
            Error::JsonValue(json_tools::JsonError::UnexpectedJsonType(
                field,
                json_tools::ExpectedType::StringOrObject,
            )) => assert_eq!(field, "capabilityInvocation"),
            other => panic!("expected UnexpectedJsonType(_, StringOrObject), got {other:?}"),
        }
    }

    /// resolve.md "Check update.proof": an embedded capabilityInvocation object
    /// whose `id` equals the proof's verificationMethod identifies it, and
    /// `publicKeyMultibase` is read from the object — no `verificationMethod`
    /// entry is needed. Round-trips through construct so the target hash
    /// matches.
    #[test]
    fn apply_update_accepts_embedded_capability_invocation() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        json["verificationMethod"] = serde_json::json!([]);
        json["capabilityInvocation"] =
            serde_json::json!([embedded_source_method_json(&did, &vm_id)]);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let document = Document::from_json_value(json.clone()).expect("document is conformant");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("construction against the embedded shape succeeds");

        let mut target =
            InitialDocument::from_json_value(json).expect("the apply target is conformant");
        target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect("an update identified by an embedded capabilityInvocation object applies");
        assert_eq!(target.hash(), update.target_hash);
    }

    /// update.md "Construct BTCR2 Signed Update": an embedded
    /// capabilityInvocation object identifies `verificationMethodId` and
    /// supplies the key the signer is checked against.
    #[test]
    fn construct_signed_update_accepts_embedded_capability_invocation() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        json["verificationMethod"] = serde_json::json!([]);
        json["capabilityInvocation"] =
            serde_json::json!([embedded_source_method_json(&did, &vm_id)]);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let document = Document::from_json_value(json).expect("document is conformant");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("an embedded capabilityInvocation object identifies the signing method");
        assert_eq!(update.proof.inner.verification_method, vm_id);
    }

    /// resolve.md "Check update.proof": a reference entry whose verification
    /// method does not exist is INVALID_DID_UPDATE — not the granular
    /// ProofVerification the resolve path used to raise.
    #[test]
    fn apply_update_rejects_reference_to_missing_verification_method() {
        let (did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("a valid signed update is produced");

        let mut json = document_json(&did, &vm_id);
        json["verificationMethod"] = serde_json::json!([]);
        json["capabilityInvocation"] = serde_json::json!([vm_id]);
        let mut target =
            InitialDocument::from_json_value(json).expect("the apply target is conformant");
        let err = target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("a dangling capabilityInvocation reference must be rejected on apply");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("not present in the document"),
                "rejection must be the dangling-reference check; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// update.md "Construct BTCR2 Signed Update": a reference entry whose
    /// verification method does not exist is INVALID_DID_UPDATE before signing.
    #[test]
    fn construct_signed_update_rejects_reference_to_missing_verification_method() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        json["verificationMethod"] = serde_json::json!([]);
        json["capabilityInvocation"] = serde_json::json!([vm_id]);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let document = Document::from_json_value(json).expect("document is conformant");
        let err = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect_err("a dangling capabilityInvocation reference must be rejected");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("not present in the document"),
                "rejection must be the dangling-reference check; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// data-structures.md: a relative DID URL in capabilityInvocation is
    /// resolved against the document id before comparison. The document's
    /// entry stays the relative `#initialKey` while the produced proof carries
    /// the absolute `<did>#initialKey`, so the resolve-side lookup matches an
    /// absolute proof id against a relative document entry, and the referenced
    /// verification method (absolute `<did>#initialKey`) supplies the key.
    #[test]
    fn apply_update_resolves_relative_did_url() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        json["capabilityInvocation"] = serde_json::json!(["#initialKey"]);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let document = Document::from_json_value(json.clone()).expect("document is conformant");
        let update = document
            .construct_signed_update(
                benign_patch(&vm_id),
                version,
                "#initialKey",
                source_secret_key(),
            )
            .expect("construction with a relative verificationMethod id succeeds");
        assert_eq!(
            update.proof.inner.verification_method,
            format!("{}#initialKey", did.encode())
        );

        let mut target =
            InitialDocument::from_json_value(json).expect("the apply target is conformant");
        target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect("an absolute proof verificationMethod matches a relative document entry");
        assert_eq!(target.hash(), update.target_hash);
    }

    /// update.md: the construction side applies the same relative-URL
    /// resolution — `#initialKey` on the call site matches the absolute
    /// `<did>#initialKey` reference the document carries — and the proof
    /// carries the absolutized id, never the caller's relative string, so a
    /// literal-comparing verifier identifies the same entry.
    #[test]
    fn construct_signed_update_resolves_relative_did_url() {
        let (did, vm_id, _initial, _document) = source_documents();
        let json = document_json(&did, &vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let document = Document::from_json_value(json).expect("document is conformant");
        let update = document
            .construct_signed_update(
                benign_patch(&vm_id),
                version,
                "#initialKey",
                source_secret_key(),
            )
            .expect("a relative verificationMethod id resolves against the document id");
        assert_eq!(
            update.proof.inner.verification_method,
            format!("{}#initialKey", did.encode())
        );
    }

    /// An embedded object identifies the proof only by its own `id`.
    /// An object under a different id does not identify `<did>#initialKey`
    /// even though its key material would verify, so the update is rejected
    /// by the capabilityInvocation lookup.
    #[test]
    fn apply_update_rejects_embedded_object_with_foreign_id() {
        let (did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("a valid signed update is produced");

        let other_id = format!("{}#other", did.encode());
        let mut json = document_json(&did, &vm_id);
        json["capabilityInvocation"] =
            serde_json::json!([embedded_source_method_json(&did, &other_id)]);
        let mut target =
            InitialDocument::from_json_value(json).expect("the apply target is conformant");
        let err = target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("an embedded object under a foreign id must not identify the proof");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("capabilityInvocation"),
                "rejection must be the capabilityInvocation lookup; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// An Ed25519 Multikey (prefix `0xed01`, 32-byte key): a valid DID Core
    /// verification method that is not a secp256k1 key.
    const ED25519_MULTIKEY: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    /// An embedded Ed25519 verification method with a `did:key` controller —
    /// the ordinary DIDComm `authentication` shape.
    fn ed25519_method_json(did: &Did) -> Value {
        serde_json::json!({
            "id": format!("{}#ed", did.encode()),
            "type": "Ed25519VerificationKey2020",
            "controller": format!("did:key:{ED25519_MULTIKEY}"),
            "publicKeyMultibase": ED25519_MULTIKEY,
        })
    }

    /// The same Ed25519 key and `did:key` controller as `ed25519_method_json`,
    /// declared with the Controlled Identifiers `Multikey` type: the shape a
    /// top-level `verificationMethod` entry carrying `publicKeyMultibase`
    /// must take.
    fn multikey_ed25519_method_json(did: &Did) -> Value {
        serde_json::json!({
            "id": format!("{}#ed", did.encode()),
            "type": "Multikey",
            "controller": format!("did:key:{ED25519_MULTIKEY}"),
            "publicKeyMultibase": ED25519_MULTIKEY,
        })
    }

    /// An embedded JWK verification method with no `publicKeyMultibase` at all
    /// and a foreign controller.
    fn jwk_method_json(did: &Did) -> Value {
        serde_json::json!({
            "id": format!("{}#jwk", did.encode()),
            "type": "JsonWebKey2020",
            "controller": "did:example:other",
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"},
        })
    }

    /// DID Core 1.1 §5.3.1: `authentication`, `assertionMethod` and
    /// `capabilityDelegation` may embed any verification method — an Ed25519
    /// key with a `did:key` controller, a JWK with no `publicKeyMultibase` —
    /// and the document still parses and resolves. The objects are retained
    /// by id and raw `publicKeyMultibase`; nothing about them is decoded
    /// because no proof invokes them.
    #[test]
    fn relationship_arrays_accept_foreign_embedded_methods() {
        let (did, vm_id, _initial, _document) = source_documents();
        let ed_id = format!("{}#ed", did.encode());
        let jwk_id = format!("{}#jwk", did.encode());
        let mut json = document_json(&did, &vm_id);
        for field in ["authentication", "assertionMethod", "capabilityDelegation"] {
            json[field] =
                serde_json::json!([vm_id, ed25519_method_json(&did), jwk_method_json(&did)]);
        }

        let parsed = InitialDocument::from_json_value(json.clone())
            .expect("a document with foreign embedded relationship entries parses");
        let arrays: [(&str, &[VerificationRelationship]); 3] = [
            ("authentication", &parsed.fields.authentication),
            ("assertionMethod", &parsed.fields.assertion_method),
            ("capabilityDelegation", &parsed.fields.capability_delegation),
        ];
        for (field, entries) in arrays {
            assert_eq!(entries.len(), 3, "{field}");
            assert!(
                matches!(entries[0], VerificationRelationship::Reference(_)),
                "{field}[0]"
            );
            assert_eq!(
                entries[1],
                VerificationRelationship::Embedded(EmbeddedVerificationMethod {
                    id: VerificationMethodId(ed_id.clone()),
                    public_key_multibase: Some(ED25519_MULTIKEY.to_string()),
                }),
                "{field}[1]"
            );
            assert_eq!(
                entries[2],
                VerificationRelationship::Embedded(EmbeddedVerificationMethod {
                    id: VerificationMethodId(jwk_id.clone()),
                    public_key_multibase: None,
                }),
                "{field}[2]"
            );
        }

        // The resolve path is unaffected: an update invoking the secp256k1
        // entry constructs and applies over the same document.
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let document = Document::from_json_value(json.clone()).expect("document is conformant");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("construction alongside foreign embedded methods succeeds");
        let mut target =
            InitialDocument::from_json_value(json).expect("the apply target is conformant");
        target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect("an update applies over a document carrying foreign embedded methods");
        assert_eq!(target.hash(), update.target_hash);
    }

    /// DID Core 1.1 §5.2: the top-level `verificationMethod` array may carry
    /// verification methods that are not secp256k1 keys — an Ed25519
    /// Multikey with a `did:key` controller, a JWK with no
    /// `publicKeyMultibase` and a foreign controller — referenced from
    /// `authentication` (the common DIDComm layout). The document parses
    /// with the entries retained verbatim, and
    /// an update invoking the secp256k1 entry constructs and applies over it:
    /// nothing about the foreign entries is decoded because no proof invokes
    /// them.
    #[test]
    fn verification_method_array_accepts_foreign_methods() {
        let (did, vm_id, _initial, _document) = source_documents();
        let ed_id = format!("{}#ed", did.encode());
        let jwk_id = format!("{}#jwk", did.encode());
        let mut json = document_json(&did, &vm_id);
        let secp256k1_entry = json["verificationMethod"][0].clone();
        json["verificationMethod"] = serde_json::json!([
            secp256k1_entry,
            multikey_ed25519_method_json(&did),
            jwk_method_json(&did)
        ]);
        json["authentication"] = serde_json::json!([vm_id, ed_id, jwk_id]);

        let parsed = InitialDocument::from_json_value(json.clone())
            .expect("a document with foreign top-level verification methods parses");
        let methods = &parsed.fields.verification_method;
        assert_eq!(methods.len(), 3);
        assert_eq!(
            methods[1],
            VerificationMethod {
                id: VerificationMethodId(ed_id.clone()),
                type_: "Multikey".to_string(),
                controller: format!("did:key:{ED25519_MULTIKEY}"),
                public_key_multibase: Some(ED25519_MULTIKEY.to_string()),
            }
        );
        assert_eq!(methods[2].id, VerificationMethodId(jwk_id.clone()));
        assert_eq!(methods[2].controller, "did:example:other");
        assert_eq!(methods[2].public_key_multibase, None);

        // The resolve path is unaffected: an update invoking the secp256k1
        // entry constructs and applies over the same document.
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let document = Document::from_json_value(json.clone()).expect("document is conformant");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("construction alongside foreign top-level methods succeeds");
        let mut target =
            InitialDocument::from_json_value(json).expect("the apply target is conformant");
        target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect("an update applies over a document carrying foreign top-level methods");
        assert_eq!(target.hash(), update.target_hash);
    }

    /// resolve.md "Check update.proof": when the `capabilityInvocation` entry
    /// is a reference, `publicKeyMultibase` is read from the
    /// `verificationMethod` entry with that `id` and handed to the BIP340
    /// cryptosuite, so it must decode as a secp256k1 Multikey. A top-level
    /// Ed25519 Multikey parses (the document is still a valid DID document)
    /// but is INVALID_DID_UPDATE the moment a proof names it as the invoker
    /// — on both the construct and the apply path — and so is a top-level
    /// method with no `publicKeyMultibase` at all.
    #[test]
    fn top_level_foreign_key_is_rejected_as_invoker() {
        let (did, vm_id, _initial, document) = source_documents();
        let ed_id = format!("{}#ed", did.encode());
        let jwk_id = format!("{}#jwk", did.encode());
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let mut json = document_json(&did, &vm_id);
        let secp256k1_entry = json["verificationMethod"][0].clone();
        json["verificationMethod"] = serde_json::json!([
            secp256k1_entry,
            multikey_ed25519_method_json(&did),
            jwk_method_json(&did)
        ]);
        json["capabilityInvocation"] = serde_json::json!([vm_id, ed_id, jwk_id]);
        let foreign =
            Document::from_json_value(json.clone()).expect("the document parses as a whole");

        // Construct path: the proof names the Ed25519 reference.
        let err = foreign
            .construct_signed_update(benign_patch(&vm_id), version, &ed_id, source_secret_key())
            .expect_err("an Ed25519 invoker must be rejected before signing");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("not a secp256k1 Multikey"),
                "rejection must be the invoker key decode; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }

        // Construct path: the proof names the keyless JWK reference.
        let err = foreign
            .construct_signed_update(benign_patch(&vm_id), version, &jwk_id, source_secret_key())
            .expect_err("a keyless invoker must be rejected before signing");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("has no publicKeyMultibase"),
                "rejection must be the missing-key check; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }

        // Apply path: a valid update whose proof is re-pointed at each
        // foreign entry, applied to a target that lists all three invokers.
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("a valid signed update is produced");
        for (invoker, expected) in [
            (&ed_id, "not a secp256k1 Multikey"),
            (&jwk_id, "has no publicKeyMultibase"),
        ] {
            let mut update_json = update.as_ref().clone();
            update_json["proof"]["verificationMethod"] = Value::String(invoker.clone());
            let repointed = Update::from_json_value(update_json)
                .expect("a verificationMethod swap still re-parses");
            let mut target = InitialDocument::from_json_value(json.clone())
                .expect("the apply target parses as a whole");
            let err = target
                .apply_update(&repointed, &AnnouncingBlock::fixed())
                .expect_err("a foreign invoker must be rejected on apply");
            match err {
                Btcr2Error::InvalidDidUpdate(msg) => assert!(
                    msg.contains(expected),
                    "rejection for {invoker} must be the invoker key decode; got: {msg}"
                ),
                other => panic!("expected InvalidDidUpdate for {invoker}, got {other:?}"),
            }
        }
    }

    /// An embedded relationship object with a missing or non-string `id`
    /// errors naming the array it sits in (`authentication.id`), so the
    /// failure is locatable in a document with several relationship arrays;
    /// a bare `id` would be indistinguishable from the document's own.
    #[test]
    fn relationship_entry_names_the_array_in_id_errors() {
        let (did, vm_id, _initial, _document) = source_documents();

        let mut json = document_json(&did, &vm_id);
        json["authentication"] =
            serde_json::json!([{"id": 42, "publicKeyMultibase": ED25519_MULTIKEY}]);
        match InitialDocument::from_json_value(json) {
            Err(Error::JsonValue(json_tools::JsonError::UnexpectedJsonType(field, expected))) => {
                assert_eq!(field, "authentication.id");
                assert!(matches!(expected, json_tools::ExpectedType::String));
            }
            other => panic!("expected UnexpectedJsonType(authentication.id), got {other:?}"),
        }

        let mut json = document_json(&did, &vm_id);
        json["assertionMethod"] = serde_json::json!([{"publicKeyMultibase": ED25519_MULTIKEY}]);
        match InitialDocument::from_json_value(json) {
            Err(Error::JsonValue(json_tools::JsonError::JsonMissingKey(key))) => {
                assert_eq!(key, "assertionMethod.id");
            }
            other => panic!("expected JsonMissingKey(assertionMethod.id), got {other:?}"),
        }
    }

    /// resolve.md "Check update.proof" reads `publicKeyMultibase` from the
    /// invoking entry and hands it to the BIP340 cryptosuite, so the invoking
    /// entry's key must decode as a secp256k1 Multikey. An embedded
    /// `capabilityInvocation` object of another key type parses (the document
    /// is still a valid DID document) but is INVALID_DID_UPDATE the moment a
    /// proof names it as the invoker — on both the construct and the apply
    /// path — and so is an object with no `publicKeyMultibase` at all.
    #[test]
    fn capability_invocation_embedded_foreign_key_is_rejected_as_invoker() {
        let (did, vm_id, _initial, document) = source_documents();
        let ed_id = format!("{}#ed", did.encode());
        let jwk_id = format!("{}#jwk", did.encode());
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        // Construct path: the Ed25519 object is the sole invoker.
        let mut json = document_json(&did, &vm_id);
        json["capabilityInvocation"] = serde_json::json!([ed25519_method_json(&did)]);
        let foreign =
            Document::from_json_value(json.clone()).expect("the document parses as a whole");
        let err = foreign
            .construct_signed_update(benign_patch(&vm_id), version, &ed_id, source_secret_key())
            .expect_err("an Ed25519 invoker must be rejected before signing");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("not a secp256k1 Multikey"),
                "rejection must be the invoker key decode; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }

        // Apply path: a valid update whose proof is re-pointed at the Ed25519
        // object, applied to a target whose sole invoker is that object.
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("a valid signed update is produced");
        let mut update_json = update.as_ref().clone();
        update_json["proof"]["verificationMethod"] = Value::String(ed_id.clone());
        let repointed = Update::from_json_value(update_json)
            .expect("a verificationMethod swap still re-parses");
        let mut target =
            InitialDocument::from_json_value(json).expect("the apply target parses as a whole");
        let err = target
            .apply_update(&repointed, &AnnouncingBlock::fixed())
            .expect_err("an Ed25519 invoker must be rejected on apply");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("not a secp256k1 Multikey"),
                "rejection must be the invoker key decode; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }

        // An invoker with no publicKeyMultibase at all.
        let mut json = document_json(&did, &vm_id);
        json["capabilityInvocation"] = serde_json::json!([jwk_method_json(&did)]);
        let keyless =
            Document::from_json_value(json.clone()).expect("the document parses as a whole");
        let err = keyless
            .construct_signed_update(benign_patch(&vm_id), version, &jwk_id, source_secret_key())
            .expect_err("a keyless invoker must be rejected before signing");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("has no publicKeyMultibase"),
                "rejection must be the missing-key check; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
        let mut update_json = update.as_ref().clone();
        update_json["proof"]["verificationMethod"] = Value::String(jwk_id);
        let repointed = Update::from_json_value(update_json)
            .expect("a verificationMethod swap still re-parses");
        let mut target =
            InitialDocument::from_json_value(json).expect("the apply target parses as a whole");
        let err = target
            .apply_update(&repointed, &AnnouncingBlock::fixed())
            .expect_err("a keyless invoker must be rejected on apply");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("has no publicKeyMultibase"),
                "rejection must be the missing-key check; got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// A top-level `verificationMethod` entry that carries
    /// `publicKeyMultibase` must declare `type` `Multikey` (this crate's
    /// reading of the DID Core conformance check; see
    /// `verification_method_from_value`), so a secp256k1 key declared
    /// `Ed25519VerificationKey2020` is rejected at parse, naming the entry and
    /// its declared type.
    #[test]
    fn top_level_method_with_publickeymultibase_must_declare_multikey() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        json["verificationMethod"][0]["type"] = serde_json::json!("Ed25519VerificationKey2020");

        let err = Document::from_json_value(json.clone())
            .expect_err("a publicKeyMultibase entry typed other than Multikey must be rejected");
        match err {
            Error::Btcr2Error(Btcr2Error::InvalidDidDocument(msg)) => {
                assert!(msg.contains("Multikey"), "got: {msg}");
                assert!(msg.contains(&vm_id), "must name the entry; got: {msg}");
                assert!(
                    msg.contains("Ed25519VerificationKey2020"),
                    "must name the declared type; got: {msg}"
                );
            }
            other => panic!("expected InvalidDidDocument, got {other:?}"),
        }
        assert!(matches!(
            InitialDocument::from_json_value(json),
            Err(Error::Btcr2Error(Btcr2Error::InvalidDidDocument(_)))
        ));
    }

    /// The top-level `Multikey` type rule does not reach an embedded method:
    /// a `capabilityInvocation` object typed `JsonWebKey2020` carrying the
    /// secp256k1 key parses, and a proof may invoke it. The asymmetry is
    /// intentional (see `verification_method_from_value`); this pins it so a
    /// change to it is a decision, not a side effect.
    #[test]
    fn embedded_method_with_publickeymultibase_keeps_its_declared_type() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        let mut embedded = json["verificationMethod"][0].clone();
        let embedded_id = format!("{}#embeddedJwk", did.encode());
        embedded["id"] = serde_json::json!(embedded_id);
        embedded["type"] = serde_json::json!("JsonWebKey2020");
        json["capabilityInvocation"] = serde_json::json!([embedded]);

        let document =
            Document::from_json_value(json).expect("an embedded method's type is not checked");
        let key = document
            .fields
            .invoking_public_key(&embedded_id)
            .expect("the embedded method is an invoking key");
        assert_eq!(
            key,
            source_secret_key().as_inner().public_key(&Secp256k1::new())
        );
    }

    /// An Ed25519 key declared with its legacy `Ed25519VerificationKey2020`
    /// type is rejected in the top-level array, even beside a conformant
    /// secp256k1 entry: the rule is per entry, not per invoked entry.
    #[test]
    fn top_level_ed25519_verification_key_type_is_rejected() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        let secp256k1_entry = json["verificationMethod"][0].clone();
        json["verificationMethod"] =
            serde_json::json!([secp256k1_entry, ed25519_method_json(&did)]);

        match InitialDocument::from_json_value(json) {
            Err(Error::Btcr2Error(Btcr2Error::InvalidDidDocument(msg))) => {
                assert!(msg.contains("Multikey"), "got: {msg}");
                assert!(msg.contains(&format!("{}#ed", did.encode())), "got: {msg}");
            }
            other => panic!("expected InvalidDidDocument, got {other:?}"),
        }
    }

    /// The Multikey rule gates only entries that carry `publicKeyMultibase`:
    /// a JWK entry with no `publicKeyMultibase` keeps its own `type` and the
    /// document parses.
    #[test]
    fn top_level_jwk_without_publickeymultibase_is_accepted() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        let secp256k1_entry = json["verificationMethod"][0].clone();
        let mut jwk = jwk_method_json(&did);
        jwk["type"] = serde_json::json!("JsonWebKey");
        json["verificationMethod"] = serde_json::json!([secp256k1_entry, jwk]);

        let parsed = InitialDocument::from_json_value(json)
            .expect("a top-level JWK without publicKeyMultibase parses");
        let methods = &parsed.fields.verification_method;
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[1].type_, "JsonWebKey");
        assert_eq!(methods[1].public_key_multibase, None);
    }

    /// Sign an update over `patch` by hand, bypassing construction's checks,
    /// so the apply path can be exercised with a patch construction would
    /// refuse. `target_hash` is taken as given.
    fn hand_signed_update(
        initial: &InitialDocument,
        vm_id: &str,
        patch: &Patch,
        target_hash: Sha256Hash,
        version: NonZeroU64,
    ) -> Update {
        let unsigned = UnsecuredUpdate::construct(patch, initial.hash(), target_hash, version);
        let capability = derive_root_capability(initial.fields.id.clone());
        let inner = ProofInner {
            id: None,
            proof_type: ProofType::DataIntegrityProof,
            proof_purpose: ProofPurpose::CapabilityInvocation,
            verification_method: vm_id.to_string(),
            cryptosuite: CryptoSuiteName::Jcs,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            previous_proof: None,
            nonce: None,
            context: vec![],
            capability,
            capability_action: "Write".to_string(),
            invocation_target: None,
        };
        let proof = CryptoSuite
            .create_proof(&unsigned, inner, &source_secret_key())
            .expect("the hand-built update signs");
        let mut signed_json = unsigned.as_ref().clone();
        if let Value::Object(map) = &mut signed_json {
            map.insert(
                "proof".to_string(),
                serde_json::to_value(&proof).expect("proof serializes"),
            );
        }
        Update::from_json_value(signed_json).expect("the signed update parses")
    }

    /// A signed update whose patch retypes the secp256k1 method to
    /// `JsonWebKey2020` produces a document that no longer conforms, so
    /// resolve.md ("the current document conforms to DID Core") makes it
    /// INVALID_DID_UPDATE on apply; construction refuses the same patch.
    /// Both rejections name the method, its declared type and `Multikey`.
    /// The update is built by hand because construction would refuse it.
    #[test]
    fn apply_update_rejects_a_patch_that_retypes_a_multikey_method() {
        /// A raw JSON value hashed through the crate's canonical hash, for a
        /// target document that cannot parse as a `Document`.
        struct RawDocument(Value);
        impl AsRef<Value> for RawDocument {
            fn as_ref(&self) -> &Value {
                &self.0
            }
        }
        impl CanonicalHash for RawDocument {}

        let (_did, vm_id, initial, document) = source_documents();
        let retype_patch: Patch = serde_json::from_value(serde_json::json!([
            {"op": "replace", "path": "/verificationMethod/0/type", "value": "JsonWebKey2020"}
        ]))
        .expect("retype patch is a valid RFC 6902 op array");
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let names_the_cause = |m: &str| {
            m.contains("non-conformant")
                && m.contains(&vm_id)
                && m.contains("JsonWebKey2020")
                && m.contains("Multikey")
        };

        // Construct path.
        let err = document
            .construct_signed_update(retype_patch.clone(), version, &vm_id, source_secret_key())
            .expect_err("construction must refuse a patch that retypes the method");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref m) if names_the_cause(m)),
            "got: {err:?}"
        );

        // Apply path: target hash over the raw patched JSON so the hash check
        // cannot be what rejects it.
        let mut target_value = initial.as_ref().clone();
        json_patch::patch(&mut target_value, &retype_patch)
            .expect("the retype patch applies to the genesis json");
        let target_hash = RawDocument(target_value).hash();
        let update = hand_signed_update(&initial, &vm_id, &retype_patch, target_hash, version);

        let mut target = initial.clone();
        let err = target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("a patch that retypes a Multikey method must be rejected on apply");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref m) if names_the_cause(m)),
            "got: {err:?}"
        );
        assert_eq!(
            target.hash(),
            initial.hash(),
            "a rejected update leaves the document unchanged"
        );
    }

    /// A JSON Patch that cannot apply (removing a member that does not exist)
    /// is INVALID_DID_UPDATE on both the construct and the apply path, and
    /// the message names the path that failed.
    #[test]
    fn update_rejects_a_patch_that_cannot_apply_naming_the_path() {
        let (_did, vm_id, initial, document) = source_documents();
        let remove_patch: Patch = serde_json::from_value(serde_json::json!([
            {"op": "remove", "path": "/doesNotExist"}
        ]))
        .expect("remove patch is a valid RFC 6902 op array");
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let names_the_path =
            |m: &str| m.contains("Unable to apply JSON Patch") && m.contains("/doesNotExist");

        // Construct path.
        let err = document
            .construct_signed_update(remove_patch.clone(), version, &vm_id, source_secret_key())
            .expect_err("construction must refuse a patch that cannot apply");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref m) if names_the_path(m)),
            "got: {err:?}"
        );

        // Apply path: the proof is valid and the patch fails before the
        // target hash is compared, so any target hash will do.
        let update = hand_signed_update(&initial, &vm_id, &remove_patch, initial.hash(), version);
        let mut target = initial.clone();
        let err = target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("a patch that cannot apply must be rejected on apply");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref m) if names_the_path(m)),
            "got: {err:?}"
        );
        assert_eq!(
            target.hash(),
            initial.hash(),
            "a rejected update leaves the document unchanged"
        );
    }

    /// A spec-level error is unwrapped to its own title and detail; any
    /// other parse error is rendered with its source, not only the
    /// wrapper's summary.
    #[test]
    fn conformance_cause_renders_the_source_of_a_non_spec_error() {
        let json_err = serde_json::from_str::<Value>("{").expect_err("truncated JSON fails");
        let cause = conformance_cause(&Error::from(json_err));
        assert!(cause.contains("EOF"), "got: {cause}");

        let spec = Error::Btcr2Error(Btcr2Error::InvalidDidDocument("x".into()));
        assert_eq!(
            conformance_cause(&spec),
            "The DID document was malformed: x"
        );
    }

    /// An embedded relationship object whose `publicKeyMultibase` is present
    /// but not a string is a typed JSON error, never a panic (only `id` and
    /// `publicKeyMultibase` are read from the object).
    #[test]
    fn relationship_entry_rejects_non_string_public_key_multibase() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        json["authentication"] = serde_json::json!([{
            "id": format!("{}#x", did.encode()),
            "publicKeyMultibase": 42,
        }]);
        let err = InitialDocument::from_json_value(json)
            .expect_err("a numeric publicKeyMultibase must be rejected");
        match err {
            Error::JsonValue(json_tools::JsonError::UnexpectedJsonType(
                field,
                json_tools::ExpectedType::String,
            )) => assert_eq!(field, "authentication.publicKeyMultibase"),
            other => panic!("expected UnexpectedJsonType(_, String), got {other:?}"),
        }
    }

    /// The pre-sign key-match guard: a secret key whose public key does not
    /// match the named method is rejected before signing.
    #[test]
    fn update_rejects_key_mismatch() {
        let (_did, vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        // A different, valid key than the one matching the method.
        let wrong_key =
            SecretKey::try_from([9u8; 32]).expect("[9u8; 32] is a valid secp256k1 secret key");

        let err = document
            .construct_signed_update(patch, version, &vm_id, wrong_key)
            .expect_err("a key not matching the method public key must be rejected");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => {
                assert!(
                    msg.contains("secret key"),
                    "expected a key-mismatch message, got: {msg}"
                );
            }
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// a deactivated DID is terminal and MUST NOT mint a new signed
    /// update. The deactivated guard fires before any of the membership/key
    /// guards, so even an otherwise-valid (patch, version, vm_id, key) is
    /// rejected. Spec: did-btcr2/src/operations/deactivate.md.
    #[test]
    fn construct_rejects_deactivated_document() {
        let (did, vm_id, _initial, _document) = source_documents();
        let mut json = document_json(&did, &vm_id);
        json.as_object_mut()
            .expect("document_json builds an object")
            .insert("deactivated".to_string(), serde_json::json!(true));
        let document =
            Document::from_json_value(json).expect("a deactivated document is still conformant");

        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let err = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect_err("a deactivated document must not produce a signed update");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("deactivated"),
                "expected a deactivated-document message, got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// applying any update to a deactivated DID document is rejected by
    /// the terminal-state guard, before the proof is even verified. This is the
    /// application-side counterpart to `construct_rejects_deactivated_document`.
    /// Spec: did-btcr2/src/operations/deactivate.md.
    #[test]
    fn apply_rejects_deactivated_document() {
        // Build a real, valid signed update against the live (non-deactivated)
        // document so the update itself is well-formed; the rejection must come
        // purely from the target document being deactivated.
        let (did, vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("a valid update is produced against the live document");

        // Now build a deactivated InitialDocument as the apply target.
        let mut json = document_json(&did, &vm_id);
        json.as_object_mut()
            .expect("document_json builds an object")
            .insert("deactivated".to_string(), serde_json::json!(true));
        let mut deactivated = InitialDocument::from_json_value(json)
            .expect("a deactivated document is still conformant");

        let err = deactivated
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("an update must not apply to a deactivated document");
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("deactivated"),
                "expected a deactivated-document message, got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// the `deactivated` parse boundary distinguishes three cases on
    /// subject-controlled JSON (data-structures.md:361 — `deactivated` is a
    /// REQUIRED boolean):
    ///   - absent  -> defaults to `false` (legitimate for initial documents,
    ///     which never carry the field),
    ///   - boolean -> carries its value,
    ///   - present-but-non-boolean -> rejected with `InvalidDidDocument`, NOT
    ///     silently coerced to `false` (active). A crafted `deactivated: "true"`
    ///     can no longer mask a deactivated DID as active.
    #[test]
    fn deactivated_parse_distinguishes_absent_bool_non_bool() {
        let (did, vm_id, _initial, _document) = source_documents();

        // absent -> false: the base document JSON carries no `deactivated` key.
        let absent = document_json(&did, &vm_id);
        assert!(
            !absent
                .as_object()
                .expect("document_json builds an object")
                .contains_key("deactivated"),
            "the base fixture must not carry a deactivated key"
        );
        let document =
            Document::from_json_value(absent).expect("a document with no deactivated key parses");
        assert!(
            !document.fields.deactivated,
            "an absent deactivated field defaults to false"
        );

        // bool -> value: an explicit `true` is carried through.
        let mut active_true = document_json(&did, &vm_id);
        active_true
            .as_object_mut()
            .expect("document_json builds an object")
            .insert("deactivated".to_string(), serde_json::json!(true));
        let document =
            Document::from_json_value(active_true).expect("a boolean deactivated field parses");
        assert!(
            document.fields.deactivated,
            "a present boolean deactivated field carries its value"
        );

        // non-bool -> Err(InvalidDidDocument): string, number, and null are all
        // rejected rather than coerced to active.
        for non_bool in [
            serde_json::json!("true"),
            serde_json::json!(1),
            serde_json::json!(null),
        ] {
            let mut json = document_json(&did, &vm_id);
            json.as_object_mut()
                .expect("document_json builds an object")
                .insert("deactivated".to_string(), non_bool.clone());

            let err = Document::from_json_value(json)
                .expect_err("a present-but-non-boolean deactivated field must be rejected");
            match err {
                Error::Btcr2Error(Btcr2Error::InvalidDidDocument(msg)) => assert!(
                    msg.contains("deactivated"),
                    "expected a deactivated type message, got: {msg}"
                ),
                other => panic!(
                    "expected InvalidDidDocument for deactivated = {non_bool}, got {other:?}"
                ),
            }
        }
    }

    /// update.md:11 — a patch that changes the DID document `id` is rejected
    /// (identifier immutability).
    #[test]
    fn update_rejects_id_change() {
        let (_did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let patch: Patch = serde_json::from_value(serde_json::json!([
            {"op": "replace", "path": "/id", "value": "did:btcr2:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx"}
        ]))
        .expect("id-change patch is a valid RFC 6902 op array");

        let err = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect_err("a patch that changes id must be rejected");
        let detail = invalid_did_update_detail(err);
        assert!(
            detail.contains("may not change the DID document id"),
            "unexpected detail: {detail}"
        );
    }

    /// update.md:11 — an id rewritten to a non-bech32 did:btcr2 string is
    /// rejected on construction with the same id-change detail as on resolve.
    #[test]
    fn update_rejects_id_change_to_a_non_btcr2_id() {
        let (_did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let patch: Patch = serde_json::from_value(serde_json::json!([
            {"op": "replace", "path": "/id", "value": "did:btcr2:k1qexample"}
        ]))
        .expect("id-change patch is a valid RFC 6902 op array");

        let err = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect_err("a patch that changes id must be rejected");
        let detail = invalid_did_update_detail(err);
        assert!(
            detail.contains("may not change the DID document id"),
            "unexpected detail: {detail}"
        );
    }

    /// The constructor does not mutate `self`: the document hash is unchanged
    /// after a successful construct_signed_update call.
    #[test]
    fn update_does_not_mutate_self() {
        let (_did, vm_id, _initial, document) = source_documents();
        let before = document.hash();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let _update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("construction must succeed");
        assert_eq!(
            document.hash(),
            before,
            "construct_signed_update must not mutate the source document"
        );
    }

    /// update.md:114 — the produced Data Integrity Config is shaped as a
    /// capabilityInvocation Write over this DID's root capability, with the
    /// bip340-jcs-2025 cryptosuite and NO `created` field.
    #[test]
    fn data_integrity_config_shape() {
        let (did, vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("construction must succeed");

        let inner = &update.proof.inner;
        assert_eq!(inner.capability, derive_root_capability(did.clone()));
        assert!(inner.capability.starts_with("urn:zcap:root:"));
        // The capability round-trips back to the source DID.
        let dereferenced =
            dereference_root_capability(&inner.capability).expect("capability dereferences");
        assert_eq!(dereferenced.encode(), did.encode());

        assert_eq!(inner.capability_action, "Write");
        assert_eq!(inner.cryptosuite, CryptoSuiteName::Jcs);
        assert_eq!(inner.proof_purpose, ProofPurpose::CapabilityInvocation);

        // The serialized proof must carry no "created" key (determinism).
        let serialized = serde_json::to_value(&update.proof).expect("proof serializes");
        assert!(
            serialized.get("created").is_none(),
            "a deterministic proof must omit the created field"
        );
    }

    /// data-structures.md:206 — proofValue is a base58-btc multibase string
    /// (leading `z`) whose decoded body is exactly the 64-byte Schnorr signature.
    #[test]
    fn proof_value_is_base58btc_64_bytes() {
        let (_did, vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("construction must succeed");

        let proof_value = &update.proof.proof_value.0;
        assert!(
            proof_value.starts_with('z'),
            "proofValue must be base58-btc multibase (prefix 'z'), got: {proof_value}"
        );
        let (_base, decoded) =
            multibase::decode(proof_value).expect("proofValue must be valid multibase");
        assert_eq!(
            decoded.len(),
            64,
            "a BIP340 detached Schnorr signature is exactly 64 bytes"
        );
    }

    /// data-structures.md:118 — `targetVersionId` must be one more than the
    /// current versionId. Construction-time enforcement is intentionally
    /// deferred to the resolver round-trip (the round-trip is the guard): an
    /// update built with targetVersionId 1 still produces a valid signed
    /// update, but fails the resolver's duplicate-check (which requires >= 2).
    #[test]
    fn wrong_target_version_id_fails_round_trip() {
        let (_did, vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(1).expect("1 is non-zero");

        let update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("construction succeeds even with a wrong target_version_id");

        // confirm_duplicate requires target_version_id >= 2.
        let err = update
            .confirm_duplicate(&[])
            .expect_err("targetVersionId 1 must fail the resolver duplicate-check");
        assert!(matches!(err, Btcr2Error::InvalidDidUpdate(_)));
    }

    /// Deterministic golden vector: the produced signed-update JSON matches a
    /// committed fixture byte-for-byte on every run. The fixed inputs are
    /// `SOURCE_SECRET_KEY_BYTES`, the source document deterministically
    /// generated from that key's DID, the `benign_patch` above, and
    /// targetVersionId 2. Signing is deterministic (sign_schnorr_no_aux_rand),
    /// so the bytes are stable.
    ///
    /// The committed fixture uses the four-context unsigned-update set.
    /// Assert a produced artifact equals a committed golden, or REWRITE the
    /// golden when `BLESS=1` is set. Hashes/bytes always flow through the
    /// real code path (`construct_signed_update` → `serde_json`), never
    /// hand-edited. Read and write both use runtime `std::fs` on the SAME path —
    /// deliberately NOT `include_str!` (compile-time embed), which cannot observe
    /// a runtime `fs::write` and would diverge across a stale build.
    ///
    /// NOTE: this helper is intentionally duplicated across the unit/integration
    /// boundary — `tests/conformance.rs` defines its own copy because a
    /// `#[cfg(test)]` helper in this crate cannot be shared into an external
    /// integration test crate.
    fn bless_or_assert(produced: &str, golden_path: &str) {
        if std::env::var("BLESS").as_deref() == Ok("1") {
            std::fs::write(golden_path, produced)
                .unwrap_or_else(|e| panic!("BLESS write {golden_path}: {e}"));
            return;
        }
        let golden = std::fs::read_to_string(golden_path)
            .unwrap_or_else(|e| panic!("read golden {golden_path} (run BLESS=1 to create): {e}"));
        assert_eq!(
            produced,
            golden.trim_end_matches('\n'),
            "{golden_path} drift — re-run `BLESS=1 cargo test` if the change is intended"
        );
    }

    #[test]
    fn golden_signed_update_bytes() {
        let (_did, vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("construction must succeed");

        let produced = serde_json::to_string_pretty(update.as_ref())
            .expect("signed update JSON serializes to pretty string");
        let golden_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/spec-form/golden-signed-update.json"
        );
        bless_or_assert(&produced, golden_path);
    }

    /// The second deterministic golden: the same benign v2 update over the
    /// same source DID as `golden-signed-update.json`, differing only in
    /// that the proof carries `expires` (and still no `created`). The client
    /// crate resolves this fixture end to end through its block-fetch path,
    /// where the announcing block's `mediantime` is checked against
    /// `expires`. Byte-exact so a proof-shape change surfaces here first.
    #[test]
    fn golden_signed_update_with_expires_bytes() {
        let expires = ts(1_700_003_600);
        let (_did, update) = signed_update_with_times(None, Some(expires));

        assert!(
            update.as_ref()["proof"]["expires"].is_string(),
            "proof must carry `expires`"
        );
        assert!(
            update.as_ref()["proof"].get("created").is_none(),
            "proof must not carry `created`"
        );

        let produced = serde_json::to_string_pretty(update.as_ref())
            .expect("signed update JSON serializes to pretty string");
        let golden_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/spec-form/signed-update-with-expires.json"
        );
        bless_or_assert(&produced, golden_path);

        Update::from_json_string(&produced).expect("the blessed wire form parses as an Update");
    }

    /// the deterministically generated genesis document is
    /// spec-conformant on `@context`/`controller`, matching the migrated
    /// test-suite resolve vectors (the interop oracle) and the
    /// `key-based-initial-did-document-template.hbs` template:
    ///   (a) `@context` is exactly
    ///       `["https://www.w3.org/ns/did/v1.1","https://btcr2.dev/context/v1"]`,
    ///   (b) there is NO top-level `controller` key, and
    ///   (c) the per-verification-method `controller` is still present as a
    ///       string.
    #[test]
    fn deterministically_generate() {
        let (_did, _vm_id, _initial, document) = source_documents();
        let json: Value = serde_json::from_str(
            &serde_json::to_string(document.as_ref()).expect("genesis document serializes to JSON"),
        )
        .expect("serialized genesis document parses as JSON value");

        // (a) @context is the exact two-element spec array, in order.
        assert_eq!(
            json["@context"],
            serde_json::json!([
                "https://www.w3.org/ns/did/v1.1",
                "https://btcr2.dev/context/v1"
            ]),
            "genesis @context must match the migrated resolve vectors"
        );

        // (b) no top-level controller (the .hbs template and vectors omit it).
        assert!(
            json.get("controller").is_none(),
            "genesis document must NOT emit a top-level controller"
        );

        // (c) the per-VM controller stays, and is a string (not an array).
        assert!(
            json["verificationMethod"][0]["controller"].is_string(),
            "the per-verification-method controller must remain a string"
        );
    }

    /// Build a minimal conformant key-based DID document JSON with a single
    /// verification method whose id is `vm_id` and whose public key is derived
    /// from `SOURCE_SECRET_KEY_BYTES`. Used by the capabilityInvocation-membership
    /// test which needs to manipulate the raw document shape.
    fn document_json(did: &Did, vm_id: &str) -> Value {
        let secp = Secp256k1::new();
        let public_key = source_secret_key().as_inner().public_key(&secp);
        let did_str = did.encode();
        serde_json::json!({
            "id": did_str,
            "@context": [DID_CORE_V1_1_CONTEXT, DID_BTC1_CONTEXT],
            "controller": [did_str],
            "verificationMethod": [{
                "id": vm_id,
                "type": "Multikey",
                "controller": did_str,
                "publicKeyMultibase": public_key.to_multikey(),
            }],
            "authentication": [vm_id],
            "assertionMethod": [vm_id],
            "capabilityInvocation": [vm_id],
            "capabilityDelegation": [vm_id],
            "service": did_service_entries(did),
        })
    }

    /// The three default beacon services for `did`, in JSON form — reused so a
    /// hand-built document stays conformant (non-empty service set).
    fn did_service_entries(did: &Did) -> Value {
        let resolution_options = ResolutionOptions::default();
        let initial = InitialDocument::from_did(did, &resolution_options)
            .expect("key DID generates its initial document");
        initial.as_ref()["service"].clone()
    }

    /// `proofValue` on a beacon-signalled update is
    /// attacker-influenceable — a tampered signature MUST be rejected by
    /// `apply_update`. This reuses the exact golden signed update
    /// (`source_documents()` + `construct_signed_update`, the same bytes
    /// `golden_signed_update_bytes` pins) and corrupts a single byte of the
    /// detached signature rather than minting a fresh update. This asserts
    /// REJECTION only — it neither creates nor re-blesses any golden vector.
    ///
    /// NOTE (error-code collapse): the corruption here keeps the proofValue a
    /// well-formed 64-byte base58-btc signature (decode → flip one signature byte →
    /// re-encode), so `multibase_decode` succeeds and the rejection lands one step
    /// deeper at BIP340 verification inside `data_integrity_verify_proof`. Prior to
    /// that collapse this surfaced the granular `InvalidUpdateProof` (cryptosuite.rs:228);
    /// the resolve-path `apply_update` site now wraps ANY proof-verification failure
    /// into the spec-uniform `INVALID_DID_UPDATE` (resolve.md:257), so this security
    /// regression test asserts `InvalidDidUpdate`. The rejection property (a tampered
    /// signature is refused) is unchanged — only the wire variant is spec-aligned.
    #[test]
    fn test_apply_update_rejects_corrupted_proof_value() {
        let (_did, vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        // The golden signed update (identical bytes to golden_signed_update_bytes).
        let update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("construction of the golden signed update must succeed");

        // Corrupt the signature: decode the base58-btc proofValue to its 64-byte
        // detached signature, flip one byte, re-encode. The result stays a valid
        // 64-byte base58-btc multibase string, so it reaches BIP340 verification.
        let (base, mut sig_bytes) = multibase::decode(&update.proof.proof_value.0)
            .expect("golden proofValue is valid multibase");
        assert_eq!(
            sig_bytes.len(),
            64,
            "detached Schnorr signature is 64 bytes"
        );
        sig_bytes[10] ^= 0x01;
        let corrupted_proof_value = multibase::encode(base, &sig_bytes);

        // Rewrite the proofValue in the update JSON and re-parse via the real
        // parse path, so the tampered signature flows through apply_update exactly
        // as an attacker-supplied one would.
        let mut json = update.as_ref().clone();
        json["proof"]["proofValue"] = Value::String(corrupted_proof_value);
        let corrupted = Update::from_json_value(json)
            .expect("a proofValue-only byte flip stays well-formed enough to re-parse");

        // Apply against the same source document the update was built for.
        let mut target = InitialDocument::from_did(&_did, &ResolutionOptions::default())
            .expect("key DID regenerates its initial document");
        let err = target
            .apply_update(&corrupted, &AnnouncingBlock::fixed())
            .expect_err("a corrupted-proofValue update must be rejected");
        match err {
            Btcr2Error::InvalidDidUpdate(_) => {}
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// resolve.md:257: a proof-verification failure raised on the resolve
    /// path inside `apply_update` MUST surface as `INVALID_DID_UPDATE`, not the
    /// granular BIP340 `InvalidUpdateProof`. This pins the wire-code collapse at the
    /// `data_integrity_verify_proof` apply site. A find-refs scope check confirmed
    /// `apply_update` has one production caller (the resolver resolve path), so the
    /// collapse costs no non-resolve caller its granular variant.
    #[test]
    fn apply_update_bad_proof_surfaces_invalid_did_update() {
        let (did, vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        // A structurally valid signed update whose signature is then invalidated.
        let update = document
            .construct_signed_update(patch, version, &vm_id, source_secret_key())
            .expect("construction of the signed update must succeed");

        // Replace the detached Schnorr signature with a well-formed 64-byte all-zero
        // signature: valid multibase (reaches BIP340 verification) but never a valid
        // signature over this update, so verification fails at the apply site.
        let (base, _sig) = multibase::decode(&update.proof.proof_value.0)
            .expect("golden proofValue is valid multibase");
        let bad_proof_value = multibase::encode(base, [0u8; 64]);

        let mut json = update.as_ref().clone();
        json["proof"]["proofValue"] = Value::String(bad_proof_value);
        let bad_update = Update::from_json_value(json)
            .expect("a proofValue-only swap stays well-formed enough to re-parse");

        let mut target = InitialDocument::from_did(&did, &ResolutionOptions::default())
            .expect("key DID regenerates its initial document");
        let err = target
            .apply_update(&bad_update, &AnnouncingBlock::fixed())
            .expect_err("an update whose proof fails verification must be rejected");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(_)),
            "resolve-path proof-verify failure must surface INVALID_DID_UPDATE, got: {err:?}"
        );
    }

    /// The array the emitter carried before the spec pinned the update
    /// `@context`; the negative case for the resolve-side check.
    fn pre_pin_context() -> Value {
        serde_json::json!([
            "https://w3id.org/security/v2",
            "https://w3id.org/zcap/v1",
            "https://w3id.org/json-ld-patch/v1",
            "https://btcr2.dev/context/v1"
        ])
    }

    /// Re-parse a mutated signed update and apply it to a fresh copy of the
    /// source document, returning the rejection.
    fn apply_mutated(did: &Did, json: Value) -> Btcr2Error {
        let update = Update::from_json_value(json).expect("a context swap still re-parses");
        let mut target = InitialDocument::from_did(did, &ResolutionOptions::default())
            .expect("key DID regenerates its initial document");
        target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("a mutated update must be rejected")
    }

    /// resolve.md "Check update.proof": an update whose `@context` is the old
    /// array, the pinned URLs reordered, or a strict prefix of them is rejected
    /// by `apply_update` with `INVALID_DID_UPDATE`. The proof is otherwise
    /// intact, so the rejection is the context check, not the signature.
    #[test]
    fn apply_update_rejects_unpinned_context() {
        let (did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("construction of the signed update must succeed");

        let mut reversed: Vec<&str> = UPDATE_CONTEXT.to_vec();
        reversed.reverse();
        let mutations: [(&str, Value); 3] = [
            ("old array", pre_pin_context()),
            ("reversed", serde_json::json!(reversed)),
            ("three elements", serde_json::json!(&UPDATE_CONTEXT[..3])),
        ];
        for (label, context) in mutations {
            let mut json = update.as_ref().clone();
            json["@context"] = context;
            let err = apply_mutated(&did, json);
            match err {
                Btcr2Error::InvalidDidUpdate(msg) => assert!(
                    msg.contains("@context"),
                    "{label}: message must name @context, got: {msg}"
                ),
                other => panic!("{label}: expected InvalidDidUpdate, got {other:?}"),
            }
        }
    }

    /// resolve.md "Check update.proof": a proof whose `@context` differs from
    /// the pinned array — the update's own is left correct — is rejected by
    /// `apply_update` with `INVALID_DID_UPDATE` naming the proof.
    #[test]
    fn apply_update_rejects_proof_context_mismatch() {
        let (did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("construction of the signed update must succeed");

        let mut json = update.as_ref().clone();
        json["proof"]["@context"] = pre_pin_context();
        let err = apply_mutated(&did, json);
        match err {
            Btcr2Error::InvalidDidUpdate(msg) => assert!(
                msg.contains("proof @context"),
                "message must name the proof @context, got: {msg}"
            ),
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// A `DateTime<Utc>` from a unix timestamp (seconds).
    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("in-range unix timestamp")
    }

    /// A validly signed benign update over the source document whose proof
    /// carries the given `created` / `expires`; the construct path never sets
    /// either, so the proof is assembled through the test signer.
    fn signed_update_with_times(
        created: Option<DateTime<Utc>>,
        expires: Option<DateTime<Utc>>,
    ) -> (Did, Update) {
        let (did, vm_id, _initial, document) = source_documents();
        let patch = benign_patch(&vm_id);
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let (unsigned, _source_hash, _target_hash) = document
            .construct_unsigned_update(&patch, version)
            .expect("unsigned update constructs against the source document");
        let update = crate::test_signing::sign_unsigned_update_for_test(
            &unsigned,
            &did,
            &vm_id,
            &source_secret_key(),
            created,
            expires,
        );
        (did, update)
    }

    /// A validly signed update whose proof carries the given `created` /
    /// `expires`, applied to a fresh initial document against `block`.
    fn apply_with_times(
        created: Option<DateTime<Utc>>,
        expires: Option<DateTime<Utc>>,
        block: &AnnouncingBlock,
    ) -> Result<(), Btcr2Error> {
        let (did, update) = signed_update_with_times(created, expires);
        let mut target = InitialDocument::from_did(&did, &ResolutionOptions::default())
            .expect("key DID regenerates its initial document");
        target.apply_update(&update, block)
    }

    /// resolve.md "Check update.proof": `proofPurpose` must equal
    /// `capabilityInvocation`. The proof is otherwise intact, so the
    /// rejection names proofPurpose, not a later check.
    #[test]
    fn apply_update_rejects_non_capability_invocation_proof_purpose() {
        let (did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("construction of the signed update must succeed");

        let mut json = update.as_ref().clone();
        json["proof"]["proofPurpose"] = Value::String("assertionMethod".into());
        let err = apply_mutated(&did, json);
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref msg) if msg.contains("proofPurpose")),
            "expected the proofPurpose rejection, got {err:?}"
        );
    }

    /// resolve.md "Check update.proof": `capabilityAction` must equal `Write`.
    #[test]
    fn apply_update_rejects_non_write_capability_action() {
        let (did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("construction of the signed update must succeed");

        let mut json = update.as_ref().clone();
        json["proof"]["capabilityAction"] = Value::String("Read".into());
        let err = apply_mutated(&did, json);
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref msg) if msg.contains("capabilityAction")),
            "expected the capabilityAction rejection, got {err:?}"
        );
    }

    /// resolve.md "Check update.proof": `capability` must equal the root
    /// capability URN of the DID being resolved. A well-formed URN for a
    /// different DID is rejected before any signature work.
    #[test]
    fn apply_update_rejects_foreign_root_capability() {
        let (did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let update = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("construction of the signed update must succeed");

        let mut json = update.as_ref().clone();
        json["proof"]["capability"] = Value::String(
            "urn:zcap:root:did%3Abtcr2%3Ak1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
                .into(),
        );
        let err = apply_mutated(&did, json);
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref msg) if msg.contains("root capability URN")),
            "expected the root-capability rejection, got {err:?}"
        );
    }

    /// resolve.md "Check update.proof": `created` after the announcing block's
    /// header timestamp is rejected.
    #[test]
    fn apply_update_rejects_created_after_block_header_time() {
        let err = apply_with_times(Some(ts(1_700_000_001)), None, &AnnouncingBlock::fixed())
            .expect_err("a proof created after the block header time must be rejected");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref msg) if msg.contains("created is after")),
            "expected the created rejection, got {err:?}"
        );
    }

    /// resolve.md "Check update.proof": `expires` before the announcing block's
    /// `mediantime` is rejected.
    #[test]
    fn apply_update_rejects_expires_before_block_mediantime() {
        let err = apply_with_times(None, Some(ts(1_699_996_399)), &AnnouncingBlock::fixed())
            .expect_err("a proof expired before the block mediantime must be rejected");
        assert!(
            matches!(
                err,
                Btcr2Error::InvalidDidUpdate(ref msg)
                    if msg.contains("expires is before the announcing block")
            ),
            "expected the expires-before-mediantime rejection, got {err:?}"
        );
    }

    /// resolve.md "Check update.proof": `expires` before `created` is rejected
    /// even when each is individually inside the block's bounds.
    #[test]
    fn apply_update_rejects_expires_before_created() {
        let err = apply_with_times(
            Some(ts(1_699_999_000)),
            Some(ts(1_699_998_000)),
            &AnnouncingBlock::fixed(),
        )
        .expect_err("a proof that expires before it was created must be rejected");
        assert!(
            matches!(
                err,
                Btcr2Error::InvalidDidUpdate(ref msg)
                    if msg.contains("expires is before proof created")
            ),
            "expected the expires-before-created rejection, got {err:?}"
        );
    }

    /// The `expires` check is unconditional when the value is present, so a
    /// caller that has not obtained the block's mediantime cannot skip it:
    /// the proof is rejected (fail-closed), never silently accepted.
    #[test]
    fn apply_update_rejects_expires_when_mediantime_unavailable() {
        let block = AnnouncingBlock {
            timestamp: ts(1_700_000_000),
            mediantime: None,
        };
        let err = apply_with_times(None, Some(ts(1_700_003_600)), &block)
            .expect_err("a proof carrying expires must be rejected without a mediantime");
        assert!(
            matches!(
                err,
                Btcr2Error::InvalidDidUpdate(ref msg) if msg.contains("mediantime is not available")
            ),
            "expected the fail-closed rejection, got {err:?}"
        );
    }

    /// Happy path: `created` at or before the header timestamp and `expires`
    /// at or after the mediantime apply. The comparisons are strict, so equal
    /// timestamps pass on both bounds; the two equalities are checked in
    /// separate updates because the fixed block's mediantime precedes its
    /// header time, and a single proof with both would expire before it was
    /// created.
    #[test]
    fn apply_update_accepts_proof_times_inside_the_block_bounds() {
        let block = AnnouncingBlock::fixed();
        let cases = [
            (
                Some(ts(1_699_999_000)),
                Some(ts(1_700_003_600)),
                "proof times strictly inside the block bounds apply",
            ),
            (
                Some(ts(1_700_000_000)),
                None,
                "created equal to the header timestamp applies",
            ),
            (
                None,
                Some(ts(1_699_996_400)),
                "expires equal to the mediantime applies",
            ),
        ];
        for (created, expires, what) in cases {
            let (did, update) = signed_update_with_times(created, expires);
            let mut target = InitialDocument::from_did(&did, &ResolutionOptions::default())
                .expect("key DID regenerates its initial document");
            target.apply_update(&update, &block).expect(what);
            assert_eq!(target.hash(), update.target_hash, "{what}");
        }
    }

    /// A rejected update leaves the document exactly as it was, whether the
    /// rejection happens before the patch (proofPurpose) or after it (target
    /// hash mismatch, where the signature verifies and the patch applies to
    /// the clone before the hash check fails).
    #[test]
    fn apply_update_failure_after_patch_leaves_document_unchanged() {
        let (did, vm_id, _initial, document) = source_documents();
        let version = NonZeroU64::new(2).expect("2 is non-zero");

        let unsigned = UnsecuredUpdate::construct(
            &benign_patch(&vm_id),
            document.hash(),
            Sha256Hash::from([0xAB; 32]),
            version,
        );
        let update = crate::test_signing::sign_unsigned_update_for_test(
            &unsigned,
            &did,
            &vm_id,
            &source_secret_key(),
            None,
            None,
        );

        let mut target = InitialDocument::from_did(&did, &ResolutionOptions::default())
            .expect("key DID regenerates its initial document");
        let before = target.clone();
        let err = target
            .apply_update(&update, &AnnouncingBlock::fixed())
            .expect_err("a validly signed update over the wrong target hash must be rejected");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref msg) if msg.contains("target hash")),
            "expected the target-hash rejection, got {err:?}"
        );
        assert_eq!(target, before);
        assert_eq!(
            serde_json::to_string(target.as_ref()).expect("document serializes"),
            serde_json::to_string(before.as_ref()).expect("document serializes")
        );

        let good = document
            .construct_signed_update(benign_patch(&vm_id), version, &vm_id, source_secret_key())
            .expect("construction of the signed update must succeed");
        let mut json = good.as_ref().clone();
        json["proof"]["proofPurpose"] = Value::String("assertionMethod".into());
        let bad_purpose = Update::from_json_value(json).expect("a proofPurpose swap re-parses");
        let err = target
            .apply_update(&bad_purpose, &AnnouncingBlock::fixed())
            .expect_err("a proof whose purpose is not capabilityInvocation must be rejected");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(ref msg) if msg.contains("proofPurpose")),
            "expected the proofPurpose rejection, got {err:?}"
        );
        assert_eq!(target, before);
        assert_eq!(
            serde_json::to_string(target.as_ref()).expect("document serializes"),
            serde_json::to_string(before.as_ref()).expect("document serializes")
        );
    }

    /// A resolution result is an owned value a caller may keep and hand out
    /// copies of; the copy carries every field of the original.
    #[test]
    fn resolution_result_clone_is_field_equal() {
        use crate::key::KeyPair;
        use chrono::TimeZone as _;

        let id_type = IdType::from(KeyPair::generate().public_key);
        let did: Did = DidComponents::new(DidVersion::One, Network::Regtest, id_type)
            .expect("regtest is a valid network")
            .try_into()
            .expect("version 1 + regtest + key id type encode to a valid did");
        let initial = InitialDocument::from_did(&did, &ResolutionOptions::default())
            .expect("key-based DID deterministically generates its initial document");

        let original = ResolutionResult {
            resolution_metadata: ResolutionMetadata {
                content_type: Some("application/did+json".to_string()),
            },
            document: Document::from(initial),
            document_metadata: DocumentMetadata {
                version_id: NonZeroU64::new(7).expect("7 is non-zero"),
                confirmations: Some(3),
                deactivated: true,
                updated: Some(Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap()),
            },
        };

        let copy = original.clone();

        assert_eq!(
            copy.resolution_metadata.content_type,
            original.resolution_metadata.content_type
        );
        assert_eq!(copy.document, original.document);
        assert_eq!(
            copy.document_metadata.version_id,
            original.document_metadata.version_id
        );
        assert_eq!(
            copy.document_metadata.confirmations,
            original.document_metadata.confirmations
        );
        assert_eq!(
            copy.document_metadata.deactivated,
            original.document_metadata.deactivated
        );
        assert_eq!(
            copy.document_metadata.updated,
            original.document_metadata.updated
        );
    }
}
