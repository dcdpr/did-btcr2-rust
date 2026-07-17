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
use crate::verification::{VerificationMethod, VerificationMethodId};
use crate::zcap::proof::{CryptoSuiteName, ProofInner, ProofType};
use crate::zcap::{dereference_root_capability, derive_root_capability, proof::ProofPurpose};
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
use std::{collections::HashMap, fs, num::NonZeroU64, path::Path, str::FromStr};

const DID_CORE_V1_1_CONTEXT: &str = "https://www.w3.org/ns/did/v1.1";
const DID_BTC1_CONTEXT: &str = "https://btcr2.dev/context/v1";

// The genesis-document placeholder DID. Externally-prepared intermediate
// documents are authored with this placeholder in every `id` position; binding
// to a real DID substitutes it for the encoded `did:btcr2:…` string. Spec:
// did-btcr2/src/data-structures.md:49, terminology.md:148-149.
const DID_PLACEHOLDER: &str = "did:btcr2:_";

mod version_id_serde {
    //! Custom serde for `NonZeroU64` ↔ ASCII string.
    //!
    //! Spec: did-btcr2/src/data-structures.md:341 — versionId is an
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
pub(crate) trait DocumentMode: document_mode::Sealed {
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

    /// Document controller
    controller: Vec<T>,

    pub(crate) verification_method: Vec<VerificationMethod<T>>,

    authentication: Vec<VerificationMethodId>,
    assertion_method: Vec<VerificationMethodId>,
    capability_invocation: <T as DocumentMode>::Sequence<VerificationMethodId>,
    capability_delegation: Vec<VerificationMethodId>,

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
        + SequenceFromVec<VerificationMethodId>
        + SequenceFromVec<Beacon>,
    VerificationMethodId: FromStr,
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
            return Err(JsonError::JsonMissingKey("@context".into()))?;
        }
        let context = vec_from_object(value, "@context", |id| {
            string_from_value(id).map(ToString::to_string)
        })?;

        // TODO: All of these are optional. Only `vec_from_value` has been fixed
        let controller = vec_from_value(value, "controller")?;
        // Lenient envelope: carry the method's declared `type` verbatim rather
        // than hard-coding "Multikey". A present, well-formed publicKeyMultibase
        // is retained regardless of the declared type; strictness is deferred to
        // VerificationMethod::public_key (which rejects non-Multikey at the
        // crypto-trust boundary). D-09b.
        let verification_method = vec_from_object(value, "verificationMethod", |method| {
            Ok(VerificationMethod::with_type(
                string_from_object(method, "id")?.parse()?,
                string_from_object(method, "controller")?.parse()?,
                PublicKey::from_multikey(string_from_object(method, "publicKeyMultibase")?)?,
                string_from_object(method, "type")?.to_string(),
            ))
        })?;
        let authentication = vec_from_value(value, "authentication")?;
        let assertion_method = vec_from_value(value, "assertionMethod")?;
        let capability_invocation_vec: Vec<VerificationMethodId> =
            vec_from_value(value, "capabilityInvocation")?;
        let capability_delegation = vec_from_value(value, "capabilityDelegation")?;
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
            <T as SequenceFromVec<VerificationMethodId>>::sequence_from_vec(
                capability_invocation_vec,
                "capabilityInvocation",
            )?;
        let service =
            <T as SequenceFromVec<Beacon>>::sequence_from_vec(service_vec, "beacon service")?;

        // an absent field defaults to false for initial documents (which
        // never carry it); the deactivate JSON Patch flips it to true via the
        // normal apply_update re-parse path — no special case here. A present
        // field MUST be a JSON boolean (data-structures.md:339): a
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

    /// Chain tip height for computing `confirmations` in `DocumentMetadata`.
    /// `None` means the caller did not supply the tip and
    /// `DocumentMetadata.confirmations` will be `None` (fail-closed rather
    /// than misleadingly returning 0).
    ///
    /// Sans-I/O: the resolver does NOT fetch the tip. The
    /// did-btcr2-cli client crate owns the `/blocks/tip/height` call.
    pub chain_tip_height: Option<u32>,

    /// Esplora base URL override (network selector). `None` => resolver falls
    /// back to `DEFAULT_RPC_BASE_URL` (testnet). Sans-I/O caller-injected config
    /// same category as `chain_tip_height`. NO trailing slash: the
    /// resolver appends `/address/{descriptor}/txs`.
    pub esplora_url: Option<String>,
}

/// Spec triple per did-btcr2/src/operations/resolve.md:16-17:
/// `(didResolutionMetadata, didDocument, didDocumentMetadata)`.
///
/// Named struct — positional tuples invite swap bugs; most callers
/// want only one or two of the three fields. The clean-break choice
/// accepts that the crate is not yet published.
#[derive(Debug)]
pub struct ResolutionResult {
    /// The `didResolutionMetadata` describing the resolution process.
    pub resolution_metadata: ResolutionMetadata,
    /// The resolved DID document.
    pub document: Document,
    /// The `didDocumentMetadata` describing the resolved document.
    pub document_metadata: DocumentMetadata,
}

/// `didResolutionMetadata` per resolve.md:43 ("MAY be empty"). Empty in
/// empty for now; `#[non_exhaustive]` lets later work add
/// `contentType` and error JSON-LD fields without a breaking change.
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ResolutionMetadata {}

/// `didDocumentMetadata` per adrs/0004-did-document-metadata-shape.md
/// UNION resolution:
/// - `version_id`: REQUIRED per resolve.md:45-50; OPTIONAL per
///   data-structures.md:333-341. Always emitted as a UNION.
/// - `confirmations`: REQUIRED per resolve.md:47; ABSENT in
///   data-structures.md. None when caller did not supply chain_tip_height
///   (fail-closed).
/// - `deactivated`: REQUIRED per both sources.
/// - `updated`: OPTIONAL per data-structures.md; ABSENT in resolve.md.
///   Always emitted as a UNION.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DocumentMetadata {
    /// Spec wire shape: ASCII string per data-structures.md:341.
    /// Custom serde — `5` (number) would silently break interop.
    #[serde(rename = "versionId", with = "version_id_serde")]
    pub version_id: std::num::NonZeroU64,

    /// `None` when caller did not supply `ResolutionOptions::chain_tip_height`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub confirmations: Option<u32>,

    /// Sourced from `contemporary_doc.fields.deactivated` after the
    /// resolver's final apply_update.
    // Always emitted (no skip_serializing_if): REQUIRED by both resolve.md:48 and data-structures.md.
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
    /// with the same [`Update::hash()`] is already present (the resolver
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
    /// The single definition of the capabilityInvocation-membership rule, shared
    /// by both the construction primitive (`Document::construct_signed_update`)
    /// and the resolve path (`InitialDocument::apply_update`) so the spec rule has
    /// one home and cannot drift between the two sides.
    ///
    /// A proof's `verificationMethod` id MUST appear in this document's
    /// `capabilityInvocation` set — only a key the document authorized to invoke
    /// its root capability may sign an update. A non-member is rejected with the
    /// spec-literal INVALID_DID_UPDATE (`Btcr2Error::InvalidDidUpdate`), matching
    /// did-btcr2/src/operations/update.md (construction) and
    /// did-btcr2/src/operations/resolve.md:198 (resolution) — the same code on
    /// both sides, so no interop-visible divergence ships.
    fn ensure_capability_invocation_member(
        &self,
        verification_method_id: &str,
    ) -> Result<(), Btcr2Error> {
        if self
            .capability_invocation
            .iter()
            .any(|id| id.0 == verification_method_id)
        {
            Ok(())
        } else {
            Err(Btcr2Error::InvalidDidUpdate(
                "verificationMethod id not present in the capabilityInvocation set".into(),
            ))
        }
    }
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

        Ok(Resolver::new(initial_document, resolution_options))
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
    fn construct_unsigned_update(
        &self,
        patch: &Patch,
        target_version_id: NonZeroU64,
    ) -> Result<(UnsecuredUpdate, Sha256Hash, Sha256Hash), Btcr2Error> {
        let source_hash = self.hash();

        // Apply the patch to a clone so `self` is left untouched. The resolver's
        // apply_update applies the identical call to its own json_data, so the
        // two target documents canonicalize to the same JCS bytes.
        let mut target_value = self.json_data.clone();
        json_patch::patch(&mut target_value, patch)
            .map_err(|_| Btcr2Error::InvalidDidUpdate("Unable to apply JSON Patch".into()))?;

        // The DID document identifier is immutable across an update.
        if target_value.get("id") != self.json_data.get("id") {
            return Err(Btcr2Error::InvalidDidUpdate(
                "update may not change the DID document id".into(),
            ));
        }

        // Re-validate conformance (mirrors apply_update's DocumentFields check)
        // and hash the patched document for the targetHash.
        let target_hash = Document::from_json_value(target_value)
            .map_err(|_| Btcr2Error::InvalidDidUpdate("patched document is non-conformant".into()))?
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
    /// Before any signing, three guards run:
    ///   1. `verification_method_id` must name a method in this document's
    ///      verification method set,
    ///   2. that same id must appear in the document's capabilityInvocation
    ///      set, and
    ///   3. the public key derived from `secret_key` must equal the matched
    ///      method's public key.
    ///
    /// The first two checks are spec requirements (raising `INVALID_DID_UPDATE`
    /// on failure); the third is a project correctness guard that prevents
    /// emitting a signed update nobody could verify (see adrs/0006).
    ///
    /// Spec: did-btcr2/src/operations/update.md — the verificationMethod and
    /// capabilityInvocation membership requirements and the Data Integrity
    /// Config shape.
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

        // Guard 1: the id must name a method in the verificationMethod set.
        let method = self
            .fields
            .verification_method
            .iter()
            .find(|m| m.id.0 == verification_method_id)
            .ok_or_else(|| {
                Btcr2Error::InvalidDidUpdate(
                    "verificationMethod id not present in the document verificationMethod set"
                        .into(),
                )
            })?;

        // Guard 2: the id must also appear in the capabilityInvocation set
        // (shared with apply_update via the single membership helper).
        self.fields
            .ensure_capability_invocation_member(verification_method_id)?;

        // Guard 3: the caller key must match the matched method's public key,
        // so the produced signature will verify against this document.
        let derived = secret_key
            .as_inner()
            .public_key(&secp256k1::Secp256k1::new());
        if derived != method.public_key {
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
            verification_method: verification_method_id.to_string(),
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
        // If neither is present (no sidecar, or both fields None) the genesis-CAS
        // retrieval path is not yet implemented — preserve the typed error.
        let initial_document = if let Some(doc) =
            sidecar.and_then(|data| data.initial_document.as_ref())
        {
            doc.sidecar_initial_validation(hash)?
        } else if let Some(genesis) = sidecar.and_then(|data| data.genesis_document.as_ref()) {
            // Build the initial document from the genesis (intermediate) document
            // using this DID's own network — NOT a hardcoded network. Structural
            // errors in the genesis document propagate as typed errors (no unwrap).
            let intermediate =
                IntermediateDocument::from_json_value(genesis.clone(), did.components().network())?;
            let initial = intermediate.into_initial(did)?;
            initial.sidecar_initial_validation(hash)?
        } else {
            return Err(Btcr2Error::Unsupported(
                "genesis-CAS retrieval is not yet implemented".into(),
            ))?;
        };

        // Step 3: Validate conformant DID document according to the DID Core 1.1 specification

        // todo: Add a function to validate DID document conformance

        Ok(initial_document)
    }

    // Spec section 7.2.1.2.1
    fn sidecar_initial_validation(&self, hash: Sha256Hash) -> Result<Self, Error> {
        let intermediate_doc = IntermediateDocument::from_initial(self);

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

    // Spec Section 7.2.2.5
    pub(crate) fn apply_update(&mut self, update: &Update) -> Result<(), Btcr2Error> {
        // A deactivated DID is terminal and MUST NOT accept further updates
        // (spec: did-btcr2/src/operations/deactivate.md). The resolver FSM
        // short-circuits on deactivation, but the application primitive must also
        // refuse so a post-deactivation update cannot be applied directly.
        if self.fields.deactivated {
            return Err(Btcr2Error::InvalidDidUpdate(
                "cannot apply an update to a deactivated DID document".into(),
            ));
        }

        let capability_id = &update.proof.inner.capability;
        let did = dereference_root_capability(capability_id)?;

        if self.fields.id != did {
            return Err(Btcr2Error::InvalidDidUpdate(
                "Proof root capability is not for this DID document".into(),
            ));
        }

        let crypto_suite = CryptoSuite;

        // Extract public key from the document
        let verification_method = &update.proof.inner.verification_method;
        let public_key = self
            .fields
            .verification_method
            .iter()
            .find_map(|method| (&method.id.0 == verification_method).then_some(method.public_key))
            .ok_or_else(|| {
                Btcr2Error::ProofVerification(format!(
                    "verificationMethod `{verification_method}` not found in document "
                ))
            })?;

        // The proof's verificationMethod MUST be an authorized invoker — a member
        // of this document's capabilityInvocation set (resolve.md:198). Shared with
        // construct_signed_update via the single membership helper, mapped to the
        // spec-literal INVALID_DID_UPDATE.
        self.fields
            .ensure_capability_invocation_member(verification_method)?;

        // NOTE (resolve-path proof checks, O-1/O-2): proof.expires and
        // proof.capabilityAction are NOT enforced here — they appear nowhere in
        // resolve.md or any migrated resolve vector (the spec is silent on them on
        // the resolve path). Enforcing one now would bake an interop divergence in
        // before the Rust/JS/Java implementations agree (a T7-class hazard), so the
        // open question is escalated to QUESTIONS.txt rather than invented here.
        // capabilityAction == "Write" remains a CONSTRUCTION must (data-structures.md);
        // only its resolve-path enforcement is deferred.

        // Resolve-path apply site: a proof-verification failure MUST surface as
        // INVALID_DID_UPDATE (resolve.md:200), not the granular ProofVerification
        // code. Every other error apply_update raises is already InvalidDidUpdate,
        // so the whole apply step is spec-uniform. Find-refs confirms apply_update
        // has one production caller — the resolver resolve path — so this collapse
        // is resolve-path-only (no construction caller loses a granular variant).
        crypto_suite
            .data_integrity_verify_proof(public_key, update, &ProofPurpose::CapabilityInvocation)
            .map_err(|e| {
                Btcr2Error::InvalidDidUpdate(format!("update proof failed verification: {e}"))
            })?;

        // Step 11
        json_patch::patch(&mut self.json_data, &update.patch)
            .map_err(|_| Btcr2Error::InvalidDidUpdate("Unable to apply JSON Patch".into()))?;

        // Step 12
        self.fields = DocumentFields::try_from((&self.json_data, None)).map_err(|_| {
            Btcr2Error::InvalidDidUpdate("Updated DID document is non-conformant".into())
        })?;

        // The document identifier is immutable across an update: the post-patch
        // document id MUST still equal this DID (resolve.md:187). `did` is the DID
        // decoded from the proof's root capability above; rejecting a mismatch
        // stops a patch from re-pointing the document identity. Spec-literal
        // INVALID_DID_UPDATE, matching the pre-patch capability check above.
        if self.fields.id != did {
            return Err(Btcr2Error::InvalidDidUpdate(
                "post-patch document id does not equal the DID".into(),
            ));
        }

        if self.hash() != update.target_hash {
            return Err(Btcr2Error::InvalidDidUpdate(
                "Hash of updated document does not match target hash".into(),
            ));
        }

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

    pub(crate) fn into_initial(self, did: &Did) -> Result<InitialDocument, Btcr2Error> {
        // Find and replace all DID placeholder strings with the DID.
        let mut json_data = self.json_data.clone();
        find_and_replace(&mut json_data, DID_PLACEHOLDER, did.encode());

        // A nonconforming genesis (e.g. empty service/capabilityInvocation on an
        // x1 sidecar) is structurally invalid as an initial document — surface a
        // typed error, never panic on attacker-supplied sidecar data.
        InitialDocument::from_json_value(json_data)
            .map_err(|e| Btcr2Error::InvalidDidDocument(e.to_string()))
    }

    pub(crate) fn from_initial(initial_doc: &InitialDocument) -> Self {
        // Find and replace all DIDs with the DID placeholder string.
        let did = &initial_doc.fields.id;
        let mut json_data = initial_doc.json_data.clone();
        find_and_replace(&mut json_data, did.encode(), DID_PLACEHOLDER);

        // `DocumentFields<Did>::service` is `NonEmpty<Beacon>`; the
        // intermediate-document field stays `Vec<Beacon>`.
        let service: Vec<Beacon> = initial_doc.fields.service.iter().cloned().collect();

        Self { service, json_data }
    }
}

fn find_and_replace(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::String(s) => {
            // replace only whole DID strings (`s == from`) or DID-fragment
            // strings (`from` followed by `#…`, e.g. a verification-method or
            // service id `did:btcr2:…#key-0`). This rewrites every legitimate DID
            // occurrence — `id`, `controller`, verification-method/service ids —
            // while removing the substring-collision risk of the old
            // unconditional substring substitution (a `from` that merely appeared
            // inside an unrelated field value would no longer be rewritten).
            if s == from {
                *s = to.to_owned();
            } else if let Some(fragment) = s.strip_prefix(from)
                && fragment.starts_with('#')
            {
                *s = format!("{to}{fragment}");
            }
        }
        Value::Array(array) => {
            for item in array {
                find_and_replace(item, from, to);
            }
        }
        Value::Object(obj) => {
            for (_, value) in obj {
                find_and_replace(value, from, to);
            }
        }
        _ => (),
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
    // ResolverState is only used by test_document_from_did_components, which is
    // feature-gated under `old-spec-fixtures`. Gate the import to match.
    #[cfg(feature = "old-spec-fixtures")]
    use crate::resolver::ResolverState;

    impl Did {
        fn hash_unchecked(&self) -> Sha256Hash {
            match self.components().id_type() {
                IdType::Key(_) => unreachable!(), // todo: parse don't validate
                IdType::External(hash) => hash,
            }
        }
    }

    /// `find_and_replace` rewrites a whole-DID string and a `did#fragment`
    /// string, but leaves the DID untouched when it merely appears mid-text or
    /// is immediately followed by a non-`#` character — the substring-collision
    /// guard the function was written to add. The `list` field exercises the
    /// `Value::Array` recursion arm (document.rs Array branch), not just
    /// top-level object fields.
    #[test]
    fn find_and_replace_only_touches_whole_did_and_fragment_ids() {
        let mut v = json!({
            "id": "did:btcr2:x1abc",                   // whole DID  -> replaced
            "vm": "did:btcr2:x1abc#key-0",             // DID#frag   -> replaced
            "note": "see did:btcr2:x1abc in the log",  // mid-text   -> untouched
            "sibling": "did:btcr2:x1abcXYZ",           // prefix+non-'#' -> untouched
            "list": [
                "did:btcr2:x1abc",                     // array elem, whole DID -> replaced
                "did:btcr2:x1abc#svc"                  // array elem, DID#frag  -> replaced
            ]
        });
        find_and_replace(&mut v, "did:btcr2:x1abc", "did:btcr2:_");
        assert_eq!(v["id"], "did:btcr2:_");
        assert_eq!(v["vm"], "did:btcr2:_#key-0");
        assert_eq!(v["note"], "see did:btcr2:x1abc in the log");
        assert_eq!(v["sibling"], "did:btcr2:x1abcXYZ");
        assert_eq!(v["list"][0], "did:btcr2:_"); // exercises Array recursion arm
        assert_eq!(v["list"][1], "did:btcr2:_#svc");
    }

    /// True iff the `test-suite/` submodule is checked out (vs. an empty
    /// placeholder directory left by a non-recursive clone). The probe is the
    /// presence of the `test-suite/regtest/` directory — the common root of every
    /// operation-vector fixture; a non-recursive clone leaves `test-suite/` empty
    /// with no `regtest/` child.
    ///
    /// Intentionally duplicated in the `resolver.rs` test module — a private
    /// `#[cfg(test)]` helper in one file cannot be shared into another file's
    /// test module.
    fn test_suite_checked_out() -> bool {
        let root = format!("{}/test-suite/regtest", env!("CARGO_MANIFEST_DIR"));
        std::path::Path::new(&root).is_dir()
    }

    /// Read a fixture from the nested `test-suite/` submodule at RUNTIME.
    ///
    /// Distinguishes two cases: the submodule is **entirely absent**
    /// (non-recursive clone) — return `None` with a SKIP note so the caller can
    /// cleanly skip; or it is **present but this specific fixture is
    /// missing** (partial checkout / upstream rename of one vector) — `panic!`,
    /// because a silent `return` here would skip every later vector in the loop
    /// and pass the test vacuously. Submodule-backed tests SKIP
    /// cleanly on a non-recursive clone instead of failing to compile (which is
    /// what `include_str!`, a compile-time read, would do).
    ///
    /// Intentionally duplicated in the `resolver.rs` test module — a private
    /// `#[cfg(test)]` helper in one file cannot be shared into another file's
    /// test module.
    fn read_fixture_or_skip(rel: &str) -> Option<String> {
        let path = format!("{}/test-suite/{}", env!("CARGO_MANIFEST_DIR"), rel);
        match std::fs::read_to_string(&path) {
            Ok(s) => Some(s),
            Err(e) if !test_suite_checked_out() => {
                eprintln!(
                    "SKIP: test-suite submodule absent ({path}: {e}); \
                     run `git submodule update --init --recursive` to enable"
                );
                None
            }
            Err(e) => panic!(
                "test-suite submodule is checked out but fixture is missing: {path} ({e}). \
                 A partial checkout or an upstream rename must fail the suite, not skip it \
                 silently."
            ),
        }
    }

    // This helper reads the legacy fixture `resolutionOptions.json`, which keys
    // its `signalsMetadata` by txid. The spec-form resolver keys its
    // sidecar lookup by the JSON Document Hash of each update (`Update::hash()`),
    // which equals the OP_RETURN beacon-signal bytes — so the txid key is
    // discarded here and the update payloads are collected into a
    // `SidecarData` whose `update_lookup_table` is built by `SidecarData::new`.
    //
    // Feature-gated to match its only remaining callers — the two
    // `old-spec-fixtures`-gated legacy tests (`test_document_from_did_components`
    // and `resolver::tests::test_traversal`). The default-build re-homed tests
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
        let Some(resolve_output) = read_fixture_or_skip("regtest/k1/qgpakaw4/resolve/output.json")
        else {
            return;
        };
        let resolve_output: Value = serde_json::from_str(&resolve_output).unwrap();
        let did_document = resolve_output["didDocument"].to_string();
        let doc = Document::from_json_string(&did_document).unwrap();

        assert_eq!(doc.fields.service.len(), 3);
        assert_eq!(doc.fields.verification_method.len(), 1);
    }

    /// D-09a (#170): a document carrying a non-beacon `service`
    /// (`LinkedDomains`) alongside its beacons parses successfully — the
    /// non-beacon service is retain-and-ignored (excluded from the typed beacon
    /// vec / `beacons()`, but retained in `json_data`) rather than failing the
    /// whole document.
    #[test]
    fn non_beacon_service_is_retained_not_fatal() {
        let Some(resolve_output) = read_fixture_or_skip("regtest/k1/qgpakaw4/resolve/output.json")
        else {
            return;
        };
        let resolve_output: Value = serde_json::from_str(&resolve_output).unwrap();
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
        let Some(resolve_output) = read_fixture_or_skip("regtest/k1/qgpakaw4/resolve/output.json")
        else {
            return;
        };
        let resolve_output: Value = serde_json::from_str(&resolve_output).unwrap();
        let mut did_document = resolve_output["didDocument"].clone();

        let service = &mut did_document["service"].as_array_mut().unwrap()[0];
        service.as_object_mut().unwrap().remove("type");

        assert!(Document::from_json_value(did_document).is_err());
    }

    /// D-09b: a verification method whose `type` is not `"Multikey"` is retained
    /// in the parsed document (lenient envelope), but its key cannot be
    /// extracted for proof verification (strict crypto-trust boundary).
    #[test]
    fn non_multikey_vm_is_retained_but_key_extraction_fails() {
        let Some(resolve_output) = read_fixture_or_skip("regtest/k1/qgpakaw4/resolve/output.json")
        else {
            return;
        };
        let resolve_output: Value = serde_json::from_str(&resolve_output).unwrap();
        let mut did_document = resolve_output["didDocument"].clone();

        did_document["verificationMethod"].as_array_mut().unwrap()[0]["type"] =
            json!("Ed25519VerificationKey2020");

        let doc = Document::from_json_value(did_document).expect("parse must succeed");
        let vm = &doc.fields.verification_method[0];
        assert_eq!(vm.type_, "Ed25519VerificationKey2020");
        assert!(matches!(
            vm.public_key(),
            Err(crate::verification::Error::UnsupportedVerificationMethod)
        ));
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
        let Some(other) = read_fixture_or_skip("regtest/x1/q26jeds9/other.json") else {
            return;
        };
        let other: Value = serde_json::from_str(&other).unwrap();

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
        let Some(other) = read_fixture_or_skip("regtest/x1/q26jeds9/other.json") else {
            return;
        };
        let other: Value = serde_json::from_str(&other).unwrap();

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

    // `sidecar_initial_validation` recomputes the intermediate-document hash from
    // the supplied initial document and rejects it when that hash does not equal
    // the External `genesisBytes`. Here the bound initial document is correct; the
    // only divergence is a deliberately corrupted hash argument (one byte flipped
    // in the External genesisBytes), so the failure is isolated to the hash check
    // and the error must be `InvalidDid`.
    #[test]
    fn test_sidecar_initial_validation_hash_mismatch() {
        let Some(other) = read_fixture_or_skip("regtest/x1/q26jeds9/other.json") else {
            return;
        };
        let other: Value = serde_json::from_str(&other).unwrap();

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

    // when `resolve_external` is given no sidecar initial document, the
    // genesis-CAS retrieval fallback is not yet implemented. It must return the
    // typed `Btcr2Error::Unsupported` rather than panicking — a remote-published
    // External DID with no sidecar genesis cannot crash the resolver.
    #[test]
    fn external_genesis_cas_fallback_returns_unsupported() {
        let did: Did = "did:btcr2:x1q26jeds9at48fu5jvpya5s88eqpzne77sp6zlrr9v5dtg7jppa08uhacp3f"
            .parse()
            .unwrap();

        // No sidecar genesis document supplied → the `.and_then` chain yields
        // None and the genesis-CAS fallback fires.
        let resolution_options = ResolutionOptions::default();

        let hash = did.hash_unchecked();
        let result = InitialDocument::resolve_external(&did, hash, &resolution_options);
        assert!(
            matches!(result, Err(Error::Btcr2Error(Btcr2Error::Unsupported(_)))),
            "genesis-CAS fallback must error Unsupported, got: {result:?}"
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

        let did: Did = "did:btcr2:x1q26jeds9at48fu5jvpya5s88eqpzne77sp6zlrr9v5dtg7jppa08uhacp3f"
            .parse()
            .unwrap();

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
            "../test-suite/regtest/k1/qgppexmy/resolve/input.json"
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

        let json = include_str!(
            "../fixtures/k1qypa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dagl0mgs4-transactions.json"
        );
        let transactions: HashMap<_, _> = serde_json::from_str(json).unwrap();
        let fsm = next_state.process_responses(transactions);

        let ResolverState::Resolved(result) = fsm.resolve().unwrap() else {
            unreachable!()
        };
        assert_eq!(result.document.fields.id.encode(), did.encode());

        // Re-pointed to a surviving regtest vector so the gated build compiles.
        let target_doc = Document::from_json_string(include_str!(
            "../test-suite/regtest/k1/qgppexmy/update/input.json"
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
    /// invariant holds). Returns `None` when the test-suite submodule is absent
    /// callers skip.
    fn valid_resolved_doc_json() -> Option<Value> {
        let resolve_output = read_fixture_or_skip("regtest/k1/qgpakaw4/resolve/output.json")?;
        let resolve_output: Value = serde_json::from_str(&resolve_output).unwrap();
        Some(resolve_output["didDocument"].clone())
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
        let Some(mut json) = valid_resolved_doc_json() else {
            return;
        };
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
        let Some(mut json) = valid_resolved_doc_json() else {
            return;
        };
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
        let Some(json) = valid_resolved_doc_json() else {
            return;
        };
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
        let Some(other) = read_fixture_or_skip("regtest/x1/q26jeds9/other.json") else {
            return;
        };
        let other: Value = serde_json::from_str(&other).unwrap();
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
        let Some(other) = read_fixture_or_skip("regtest/x1/q26jeds9/other.json") else {
            return;
        };
        let Some(create_output) = read_fixture_or_skip("regtest/x1/q26jeds9/create/output.json")
        else {
            return;
        };
        let other: Value = serde_json::from_str(&other).unwrap();
        let create_output: Value = serde_json::from_str(&create_output).unwrap();

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
        let rebuilt = IntermediateDocument::from_initial(&initial_doc);
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
    /// Spec: did-btcr2/src/data-structures.md:341.
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
    // Source spec lines are cited inline (e.g. update.md:85) rather than the
    // project's internal requirement ids.
    // ──────────────────────────────────────────────────────────────────────

    use crate::key::SecretKey;
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

        let mut applied = initial.clone();
        applied
            .apply_update(&update)
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
            .apply_update(&update)
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
        use crate::beacon::BeaconType;
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
            ..Default::default()
        };
        let resolver = Resolver::new(initial.clone(), resolution_options);

        // Drive the FSM: Init -> feed the bridged tx on the matching beacon ->
        // resolve. The beacon the signal arrives on must be the one we announced
        // from (P2WPKH), so route the tx under BeaconType::Singleton.
        let ResolverState::Requests(next_state, _requests) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        let mut transactions: HashMap<BeaconType, Vec<esploda::esplora::Transaction>> =
            HashMap::new();
        transactions.insert(BeaconType::Singleton, vec![bridged]);
        let fsm = next_state.process_responses(transactions);

        // The resolver may need additional empty-signal steps to terminate.
        let mut state = fsm
            .resolve()
            .expect("processing the beacon signal resolves a step");
        let result = loop {
            match state {
                ResolverState::Resolved(result) => break result,
                ResolverState::Requests(next, _requests) => {
                    let empty: HashMap<BeaconType, Vec<esploda::esplora::Transaction>> =
                        HashMap::new();
                    state = next
                        .process_responses(empty)
                        .resolve()
                        .expect("empty-signal step resolves");
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
        use crate::beacon::BeaconType;
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
            .apply_update(&update1)
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
            ..Default::default()
        };
        let resolver = Resolver::new(genesis.clone(), resolution_options);

        let ResolverState::Requests(next_state, _requests) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        let mut transactions: HashMap<BeaconType, Vec<esploda::esplora::Transaction>> =
            HashMap::new();
        // Each update arrives TWICE on the Singleton beacon: the dups must not
        // trip a false late-publishing.
        transactions.insert(BeaconType::Singleton, vec![b1, b1_dup, b2, b2_dup]);
        let fsm = next_state.process_responses(transactions);

        let mut state = fsm.resolve().expect(
            "processing the duplicate beacon signals resolves a step without late-publishing",
        );
        let result = loop {
            match state {
                ResolverState::Resolved(result) => break result,
                ResolverState::Requests(next, _requests) => {
                    let empty: HashMap<BeaconType, Vec<esploda::esplora::Transaction>> =
                        HashMap::new();
                    state = next
                        .process_responses(empty)
                        .resolve()
                        .expect("empty-signal step resolves without a false late-publishing");
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
        use crate::beacon::BeaconType;
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
            .apply_update(&update1)
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
            ..Default::default()
        };
        let resolver = Resolver::new(genesis.clone(), resolution_options);

        let ResolverState::Requests(next_state, _requests) = resolver
            .resolve()
            .expect("Init step yields beacon requests")
        else {
            panic!("expected Requests from Init step");
        };
        let mut transactions: HashMap<BeaconType, Vec<esploda::esplora::Transaction>> =
            HashMap::new();
        transactions.insert(BeaconType::Singleton, vec![bridged1, bridged2]);
        let fsm = next_state.process_responses(transactions);

        let mut state = fsm
            .resolve()
            .expect("processing the beacon signals resolves a step");
        let result = loop {
            match state {
                ResolverState::Resolved(result) => break result,
                ResolverState::Requests(next, _requests) => {
                    let empty: HashMap<BeaconType, Vec<esploda::esplora::Transaction>> =
                        HashMap::new();
                    state = next
                        .process_responses(empty)
                        .resolve()
                        .expect("empty-signal step resolves");
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

    /// update.md:85 — a vm_id absent from the verificationMethod set is rejected
    /// before any signing.
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

    /// resolve.md:198 — apply_update MUST reject an update whose proof
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
            .apply_update(&update)
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

    /// resolve.md:187 — apply_update MUST reject an update whose patch changes the
    /// document `id` (a post-patch `id != did`): a patch cannot re-point the
    /// document identity. Mapped to the spec-literal INVALID_DID_UPDATE
    /// (`Btcr2Error::InvalidDidUpdate`).
    ///
    /// The construction primitive refuses an id-changing patch, so this builds the
    /// signed id-changing update directly (mirroring construct_signed_update but
    /// without the construct-side id-immutability guard), then applies it: the
    /// signature verifies against the genesis VM, the patch re-parses to a
    /// conformant (but re-identified) document whose hash matches the update's
    /// targetHash, and the new resolve-path id==did check is the rejecting gate.
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

        // Build the signed update by hand (construct_signed_update would reject
        // the id change). target_hash is computed from the patched document so the
        // resolve-path hash check passes and the id check is what fires.
        let source_hash = initial.hash();
        let mut target_value = initial.as_ref().clone();
        json_patch::patch(&mut target_value, &id_change_patch)
            .expect("the id-change patch applies to the genesis json");
        let target_hash = Document::from_json_value(target_value)
            .expect("the re-identified document still parses as conformant")
            .hash();
        let version = NonZeroU64::new(2).expect("2 is non-zero");
        let unsigned =
            UnsecuredUpdate::construct(&id_change_patch, source_hash, target_hash, version);

        let capability = derive_root_capability(initial.fields.id.clone());
        let inner = ProofInner {
            id: None,
            proof_type: ProofType::DataIntegrityProof,
            proof_purpose: ProofPurpose::CapabilityInvocation,
            verification_method: vm_id.clone(),
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
            .expect("the id-changing update signs");
        let mut signed_json = unsigned.as_ref().clone();
        if let Value::Object(map) = &mut signed_json {
            map.insert(
                "proof".to_string(),
                serde_json::to_value(&proof).expect("proof serializes"),
            );
        }
        let update =
            Update::from_json_value(signed_json).expect("the signed id-changing update parses");

        let mut target = initial.clone();
        let err = target
            .apply_update(&update)
            .expect_err("a patch that changes the document id must be rejected on apply");
        assert!(matches!(err, Btcr2Error::InvalidDidUpdate(_)));
    }

    /// update.md:87 — a vm_id present in verificationMethod but absent from
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
            .apply_update(&update)
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
    /// subject-controlled JSON (data-structures.md:339 — `deactivated` is a
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

    /// update.md:51 — a patch that changes the DID document `id` is rejected
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
        assert!(matches!(err, Btcr2Error::InvalidDidUpdate(_)));
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

    /// data-structures.md:195 — proofValue is a base58-btc multibase string
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

    /// data-structures.md:106 — `targetVersionId` must be one more than the
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
    /// into the spec-uniform `INVALID_DID_UPDATE` (resolve.md:200), so this security
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
            .apply_update(&corrupted)
            .expect_err("a corrupted-proofValue update must be rejected");
        match err {
            Btcr2Error::InvalidDidUpdate(_) => {}
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// resolve.md:200: a proof-verification failure raised on the resolve
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
            .apply_update(&bad_update)
            .expect_err("an update whose proof fails verification must be rejected");
        assert!(
            matches!(err, Btcr2Error::InvalidDidUpdate(_)),
            "resolve-path proof-verify failure must surface INVALID_DID_UPDATE, got: {err:?}"
        );
    }
}
