#![warn(clippy::unwrap_used)]
//! Panic-sweep policy: legitimately fallible sites use Result;
//! type-system-guaranteed sites use `.expect("<invariant>")` with a structural
//! justification. Test code is exempted via clippy.toml's `allow-unwrap-in-tests`.

use crate::beacon::{AddressExt as _, Beacon, BeaconType};
use crate::canonical_hash::CanonicalHash;
use crate::cryptosuite::CryptoSuite;
use crate::error::{Btc1Error, ProblemDetails};
use crate::identifier::{Did, DidComponents, DidVersion, IdType, Network, Sha256Hash};
use crate::key::{PublicKey, PublicKeyExt as _};
use crate::verification::{VerificationMethod, VerificationMethodId};
use crate::zcap::{dereference_root_capability, proof::ProofPurpose};
use crate::{identifier::TryNetworkExt, json_tools, resolver::Resolver, update::Update};
use chrono::{DateTime, Utc};
use esploda::bitcoin::{Address, Txid};
use json_patch::Patch;
use nonempty::NonEmpty;
use onlyerror::Error;
use serde_json::{Value, json};
use std::{collections::HashMap, fs, num::NonZeroU64, path::Path, str::FromStr};

const DID_CORE_V1_1_CONTEXT: &str = "https://www.w3.org/TR/did-1.1";
// TODO: Needs to be updated (eventually) to "https://btc1.dev/context/v1"
const DID_BTC1_CONTEXT: &str = "https://did-btc1/TBD/context";

const DID_PLACEHOLDER: &str =
    "did:btc1:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

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

    /// DID:BTC1 error
    Btc1Error(#[from] Btc1Error),

    /// This should not happen: Only needed to satisfy `String: FromStr` trait bound
    Infallible(#[from] std::convert::Infallible),

    /// Bitcoin address parse error
    AddressParse(#[from] esploda::bitcoin::address::Error),

    /// Unexpected DID
    #[error("Expected `{0}` but found `{1}`")]
    UnexpectedDid(String, String),
}

impl ProblemDetails for Error {
    fn details(&self) -> Option<Value> {
        match self {
            Self::Btc1Error(err) => err.details(),
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
    ) -> Result<Self::Sequence<U>, Btc1Error>;
}

impl<U> SequenceFromVec<U> for crate::identifier::Did
where
    U: Clone + std::fmt::Debug + PartialEq + Eq,
{
    fn sequence_from_vec(
        items: Vec<U>,
        field_name: &'static str,
    ) -> Result<NonEmpty<U>, Btc1Error> {
        NonEmpty::from_vec(items).ok_or_else(|| {
            Btc1Error::InvalidDidDocument(format!(
                "updatable DID document must contain at least one {field_name}"
            ))
        })
    }
}

impl<U> SequenceFromVec<U> for String
where
    U: Clone + std::fmt::Debug + PartialEq + Eq,
{
    fn sequence_from_vec(items: Vec<U>, _field_name: &'static str) -> Result<Vec<U>, Btc1Error> {
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
            Btc1Error::InvalidDid("no network derivable from id and none provided".into())
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
        let verification_method = vec_from_object(value, "verificationMethod", |method| {
            Ok(VerificationMethod::new(
                string_from_object(method, "id")?.parse()?,
                string_from_object(method, "controller")?.parse()?,
                PublicKey::from_multikey(string_from_object(method, "publicKeyMultibase")?)?,
            ))
        })?;
        let authentication = vec_from_value(value, "authentication")?;
        let assertion_method = vec_from_value(value, "assertionMethod")?;
        let capability_invocation_vec: Vec<VerificationMethodId> =
            vec_from_value(value, "capabilityInvocation")?;
        let capability_delegation = vec_from_value(value, "capabilityDelegation")?;
        // TODO: This will fail when the DID document contains non-Beacon services
        // https://github.com/dcdpr/did-btc1/issues/170
        let service_vec: Vec<Beacon> = vec_from_object(value, "service", |service| {
            let id = string_from_object(service, "id")?.to_string();
            let ty = string_from_object(service, "type")?.parse()?;
            let descriptor =
                Address::from_bip21(string_from_object(service, "serviceEndpoint")?, network)?;

            Ok(Beacon::new(id, ty, descriptor))
        })?;

        // parse-boundary conversion. For T = Did this enforces
        // NonEmpty (returning Btc1Error::InvalidDidDocument on empty);
        // for T = String this is a no-op pass-through.
        let capability_invocation =
            <T as SequenceFromVec<VerificationMethodId>>::sequence_from_vec(
                capability_invocation_vec,
                "capabilityInvocation",
            )?;
        let service =
            <T as SequenceFromVec<Beacon>>::sequence_from_vec(service_vec, "beacon service")?;

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
}

#[derive(Debug, Default)]
pub struct SidecarData {
    pub initial_document: Option<InitialDocument>,

    pub signals_metadata: HashMap<Txid, SignalsMetadata>,

    // TODO: Using the `url` crate is probably better.
    /// Blockchain RPC URI.
    ///
    /// Must be provided as a full URI including schema and domain:
    /// `https://esplora.example/testnet`.
    ///
    /// This can be used to override the hostname used in `Request`s returned by the [`Traversal`]
    /// FSM.
    pub blockchain_rpc_uri: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SignalsMetadata {
    pub btc1_update: Option<Update>,
    pub proofs: SmtProofs,
}

// Placeholders
#[derive(Clone, Debug)]
pub struct SmtProofs;

/// Represents a JSON or JSON-LD document
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// All structural Document fields
    pub(crate) fields: DocumentFields<Did>,
    /// The document data as a JSON Value
    json_data: Value,
}

impl Document {
    // Spec section 7.1.1
    pub fn from_did_components(
        did_components: DidComponents,
        resolution_options: ResolutionOptions,
    ) -> Result<(Did, Resolver), Error> {
        let did = Did::try_from(did_components)?;
        let resolver = Self::read(&did, resolution_options)?;

        Ok((did, resolver))
    }

    // Spec section 7.2
    //
    // TODO: Sans-I/O: This needs to not bake any I/O into the implementation. Instead, this should
    // return a finite state machine that represents the protocol described in the spec. This allows
    // the caller to do their own I/O and drive the state machine forward to `Document` resolution.
    pub fn read(did: &Did, resolution_options: ResolutionOptions) -> Result<Resolver, Error> {
        let initial_document = InitialDocument::from_did(did, &resolution_options)?;

        Ok(Resolver::new(initial_document, resolution_options))
    }

    // Spec section 7.3
    //
    // TODO: Do we really want to expose this patching concept to users? How do they create patches?
    //
    // options:
    // a) user provides Patch
    //
    // b) user provides second document and we compute the diff and patch
    //
    // c) the patch can be constructed incrementally through various mutating methods,
    //     // like `add_service()`, and then committed with `update()`. You would want a way to check
    //     // whether there are staged patches.
    //
    //
    pub fn update(
        &mut self,
        // `btc1Identifier` is implied by `self.did`
        // `sourceDocument` is implied by `self`
        // `sourceVersionId` is implied by `self.version`
        _patch: Patch,
        _verification_method_id: &str,
        _beacon_ids: &[usize],
    ) -> Result<Resolver, Error> {
        todo!()
    }

    // Spec section 7.4
    pub fn deactivate(&mut self) -> Result<Resolver, Error> {
        todo!()
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

/// Representation of initial DID document, according to did::btc1 specification.
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
    ) -> (Did, Self) {
        let hash = doc.hash();

        let id_type = IdType::External(hash);

        // Per the panic-sweep policy:
        // type-system-guaranteed encode (default DidVersion, default Network,
        // 32-byte hash payload) -> .expect() with structural invariant.
        // Result propagation here would change `from_external_intermediate`'s
        // public signature from `(Did, Self)` to `Result<(Did, Self), _>`,
        // which is architectural scope beyond the original panic sweep.
        let did: Did = DidComponents::new(
            version.unwrap_or_default(),
            network.unwrap_or_default(),
            id_type,
        )
        .try_into()
        .expect("default DidVersion + default Network + 32-byte External hash payload always encode to a valid did:btc1 string");

        let initial_document = doc.into_initial(&did);

        // Step 9 is unimplemented (this is the caller's responsibility)
        // Optionally store canonicalBytes on a Content Addressable Storage (CAS) system like the
        // InterPlanetary File System (IPFS).

        (did, initial_document)
    }

    // Spec section 7.2.1
    /// Create an initial document from an existing DID.
    pub fn from_did(did: &Did, resolution_options: &ResolutionOptions) -> Result<Self, Error> {
        match did.components().id_type() {
            IdType::Key(_) => Self::deterministically_generate(did, resolution_options),
            IdType::External(hash) => Self::resolve_external(hash, resolution_options),
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
            "controller": [did.encode()],
            "verificationMethod": [{
                "id": verification_method_id,
                "type": "Multikey",
                "controller": did.encode(),
                "publicKeyMultibase": did.public_key_unchecked().to_multikey(),
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
        hash: Sha256Hash,
        resolution_options: &ResolutionOptions,
    ) -> Result<Self, Error> {
        // Step 1
        let initial_document = resolution_options
            .sidecar_data
            .as_ref()
            .and_then(|data| {
                data.initial_document
                    .as_ref()
                    .map(|doc| doc.sidecar_initial_validation(hash))
            })
            .unwrap_or_else(|| todo!("Sans I/O CAS retrieval"))?;

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
            Err(Btc1Error::InvalidDid(
                "TODO: description for sidecar_initial_validation() hash mismatch".to_string(),
            ))?
        } else {
            Ok(self.clone())
        }
    }

    // Spec Section 7.2.2.5
    pub(crate) fn apply_update(&mut self, update: &Update) -> Result<(), Btc1Error> {
        let capability_id = &update.proof.inner.capability;
        let did = dereference_root_capability(capability_id)?;

        if self.fields.id != did {
            return Err(Btc1Error::InvalidDidUpdate(
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
                Btc1Error::ProofVerification(format!(
                    "verificationMethod `{verification_method}` not found in document "
                ))
            })?;

        crypto_suite.data_integrity_verify_proof(
            public_key,
            update,
            &ProofPurpose::CapabilityInvocation,
        )?;

        // Step 11
        json_patch::patch(&mut self.json_data, &update.patch)
            .map_err(|_| Btc1Error::InvalidDidUpdate("Unable to apply JSON Patch".into()))?;

        // Step 12
        self.fields = DocumentFields::try_from((&self.json_data, None)).map_err(|_| {
            Btc1Error::InvalidDidUpdate("Updated DID document is non-conformant".into())
        })?;

        if self.hash() != update.target_hash {
            return Err(Btc1Error::InvalidDidUpdate(
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

/// Representation of intermediate DID document, according to did::btc1 specification.
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

    fn into_initial(self, did: &Did) -> InitialDocument {
        // Find and replace all DID placeholder strings with the DID.
        let mut json_data = self.json_data.clone();
        find_and_replace(&mut json_data, DID_PLACEHOLDER, did.encode());

        InitialDocument::from_json_value(json_data).expect(
            "intermediate doc validated at construction; substituting the placeholder DID \
             string for a real DID string preserves structural validity",
        )
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
            *s = s.replace(from, to);
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
    let public_key = esploda::bitcoin::PublicKey::new(did.public_key_unchecked());

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

    impl ResolutionOptions {
        pub(crate) fn from_json_string(json: &str) -> Self {
            let json = serde_json::from_str::<Value>(json).unwrap();

            let signals_metadata = json["sidecarData"]["signalsMetadata"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(txid, metadata)| {
                    (
                        txid.parse().unwrap(),
                        SignalsMetadata {
                            btc1_update: Update::from_json_value(metadata["updatePayload"].clone())
                                .ok(),
                            proofs: SmtProofs,
                        },
                    )
                })
                .collect();

            ResolutionOptions {
                sidecar_data: Some(SidecarData {
                    signals_metadata,
                    ..Default::default()
                }),
                ..Default::default()
            }
        }
    }

    #[test]
    fn test_document_parse() {
        let doc = Document::from_json_string(include_str!(concat!(
            "../test-suite/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
            "/initialDidDoc.json",
        ))).unwrap();

        assert_eq!(doc.fields.service.len(), 3);
        assert_eq!(doc.fields.verification_method.len(), 1);
    }

    #[test]
    fn test_sidecar_initial_validation() {
        let initial_doc = InitialDocument::from_json_string(include_str!(concat!(
            "../test-suite/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
            "/initialDidDoc.json",
        )))
        .unwrap();

        let resolution_options = ResolutionOptions {
            sidecar_data: Some(SidecarData {
                initial_document: Some(initial_doc),
                ..Default::default()
            }),
            ..Default::default()
        };

        let did: Did = "did:btc1:x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf"
            .parse()
            .unwrap();
        let hash = did.hash_unchecked();
        let initial_doc = InitialDocument::resolve_external(hash, &resolution_options).unwrap();
        assert_eq!(initial_doc.fields.id, did);
    }

    #[test]
    fn test_document_validation_missing_elements() {
        let path = "./fixtures/initialDidDoc-missing-verificationMethod-id.json";
        assert!(matches!(
            InitialDocument::from_file(path),
            Err(Error::JsonValue(json_tools::JsonError::JsonMissingKey(key))) if key == "id"
        ));
    }

    // legacy fixture (test-suite/signet/.../resolutionOptions.json) uses
    // Base58-encoded sourceHash/targetHash; gated pending re-encoding
    // migrates fixtures to base64url-no-pad. CI default builds skip this test;
    // run with `--features old-spec-fixtures` to exercise.
    #[cfg(feature = "old-spec-fixtures")]
    #[test]
    fn test_document_from_did_components() {
        let id_type = IdType::from(
            PublicKey::from_slice(
                &hex::decode("03da2c07d2443fbf228aa773e5f685562158d39ee675b586b3ebdb897e7f1e56f5")
                    .unwrap(),
            )
            .unwrap(),
        );
        let did_components = DidComponents::new(DidVersion::One, Network::Signet, id_type);

        let resolution_options = ResolutionOptions::from_json_string(include_str!(concat!(
            "../test-suite/signet/k1qypa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dagl0mgs4",
            "/resolutionOptions.json",
        )));

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

        let ResolverState::Resolved(document) = fsm.resolve().unwrap() else {
            unreachable!()
        };
        assert_eq!(document.fields.id.encode(), did.encode());

        let target_doc = Document::from_json_string(include_str!(concat!(
            "../test-suite/signet/k1qypa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dagl0mgs4",
            "/targetDocument.json",
        )))
        .unwrap();
        assert_eq!(document.hash(), target_doc.hash());
    }

    // ──────────────────────────────────────────────────────────────────────
    // acceptance tests.
    //
    // The four tests below codify the type-level NonEmpty invariant on
    // `DocumentFields<Did>::capability_invocation` and `::service`, plus the
    // Carve-out that the intermediate `DocumentFields<String>`
    // variant stays unconstrained.
    // ──────────────────────────────────────────────────────────────────────

    /// Minimum valid resolved-DID JSON document. Used as a base by the four
    /// acceptance tests; the failing-case tests overwrite the field
    /// they want to test with an empty array before running TryFrom.
    fn valid_resolved_doc_json() -> Value {
        // Reuses the existing mutinynet fixture so we know
        // `verificationMethod` / `service` shapes match the parser's
        // expectations (multikey + bitcoin: BIP21 URI).
        serde_json::from_str(include_str!(concat!(
            "../test-suite/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
            "/initialDidDoc.json",
        )))
        .unwrap()
    }

    #[test]
    fn empty_capability_invocation_rejected() {
        // a resolved DID document must contain ≥1
        // capabilityInvocation entry. Spec: did-btcr2/src/data-structures.md
        // §did-document. Type-level guarantee via DocumentMode::Sequence<U> = NonEmpty<U>.
        //
        // The error must surface as Btc1Error::InvalidDidDocument with the
        // field name in the detail string (the outer Error variant prints
        // only "DID:BTC1 error" — Btc1Error doc comments are the Display form
        // so the test pattern-matches the inner variant directly).
        let mut json = valid_resolved_doc_json();
        json["capabilityInvocation"] = serde_json::json!([]);
        let result = DocumentFields::<Did>::try_from((&json, None));
        match result {
            Err(Error::Btc1Error(Btc1Error::InvalidDidDocument(detail))) => {
                assert!(
                    detail.contains("capabilityInvocation"),
                    "expected detail mentioning capabilityInvocation, got: {detail}"
                );
            }
            Err(other) => panic!("expected Btc1Error::InvalidDidDocument, got: {other:?}"),
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
            Err(Error::Btc1Error(Btc1Error::InvalidDidDocument(detail))) => {
                assert!(
                    detail.contains("beacon") || detail.contains("service"),
                    "expected detail mentioning beacon/service, got: {detail}"
                );
            }
            Err(other) => panic!("expected Btc1Error::InvalidDidDocument, got: {other:?}"),
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
        let mut json: Value = serde_json::from_str(include_str!(concat!(
            "../test-suite/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
            "/intermediateDidDoc.json",
        )))
        .unwrap();
        json["capabilityInvocation"] = serde_json::json!([]);
        json["service"] = serde_json::json!([]);
        let result = DocumentFields::<String>::try_from((&json, Some(Network::Regtest)));
        assert!(
            result.is_ok(),
            "intermediate doc should be unconstrained, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_from_external_intermediate() {
        let intermediate_doc = IntermediateDocument::from_json_string(
            include_str!(concat!(
                "../test-suite/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
                "/intermediateDidDoc.json",
            )),
            Network::Regtest,
        )
        .unwrap();
        let (did, initial_doc) = InitialDocument::from_external_intermediate(
            intermediate_doc,
            None,
            Some(Network::Regtest),
        );

        let expected_did = include_str!(concat!(
            "../test-suite/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
            "/did.txt",
        ));
        assert_eq!(did.encode(), expected_did.trim());

        let expected_doc = InitialDocument::from_json_string(include_str!(concat!(
            "../test-suite/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
            "/initialDidDoc.json",
        )))
        .unwrap();
        assert_eq!(initial_doc, expected_doc);
    }
}
