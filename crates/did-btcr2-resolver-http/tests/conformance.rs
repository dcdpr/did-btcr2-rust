//! In-process conformance suite for the GET binding, plus the binding's own rules.
//!
//! Mirrors `w3c/did-resolution-test-suite` at
//! `c3fb2a88585da1dd6167dccd59a84700fa2383ed`: one `#[test]` per `it()` in
//! `tests/4-did-resolution.js` and `tests/10-bindings.js` that has in-process
//! behaviour, the two result-shape helpers of `tests/assertions.js`, and one
//! test per rule the binding itself adds (bodiless 404/405, the method set
//! (`GET`, `POST`), strict percent-decoding, DID URLs, query options, network
//! policy, the 500 categories, the 410 shape). Each test's doc quotes the `it()` title and its
//! `file:line` at the pin.
//!
//! Every test calls `handle` directly against a scripted `Resolve`: no port,
//! no thread, no network. A row that must be rejected before resolution uses a
//! resolver that panics if reached.

use std::num::{NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};

use did_btcr2::document::{
    Document, DocumentMetadata, InitialDocument, ResolutionMetadata, ResolutionOptions,
    ResolutionResult,
};
use did_btcr2::identifier::Did;
use did_btcr2_resolver_http::{Request, Resolve, Response, handle};
use serde_json::{Value, json};

/// A regtest key-based DID; the scripted resolver never touches a network.
const VALID_DID: &str = "did:btcr2:k1qgpakaw4lwemekywf0lyth9hf6j8r2td7gqtrs4aztqfky50jnx7s8gfapup6";
const FULL: &str = "application/did-resolution";

const INVALID_DID: &str = "https://www.w3.org/ns/did#INVALID_DID";
const INVALID_OPTIONS: &str = "https://www.w3.org/ns/did#INVALID_OPTIONS";
const NOT_FOUND: &str = "https://www.w3.org/ns/did#NOT_FOUND";
const METHOD_NOT_SUPPORTED: &str = "https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED";
const FEATURE_NOT_SUPPORTED: &str = "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED";
const REPRESENTATION_NOT_SUPPORTED: &str = "https://www.w3.org/ns/did#REPRESENTATION_NOT_SUPPORTED";
const INTERNAL_ERROR: &str = "https://www.w3.org/ns/did#INTERNAL_ERROR";

type ResolveFn = dyn Fn(&Did, ResolutionOptions) -> Result<ResolutionResult, did_btcr2_client::Error>
    + Send
    + Sync;

/// A scripted resolver: the closure IS the script.
#[derive(Clone)]
struct Scripted(Arc<ResolveFn>);

impl Resolve for Scripted {
    fn resolve(
        &self,
        did: &Did,
        opts: ResolutionOptions,
    ) -> Result<ResolutionResult, did_btcr2_client::Error> {
        (self.0)(did, opts)
    }
}

/// A resolver the request must never reach.
struct Untouchable;

impl Resolve for Untouchable {
    fn resolve(
        &self,
        did: &Did,
        _: ResolutionOptions,
    ) -> Result<ResolutionResult, did_btcr2_client::Error> {
        panic!(
            "the resolver must not be reached for this request (did {})",
            did.encode()
        )
    }
}

/// The initial document of a key-based DID as a resolution result, with the
/// core's `contentType` and a version-1 metadata triple.
fn ok_result(did: &Did, deactivated: bool) -> ResolutionResult {
    let document = Document::from(
        InitialDocument::from_did(did, &ResolutionOptions::default())
            .expect("a k1 DID generates its initial document"),
    );
    let mut resolution_metadata = ResolutionMetadata::default();
    resolution_metadata.content_type = Some("application/did".to_string());
    ResolutionResult {
        resolution_metadata,
        document,
        document_metadata: DocumentMetadata {
            version_id: NonZeroU64::MIN,
            confirmations: Some(0),
            deactivated,
            updated: None,
        },
    }
}

fn ok() -> Scripted {
    Scripted(Arc::new(|did, _| Ok(ok_result(did, false))))
}

fn deactivated() -> Scripted {
    Scripted(Arc::new(|did, _| Ok(ok_result(did, true))))
}

fn failing(make: impl Fn() -> did_btcr2_client::Error + Send + Sync + 'static) -> Scripted {
    Scripted(Arc::new(move |_, _| Err(make())))
}

/// What a recording resolver saw: `opts.accept`, `opts.version_id`, `opts.min_conf`.
type Recorded = Arc<Mutex<Vec<(Option<String>, Option<NonZeroU64>, Option<NonZeroU32>)>>>;

/// A resolver that records the options it was handed, then answers `ok`.
fn recording() -> (Scripted, Recorded) {
    let seen: Recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let resolver = Scripted(Arc::new(move |did, opts| {
        sink.lock().expect("recorder lock").push((
            opts.accept.clone(),
            opts.version_id,
            opts.min_conf,
        ));
        Ok(ok_result(did, false))
    }));
    (resolver, seen)
}

/// A GET request. The request-target is split on the first `?` exactly as
/// the `tiny_http` shell splits it, so a raw `?` is the query string here too.
fn get(path: &str, headers: &[(&str, &str)]) -> Request {
    request("GET", path, headers)
}

fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
    let (path, query) = path
        .split_once('?')
        .map(|(p, q)| (p.to_string(), Some(q.to_string())))
        .unwrap_or((path.to_string(), None));
    Request {
        method: method.to_string(),
        path,
        query,
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: Vec::new(),
    }
}

fn resolve_path(did: &str) -> String {
    format!("/1.0/identifiers/{did}")
}

fn full(path: &str) -> Request {
    get(path, &[("Accept", FULL)])
}

fn body(resp: &Response) -> Value {
    serde_json::from_slice(&resp.body).expect("body is JSON")
}

fn body_text(resp: &Response) -> &str {
    std::str::from_utf8(&resp.body).expect("body is UTF-8")
}

fn content_type(resp: &Response) -> &str {
    resp.headers
        .iter()
        .find(|(k, _)| *k == "Content-Type")
        .map(|(_, v)| v.as_str())
        .expect("Content-Type present")
}

fn vary(resp: &Response) -> Option<&str> {
    resp.headers
        .iter()
        .find(|(k, _)| *k == "Vary")
        .map(|(_, v)| v.as_str())
}

fn error_type(resp: &Response) -> String {
    body(resp)["didResolutionMetadata"]["error"]["type"]
        .as_str()
        .expect("error.type is a string")
        .to_string()
}

fn error_detail(resp: &Response) -> String {
    body(resp)["didResolutionMetadata"]["error"]["detail"]
        .as_str()
        .expect("error.detail is a string")
        .to_string()
}

/// assertions.js:20-37 `checkErrorResolutionResult` — the shape every
/// 4xx/5xx body must satisfy, plus the binding's `Content-Type` rule.
fn assert_error_result(resp: &Response, expected_type: &str) {
    let b = body(resp);
    assert!(b.is_object());
    assert!(b["didResolutionMetadata"].is_object(), "{b}");
    assert!(b["didResolutionMetadata"]["error"].is_object(), "{b}");
    assert!(
        b["didResolutionMetadata"]["error"]["type"].is_string(),
        "{b}"
    );
    assert_eq!(b["didResolutionMetadata"]["error"]["type"], expected_type);
    assert!(
        b.get("didDocument").is_some() && b["didDocument"].is_null(),
        "didDocument must be present and null: {b}"
    );
    assert!(b["didDocumentMetadata"].is_object(), "{b}");
    assert_eq!(b["didDocumentMetadata"], json!({}));
    assert_eq!(content_type(resp), FULL);
}

/// assertions.js:9-18 `checkSuccessfulResolutionResult` — the success shape
/// (the `did-schema.json` validation it also runs has its own test).
fn assert_success_result(resp: &Response) {
    let b = body(resp);
    assert!(b.is_object());
    assert!(b["didResolutionMetadata"].is_object(), "{b}");
    assert!(b["didDocument"].is_object(), "{b}");
    assert!(b["didDocumentMetadata"].is_object(), "{b}");
}

// ---------------------------------------------------------------------------
// 4-did-resolution.js — successful resolution
// ---------------------------------------------------------------------------

/// 4-did-resolution.js:32 "All conformant DID resolvers MUST implement the
/// DID resolution function for at least one DID method".
#[test]
fn get_with_accept_did_resolution_returns_200_and_the_result_triple() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &ok());
    assert_eq!(resp.status, 200);
    assert_eq!(content_type(&resp), FULL);
    assert_success_result(&resp);
    let b = body(&resp);
    assert_eq!(
        b["didResolutionMetadata"],
        json!({ "contentType": "application/did" })
    );
    assert_eq!(b["didDocument"]["id"], VALID_DID);
    assert_eq!(b["didDocumentMetadata"]["deactivated"], false);
    assert_eq!(b["didDocumentMetadata"]["versionId"], "1");
    assert!(resp.diagnostic.is_none());
}

/// 4-did-resolution.js:52 "The didResolutionMetadata structure is REQUIRED."
#[test]
fn result_has_did_resolution_metadata() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &ok());
    assert_eq!(resp.status, 200);
    let b = body(&resp);
    assert!(b.get("didResolutionMetadata").is_some());
    assert!(b["didResolutionMetadata"].is_object());
}

/// 4-did-resolution.js:62 "If resolution is successful, the didDocument MUST
/// be a conformant DID document".
#[test]
fn successful_result_carries_a_did_document() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &ok());
    assert_eq!(resp.status, 200);
    let b = body(&resp);
    assert!(b.get("didDocument").is_some());
    assert!(b["didDocument"].is_object());
    assert!(b["didDocument"]["@context"].is_array());
    assert!(b["didDocument"]["verificationMethod"].is_array());
}

/// 4-did-resolution.js:72 "The value of id in the resolved DID document MUST
/// match the DID that was resolved" — for the raw and the percent-encoded
/// request forms alike; the `id` is the decoded input.
#[test]
fn did_document_id_equals_the_requested_did_for_raw_and_encoded_forms() {
    let encoded = VALID_DID.replace(':', "%3A");
    assert_ne!(encoded, VALID_DID);
    for form in [VALID_DID.to_string(), encoded] {
        let resp = handle(&full(&resolve_path(&form)), &ok());
        assert_eq!(resp.status, 200, "{form}");
        assert_eq!(body(&resp)["didDocument"]["id"], VALID_DID, "{form}");
    }
}

/// 4-did-resolution.js:83 "If the resolution is successful, the
/// `didDocumentMetadata` MUST be a metadata structure".
#[test]
fn successful_result_has_did_document_metadata_object() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &ok());
    assert_eq!(resp.status, 200);
    let b = body(&resp);
    assert!(b.get("didDocumentMetadata").is_some());
    assert!(b["didDocumentMetadata"].is_object());
}

// ---------------------------------------------------------------------------
// 10-bindings.js — successful resolution over the GET binding
// ---------------------------------------------------------------------------

/// 10-bindings.js:66 "All conforming DID resolvers MUST implement the GET
/// version of the HTTPS binding".
#[test]
fn explicit_get_returns_200() {
    let req = request("GET", &resolve_path(VALID_DID), &[("Accept", FULL)]);
    let resp = handle(&req, &ok());
    assert_eq!(resp.status, 200);
}

/// 10-bindings.js:80 "If Accept is application/did-resolution, HTTP body MUST
/// contain a DID resolution result".
#[test]
fn accept_did_resolution_body_is_a_resolution_result() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &ok());
    assert_eq!(resp.status, 200);
    assert_success_result(&resp);
}

/// 10-bindings.js:94 "If function is successful and returns a didDocument,
/// HTTP response status code MUST be 200".
#[test]
fn successful_resolution_status_is_200() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &ok());
    assert_eq!(resp.status, 200);
}

/// 10-bindings.js:107 "HTTP response MUST contain a Content-Type header whose
/// value MUST equal contentType in didResolutionMetadata". The suite asserts
/// `include`, and the exact pair is `application/did-resolution` over
/// `application/did` (the §12.2.1 example shape).
#[test]
fn content_type_header_contains_did_resolution_metadata_content_type() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &ok());
    assert_eq!(resp.status, 200);
    let header = content_type(&resp);
    let b = body(&resp);
    let content_type_property = b["didResolutionMetadata"]["contentType"]
        .as_str()
        .expect("contentType is present and a string");
    assert!(
        header.contains(content_type_property),
        "{header} should include {content_type_property}"
    );
    assert_eq!(header, "application/did-resolution");
    assert_eq!(content_type_property, "application/did");
}

/// 10-bindings.js:130 "HTTP response body MUST contain the didDocument result
/// of the DID resolution function".
#[test]
fn full_result_body_contains_the_did_document() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &ok());
    assert_eq!(resp.status, 200);
    let b = body(&resp);
    assert!(b.get("didDocument").is_some());
    assert!(b["didDocument"].is_object());
}

/// 10-bindings.js:146 "If Accept is set to a DID representation media type,
/// response body MUST contain only the didDocument (not the full resolution
/// result)" — both types the suite tries, plus `application/did`.
#[test]
fn did_representation_accept_returns_only_the_document() {
    for media_type in [
        "application/did+json",
        "application/did+ld+json",
        "application/did",
    ] {
        let resp = handle(
            &get(&resolve_path(VALID_DID), &[("Accept", media_type)]),
            &ok(),
        );
        assert_eq!(resp.status, 200, "{media_type}");
        assert_eq!(content_type(&resp), media_type);
        assert_eq!(vary(&resp), Some("Accept"), "{media_type}");
        let b = body(&resp);
        assert!(b.get("id").is_some(), "{media_type}: {b}");
        assert_eq!(b["id"], VALID_DID);
        assert!(
            b.get("didResolutionMetadata").is_none(),
            "{media_type}: {b}"
        );
        assert!(b.get("didDocument").is_none(), "{media_type}: {b}");
    }
}

/// 10-bindings.js:178 "GET binding: resolver MUST accept URL-encoded DIDs
/// (required because clients MUST URL-encode when resolution options other
/// than accept are provided)" — the suite appends the configured options, so
/// the encoded form carries `?versionId=1` here.
#[test]
fn percent_encoded_did_resolves_like_the_raw_form() {
    let encoded = VALID_DID.replace(':', "%3A");
    let raw = handle(
        &full(&format!("{}?versionId=1", resolve_path(VALID_DID))),
        &ok(),
    );
    let enc = handle(
        &full(&format!("{}?versionId=1", resolve_path(&encoded))),
        &ok(),
    );
    assert_eq!(enc.status, 200);
    assert_success_result(&enc);
    assert_eq!(enc.body, raw.body);
    assert_eq!(enc.headers, raw.headers);
}

// ---------------------------------------------------------------------------
// assertions.js — the two result-shape helpers
// ---------------------------------------------------------------------------

/// assertions.js:9 `checkSuccessfulResolutionResult`: an object with
/// `didResolutionMetadata` (object), `didDocument` (object) and
/// `didDocumentMetadata` (object).
#[test]
fn success_result_shape_matches_check_successful_resolution_result() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &ok());
    assert_success_result(&resp);
}

/// assertions.js:20 `checkErrorResolutionResult`: `didResolutionMetadata.error`
/// is an object with a `type`, `didDocument` is present and null,
/// `didDocumentMetadata` is an object — checked through `did:example`.
#[test]
fn error_result_shape_matches_check_error_resolution_result() {
    let resp = handle(&full(&resolve_path("did:example")), &Untouchable);
    assert_eq!(resp.status, 400);
    assert_error_result(&resp, INVALID_DID);
    assert!(body_text(&resp).contains("\"didDocument\":null"));
}

// ---------------------------------------------------------------------------
// Accept negotiation and options plumbing — the binding's own rules
// ---------------------------------------------------------------------------

/// No `Accept` header and `Accept: */*` both select the full result, byte for
/// byte the same as an explicit `application/did-resolution`. All three carry
/// `Vary: Accept`: the body was chosen from the header (or its absence), so a
/// shared cache must key on it.
#[test]
fn absent_and_wildcard_accept_return_the_full_result() {
    let explicit = handle(&full(&resolve_path(VALID_DID)), &ok());
    let absent = handle(&get(&resolve_path(VALID_DID), &[]), &ok());
    let wildcard = handle(&get(&resolve_path(VALID_DID), &[("Accept", "*/*")]), &ok());
    assert_eq!(vary(&explicit), Some("Accept"));
    for (name, resp) in [("absent", &absent), ("*/*", &wildcard)] {
        assert_eq!(resp.status, 200, "{name}");
        assert_eq!(content_type(resp), FULL, "{name}");
        assert_eq!(vary(resp), Some("Accept"), "{name}");
        assert_eq!(resp.body, explicit.body, "{name}");
        assert_success_result(resp);
    }
}

/// The full result asks the core for an `application/did` document; a bare
/// representation asks for exactly the negotiated type.
#[test]
fn full_mode_sets_opts_accept_application_did_and_bare_mode_echoes_type() {
    let (resolver, seen) = recording();
    handle(&full(&resolve_path(VALID_DID)), &resolver);
    handle(&get(&resolve_path(VALID_DID), &[]), &resolver);
    handle(
        &get(
            &resolve_path(VALID_DID),
            &[("Accept", "application/did+ld+json")],
        ),
        &resolver,
    );
    handle(
        &get(
            &resolve_path(VALID_DID),
            &[("Accept", "application/did+json")],
        ),
        &resolver,
    );
    let seen = seen.lock().expect("recorder lock");
    let accepts: Vec<Option<&str>> = seen.iter().map(|(a, _, _)| a.as_deref()).collect();
    assert_eq!(
        accepts,
        [
            Some("application/did"),
            Some("application/did"),
            Some("application/did+ld+json"),
            Some("application/did+json"),
        ]
    );
}

/// Header names are case-insensitive, and several `Accept` fields combine as
/// one comma-separated list (RFC 9110 §5.3).
#[test]
fn accept_header_name_is_case_insensitive_and_multiple_values_join() {
    for name in ["accept", "ACCEPT", "Accept"] {
        let resp = handle(
            &get(&resolve_path(VALID_DID), &[(name, "application/did+json")]),
            &ok(),
        );
        assert_eq!(resp.status, 200, "{name}");
        assert_eq!(content_type(&resp), "application/did+json", "{name}");
    }
    let resp = handle(
        &get(
            &resolve_path(VALID_DID),
            &[
                ("Accept", "application/x-nope"),
                ("Accept", "application/did+json"),
            ],
        ),
        &ok(),
    );
    assert_eq!(resp.status, 200);
    assert_eq!(content_type(&resp), "application/did+json");
}

/// `versionId` and `minConf` reach the resolver as typed options.
#[test]
fn options_reach_the_resolver_typed() {
    let (resolver, seen) = recording();
    let resp = handle(
        &full(&format!(
            "{}?versionId=2&minConf=1",
            resolve_path(VALID_DID)
        )),
        &resolver,
    );
    assert_eq!(resp.status, 200);
    let seen = seen.lock().expect("recorder lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1, NonZeroU64::new(2));
    assert_eq!(seen[0].2, NonZeroU32::new(1));
}

/// 10-bindings.js:246 "REPRESENTATION_NOT_SUPPORTED error MUST map to HTTP
/// status 406" — the resolver is never consulted, and the detail lists the
/// four media types on offer.
#[test]
fn unsupported_representation_maps_to_406() {
    let resp = handle(
        &get(
            &resolve_path(VALID_DID),
            &[(
                "Accept",
                "application/x-unsupported-did-representation-99999",
            )],
        ),
        &Untouchable,
    );
    assert_eq!(resp.status, 406);
    assert_error_result(&resp, REPRESENTATION_NOT_SUPPORTED);
    assert_eq!(
        vary(&resp),
        Some("Accept"),
        "the 406 is a function of Accept"
    );
    let detail = error_detail(&resp);
    for offered in [
        "application/did-resolution",
        "application/did",
        "application/did+json",
        "application/did+ld+json",
    ] {
        assert!(detail.contains(offered), "{detail} lacks {offered}");
    }
    assert!(resp.diagnostic.is_none());
}

// ---------------------------------------------------------------------------
// 4-did-resolution.js — error rows
// ---------------------------------------------------------------------------

/// 4-did-resolution.js:95 "The did input to the resolve function is
/// REQUIRED" — `GET /1.0/identifiers/` is a 400 `INVALID_DID` problem body;
/// the resolver is never consulted.
#[test]
fn empty_did_segment_is_400_invalid_did() {
    let resp = handle(&full("/1.0/identifiers/"), &Untouchable);
    assert_eq!(resp.status, 400);
    assert_error_result(&resp, INVALID_DID);
    assert!(error_detail(&resp).contains("empty"));
}

/// 4-did-resolution.js:108 "The did input value MUST be a conformant DID as
/// defined in Decentralized Identifiers (DIDs) v1.0." — both suite inputs.
#[test]
fn not_a_did_and_did_example_are_rejected() {
    for bad in ["not-a-did", "did:example"] {
        let resp = handle(&full(&resolve_path(bad)), &Untouchable);
        assert!(!(200..300).contains(&resp.status), "{bad}: {}", resp.status);
        assert_eq!(resp.status, 400, "{bad}");
    }
}

/// 4-did-resolution.js:116 "Produces a INVALID_DID error and conformant
/// resolution result".
#[test]
fn bad_dids_produce_invalid_did_error_resolution_result() {
    for bad in ["not-a-did", "did:example"] {
        let resp = handle(&full(&resolve_path(bad)), &Untouchable);
        assert_eq!(resp.status, 400, "{bad}");
        assert_error_result(&resp, INVALID_DID);
    }
}

/// 4-did-resolution.js:126 "The error property in DID Document Metadata is
/// REQUIRED when there is an error in the resolution process."
#[test]
fn error_result_carries_the_error_property() {
    for bad in ["not-a-did", "did:example"] {
        let resp = handle(&full(&resolve_path(bad)), &Untouchable);
        let b = body(&resp);
        assert!(b.get("didResolutionMetadata").is_some(), "{bad}");
        assert!(
            b["didResolutionMetadata"].get("error").is_some(),
            "{bad}: {b}"
        );
        assert!(b["didResolutionMetadata"]["error"]["title"].is_string());
        assert!(b["didResolutionMetadata"]["error"]["detail"].is_string());
    }
}

/// 4-did-resolution.js:139 "If the resolution is unsuccessful, the
/// `didDocumentMetadata` output MUST be an empty metadata structure".
#[test]
fn error_result_did_document_metadata_is_an_empty_object() {
    for bad in ["not-a-did", "did:example"] {
        let resp = handle(&full(&resolve_path(bad)), &Untouchable);
        let b = body(&resp);
        assert!(b.get("didDocumentMetadata").is_some(), "{bad}");
        assert_eq!(b["didDocumentMetadata"], json!({}), "{bad}");
    }
}

/// 4-did-resolution.js:154 "If the DID method is not supported, produces a
/// METHOD_NOT_SUPPORTED error and conformant resolution result".
#[test]
fn unsupported_method_produces_method_not_supported_501() {
    let resp = handle(
        &full(&resolve_path("did:unsupported:123456789abcdefghi")),
        &Untouchable,
    );
    assert_eq!(resp.status, 501);
    assert_error_result(&resp, METHOD_NOT_SUPPORTED);
    assert!(error_detail(&resp).contains("unsupported"));
}

// ---------------------------------------------------------------------------
// 10-bindings.js — the error -> status table
// ---------------------------------------------------------------------------

/// 10-bindings.js:200 "INVALID_DID error MUST map to HTTP status 400
/// (input: "not-a-did")" and "(input: "did:example")".
#[test]
fn invalid_did_maps_to_400() {
    for bad in ["not-a-did", "did:example"] {
        let resp = handle(&full(&resolve_path(bad)), &Untouchable);
        assert_eq!(resp.status, 400, "{bad}");
        assert_eq!(error_type(&resp), INVALID_DID, "{bad}");
    }
}

/// 10-bindings.js:213 "METHOD_NOT_SUPPORTED error MUST map to HTTP status 501".
#[test]
fn method_not_supported_maps_to_501() {
    let resp = handle(
        &full(&resolve_path("did:unsupported:123456789abcdefghi")),
        &Untouchable,
    );
    assert_eq!(resp.status, 501);
    assert_eq!(error_type(&resp), METHOD_NOT_SUPPORTED);
    assert_error_result(&resp, METHOD_NOT_SUPPORTED);
}

/// 10-bindings.js:232 "NOT_FOUND error MUST map to HTTP status 404" —
/// through every wrapping the facade emits for a `NotFound`:
/// - `Error::Core(document::Error::Btcr2Error(NotFound))`: genesis-document
///   retrieval inside `InitialDocument::from_did` (`document.rs`, the
///   `Btcr2Error::NotFound` return in `from_did`);
/// - `Error::Resolver(resolver::Error::Btcr2Error(NotFound))`: the resolver
///   FSM (`resolver.rs`, the `Error::Btcr2Error(Btcr2Error::NotFound(..))`
///   return while stepping);
/// - bare `Error::Btcr2(NotFound)`: the facade's direct `From` conversion.
///
/// Each row is a 404 with `#NOT_FOUND` and the error-result shape.
#[test]
fn not_found_maps_to_404() {
    use did_btcr2::error::Btcr2Error;
    use did_btcr2_client::Error;
    let rows: [(&str, Scripted); 3] = [
        (
            "Error::Core(document::Error::Btcr2Error(NotFound)) — genesis retrieval",
            failing(|| {
                Error::Core(did_btcr2::document::Error::Btcr2Error(
                    Btcr2Error::NotFound("no genesis document".into()),
                ))
            }),
        ),
        (
            "Error::Resolver(resolver::Error::Btcr2Error(NotFound)) — resolver step",
            failing(|| {
                Error::Resolver(did_btcr2::resolver::Error::Btcr2Error(
                    Btcr2Error::NotFound("no genesis document".into()),
                ))
            }),
        ),
        (
            "Error::Btcr2(NotFound) — bare",
            failing(|| Error::Btcr2(Btcr2Error::NotFound("no genesis document".into()))),
        ),
    ];
    for (name, resolver) in rows {
        let resp = handle(&full(&resolve_path(VALID_DID)), &resolver);
        assert_eq!(resp.status, 404, "{name}");
        assert_eq!(error_type(&resp), NOT_FOUND, "{name}");
        assert_error_result(&resp, NOT_FOUND);
        assert!(resp.diagnostic.is_none(), "{name}: a 404 carries no chain");
    }
}

/// 10-bindings.js:276 "If deactivated metadata property is true, HTTP
/// response status MUST be 410".
#[test]
fn deactivated_document_maps_to_410() {
    let resp = handle(&full(&resolve_path(VALID_DID)), &deactivated());
    assert_eq!(resp.status, 410);
    assert_eq!(content_type(&resp), FULL);
    assert_eq!(body(&resp)["didDocumentMetadata"]["deactivated"], true);
}

/// The method spec's shape (`resolve.md:164`): a deactivated DID resolves to
/// its deactivated document, so the 410 body is the full triple with
/// `didDocument` present as an object, not null — under a bare `Accept` too,
/// since a deactivated result is a resolution result whatever was negotiated.
/// `contentType` names the representation each request negotiated: the
/// binding stamps it from the negotiated mode, exactly as the core stamps it
/// from `resolutionOptions.accept`.
#[test]
fn deactivated_body_carries_the_document_not_null() {
    for (headers, negotiated) in [
        (vec![("Accept", FULL)], "application/did"),
        (
            vec![("Accept", "application/did+json")],
            "application/did+json",
        ),
        (vec![], "application/did"),
    ] {
        let resp = handle(&get(&resolve_path(VALID_DID), &headers), &deactivated());
        assert_eq!(resp.status, 410, "{headers:?}");
        assert_eq!(content_type(&resp), FULL, "{headers:?}");
        let b = body(&resp);
        assert!(b["didDocument"].is_object(), "{headers:?}: {b}");
        assert_eq!(b["didDocument"]["id"], VALID_DID, "{headers:?}");
        assert_eq!(b["didDocumentMetadata"]["deactivated"], true, "{headers:?}");
        assert_eq!(
            b["didResolutionMetadata"],
            json!({ "contentType": negotiated }),
            "{headers:?}"
        );
        assert!(b["didResolutionMetadata"].get("error").is_none());
    }
}

// ---------------------------------------------------------------------------
// Binding-originated rules: route and method
// ---------------------------------------------------------------------------

/// A path outside the one route is a bodiless 404 with no `Content-Type` —
/// nothing reached the resolution function, so there is no resolution result.
#[test]
fn unknown_path_is_plain_404_without_body() {
    for path in ["/nope", "/1.0/identifiers", "/", "/2.0/identifiers/x"] {
        let resp = handle(&full(path), &Untouchable);
        assert_eq!(resp.status, 404, "{path}");
        assert!(resp.body.is_empty(), "{path}");
        assert!(resp.headers.is_empty(), "{path}: {:?}", resp.headers);
        assert!(resp.diagnostic.is_none());
    }
}

/// A method other than GET or POST on the resolver path is a bodiless 405
/// with `Allow: GET, POST`, before any parsing of the DID.
#[test]
fn other_methods_on_resolver_path_are_405_with_allow_get_post() {
    for method in ["HEAD", "PUT", "DELETE"] {
        let resp = handle(
            &request(method, &resolve_path(VALID_DID), &[("Accept", FULL)]),
            &Untouchable,
        );
        assert_eq!(resp.status, 405, "{method}");
        assert_eq!(
            resp.headers,
            vec![("Allow", "GET, POST".to_string())],
            "{method}"
        );
        assert!(resp.body.is_empty(), "{method}");
    }
    // Even a segment that would be rejected as a DID is answered by the
    // method check first.
    let resp = handle(
        &request("PUT", "/1.0/identifiers/not-a-did", &[]),
        &Untouchable,
    );
    assert_eq!(resp.status, 405);
}

// ---------------------------------------------------------------------------
// Binding-originated rules: the DID path segment
// ---------------------------------------------------------------------------

/// A malformed percent-escape (non-hex, truncated, non-UTF-8) is a 400
/// `INVALID_DID` naming percent-encoding, never passed through.
#[test]
fn malformed_percent_encoding_is_400_invalid_did() {
    for segment in ["did%3G", "did%2", "%FF"] {
        let resp = handle(&full(&resolve_path(segment)), &Untouchable);
        assert_eq!(resp.status, 400, "{segment}");
        assert_error_result(&resp, INVALID_DID);
        assert!(
            error_detail(&resp).contains("percent-encoding"),
            "{segment}: {}",
            error_detail(&resp)
        );
    }
}

/// A decoded segment that is a DID URL (a path, query or fragment after the
/// DID) is a 501 `FEATURE_NOT_SUPPORTED` naming DID URL dereferencing.
#[test]
fn did_url_segment_is_501_feature_not_supported() {
    for suffix in ["%2Fpath", "%3Fservice=files", "%23key-0"] {
        let resp = handle(
            &full(&resolve_path(&format!("{VALID_DID}{suffix}"))),
            &Untouchable,
        );
        assert_eq!(resp.status, 501, "{suffix}");
        assert_error_result(&resp, FEATURE_NOT_SUPPORTED);
        assert!(
            error_detail(&resp).contains("DID URL dereferencing"),
            "{suffix}: {}",
            error_detail(&resp)
        );
    }
}

/// A raw `?` on the request-target is the query string, not part of the DID:
/// the shell and this suite both split the request-target on the first `?`,
/// so `{VALID_DID}?service=files` is a valid DID with an unknown option (400
/// `INVALID_OPTIONS` naming `service`). Only the percent-encoded `%3F` form
/// reaches the DID-URL arm.
#[test]
fn raw_query_on_the_resolver_path_is_options_not_a_did_url() {
    let resp = handle(
        &full(&format!("{}?service=files", resolve_path(VALID_DID))),
        &Untouchable,
    );
    assert_eq!(resp.status, 400);
    assert_error_result(&resp, INVALID_OPTIONS);
    assert!(
        error_detail(&resp).contains("service"),
        "{}",
        error_detail(&resp)
    );
}

/// The path segment is decoded exactly once, so a double-encoded DID is an
/// invalid DID — by two different mechanisms:
/// - `{VALID_DID}%253A` decodes to `…%3A`, passes the ABNF as `pct-encoded`,
///   and fails the bech32 layer (`%` is not in the charset);
/// - `did%253Abtcr2%253Ak1…` decodes to `did%3Abtcr2%3A…`, which fails the
///   `did:` prefix check before any method-specific parsing.
///
/// Both are 400 `INVALID_DID`; neither reaches the resolver.
#[test]
fn double_encoded_did_decodes_once_and_fails_as_invalid_did() {
    let inside_msid = format!("{VALID_DID}%253A");
    let leading = VALID_DID.replace(':', "%253A");
    assert!(leading.starts_with("did%253Abtcr2%253Ak1"));
    for (name, segment) in [("inside the msid", inside_msid), ("leading", leading)] {
        let resp = handle(&full(&resolve_path(&segment)), &Untouchable);
        assert_eq!(resp.status, 400, "{name}");
        assert_error_result(&resp, INVALID_DID);
        assert!(
            !error_detail(&resp).contains("DID URL"),
            "{name}: a double-encoded DID is not a DID URL"
        );
    }
}

// ---------------------------------------------------------------------------
// Binding-originated rules: query options
// ---------------------------------------------------------------------------

/// A malformed, zero, unknown or header-only option is a 400
/// `INVALID_OPTIONS` naming the parameter; the resolver is never consulted.
#[test]
fn invalid_options_rows_are_400() {
    for (query, name) in [
        ("versionId=abc", "versionId"),
        ("versionId=0", "versionId"),
        ("minConf=0", "minConf"),
        ("versionTime=yesterday", "versionTime"),
        ("foo=1", "foo"),
        ("accept=application/did", "accept"),
        ("noCache=1", "noCache"),
        ("noCache=", "noCache"),
    ] {
        let resp = handle(
            &full(&format!("{}?{query}", resolve_path(VALID_DID))),
            &Untouchable,
        );
        assert_eq!(resp.status, 400, "{query}");
        assert_error_result(&resp, INVALID_OPTIONS);
        assert!(
            error_detail(&resp).contains(name),
            "{query}: {}",
            error_detail(&resp)
        );
    }
}

/// DID Resolution §13.2: `noCache=false` is the default ("caching of DID
/// documents is allowed"), so a request that spells it out resolves exactly
/// as one that omits it — 200, the resolver reached with default options.
#[test]
fn no_cache_false_is_the_default_and_resolves() {
    let (resolver, seen) = recording();
    let resp = handle(
        &full(&format!("{}?noCache=false", resolve_path(VALID_DID))),
        &resolver,
    );
    assert_eq!(resp.status, 200);
    assert_eq!(content_type(&resp), FULL);
    assert_success_result(&resp);
    assert_eq!(body(&resp)["didDocument"]["id"], VALID_DID);
    let seen = seen.lock().expect("recorder lock");
    assert_eq!(seen.len(), 1, "the resolver was reached once");
    assert_eq!(seen[0], (Some("application/did".to_string()), None, None));
}

/// `versionId` and `versionTime` together are a 400 `INVALID_OPTIONS` decided
/// by the binding alone: the resolver — and so the Bitcoin backend the
/// production resolver contacts before the core's own check — is never
/// reached, and the detail is the core's text so both checks read the same.
#[test]
fn version_id_with_version_time_is_400_before_the_resolver_is_reached() {
    for query in [
        "versionId=1&versionTime=2026-01-02T03:04:05Z",
        "versionTime=2026-01-02T03:04:05Z&versionId=1",
    ] {
        let resp = handle(
            &full(&format!("{}?{query}", resolve_path(VALID_DID))),
            &Untouchable,
        );
        assert_eq!(resp.status, 400, "{query}");
        assert_error_result(&resp, INVALID_OPTIONS);
        assert_eq!(
            error_detail(&resp),
            "versionId and versionTime are mutually exclusive; supply at most one",
            "{query}"
        );
        assert!(resp.diagnostic.is_none(), "{query}");
    }
}

/// The registered options this resolver does not implement are a 501
/// `FEATURE_NOT_SUPPORTED` naming the option: the `noCache=true` bypass
/// (DID Resolution §13.2, the MUST for a resolver that denies resolution
/// without caching) and `expandRelativeUrls` for any value.
#[test]
fn unsupported_registered_options_are_501() {
    for (query, name) in [
        ("noCache=true", "noCache"),
        ("versionId=1&noCache=true", "noCache"),
        ("expandRelativeUrls=true", "expandRelativeUrls"),
        ("expandRelativeUrls=false", "expandRelativeUrls"),
    ] {
        let resp = handle(
            &full(&format!("{}?{query}", resolve_path(VALID_DID))),
            &Untouchable,
        );
        assert_eq!(resp.status, 501, "{query}");
        assert_error_result(&resp, FEATURE_NOT_SUPPORTED);
        assert!(
            error_detail(&resp).contains(name),
            "{query}: {}",
            error_detail(&resp)
        );
    }
}

// ---------------------------------------------------------------------------
// Binding-originated rules: what the resolver reports back
// ---------------------------------------------------------------------------

/// A DID on a network with no configured Esplora endpoint is a 501
/// `FEATURE_NOT_SUPPORTED` naming the network — not a 500.
#[test]
fn network_without_endpoint_is_501_feature_not_supported() {
    let resp = handle(
        &full(&resolve_path(VALID_DID)),
        &failing(|| did_btcr2_client::Error::NoDefaultEndpoint("regtest")),
    );
    assert_eq!(resp.status, 501);
    assert_error_result(&resp, FEATURE_NOT_SUPPORTED);
    assert!(
        error_detail(&resp).contains("regtest"),
        "{}",
        error_detail(&resp)
    );
    assert!(resp.diagnostic.is_none());
}

/// A transport failure is a 500 `INTERNAL_ERROR` whose detail is a category
/// only: what the backend said stays out of the body and goes to the
/// operator-only diagnostic.
#[test]
fn transport_failures_are_500_with_category_only_detail() {
    use did_btcr2_client::{Error, TransportError};
    let rows: [(&str, &str, &str, Scripted); 3] = [
        (
            "Transport(Malformed)",
            "secret body",
            "the Bitcoin backend returned a malformed response",
            failing(|| Error::Transport(TransportError::Malformed("secret body".into()))),
        ),
        (
            "Transport(Status)",
            "upstream-secret",
            "the Bitcoin backend returned an error response",
            failing(|| {
                Error::Transport(TransportError::Status {
                    status: 502,
                    body: "upstream-secret".into(),
                })
            }),
        ),
        (
            "Json",
            "line 1",
            "the Bitcoin backend returned a malformed response",
            failing(|| Error::Json(serde_json::from_str::<Value>("{").unwrap_err())),
        ),
    ];
    for (name, secret, category, resolver) in rows {
        let resp = handle(&full(&resolve_path(VALID_DID)), &resolver);
        assert_eq!(resp.status, 500, "{name}");
        assert_error_result(&resp, INTERNAL_ERROR);
        assert_eq!(error_detail(&resp), category, "{name}");
        assert!(
            !body_text(&resp).contains(secret),
            "{name}: the body leaks `{secret}`: {}",
            body_text(&resp)
        );
        let diagnostic = resp
            .diagnostic
            .as_deref()
            .unwrap_or_else(|| panic!("{name}: a 500 carries its chain"));
        assert!(
            diagnostic.contains(secret),
            "{name}: the diagnostic lacks `{secret}`: {diagnostic}"
        );
    }
}

/// A facade error that is not a resolution outcome (here: an unknown network
/// name) is a 500 `INTERNAL_ERROR` with the generic category.
#[test]
fn unknown_client_errors_are_500_internal_error() {
    let resp = handle(
        &full(&resolve_path(VALID_DID)),
        &failing(|| did_btcr2_client::Error::UnknownNetwork("x".into())),
    );
    assert_eq!(resp.status, 500);
    assert_error_result(&resp, INTERNAL_ERROR);
    assert_eq!(error_detail(&resp), "the resolver failed internally");
    let diagnostic = resp.diagnostic.expect("a 500 carries its chain");
    assert!(diagnostic.contains("unknown network 'x'"), "{diagnostic}");
}

/// A method-specific error (a `btcr2.dev`-namespaced type) is a 500 with its
/// type URI, title and detail kept verbatim, and the chain in the diagnostic.
#[test]
fn method_specific_errors_are_500_with_uri_verbatim() {
    use did_btcr2::error::Btcr2Error;
    let resp = handle(
        &full(&resolve_path(VALID_DID)),
        &failing(|| {
            did_btcr2_client::Error::Btcr2(Btcr2Error::LatePublishingError(
                "update 2 was published after update 3".into(),
            ))
        }),
    );
    assert_eq!(resp.status, 500);
    let kind = error_type(&resp);
    assert!(kind.starts_with("https://btcr2.dev/"), "{kind}");
    assert!(kind.ends_with("#LATE_PUBLISHING"), "{kind}");
    assert_error_result(&resp, &kind);
    assert_eq!(error_detail(&resp), "update 2 was published after update 3");
    assert!(resp.diagnostic.is_some());

    // The same through the resolver wrapping: a spec-shaped resolver
    // variant carries its own method-specific details.
    let resp = handle(
        &full(&resolve_path(VALID_DID)),
        &failing(|| {
            did_btcr2_client::Error::Resolver(did_btcr2::resolver::Error::UpdateHashMismatch)
        }),
    );
    assert_eq!(resp.status, 500);
    let kind = error_type(&resp);
    assert!(kind.starts_with("https://btcr2.dev/"), "{kind}");
    assert!(kind.ends_with("#INVALID_DID_UPDATE"), "{kind}");
    assert_error_result(&resp, &kind);
    assert!(resp.diagnostic.is_some());
}

/// Every error response and the 410 is a resolution result, so every one
/// carries `Content-Type: application/did-resolution` — whatever `Accept`
/// asked for. Only the 406 and the 410 also carry `Vary: Accept`: the 406
/// exists because of the header, and the 410 shares the negotiated 200's
/// URL, so a cache must key both on it. The other errors are the same
/// bytes for every `Accept` and carry exactly the one header.
#[test]
fn error_and_410_responses_carry_did_resolution_content_type() {
    let bare = [("Accept", "application/did+json")];
    let rows: Vec<(&str, Response)> = vec![
        (
            "400 empty",
            handle(&get("/1.0/identifiers/", &bare), &Untouchable),
        ),
        (
            "400 invalid",
            handle(&get(&resolve_path("not-a-did"), &bare), &Untouchable),
        ),
        (
            "400 options",
            handle(
                &get(&format!("{}?foo=1", resolve_path(VALID_DID)), &bare),
                &Untouchable,
            ),
        ),
        (
            "404",
            handle(
                &get(&resolve_path(VALID_DID), &bare),
                &failing(|| {
                    did_btcr2_client::Error::Btcr2(did_btcr2::error::Btcr2Error::NotFound(
                        "g".into(),
                    ))
                }),
            ),
        ),
        (
            "406",
            handle(
                &get(&resolve_path(VALID_DID), &[("Accept", "text/html")]),
                &Untouchable,
            ),
        ),
        (
            "410",
            handle(&get(&resolve_path(VALID_DID), &bare), &deactivated()),
        ),
        (
            "500",
            handle(
                &get(&resolve_path(VALID_DID), &bare),
                &failing(|| did_btcr2_client::Error::UnknownNetwork("x".into())),
            ),
        ),
        (
            "501 method",
            handle(
                &get(&resolve_path("did:unsupported:123456789abcdefghi"), &bare),
                &Untouchable,
            ),
        ),
        (
            "501 network",
            handle(
                &get(&resolve_path(VALID_DID), &bare),
                &failing(|| did_btcr2_client::Error::NoDefaultEndpoint("regtest")),
            ),
        ),
    ];
    for (name, resp) in rows {
        assert!(resp.status >= 400, "{name}: {}", resp.status);
        assert_eq!(content_type(&resp), FULL, "{name}");
        let expected: Vec<(&str, String)> = if name == "406" || name == "410" {
            vec![
                ("Content-Type", FULL.to_string()),
                ("Vary", "Accept".to_string()),
            ]
        } else {
            vec![("Content-Type", FULL.to_string())]
        };
        assert_eq!(resp.headers, expected, "{name}");
    }
}

/// An identifier error surfacing from the facade (`Error::Identifier`) is
/// bridged into the resolution vocabulary exactly as the handler's own DID
/// parse is: an unsupported method is 501 `METHOD_NOT_SUPPORTED`, any other
/// parse failure is 400 `INVALID_DID`.
#[test]
fn facade_identifier_errors_bridge_to_the_resolution_vocabulary() {
    use did_btcr2::identifier::Error as IdError;
    use did_btcr2_client::Error;
    let rows: [(&str, u16, &str, Scripted); 2] = [
        (
            "MethodNotSupported",
            501,
            METHOD_NOT_SUPPORTED,
            failing(|| Error::Identifier(IdError::MethodNotSupported("other".into()))),
        ),
        (
            "InvalidDidFormat",
            400,
            INVALID_DID,
            failing(|| Error::Identifier(IdError::InvalidDidFormat("bad".into()))),
        ),
    ];
    for (name, status, kind, resolver) in rows {
        let resp = handle(&full(&resolve_path(VALID_DID)), &resolver);
        assert_eq!(resp.status, status, "{name}");
        assert_error_result(&resp, kind);
        assert!(resp.diagnostic.is_none(), "{name}");
    }
}

/// A `Core` or `Resolver` error that is not a spec-shaped `Btcr2Error` has no
/// problem details of its own, so it is a 500 `INTERNAL_ERROR` with the
/// generic category and its chain in the diagnostic — never a panic.
#[test]
fn non_spec_core_and_resolver_errors_are_500_internal_error() {
    use did_btcr2_client::Error;
    let rows: [(&str, Scripted); 2] = [
        (
            "Core(MissingGenesisKey)",
            failing(|| Error::Core(did_btcr2::document::Error::MissingGenesisKey)),
        ),
        (
            "Resolver(UnrequestedBeaconHistory) — a driver precondition",
            failing(|| {
                Error::Resolver(did_btcr2::resolver::Error::UnrequestedBeaconHistory {
                    address: "bcrt1qexample".into(),
                })
            }),
        ),
    ];
    for (name, resolver) in rows {
        let resp = handle(&full(&resolve_path(VALID_DID)), &resolver);
        assert_eq!(resp.status, 500, "{name}");
        assert_error_result(&resp, INTERNAL_ERROR);
        assert_eq!(
            error_detail(&resp),
            "the resolver failed internally",
            "{name}"
        );
        assert!(resp.diagnostic.is_some(), "{name}");
    }
}
