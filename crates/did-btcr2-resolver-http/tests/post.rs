//! In-process tests for the POST binding: DID Resolution §12.1's HTTP(S) POST
//! form, where every resolution option except `accept` travels as a JSON
//! object in the request body and the did:btcr2 method option `sidecar`
//! carries out-of-band update data.
//!
//! These rows live apart from `conformance.rs` on purpose. POST is a MAY in
//! §12.1 and the pinned W3C suite issues GET only, so a POST row mirrors no
//! `it()` and `guard.rs` (which scans only `conformance.rs` and `schema.rs`
//! for the suite's Covered rows) must not see one. Keeping them here keeps the
//! `CONFORMANCE.md` ledger honest: the binding's own POST rules are tested,
//! but none of them claims a suite row.
//!
//! Every test calls `handle` directly against a scripted `Resolve`: no port,
//! no thread, no network. A row that must be rejected before resolution uses
//! a resolver that panics if reached (`Untouchable`).

use std::num::{NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};

use did_btcr2::document::{
    Document, DocumentMetadata, InitialDocument, ResolutionMetadata, ResolutionOptions,
    ResolutionResult,
};
use did_btcr2::error::Btcr2Error;
use did_btcr2::identifier::{Did, Sha256Hash};
use did_btcr2_resolver_http::{Request, Resolve, Response, handle};
use serde_json::{Value, json};

/// A regtest key-based DID; the scripted resolver never touches a network.
const VALID_DID: &str = "did:btcr2:k1qgpakaw4lwemekywf0lyth9hf6j8r2td7gqtrs4aztqfky50jnx7s8gfapup6";
const FULL: &str = "application/did-resolution";

const INVALID_DID: &str = "https://www.w3.org/ns/did#INVALID_DID";
const INVALID_OPTIONS: &str = "https://www.w3.org/ns/did#INVALID_OPTIONS";
const FEATURE_NOT_SUPPORTED: &str = "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED";
const REPRESENTATION_NOT_SUPPORTED: &str = "https://www.w3.org/ns/did#REPRESENTATION_NOT_SUPPORTED";

/// The minted `clean` scenario: a multi-update chain ending deactivated, with
/// the sidecar its Singleton beacons need. Read at test time — the update
/// count and the expected `versionId` come from the file, never from a
/// literal, so a re-capture on another network keeps these rows honest.
const CLEAN_FIXTURE: &str =
    include_str!("../../../fixtures/chain/minted/clean-rotating-beacons.json");

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

/// What a recording resolver saw: `opts.accept`, `opts.version_id`,
/// `opts.min_conf`, and the sidecar in its wire form (`None` when the body
/// carried none). The sidecar is compared through its serialisation — the
/// core keeps its fields private — so the assertion reads "the resolver
/// received the same `updates` the client sent".
type Seen = (
    Option<String>,
    Option<NonZeroU64>,
    Option<NonZeroU32>,
    Option<Value>,
);
type Recorded = Arc<Mutex<Vec<Seen>>>;

/// A resolver that records the options it was handed, then answers `ok`.
fn recording() -> (Scripted, Recorded) {
    let seen: Recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let resolver = Scripted(Arc::new(move |did, opts| {
        sink.lock().expect("recorder lock").push((
            opts.accept.clone(),
            opts.version_id,
            opts.min_conf,
            opts.sidecar_data
                .as_ref()
                .map(|s| serde_json::to_value(s).expect("sidecar serialises")),
        ));
        Ok(ok_result(did, false))
    }));
    (resolver, seen)
}

/// The request-target is split on the first `?` exactly as the `tiny_http`
/// shell splits it, so a raw `?` is the query string here too.
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

fn get(path: &str, headers: &[(&str, &str)]) -> Request {
    request("GET", path, headers)
}

fn post(path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
    let mut req = request("POST", path, headers);
    req.body = body.to_vec();
    req
}

/// A POST asking for the full resolution result with a JSON body.
fn post_full(path: &str, body: &[u8]) -> Request {
    post(
        path,
        &[("Accept", FULL), ("Content-Type", "application/json")],
        body,
    )
}

fn resolve_path(did: &str) -> String {
    format!("/1.0/identifiers/{did}")
}

fn clean_fixture() -> Value {
    serde_json::from_str(CLEAN_FIXTURE).expect("the minted fixture is JSON")
}

/// The fixture's `sidecar` member: an object with a non-empty `updates` array.
fn clean_sidecar() -> Value {
    let sidecar = clean_fixture()["sidecar"].clone();
    assert!(sidecar.is_object(), "the fixture's sidecar is an object");
    assert!(
        sidecar["updates"].as_array().is_some_and(|u| !u.is_empty()),
        "the fixture's sidecar carries updates"
    );
    sidecar
}

fn body(resp: &Response) -> Value {
    serde_json::from_slice(&resp.body).expect("body is JSON")
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

/// The shape every 4xx/5xx body must satisfy (the suite's
/// `checkErrorResolutionResult`), plus the binding's `Content-Type` rule.
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

/// The success shape (the suite's `checkSuccessfulResolutionResult`).
fn assert_success_result(resp: &Response) {
    let b = body(resp);
    assert!(b.is_object());
    assert!(b["didResolutionMetadata"].is_object(), "{b}");
    assert!(b["didDocument"].is_object(), "{b}");
    assert!(b["didDocumentMetadata"].is_object(), "{b}");
}

// ---------------------------------------------------------------------------
// What reaches the resolver
// ---------------------------------------------------------------------------

/// The body's options reach the resolver typed: `versionId` and `minConf` as
/// their integer types whether the client sent a JSON number or a string of
/// digits (the shape a client that mirrors the query string sends), the
/// sidecar as `SidecarData` whose wire form is the `updates` the client sent,
/// and `accept` from the negotiated representation as for a GET. A sidecar
/// with no members is still a sidecar: its wire form always writes `updates`.
#[test]
fn sidecar_body_reaches_the_resolver_typed() {
    let (resolver, seen) = recording();
    let sidecar = clean_sidecar();

    let payload = json!({ "sidecar": sidecar, "versionId": 2, "minConf": 3 });
    let resp = handle(
        &post_full(&resolve_path(VALID_DID), payload.to_string().as_bytes()),
        &resolver,
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    assert_success_result(&resp);

    let resp = handle(
        &post_full(&resolve_path(VALID_DID), br#"{"sidecar": {}}"#),
        &resolver,
    );
    assert_eq!(resp.status, 200);

    let resp = handle(
        &post_full(
            &resolve_path(VALID_DID),
            br#"{"versionId": "1", "minConf": "6"}"#,
        ),
        &resolver,
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));

    let seen = seen.lock().expect("recorder lock");
    assert_eq!(seen.len(), 3, "the resolver was reached three times");

    let (accept, version_id, min_conf, wire) = &seen[0];
    assert_eq!(accept.as_deref(), Some("application/did"));
    assert_eq!(*version_id, NonZeroU64::new(2));
    assert_eq!(*min_conf, NonZeroU32::new(3));
    let wire = wire.as_ref().expect("the sidecar reached the resolver");
    assert_eq!(wire["updates"], sidecar["updates"]);

    let (_, version_id, min_conf, wire) = &seen[1];
    assert_eq!(*version_id, None);
    assert_eq!(*min_conf, None);
    assert_eq!(*wire, Some(json!({ "updates": [] })));

    let (_, version_id, min_conf, wire) = &seen[2];
    assert_eq!(*version_id, NonZeroU64::new(1));
    assert_eq!(*min_conf, NonZeroU32::new(6));
    assert_eq!(*wire, None);
}

/// Both the raw and the percent-encoded DID path segment are accepted on a
/// POST, as on a GET: the specification's POST example is un-encoded, its
/// GET example encoded.
#[test]
fn post_percent_encoded_did_matches_raw() {
    let payload = json!({ "sidecar": clean_sidecar() }).to_string();
    let raw = handle(
        &post_full(&resolve_path(VALID_DID), payload.as_bytes()),
        &ok(),
    );
    let encoded = handle(
        &post_full(
            &resolve_path(&VALID_DID.replace(':', "%3A")),
            payload.as_bytes(),
        ),
        &ok(),
    );
    assert_eq!(raw.status, 200);
    assert_eq!(encoded.status, 200);
    assert_eq!(body(&raw)["didDocument"]["id"], VALID_DID);
    assert_eq!(body(&encoded)["didDocument"]["id"], VALID_DID);
    assert_eq!(raw, encoded);
}

// ---------------------------------------------------------------------------
// Rejections decided before the resolver
// ---------------------------------------------------------------------------

/// The query string's strictness applies to the body: a body that is not a
/// JSON object, a malformed or zero `versionId`/`minConf` (number or string),
/// `versionId` with `versionTime`, `accept` in the body, an unknown key, a
/// `sidecar` that is not sidecar data — all 400 `INVALID_OPTIONS`;
/// `noCache: true` and `expandRelativeUrls` — 501 `FEATURE_NOT_SUPPORTED`.
/// Every row carries the problem body and never reaches the resolver. The
/// rejected value is never echoed; the controls show a digit string and
/// `noCache: false` are accepted.
#[test]
fn post_rejections_are_400_or_501_before_the_resolver() {
    for (payload, status, type_uri, detail_substring) in [
        ("[]", 400, INVALID_OPTIONS, "JSON object"),
        ("{", 400, INVALID_OPTIONS, "valid JSON"),
        ("{\"versionId\": \"0\"}", 400, INVALID_OPTIONS, "versionId"),
        (
            "{\"versionId\": \"abc\"}",
            400,
            INVALID_OPTIONS,
            "versionId",
        ),
        ("{\"versionId\": \"\"}", 400, INVALID_OPTIONS, "versionId"),
        (
            "{\"versionId\": \"1.5\"}",
            400,
            INVALID_OPTIONS,
            "versionId",
        ),
        ("{\"versionId\": 0}", 400, INVALID_OPTIONS, "versionId"),
        ("{\"minConf\": \"-1\"}", 400, INVALID_OPTIONS, "minConf"),
        (
            "{\"versionId\": 1, \"versionTime\": \"2026-01-02T03:04:05Z\"}",
            400,
            INVALID_OPTIONS,
            "mutually exclusive",
        ),
        (
            "{\"accept\": \"application/did\"}",
            400,
            INVALID_OPTIONS,
            "accept",
        ),
        ("{\"foo\": 1}", 400, INVALID_OPTIONS, "foo"),
        ("{\"sidecar\": 1}", 400, INVALID_OPTIONS, "sidecar"),
        (
            "{\"sidecar\": {\"updates\": [{}]}}",
            400,
            INVALID_OPTIONS,
            "sidecar",
        ),
        ("{\"noCache\": true}", 501, FEATURE_NOT_SUPPORTED, "noCache"),
        (
            "{\"expandRelativeUrls\": true}",
            501,
            FEATURE_NOT_SUPPORTED,
            "expandRelativeUrls",
        ),
    ] {
        let resp = handle(
            &post_full(&resolve_path(VALID_DID), payload.as_bytes()),
            &Untouchable,
        );
        assert_eq!(resp.status, status, "{payload}");
        assert_error_result(&resp, type_uri);
        let detail = error_detail(&resp);
        assert!(
            detail.contains(detail_substring),
            "{payload}: {detail} lacks {detail_substring}"
        );
        assert!(resp.diagnostic.is_none(), "{payload}");
        if payload.contains("abc") {
            assert!(!detail.contains("abc"), "the value is echoed: {detail}");
        }
    }

    // The controls: `noCache: false` is the default and resolves; a digit
    // string is the same `versionId` as the number.
    for payload in [
        "{\"noCache\": false, \"versionId\": 1}",
        "{\"versionId\": \"2\"}",
    ] {
        let resp = handle(
            &post_full(&resolve_path(VALID_DID), payload.as_bytes()),
            &ok(),
        );
        assert_eq!(resp.status, 200, "{payload}");
        assert_success_result(&resp);
    }
}

/// `sidecar` belongs in a POST body; in a GET query string it is an unknown
/// option, 400 `INVALID_OPTIONS`, before the resolver.
#[test]
fn sidecar_in_a_get_query_is_400_invalid_options() {
    let resp = handle(
        &get(
            &format!("{}?sidecar=%7B%7D", resolve_path(VALID_DID)),
            &[("Accept", FULL)],
        ),
        &Untouchable,
    );
    assert_eq!(resp.status, 400);
    assert_error_result(&resp, INVALID_OPTIONS);
    assert!(
        error_detail(&resp).contains("sidecar"),
        "{}",
        error_detail(&resp)
    );
}

/// A POST whose `Content-Type` is neither absent nor JSON is a bodiless 415
/// — a transport-level rejection like the 404/405, with no headers, no body
/// and no diagnostic. No header, `application/json` (with parameters) and a
/// `+json` suffix type are parsed.
#[test]
fn post_content_type_gate_is_bodiless_415() {
    for media_type in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "text/json",
    ] {
        let resp = handle(
            &post(
                &resolve_path(VALID_DID),
                &[("Accept", FULL), ("Content-Type", media_type)],
                b"{}",
            ),
            &Untouchable,
        );
        assert_eq!(resp.status, 415, "{media_type}");
        assert!(resp.headers.is_empty(), "{media_type}: {:?}", resp.headers);
        assert!(resp.body.is_empty(), "{media_type}");
        assert!(resp.diagnostic.is_none(), "{media_type}");
    }

    let accepted: [&[(&str, &str)]; 4] = [
        &[("Accept", FULL)],
        &[("Accept", FULL), ("Content-Type", "application/json")],
        &[
            ("Accept", FULL),
            ("Content-Type", "application/json; charset=utf-8"),
        ],
        &[
            ("Accept", FULL),
            ("Content-Type", "application/did-resolution+json"),
        ],
    ];
    for headers in accepted {
        let resp = handle(&post(&resolve_path(VALID_DID), headers, b"{}"), &ok());
        assert_eq!(resp.status, 200, "{headers:?}");
        assert_success_result(&resp);
    }
}

/// A POST carries its options in the body and nothing in the query string:
/// any query at all — option names, a bare `?`, or the specification's own
/// second POST example, `?service=files&relativeRef=/resume.pdf`, which is a
/// DID URL dereferencing request this binding does not perform (a GET with
/// that query is already `INVALID_OPTIONS`) — is 400 `INVALID_OPTIONS`
/// before the resolver. The same body without a query resolves.
#[test]
fn post_with_query_string_is_400_invalid_options() {
    for query in [
        "?versionId=1",
        "?",
        "?minConf=1&versionId=2",
        "?service=files&relativeRef=/resume.pdf",
    ] {
        let req = post_full(&format!("{}{query}", resolve_path(VALID_DID)), b"{}");
        assert!(req.query.is_some(), "{query}: the query is present");
        let resp = handle(&req, &Untouchable);
        assert_eq!(resp.status, 400, "{query}");
        assert_error_result(&resp, INVALID_OPTIONS);
        assert!(
            error_detail(&resp).contains("query string"),
            "{query}: {}",
            error_detail(&resp)
        );
        assert!(resp.diagnostic.is_none(), "{query}");
    }

    let resp = handle(&post_full(&resolve_path(VALID_DID), b"{}"), &ok());
    assert_eq!(resp.status, 200);
    assert_success_result(&resp);
}

/// An empty body or `{}` resolves with default options — no `versionId`, no
/// `minConf`, no sidecar — and the response is byte for byte the GET's for
/// the same DID over the same resolver.
#[test]
fn post_empty_body_resolves_like_get() {
    let (resolver, seen) = recording();
    let reference = handle(
        &get(&resolve_path(VALID_DID), &[("Accept", FULL)]),
        &resolver,
    );
    assert_eq!(reference.status, 200);

    let bodies: [&[u8]; 2] = [b"", b"{}"];
    for payload in bodies {
        let resp = handle(
            &post(&resolve_path(VALID_DID), &[("Accept", FULL)], payload),
            &resolver,
        );
        assert_eq!(resp.status, 200, "{payload:?}");
        assert_eq!(resp.body, reference.body, "{payload:?}");
        assert_eq!(resp.headers, reference.headers, "{payload:?}");
    }

    let seen = seen.lock().expect("recorder lock");
    assert_eq!(seen.len(), 3, "the GET and both POSTs reached the resolver");
    for (accept, version_id, min_conf, wire) in seen.iter() {
        assert_eq!(accept.as_deref(), Some("application/did"));
        assert_eq!(*version_id, None);
        assert_eq!(*min_conf, None);
        assert_eq!(*wire, None);
    }
}

// ---------------------------------------------------------------------------
// The result's shape after a POST
// ---------------------------------------------------------------------------

/// A deactivated result on a POST is the same 410 as on a GET: the full
/// triple with the document as an object, `application/did-resolution` and
/// `Vary: Accept`, under a bare `Accept` too.
#[test]
fn post_deactivated_result_is_410() {
    let payload = json!({ "sidecar": clean_sidecar() }).to_string();
    for accept in [FULL, "application/did"] {
        let resp = handle(
            &post(
                &resolve_path(VALID_DID),
                &[("Accept", accept), ("Content-Type", "application/json")],
                payload.as_bytes(),
            ),
            &deactivated(),
        );
        assert_eq!(resp.status, 410, "{accept}");
        assert_eq!(content_type(&resp), FULL, "{accept}");
        assert_eq!(vary(&resp), Some("Accept"), "{accept}");
        let b = body(&resp);
        assert!(b["didResolutionMetadata"].is_object(), "{accept}: {b}");
        assert!(b["didDocument"].is_object(), "{accept}: {b}");
        assert_eq!(b["didDocument"]["id"], VALID_DID, "{accept}");
        assert_eq!(b["didDocumentMetadata"]["deactivated"], true, "{accept}");
    }
}

/// `Accept` stays in the header on a POST and negotiates as for a GET: a
/// bare representation is the document alone, an unsupported one is 406
/// `REPRESENTATION_NOT_SUPPORTED` before the resolver. Negotiation runs
/// after the body parsed, so the 406 row's body is valid.
#[test]
fn post_accept_negotiation_applies() {
    let resp = handle(
        &post(
            &resolve_path(VALID_DID),
            &[
                ("Accept", "application/did"),
                ("Content-Type", "application/json"),
            ],
            b"{}",
        ),
        &ok(),
    );
    assert_eq!(resp.status, 200);
    assert_eq!(content_type(&resp), "application/did");
    let b = body(&resp);
    assert_eq!(b["id"], VALID_DID);
    assert!(b.get("didResolutionMetadata").is_none(), "{b}");

    let resp = handle(
        &post(
            &resolve_path(VALID_DID),
            &[
                ("Accept", "text/plain"),
                ("Content-Type", "application/json"),
            ],
            b"{}",
        ),
        &Untouchable,
    );
    assert_eq!(resp.status, 406);
    assert_error_result(&resp, REPRESENTATION_NOT_SUPPORTED);
    assert_eq!(vary(&resp), Some("Accept"));
}

// ---------------------------------------------------------------------------
// The minted fixture's sidecar, and the resolver's own errors
// ---------------------------------------------------------------------------

/// The minted fixture's sidecar survives the binding's parse intact: a
/// resolver that counts the updates it received answers a deactivated result
/// at version `updates + 1`, and that is the `versionId` the fixture's own
/// `expected` block records. The count the log reports is the count the
/// resolver sees.
#[test]
fn clean_fixture_sidecar_resolves_through_the_binding() {
    let fixture = clean_fixture();
    let sidecar = clean_sidecar();
    let updates = sidecar["updates"].as_array().expect("updates").len();
    let expected_version = fixture["expected"]["didDocumentMetadata"]["versionId"]
        .as_str()
        .expect("the fixture's expected versionId is a string")
        .to_string();
    assert_eq!(expected_version, (updates + 1).to_string());

    let resolver = Scripted(Arc::new(|did, opts| {
        let n = serde_json::to_value(opts.sidecar_data.as_ref().expect("sidecar"))
            .expect("sidecar serialises")["updates"]
            .as_array()
            .expect("updates")
            .len();
        let mut r = ok_result(did, true);
        r.document_metadata.version_id = NonZeroU64::new(n as u64 + 1).expect("non-zero");
        Ok(r)
    }));
    let payload = json!({ "sidecar": sidecar }).to_string();
    let resp = handle(
        &post_full(&resolve_path(VALID_DID), payload.as_bytes()),
        &resolver,
    );
    assert_eq!(resp.status, 410);
    let b = body(&resp);
    assert_eq!(b["didDocumentMetadata"]["deactivated"], true);
    assert_eq!(b["didDocumentMetadata"]["versionId"], expected_version);
}

/// A well-formed sidecar that does not verify keeps the GET mapping: an
/// update the resolver could not locate is `MISSING_UPDATE_DATA`, a
/// method-specific error, so a 500 with the type URI verbatim and the hash
/// in the detail; a genesis document that does not match the identifier is
/// `INVALID_DID`, 400.
#[test]
fn post_error_from_the_resolver_keeps_the_get_mapping() {
    let resp = handle(
        &post_full(&resolve_path(VALID_DID), br#"{"sidecar": {}}"#),
        &failing(|| {
            did_btcr2_client::Error::Btcr2(Btcr2Error::MissingUpdateData {
                update_hash: Sha256Hash::from([0u8; 32]),
            })
        }),
    );
    assert_eq!(resp.status, 500);
    let kind = error_type(&resp);
    assert!(kind.starts_with("https://btcr2.dev/"), "{kind}");
    assert!(kind.ends_with("#MISSING_UPDATE_DATA"), "{kind}");
    assert_error_result(&resp, &kind);
    assert_eq!(
        error_detail(&resp),
        format!("update_hash={}", "0".repeat(64))
    );
    assert!(resp.diagnostic.is_some());

    let resp = handle(
        &post_full(&resolve_path(VALID_DID), br#"{"sidecar": {}}"#),
        &failing(|| {
            did_btcr2_client::Error::Btcr2(Btcr2Error::InvalidDid(
                "genesis document hash does not match the identifier".into(),
            ))
        }),
    );
    assert_eq!(resp.status, 400);
    assert_error_result(&resp, INVALID_DID);
    assert_eq!(
        error_detail(&resp),
        "genesis document hash does not match the identifier"
    );
}
