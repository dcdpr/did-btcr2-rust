//! The one test through a socket; every other conformance test calls `handle`
//! directly. This binds an ephemeral loopback port, runs the `tiny_http`
//! worker pool over a scripted resolver, and drives it with `ureq` to prove
//! the request/response adaptation, the status and header plumbing, and the
//! `unblock` shutdown path.

use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;

use did_btcr2::document::{
    Document, DocumentMetadata, InitialDocument, ResolutionMetadata, ResolutionOptions,
    ResolutionResult,
};
use did_btcr2::identifier::Did;
use did_btcr2_resolver_http::{Resolve, serve};

/// A regtest key-based DID; the scripted resolver never touches a network.
const VALID_DID: &str = "did:btcr2:k1qgpakaw4lwemekywf0lyth9hf6j8r2td7gqtrs4aztqfky50jnx7s8gfapup6";

/// A resolver that answers the DID's own initial document.
#[derive(Clone)]
struct OkMock;

impl Resolve for OkMock {
    fn resolve(
        &self,
        did: &Did,
        _: ResolutionOptions,
    ) -> Result<ResolutionResult, did_btcr2_client::Error> {
        Ok(ok_result(did))
    }
}

/// The initial document of a key-based DID as a resolution result, with the
/// core's `contentType` and a version-1 metadata triple.
fn ok_result(did: &Did) -> ResolutionResult {
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
            deactivated: false,
            updated: None,
        },
    }
}

fn header<'a>(resp: &'a ureq::http::Response<ureq::Body>, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

#[test]
fn socket_round_trip_through_the_tiny_http_shell() {
    let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind an ephemeral port"));
    let addr = server.server_addr().to_ip().expect("TCP listener");
    let threads = NonZeroUsize::new(2).expect("2 is non-zero");
    let workers = serve(Arc::clone(&server), threads, OkMock);
    assert_eq!(workers.len(), threads.get());
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();

    let mut resp = agent
        .get(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .header("Accept", "application/did-resolution")
        .call()
        .expect("GET the valid DID");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        header(&resp, "content-type"),
        Some("application/did-resolution")
    );
    let body: serde_json::Value =
        serde_json::from_str(&resp.body_mut().read_to_string().expect("body")).expect("JSON");
    assert_eq!(body["didDocument"]["id"], VALID_DID);
    assert_eq!(
        body["didResolutionMetadata"]["contentType"],
        "application/did"
    );

    let mut resp = agent
        .get(format!("http://{addr}/nope"))
        .call()
        .expect("GET an unknown path");
    assert_eq!(resp.status().as_u16(), 404);
    assert_eq!(resp.body_mut().read_to_string().expect("body"), "");

    let resp = agent
        .post(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .send_empty()
        .expect("POST the resolver path");
    assert_eq!(resp.status().as_u16(), 405);
    assert_eq!(header(&resp, "allow"), Some("GET"));

    let mut resp = agent
        .get(format!("http://{addr}/1.0/identifiers/did:example"))
        .call()
        .expect("GET a DID of no method");
    assert_eq!(resp.status().as_u16(), 400);
    assert_eq!(
        header(&resp, "content-type"),
        Some("application/did-resolution")
    );
    let body: serde_json::Value =
        serde_json::from_str(&resp.body_mut().read_to_string().expect("body")).expect("JSON");
    assert_eq!(
        body["didResolutionMetadata"]["error"]["type"],
        "https://www.w3.org/ns/did#INVALID_DID"
    );
    assert!(body["didDocument"].is_null());
    assert!(
        body.get("didDocument").is_some(),
        "didDocument is present, not omitted"
    );

    // `unblock` wakes one blocked `recv()` per call; every worker must exit.
    for _ in 0..threads.get() {
        server.unblock();
    }
    for worker in workers {
        worker.join().expect("worker exits after unblock");
    }
}
