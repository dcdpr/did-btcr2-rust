//! The tests through a socket; every other conformance test calls `handle`
//! directly. These bind an ephemeral loopback port, run the `tiny_http`
//! worker pool over a scripted resolver, and drive it with `ureq` to prove
//! the request/response adaptation, the status and header plumbing, the
//! request-body plumbing (a JSON body of options, the media-type gate decided
//! before the body is read, the honest body limit, a body on a GET), and the
//! `unblock` shutdown path.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use did_btcr2::document::{
    Document, DocumentMetadata, InitialDocument, ResolutionMetadata, ResolutionOptions,
    ResolutionResult,
};
use did_btcr2::identifier::Did;
use did_btcr2_resolver_http::{BODY_LIMIT, Resolve, serve};

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

/// A resolver that panics on its first call and answers like `OkMock` after.
#[derive(Clone)]
struct PanicsOnce(Arc<AtomicBool>);

impl Resolve for PanicsOnce {
    fn resolve(
        &self,
        did: &Did,
        _: ResolutionOptions,
    ) -> Result<ResolutionResult, did_btcr2_client::Error> {
        if !self.0.swap(true, Ordering::SeqCst) {
            panic!("scripted panic on the first resolution");
        }
        Ok(ok_result(did))
    }
}

/// A resolver that raises its flag when the options it receives carry a
/// sidecar, and answers like `OkMock`.
#[derive(Clone)]
struct RecordsSidecar(Arc<AtomicBool>);

impl Resolve for RecordsSidecar {
    fn resolve(
        &self,
        did: &Did,
        opts: ResolutionOptions,
    ) -> Result<ResolutionResult, did_btcr2_client::Error> {
        if opts.sidecar_data.is_some() {
            self.0.store(true, Ordering::SeqCst);
        }
        Ok(ok_result(did))
    }
}

fn header<'a>(resp: &'a ureq::http::Response<ureq::Body>, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Send a `HEAD` for `path` over a bare socket and return everything the
/// server writes back: to EOF when it honours `Connection: close`, otherwise
/// until nothing more arrives within the read timeout. Unlike an HTTP client,
/// this does not discard a body the server should not have sent.
fn raw_head(addr: std::net::SocketAddr, path: &str) -> String {
    let mut sock = TcpStream::connect(addr).expect("connect to the shell");
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set a read timeout");
    sock.write_all(
        format!("HEAD {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .expect("write the request");
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(e) => panic!("read the response: {e}"),
        }
    }
    String::from_utf8(raw).expect("the response is UTF-8")
}

/// A panic inside the handler is confined to its request: that request gets
/// the crate's 500 `INTERNAL_ERROR` resolution result (a body, not
/// `tiny_http`'s empty default), and the same — only — worker serves the next
/// request normally. One worker so the second request cannot be picked up by
/// a sibling; a client timeout so a retired worker fails the test instead of
/// hanging it.
#[test]
fn a_panicking_request_is_answered_500_and_the_worker_keeps_serving() {
    let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind an ephemeral port"));
    let addr = server.server_addr().to_ip().expect("TCP listener");
    let threads = NonZeroUsize::MIN;
    let workers = serve(
        Arc::clone(&server),
        threads,
        PanicsOnce(Arc::new(AtomicBool::new(false))),
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let url = format!("http://{addr}/1.0/identifiers/{VALID_DID}");

    let mut resp = agent
        .get(&url)
        .header("Accept", "application/did-resolution")
        .call()
        .expect("the panicking request is still answered");
    assert_eq!(resp.status().as_u16(), 500);
    assert_eq!(
        header(&resp, "content-type"),
        Some("application/did-resolution")
    );
    let body: serde_json::Value =
        serde_json::from_str(&resp.body_mut().read_to_string().expect("body")).expect("JSON");
    assert_eq!(
        body["didResolutionMetadata"]["error"]["type"],
        "https://www.w3.org/ns/did#INTERNAL_ERROR"
    );
    assert_eq!(
        body["didResolutionMetadata"]["error"]["detail"],
        "the resolver failed internally"
    );
    assert!(body["didDocument"].is_null());
    assert_eq!(body["didDocumentMetadata"], serde_json::json!({}));
    let text = serde_json::to_string(&body).expect("re-serialise");
    assert!(
        !text.contains("scripted panic"),
        "the panic message stays off the wire: {text}"
    );

    let mut resp = agent
        .get(&url)
        .header("Accept", "application/did-resolution")
        .call()
        .expect("the worker is still serving");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value =
        serde_json::from_str(&resp.body_mut().read_to_string().expect("body")).expect("JSON");
    assert_eq!(body["didDocument"]["id"], VALID_DID);

    server.unblock();
    for worker in workers {
        worker
            .join()
            .expect("the worker exits normally, not by the panic");
    }
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
    assert_eq!(header(&resp, "vary"), Some("Accept"));
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
        .put(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .send_empty()
        .expect("PUT the resolver path");
    assert_eq!(resp.status().as_u16(), 405);
    assert_eq!(header(&resp, "allow"), Some("GET, POST"));

    // POST: an empty body resolves like a GET (uncached) …
    let mut resp = agent
        .post(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .header("Accept", "application/did-resolution")
        .send_empty()
        .expect("POST with no body");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value =
        serde_json::from_str(&resp.body_mut().read_to_string().expect("body")).expect("JSON");
    assert_eq!(body["didDocument"]["id"], VALID_DID);
    // … a JSON body of options is read through the shell, number or digit
    // string alike …
    let resp = agent
        .post(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .header("Content-Type", "application/json")
        .send(br#"{"versionId": 1}"#)
        .expect("POST a JSON body");
    assert_eq!(resp.status().as_u16(), 200);
    let resp = agent
        .post(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .header("Content-Type", "application/json")
        .send(br#"{"versionId": "1"}"#)
        .expect("POST a JSON body with a digit string");
    assert_eq!(resp.status().as_u16(), 200);
    // … a non-JSON Content-Type is a bodiless 415 …
    let mut resp = agent
        .post(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .header("Content-Type", "text/plain")
        .send(b"versionId=1")
        .expect("POST text/plain");
    assert_eq!(resp.status().as_u16(), 415);
    assert_eq!(resp.body_mut().read_to_string().expect("body"), "");
    // … a body of exactly the limit is read in full: whitespace parses as an
    // empty body, so this resolves …
    let at_limit = vec![b' '; BODY_LIMIT];
    let resp = agent
        .post(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .header("Content-Type", "application/json")
        .send(&at_limit)
        .expect("POST exactly the limit");
    assert_eq!(resp.status().as_u16(), 200);
    // … one byte past the limit, sent in full with an honest Content-Length,
    // is a bodiless 413 that does not retire the worker. This row exercises
    // the honest oversize path only: the shell reads every byte before
    // answering. It says nothing about a Content-Length that declares more
    // than the client sends — that remainder is the shell library's to
    // drain, and it is not sent here.
    let oversize = vec![b' '; BODY_LIMIT + 1];
    let mut resp = agent
        .post(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .header("Content-Type", "application/json")
        .send(&oversize)
        .expect("POST one byte past the limit");
    assert_eq!(resp.status().as_u16(), 413);
    assert_eq!(resp.body_mut().read_to_string().expect("body"), "");
    let resp = agent
        .get(format!("http://{addr}/health"))
        .call()
        .expect("the worker still serves after a 413");
    assert_eq!(resp.status().as_u16(), 200);
    // … and a GET that carries a small honest body is answered as a plain
    // GET: the shell reads a body only on POST, the library drains this one
    // when the request is dropped, and the connection is still usable
    // afterwards.
    let mut resp = agent
        .get(format!("http://{addr}/1.0/identifiers/{VALID_DID}"))
        .header("Accept", "application/did-resolution")
        .header("Content-Type", "application/json")
        .force_send_body()
        .send(br#"{"versionId": 9}"#)
        .expect("GET with a body");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value =
        serde_json::from_str(&resp.body_mut().read_to_string().expect("body")).expect("JSON");
    assert_eq!(body["didDocument"]["id"], VALID_DID);
    let resp = agent
        .get(format!("http://{addr}/health"))
        .call()
        .expect("the worker still serves after a GET with a body");
    assert_eq!(resp.status().as_u16(), 200);

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

    let mut resp = agent
        .get(format!("http://{addr}/health"))
        .call()
        .expect("GET the liveness path");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(header(&resp, "content-type"), Some("application/json"));
    assert_eq!(header(&resp, "vary"), None);
    assert_eq!(
        resp.body_mut().read_to_string().expect("body"),
        r#"{"status":"ok"}"#
    );

    // The handler returns the GET response for HEAD; the shell drops the body
    // (RFC 9110 §9.3.2: the GET's `Content-Length`, no body). An HTTP client
    // never reads a HEAD body, so this row speaks raw HTTP and asserts the
    // bytes on the wire: nothing follows the header terminator.
    let raw = raw_head(addr, "/health");
    assert!(raw.starts_with("HTTP/1.1 200 "), "{raw:?}");
    let (headers, rest) = raw.split_once("\r\n\r\n").expect("a complete header block");
    let headers = headers.to_ascii_lowercase();
    assert!(
        headers.contains("\r\ncontent-type: application/json"),
        "{raw:?}"
    );
    assert!(headers.contains("\r\ncontent-length: 15"), "{raw:?}");
    assert_eq!(rest, "", "HEAD carries no body: {raw:?}");

    // `unblock` wakes one blocked `recv()` per call; every worker must exit.
    for _ in 0..threads.get() {
        server.unblock();
    }
    for worker in workers {
        worker.join().expect("worker exits after unblock");
    }
}

/// The bytes `tiny_http` hands the shell become the resolver's
/// `sidecar_data`: a POST whose body carries `sidecar` raises the resolver's
/// flag, and a GET (whose body the shell never reads) does not.
#[test]
fn sidecar_body_reaches_the_resolver_through_the_socket() {
    let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind an ephemeral port"));
    let addr = server.server_addr().to_ip().expect("TCP listener");
    let saw_sidecar = Arc::new(AtomicBool::new(false));
    let workers = serve(
        Arc::clone(&server),
        NonZeroUsize::MIN,
        RecordsSidecar(Arc::clone(&saw_sidecar)),
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let url = format!("http://{addr}/1.0/identifiers/{VALID_DID}");

    let resp = agent
        .get(&url)
        .header("Content-Type", "application/json")
        .force_send_body()
        .send(br#"{"sidecar": {"updates": []}}"#)
        .expect("GET with a sidecar body");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        !saw_sidecar.load(Ordering::SeqCst),
        "a GET's body is never read, so no sidecar reaches the resolver"
    );

    let resp = agent
        .post(&url)
        .header("Content-Type", "application/json")
        .send(br#"{"sidecar": {"updates": []}}"#)
        .expect("POST a sidecar");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        saw_sidecar.load(Ordering::SeqCst),
        "the POST body became the resolver's sidecar"
    );

    server.unblock();
    for worker in workers {
        worker.join().expect("worker exits after unblock");
    }
}

/// The media-type check is decided on the headers before any body byte is
/// read, so a refused `Content-Type` is a 415 whatever the body's size — a
/// `text/plain` body one byte past the limit is not a 413. The size check
/// still applies to a media type that passes: the same oversize body under
/// `application/json` is a 413. One worker, and the same agent throughout, so
/// the trailing `/health` proves that worker and the connection survived both.
#[test]
fn oversize_non_json_post_is_415_before_the_body_is_read() {
    let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind an ephemeral port"));
    let addr = server.server_addr().to_ip().expect("TCP listener");
    let workers = serve(Arc::clone(&server), NonZeroUsize::MIN, OkMock);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let url = format!("http://{addr}/1.0/identifiers/{VALID_DID}");

    let oversize_text = vec![b'x'; BODY_LIMIT + 1];
    let mut resp = agent
        .post(&url)
        .header("Content-Type", "text/plain")
        .send(&oversize_text)
        .expect("POST an oversize text/plain body");
    assert_eq!(
        resp.status().as_u16(),
        415,
        "a refused media type is decided on the headers, before the size check"
    );
    assert_eq!(resp.body_mut().read_to_string().expect("body"), "");

    let oversize_json = vec![b' '; BODY_LIMIT + 1];
    let mut resp = agent
        .post(&url)
        .header("Content-Type", "application/json")
        .send(&oversize_json)
        .expect("POST an oversize JSON body");
    assert_eq!(
        resp.status().as_u16(),
        413,
        "a media type that passes still meets the body limit"
    );
    assert_eq!(resp.body_mut().read_to_string().expect("body"), "");

    let resp = agent
        .get(format!("http://{addr}/health"))
        .call()
        .expect("the worker still serves after the 415 and the 413");
    assert_eq!(resp.status().as_u16(), 200);

    server.unblock();
    for worker in workers {
        worker.join().expect("worker exits after unblock");
    }
}
