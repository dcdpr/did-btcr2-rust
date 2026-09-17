//! `did-btcr2-resolver-http` — the W3C DID Resolution HTTP(S) GET binding over
//! the sans-I/O `did-btcr2` core and the `did-btcr2-client` facade.
//!
//! This crate owns no resolution logic. It turns `GET /1.0/identifiers/{did}`
//! into one call through the [`Resolve`] seam — in production
//! [`ClientResolver`], which builds a `did_btcr2_client::Client` for the DID's
//! own network on every request — and turns the typed result or error back into
//! an HTTP status, a `Content-Type`, and a resolution-result body. The request
//! handler is a pure function over plain structs so the conformance suite drives
//! it in-process with a scripted resolver; a thin `tiny_http` shell adapts it to
//! a socket.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod accept;
mod options;
mod path;
mod problem;
mod resolve;

use std::any::Any;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread::JoinHandle;

use did_btcr2::document::ResolutionResult;
use did_btcr2::error::{Btcr2Error, ProblemDetails};
use did_btcr2::identifier::Did;
use serde_json::{Value, json};

pub use accept::{Mode, negotiate};
pub use options::{OptionsError, parse_options};
pub use path::{DecodeError, Route, percent_decode, route};
pub use problem::{
    Problem, RESOLUTION_RESULT, error_body, map_client_error, problem_response, status_for,
};
pub use resolve::{ClientResolver, Resolve};

/// An HTTP request, reduced to what the binding reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Request method, as received (`GET`, `POST`, …).
    pub method: String,
    /// Request-target path, verbatim and undecoded (no query string).
    pub path: String,
    /// Raw query string after `?`, if any, undecoded.
    pub query: Option<String>,
    /// Header field/value pairs as received; names compared case-insensitively.
    pub headers: Vec<(String, String)>,
}

/// An HTTP response the shell writes back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Headers to emit; every value is a fixed ASCII constant or a media type
    /// chosen from a fixed set, never echoed client input.
    pub headers: Vec<(&'static str, String)>,
    /// Response body bytes (empty for the bodiless 404/405).
    pub body: Vec<u8>,
    /// Operator-facing detail that must not reach the wire — the full error
    /// chain behind a 500. The shell writes it to stderr.
    pub diagnostic: Option<String>,
}

/// Serve one request. Pure: no I/O, no clock, no logging — the shell owns
/// those. Steps, in order: route, method, decode once, empty, parse the DID
/// (a DID URL is an unsupported feature, another method is unsupported,
/// anything else is an invalid DID), options, `Accept`, resolve, map, body.
/// Only a request that reaches the resolution function gets a
/// resolution-result body; the route and method rejections are bodiless.
pub fn handle(req: &Request, resolver: &impl Resolve) -> Response {
    let Route::Resolve { encoded_did } = route(&req.path) else {
        return plain(404, vec![]);
    };
    if req.method != "GET" {
        return plain(405, vec![("Allow", "GET".to_string())]);
    }
    let decoded = match percent_decode(encoded_did) {
        Ok(d) => d,
        Err(e) => {
            return problem_response(
                details_of(&Btcr2Error::InvalidDid(format!(
                    "the DID path segment is not valid percent-encoding: {e}"
                ))),
                None,
            );
        }
    };
    if decoded.is_empty() {
        return problem_response(
            details_of(&Btcr2Error::InvalidDid(
                "the DID path segment is empty".to_string(),
            )),
            None,
        );
    }
    let did: Did = match decoded.parse() {
        Ok(did) => did,
        Err(did_btcr2::identifier::Error::DidUrl) => {
            return problem_response(
                details_of(&Problem::FeatureNotSupported(
                    "DID URL dereferencing is not supported by this resolver; supply a DID without a path, query or fragment"
                        .to_string(),
                )),
                None,
            );
        }
        Err(e) => return problem_response(details_of(&Btcr2Error::from(e)), None),
    };
    let mut opts = match parse_options(req.query.as_deref()) {
        Ok(o) => o,
        Err(e) => return problem_response(e.details(), None),
    };
    let accept = header_values(req, "accept");
    let mode = match negotiate(accept.as_deref()) {
        Ok(m) => m,
        Err(offered) => {
            // The 406 exists only because of what `Accept` said: a cache
            // must not hand it to a client whose `Accept` would negotiate.
            let mut response = problem_response(
                details_of(&Problem::RepresentationNotSupported(format!(
                    "none of the requested media types is supported; offered: {}",
                    offered.join(", ")
                ))),
                None,
            );
            response.headers.push(vary_accept());
            return response;
        }
    };
    opts.accept = Some(mode.opts_accept().to_string());
    match resolver.resolve(&did, opts) {
        Err(e) => {
            let (details, diagnostic) = map_client_error(e);
            problem_response(details, diagnostic)
        }
        // A deactivated result is a resolution result whatever representation
        // was negotiated: the 410 carries the full triple, document included.
        Ok(result) if result.document_metadata.deactivated => {
            json_response(410, RESOLUTION_RESULT, &full_body(&result))
        }
        Ok(result) => match mode {
            Mode::Full => json_response(200, RESOLUTION_RESULT, &full_body(&result)),
            Mode::Bare(media_type) => json_response(200, media_type, result.document.as_ref()),
        },
    }
}

/// Run `threads` workers over `server`, each taking requests with `recv()`,
/// handing them to [`handle`] with its own clone of `resolver`, and writing
/// the response back. `threads` bounds handler concurrency only: `tiny_http`
/// accepts and parses connections independently and queues the parsed
/// requests, so nothing is dropped and there is no 503 path — excess
/// requests wait for a free worker. A worker exits when `recv()` fails
/// (after [`tiny_http::Server::unblock`]); the caller joins the handles.
///
/// A panic inside the handler (or the resolver behind it) is confined to the
/// request that raised it: the worker answers that request with a 500
/// `INTERNAL_ERROR` resolution result and goes on serving. Otherwise each
/// panic would retire one worker, and after `threads` of them the listener
/// would still queue requests that nothing takes.
///
/// Each worker prints one stderr line per request, `<METHOD> <request-target>
/// -> <status>`, followed by the response's diagnostic (the error chain behind
/// a 500) when there is one. The diagnostic never reaches the wire.
pub fn serve<R>(
    server: Arc<tiny_http::Server>,
    threads: NonZeroUsize,
    resolver: R,
) -> Vec<JoinHandle<()>>
where
    R: Resolve + Clone + Send + 'static,
{
    (0..threads.get())
        .map(|_| {
            let server = Arc::clone(&server);
            let resolver = resolver.clone();
            std::thread::spawn(move || {
                loop {
                    match server.recv() {
                        Ok(request) => serve_one(request, &resolver),
                        Err(e) => {
                            eprintln!("recv: {e}");
                            break;
                        }
                    }
                }
            })
        })
        .collect()
}

/// Adapt one `tiny_http` request: convert, handle, log one line, respond.
///
/// The request-target is split on the first `?`, so a raw `?` is the query
/// string and only a percent-encoded `%3F` reaches the handler as part of the
/// DID segment. The logged method is the one received, so a rejected `POST`
/// is logged as such. Both are client-supplied and `tiny_http` passes ASCII
/// control characters through, so the method, the target and the diagnostic
/// (which can carry a backend's response body) are escaped before they reach
/// stderr: no terminal control sequence or forged log line gets in.
///
/// A panic while handling is caught here: the request is answered with the
/// crate's own 500 `INTERNAL_ERROR` body (not `tiny_http`'s bodiless default)
/// and the panic message goes to the diagnostic line, so the worker survives
/// and the client still receives a resolution result.
fn serve_one(request: tiny_http::Request, resolver: &impl Resolve) {
    let target = request.url().to_string();
    let shown_target = escape_for_log(&target);
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target.clone(), None),
    };
    let plain = Request {
        method: request.method().as_str().to_string(),
        path,
        query,
        headers: request
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_string(),
                    h.value.as_str().to_string(),
                )
            })
            .collect(),
    };
    let response = match catch_unwind(AssertUnwindSafe(|| handle(&plain, resolver))) {
        Ok(response) => response,
        Err(payload) => {
            eprintln!("handler panicked on {shown_target}; the worker continues");
            problem_response(
                problem::internal("the resolver failed internally"),
                Some(format!("panic: {}", panic_message(payload.as_ref()))),
            )
        }
    };
    eprintln!(
        "{} {} -> {}",
        escape_for_log(&plain.method),
        shown_target,
        response.status
    );
    if let Some(diagnostic) = &response.diagnostic {
        eprintln!("{}", escape_for_log(diagnostic));
    }
    let mut out = tiny_http::Response::from_data(response.body).with_status_code(response.status);
    for (name, value) in &response.headers {
        // Every emitted header is a fixed ASCII constant or a media type from a
        // fixed set; a non-ASCII value would be a bug in the handler, not input.
        match tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            Ok(header) => out = out.with_header(header),
            Err(()) => eprintln!("dropping non-ASCII header {name}"),
        }
    }
    if let Err(e) = request.respond(out) {
        eprintln!("respond: {e}");
    }
}

/// The text of a panic payload: the `&str` or `String` a `panic!` carries, or
/// a placeholder for any other payload type.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Render client-supplied text for a stderr line: every non-printable or
/// non-ASCII character becomes its Rust escape (`\u{1b}`, `\n`, …), so a
/// request-target cannot carry terminal control sequences or forged log
/// lines into the operator's log.
fn escape_for_log(s: &str) -> String {
    s.chars().flat_map(char::escape_default).collect()
}

/// The full resolution result: the core's triple, `contentType` from the core.
fn full_body(result: &ResolutionResult) -> Value {
    json!({
        "didResolutionMetadata": { "contentType": result.resolution_metadata.content_type },
        "didDocument": result.document.as_ref(),
        "didDocumentMetadata": result.document_metadata,
    })
}

/// `Vary: Accept`, for every response whose body was chosen from the
/// `Accept` header: the 200 (full result or bare document), the 410 and the
/// 406. Without it a shared cache (RFC 9111 §4.1) could serve a bare document
/// to a client that asked for the resolution result, or the reverse. The
/// bodiless 404/405 and the other error results do not vary and do not
/// carry it.
fn vary_accept() -> (&'static str, String) {
    ("Vary", "Accept".to_string())
}

fn json_response(status: u16, content_type: &'static str, body: &Value) -> Response {
    Response {
        status,
        headers: vec![("Content-Type", content_type.to_string()), vary_accept()],
        body: serde_json::to_vec(body).expect("a JSON value serialises"),
        diagnostic: None,
    }
}

fn plain(status: u16, headers: Vec<(&'static str, String)>) -> Response {
    Response {
        status,
        headers,
        body: Vec::new(),
        diagnostic: None,
    }
}

fn details_of(p: &impl ProblemDetails) -> Value {
    p.details()
        .expect("spec-shaped errors carry problem details")
}

/// All values of a header, case-insensitive on the name, joined with `, `
/// (RFC 9110 §5.3 list semantics). `None` when the header is absent.
fn header_values(req: &Request, name: &str) -> Option<String> {
    let values: Vec<&str> = req
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Printable ASCII passes through; every control character, including
    /// the terminal escapes a request line can smuggle, becomes its Rust
    /// escape, and a newline cannot start a forged log line.
    #[test]
    fn escape_for_log_neutralises_control_characters() {
        let plain = "/1.0/identifiers/did:btcr2:k1abc?versionId=1";
        assert_eq!(escape_for_log(plain), plain);
        assert_eq!(
            escape_for_log("/1.0/identifiers/\x1b[31mRED\x1b[0m\x07x"),
            "/1.0/identifiers/\\u{1b}[31mRED\\u{1b}[0m\\u{7}x"
        );
        assert_eq!(
            escape_for_log("GET /x -> 200\nGET /forged -> 200"),
            "GET /x -> 200\\nGET /forged -> 200"
        );
        assert_eq!(escape_for_log("tab\there"), "tab\\there");
        assert_eq!(escape_for_log("é"), "\\u{e9}");
        for escaped in [escape_for_log("\x00\x01\x1f\x7f"), escape_for_log("\r\n")] {
            assert!(
                escaped.chars().all(|c| c.is_ascii_graphic() || c == ' '),
                "{escaped:?}"
            );
        }
    }

    #[test]
    fn panic_message_reads_str_and_string_payloads() {
        let from_str = catch_unwind(|| panic!("literal")).unwrap_err();
        assert_eq!(panic_message(from_str.as_ref()), "literal");
        let from_string = catch_unwind(|| panic!("{}", String::from("formatted"))).unwrap_err();
        assert_eq!(panic_message(from_string.as_ref()), "formatted");
        let other = catch_unwind(|| std::panic::panic_any(7u8)).unwrap_err();
        assert_eq!(panic_message(other.as_ref()), "non-string panic payload");
    }
}
