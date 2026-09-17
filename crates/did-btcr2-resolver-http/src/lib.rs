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
            return problem_response(
                details_of(&Problem::RepresentationNotSupported(format!(
                    "none of the requested media types is supported; offered: {}",
                    offered.join(", ")
                ))),
                None,
            );
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

/// The full resolution result: the core's triple, `contentType` from the core.
fn full_body(result: &ResolutionResult) -> Value {
    json!({
        "didResolutionMetadata": { "contentType": result.resolution_metadata.content_type },
        "didDocument": result.document.as_ref(),
        "didDocumentMetadata": result.document_metadata,
    })
}

fn json_response(status: u16, content_type: &'static str, body: &Value) -> Response {
    Response {
        status,
        headers: vec![("Content-Type", content_type.to_string())],
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
