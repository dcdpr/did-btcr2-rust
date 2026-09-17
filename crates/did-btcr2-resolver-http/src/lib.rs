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

pub use accept::{Mode, negotiate};
pub use options::{OptionsError, parse_options};
pub use path::{DecodeError, Route, percent_decode, route};
pub use problem::{Problem, error_body, problem_response, status_for};
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
