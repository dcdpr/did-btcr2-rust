//! `did-btcr2-resolver-http` — the W3C DID Resolution HTTP(S) GET and POST
//! bindings over the sans-I/O `did-btcr2` core and the `did-btcr2-client`
//! facade.
//!
//! This crate owns no resolution logic. It turns `GET /1.0/identifiers/{did}`
//! — or `POST /1.0/identifiers/{did}` with the resolution options as a JSON
//! body, the method option `sidecar` among them — into one call through the
//! [`Resolve`] seam — in production [`CachingResolver`] over
//! [`ClientResolver`]: a miss builds a `did_btcr2_client::Client` for the
//! DID's own network, a hit is served from memory for 60 s; a `POST` takes
//! the uncached path, so a sidecar-resolved document never serves a later
//! `GET` — and turns the typed result or error back into an HTTP status, a
//! `Content-Type`, and a resolution-result body. The request handler is a
//! pure function over plain structs so the conformance suite drives it
//! in-process with a scripted resolver; a thin `tiny_http` shell adapts it to
//! a socket.
//! `/health` is a liveness route beside the resolver path: `GET` and `HEAD`
//! answer without reaching the resolver, so a supervisor, a proxy or an
//! uptime poller can hit it without cost.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod accept;
mod options;
mod path;
mod problem;
mod resolve;

use std::any::Any;
use std::io::Read;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use did_btcr2::document::{ResolutionOptions, ResolutionResult};
use did_btcr2::error::{Btcr2Error, ProblemDetails};
use did_btcr2::identifier::Did;
use did_btcr2_client::network_name;
use serde::Serialize;
use serde_json::{Value, json};

pub use accept::{Mode, negotiate};
pub use options::{BodyOptions, OptionsError, parse_body_options, parse_options};
pub use path::{DecodeError, HEALTH_PATH, Route, percent_decode, route};
pub use problem::{
    Problem, RESOLUTION_RESULT, error_body, map_client_error, problem_response, status_for,
};
pub use resolve::{
    CACHE_CAPACITY, CACHE_TTL, CacheOutcome, CachingResolver, ClientResolver, Clock, Resolve,
    SystemClock,
};

/// The most request-body bytes the shell reads: 1 MiB, fixed. A signed update
/// is a few KB, so a sidecar of hundreds of updates fits; past the limit the
/// shell answers a bodiless 413 without handing the request to [`handle`].
/// The limit applies to a body the shell reads — a `POST` on the resolver path
/// whose `Content-Type` is absent or JSON. A `POST` whose media type is
/// refused, or to any other route, is not read at all: it is a 415 (or the
/// route's 404 / 405), whatever its size.
/// Read-then-check: the shell reads at most `BODY_LIMIT + 1` bytes and never
/// trusts `Content-Length`. This bounds what the shell reads for an honest
/// body; what the shell library does with a declared-but-unsent remainder
/// when the request is dropped is the library's (see `serve_one`).
pub const BODY_LIMIT: usize = 1 << 20;

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
    /// Request body bytes as read by the shell — at most [`BODY_LIMIT`], and
    /// only for a `POST` on the resolver path whose `Content-Type` is absent
    /// or JSON; empty otherwise (a body on a `GET`, on a `POST` to another
    /// route, or on a `POST` whose media type is refused, is not read by the
    /// shell).
    pub body: Vec<u8>,
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
/// those. Steps, in order: route (the liveness route answers here, for GET
/// and HEAD), method (`GET` or `POST`; a `POST` with a non-JSON
/// `Content-Type` ends here, 415), decode once, empty, parse the DID (a DID
/// URL is an unsupported feature, another method is unsupported, anything
/// else is an invalid DID), options (the query string for `GET`; the JSON
/// body for `POST`, which must have no query string), `Accept`, resolve
/// (`POST` through the uncached path), map, body.
/// Only a request that reaches the resolution function gets a
/// resolution-result body; the route, method and media-type rejections are
/// bodiless.
pub fn handle(req: &Request, resolver: &impl Resolve) -> Response {
    handle_traced(req, resolver).response
}

/// What one handled request yields beyond the response: the cache outcome and,
/// for a `POST` whose body carried a `sidecar`, how many updates it held.
/// Both are logged by the shell and travel with the response they belong to.
struct Handled {
    response: Response,
    /// `None` when the request was rejected before the resolver or the
    /// resolver has no cache.
    cache: Option<CacheOutcome>,
    /// `None` on every rejection, even one after the body parsed: a number
    /// means the request reached the resolver.
    sidecar_updates: Option<usize>,
}

/// [`handle`], plus what the shell logs about the resolution it made. The
/// outcome comes back with the response it belongs to, so nothing is read
/// from the resolver after the fact.
fn handle_traced(req: &Request, resolver: &impl Resolve) -> Handled {
    let (did, opts, mode, sidecar_updates) = match prepare(req) {
        Ok(ready) => ready,
        Err(response) => {
            return Handled {
                response,
                cache: None,
                sidecar_updates: None,
            };
        }
    };
    // The handler stamps the bypass itself, whatever `Resolve` sits behind
    // it: the rule is that a POST bypasses the cache, not that a sidecar
    // does, so an empty POST body bypasses too.
    let (result, cache) = if req.method == "POST" {
        (
            resolver.resolve_uncached(&did, opts),
            Some(CacheOutcome::Bypass),
        )
    } else {
        resolver.resolve_traced(&did, opts)
    };
    let response = match result {
        Err(e) => {
            let (details, diagnostic) = map_client_error(e);
            problem_response(details, diagnostic)
        }
        Ok(mut result) => {
            // The binding negotiated the representation, so it stamps it: a
            // resolver may hand back a result it produced for another request.
            result.resolution_metadata.content_type = Some(mode.opts_accept().to_string());
            if result.document_metadata.deactivated {
                // A deactivated result is a resolution result whatever representation
                // was negotiated: the 410 carries the full triple, document included.
                json_response(410, RESOLUTION_RESULT, &full_body(&result))
            } else {
                match mode {
                    Mode::Full => json_response(200, RESOLUTION_RESULT, &full_body(&result)),
                    Mode::Bare(media_type) => {
                        json_response(200, media_type, result.document.as_ref())
                    }
                }
            }
        }
    };
    Handled {
        response,
        cache,
        sidecar_updates,
    }
}

/// Everything [`handle`] does before the resolver: route, method, media
/// type, decode, empty, parse the DID, options, `Accept`. `Ok` is what the
/// resolution call needs plus the sidecar's update count (`None` on a `GET`
/// or a body without `sidecar`); `Err` is the response that ends the request
/// here.
fn prepare(req: &Request) -> Result<(Did, ResolutionOptions, Mode, Option<usize>), Response> {
    let encoded_did = match route(&req.path) {
        Route::NotFound => return Err(plain(404, vec![])),
        Route::Health if req.method == "GET" || req.method == "HEAD" => return Err(health()),
        Route::Health => return Err(plain(405, vec![("Allow", "GET, HEAD".to_string())])),
        Route::Resolve { encoded_did } => encoded_did,
    };
    if req.method != "GET" && req.method != "POST" {
        return Err(plain(405, vec![("Allow", "GET, POST".to_string())]));
    }
    if req.method == "POST" && refuses_post_body(&req.headers) {
        // A transport-level rejection like the 405: no resolution error type
        // exists for it.
        return Err(plain(415, vec![]));
    }
    let decoded = percent_decode(encoded_did).map_err(|e| {
        problem_response(
            details_of(&Btcr2Error::InvalidDid(format!(
                "the DID path segment is not valid percent-encoding: {e}"
            ))),
            None,
        )
    })?;
    if decoded.is_empty() {
        return Err(problem_response(
            details_of(&Btcr2Error::InvalidDid(
                "the DID path segment is empty".to_string(),
            )),
            None,
        ));
    }
    let did: Did = match decoded.parse() {
        Ok(did) => did,
        Err(did_btcr2::identifier::Error::DidUrl) => {
            return Err(problem_response(
                details_of(&Problem::FeatureNotSupported(
                    "DID URL dereferencing is not supported by this resolver; supply a DID without a path, query or fragment"
                        .to_string(),
                )),
                None,
            ));
        }
        Err(e) => return Err(problem_response(details_of(&Btcr2Error::from(e)), None)),
    };
    let (mut opts, sidecar_updates) = match req.method.as_str() {
        "POST" => {
            // A POST carries its options in the body and nothing in the
            // query string — a bare trailing `?` included. The
            // specification's own second POST example carries a query
            // string, but that request is a DID URL dereference
            // (`?service=…&relativeRef=…`), which this binding does not
            // perform; a GET with that query is already `INVALID_OPTIONS`
            // (unknown option), and a POST answers the same.
            if req.query.is_some() {
                return Err(problem_response(
                    details_of(&Btcr2Error::InvalidOptions(
                        "a POST carries its resolution options in the request body, not in the query string"
                            .to_string(),
                    )),
                    None,
                ));
            }
            let BodyOptions {
                opts,
                sidecar_updates,
            } = parse_body_options(&req.body).map_err(|e| problem_response(e.details(), None))?;
            (opts, sidecar_updates)
        }
        _ => (
            parse_options(req.query.as_deref()).map_err(|e| problem_response(e.details(), None))?,
            None,
        ),
    };
    let accept = header_values(&req.headers, "accept");
    let mode = negotiate(accept.as_deref()).map_err(|offered| {
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
        response
    })?;
    opts.accept = Some(mode.opts_accept().to_string());
    Ok((did, opts, mode, sidecar_updates))
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
/// Each worker prints one JSON object per request on stderr — `method`,
/// `path`, `did`, `accept`, `status`, `latency_ms`, `cache`
/// (`hit`/`miss`/`bypass`/`n/a`), `network`, `body_bytes`, `sidecar_updates`
/// — followed by the response's diagnostic (the error chain behind a 500)
/// when there is one. The diagnostic never reaches the wire.
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
///
/// Every request is logged in the same shape, `/health` and the rejected ones
/// included: those never reach the resolver, so they carry `cache: "n/a"` —
/// as does every `GET` when `resolver` has no cache (see [`cache_label`]).
///
/// The body is read here, only for a `POST` on the resolver path whose
/// `Content-Type` is absent or JSON ([`reads_body`]; a refused media type or
/// another route is not read: the handler answers 415, 404 or 405 on the
/// request line and headers), at most [`BODY_LIMIT`] + 1 bytes; past the
/// limit the request is answered with a bodiless 413 and never handed to the
/// handler, and a read failure (a malformed chunked body, a connection that
/// drops mid-body) is a bodiless 400.
fn serve_one(mut request: tiny_http::Request, resolver: &impl Resolve) {
    let started = Instant::now();
    let method = request.method().as_str().to_string();
    let target = request.url().to_string();
    let shown_target = escape_for_log(&target);
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target.clone(), None),
    };
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|h| {
            (
                h.field.as_str().as_str().to_string(),
                h.value.as_str().to_string(),
            )
        })
        .collect();
    // What the shell bounds and what it does not. The `take` bounds an honest
    // body: at most `BODY_LIMIT + 1` bytes are read, whatever
    // `Content-Length` declares, so the check below is on bytes received.
    // A request that declares a `Content-Length` far beyond what it sends is
    // drained by the shell library when the request is dropped, with one
    // allocation sized by the declared remainder, on any method — the
    // process can abort on it, and a reverse proxy in front must bound the
    // declared length. The library also sets no socket read timeout, so a
    // slow body sender holds this worker until it finishes.
    let mut body = Vec::new();
    // Only a POST on the resolver path whose `Content-Type` the handler will
    // accept has its body read. Nothing else is read: a body on a GET, on a
    // POST to another route, or on a POST whose media type is refused, stays
    // with the shell library, which drains an honest one when the request is
    // dropped (a `Content-Length` body is read off the socket to its declared
    // end on drop). Such a POST reaches the handler with an empty body, and
    // the handler answers the 404 / 405 / 415 on the request line and the
    // headers, so those rejections come whatever the body's size.
    let read = if reads_body(&method, &path, &headers) {
        request
            .as_reader()
            .take(BODY_LIMIT as u64 + 1)
            .read_to_end(&mut body)
            .map(|_| ())
    } else {
        Ok(())
    };
    let body_bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let req = Request {
        method,
        path,
        query,
        headers,
        body,
    };
    let handled = match read {
        Err(e) => {
            eprintln!("body read on {shown_target}: {e}");
            Handled {
                response: plain(400, vec![]),
                cache: None,
                sidecar_updates: None,
            }
        }
        Ok(()) if req.body.len() > BODY_LIMIT => Handled {
            response: plain(413, vec![]),
            cache: None,
            sidecar_updates: None,
        },
        Ok(()) => match catch_unwind(AssertUnwindSafe(|| handle_traced(&req, resolver))) {
            Ok(served) => served,
            Err(payload) => {
                eprintln!("handler panicked on {shown_target}; the worker continues");
                Handled {
                    response: problem_response(
                        problem::internal("the resolver failed internally"),
                        Some(format!("panic: {}", panic_message(payload.as_ref()))),
                    ),
                    cache: None,
                    sidecar_updates: None,
                }
            }
        },
    };
    let Handled {
        response,
        cache,
        sidecar_updates,
    } = handled;
    eprintln!(
        "{}",
        request_log_line(
            &req.method,
            &target,
            did_for_log(&req.path).as_ref(),
            header_values(&req.headers, "accept").as_deref(),
            response.status,
            started.elapsed(),
            cache,
            body_bytes,
            sidecar_updates,
        )
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

/// One request as the shell logs it: a single JSON object on stderr. Field
/// order is the declaration order. `method`, `path` and `accept` are client
/// text and are escaped (`escape_for_log`) before they are JSON-encoded, so a
/// control character shows as its Rust escape rather than reaching the
/// terminal. That is two layers: after JSON-decoding the field a consumer
/// holds `char::escape_default` text (`\"`, `\u{e9}`, `\u{1b}`), not the
/// request-target, and must unescape once more to compare with what the
/// client sent; for percent-encoded ASCII the two coincide. `did` is the
/// re-encoded parse result, never client bytes. `cache` is `hit`, `miss`,
/// `bypass` or `n/a`, and `n/a` means either that the resolver was not
/// reached or that the resolver serving the request has no cache — see
/// [`cache_label`]. `body_bytes` is the count the shell read (at most
/// `BODY_LIMIT + 1`; always `0` for a method other than `POST`, for a `POST`
/// to a route other than the resolver path, and for a `POST` refused on its
/// `Content-Type`),
/// `sidecar_updates` the length of the sidecar's `updates` array when a
/// `POST` carried one and reached the resolver, else `null`.
#[derive(Serialize)]
struct RequestLog<'a> {
    method: String,
    path: String,
    did: Option<String>,
    accept: Option<String>,
    status: u16,
    latency_ms: u64,
    cache: &'static str,
    network: Option<&'a str>,
    body_bytes: u64,
    sidecar_updates: Option<usize>,
}

/// The `cache` field: `hit`, `miss`, `bypass`, or `n/a`. `bypass` means the
/// request was a `POST`: the resolver was reached through `resolve_uncached`
/// and no cache was read or written. `n/a` has two readings — the resolver
/// was not reached (a rejected request, `/health`, or a panic), or the
/// resolver that served the request has no cache (the default
/// [`Resolve::resolve_traced`] reports `None`). The shipped binary always
/// wraps [`CachingResolver`], so there it means the former; a shell serving
/// the bare resolver would log `n/a` on every `GET`.
fn cache_label(outcome: Option<CacheOutcome>) -> &'static str {
    match outcome {
        Some(CacheOutcome::Hit) => "hit",
        Some(CacheOutcome::Miss) => "miss",
        Some(CacheOutcome::Bypass) => "bypass",
        None => "n/a",
    }
}

/// Render the per-request log line. Pure, so it is tested without a socket.
#[allow(clippy::too_many_arguments)]
fn request_log_line(
    method: &str,
    target: &str,
    did: Option<&Did>,
    accept: Option<&str>,
    status: u16,
    latency: Duration,
    cache: Option<CacheOutcome>,
    body_bytes: u64,
    sidecar_updates: Option<usize>,
) -> String {
    let line = RequestLog {
        method: escape_for_log(method),
        path: escape_for_log(target),
        did: did.map(|d| d.encode().to_owned()),
        accept: accept.map(escape_for_log),
        status,
        latency_ms: u64::try_from(latency.as_millis()).unwrap_or(u64::MAX),
        cache: cache_label(cache),
        network: did.map(|d| network_name(d.components().network())),
        body_bytes,
        sidecar_updates,
    };
    serde_json::to_string(&line).expect("a struct of strings and numbers serialises")
}

/// The DID a request-target names, for the log line only: the resolver path,
/// percent-decoded once, parsed. `None` for every other path and for anything
/// that does not parse — the raw target is already in `path`.
fn did_for_log(path: &str) -> Option<Did> {
    match route(path) {
        Route::Resolve { encoded_did } => percent_decode(encoded_did).ok()?.parse().ok(),
        _ => None,
    }
}

/// The full resolution result: the core's triple, `contentType` as [`handle`]
/// stamped it from the negotiated mode.
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

/// The liveness response. Built literally rather than through `json_response`
/// because that helper adds `Vary: Accept`, and this body is not negotiated.
/// The same value serves `HEAD`: the shell drops the body for that method.
fn health() -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type", "application/json".to_string())],
        body: br#"{"status":"ok"}"#.to_vec(),
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
fn header_values(headers: &[(String, String)], name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// Whether a `POST`'s `Content-Type` refuses the body: the header is present
/// and does not name JSON ([`body_media_type_is_json`] over the `, `-joined
/// values); an absent header is accepted. This is the one media-type
/// decision: the shell calls it to skip the body read, and [`prepare`] calls
/// it to answer the 415, so the two cannot disagree.
fn refuses_post_body(headers: &[(String, String)]) -> bool {
    header_values(headers, "content-type").is_some_and(|value| !body_media_type_is_json(&value))
}

/// Whether the shell reads a request's body: a `POST` on the resolver path
/// whose `Content-Type` does not refuse it ([`refuses_post_body`]). The route
/// is known from the request line as the media type is from the headers, and
/// [`prepare`] answers a `POST` to any other route (404, or 405 on the
/// liveness route) from the path alone, so a body there is never looked at:
/// reading it would cost a bounded read for a request the route rejects, and
/// past [`BODY_LIMIT`] would answer 413 where the route answers 404 / 405.
fn reads_body(method: &str, path: &str, headers: &[(String, String)]) -> bool {
    method == "POST" && matches!(route(path), Route::Resolve { .. }) && !refuses_post_body(headers)
}

/// Whether a `Content-Type` names a JSON body: `application/json` or any
/// `*/*+json` structured syntax, parameters (`; charset=…`) ignored, case-
/// insensitive. A repeated header joins to `a, b` and is refused as a whole.
fn body_media_type_is_json(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case("application/json")
        || (media_type.contains('/') && media_type.to_ascii_lowercase().ends_with("+json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use did_btcr2::identifier::{DidComponents, DidVersion, IdType, Network};

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

    fn request(method: &str, path: &str, query: Option<&str>) -> Request {
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query: query.map(str::to_string),
            headers: vec![],
            body: Vec::new(),
        }
    }

    /// Liveness is a fixed JSON body with no `Vary`: nothing about it is
    /// negotiated (an `Accept` nobody could satisfy still gets the 200, not
    /// a 406), the query string is ignored, and the resolver is never
    /// consulted.
    #[test]
    fn health_get_is_200_json_without_vary() {
        let resp = handle(&request("GET", "/health", None), &Untouchable);
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers,
            vec![("Content-Type", "application/json".to_string())]
        );
        assert_eq!(resp.body, br#"{"status":"ok"}"#);
        assert!(resp.diagnostic.is_none());
        let with_query = handle(&request("GET", "/health", Some("x=1")), &Untouchable);
        assert_eq!(with_query, resp, "the query string is ignored");
        let mut with_accept = request("GET", "/health", None);
        with_accept
            .headers
            .push(("Accept".to_string(), "text/plain".to_string()));
        assert_eq!(
            handle(&with_accept, &Untouchable),
            resp,
            "liveness is not negotiated: no 406 for an unsatisfiable Accept"
        );
    }

    /// `HEAD` is answered by the same arm: the pure handler returns the GET
    /// response and the shell suppresses the body on the wire.
    #[test]
    fn health_head_is_the_get_response() {
        let get = handle(&request("GET", "/health", None), &Untouchable);
        let head = handle(&request("HEAD", "/health", None), &Untouchable);
        assert_eq!(head, get);
    }

    #[test]
    fn health_non_get_is_405_with_allow_get_head() {
        for method in ["POST", "PUT", "DELETE"] {
            let resp = handle(&request(method, "/health", None), &Untouchable);
            assert_eq!(resp.status, 405, "{method}");
            assert_eq!(
                resp.headers,
                vec![("Allow", "GET, HEAD".to_string())],
                "{method}"
            );
            assert!(resp.body.is_empty(), "{method}");
        }
    }

    #[test]
    fn health_lookalikes_are_404() {
        for path in ["/health/", "/healthz", "/health/x", "/Health"] {
            let resp = handle(&request("GET", path, None), &Untouchable);
            assert_eq!(resp.status, 404, "{path}");
            assert!(resp.headers.is_empty(), "{path}");
            assert!(resp.body.is_empty(), "{path}");
        }
    }

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

    /// A key-based DID anchored to `network`, re-parsed from its string form
    /// exactly as a request would carry it.
    fn did_on(network: Network) -> Did {
        let public_key = did_btcr2::KeyPair::generate().public_key;
        let components = DidComponents::new(DidVersion::One, network, IdType::from(public_key))
            .expect("the components are valid");
        Did::try_from(components)
            .expect("the DID encodes")
            .encode()
            .parse()
            .expect("the encoded DID parses back")
    }

    fn parse_line(line: &str) -> serde_json::Map<String, Value> {
        match serde_json::from_str(line).expect("the log line is JSON") {
            Value::Object(map) => map,
            other => panic!("the log line is not an object: {other}"),
        }
    }

    const FIELDS: [&str; 10] = [
        "method",
        "path",
        "did",
        "accept",
        "status",
        "latency_ms",
        "cache",
        "network",
        "body_bytes",
        "sidecar_updates",
    ];

    /// The line is one JSON object with exactly the ten fields, emitted in
    /// declaration order (not sorted), the numbers as numbers, on one line.
    #[test]
    fn request_log_line_has_the_ten_fields_in_declaration_order() {
        let line = request_log_line(
            "GET",
            "/1.0/identifiers/did:btcr2:k1abc?versionId=1",
            None,
            Some("application/did-resolution"),
            200,
            Duration::from_millis(1234),
            None,
            0,
            None,
        );
        assert!(!line.contains('\n'), "{line:?}");
        let map = parse_line(&line);
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        let mut expected: Vec<&str> = FIELDS.to_vec();
        expected.sort_unstable();
        let mut got = keys.clone();
        got.sort_unstable();
        assert_eq!(got, expected, "exactly the ten fields");
        let offsets: Vec<usize> = FIELDS
            .iter()
            .map(|f| line.find(&format!("\"{f}\"")).expect(f))
            .collect();
        assert!(
            offsets.windows(2).all(|w| w[0] < w[1]),
            "declaration order in the raw text: {line}"
        );
        assert_eq!(map["status"], json!(200));
        assert_eq!(map["latency_ms"], json!(1234u64));
        assert_eq!(map["method"], json!("GET"));
        assert_eq!(
            map["path"],
            json!("/1.0/identifiers/did:btcr2:k1abc?versionId=1")
        );
        assert_eq!(map["accept"], json!("application/did-resolution"));
    }

    /// Client text is escaped before it is JSON-encoded: the raw line carries
    /// no control byte, and the parsed fields hold the Rust escape text, so a
    /// terminal escape or a forged line cannot reach the journal even through
    /// a consumer that unescapes the JSON.
    #[test]
    fn request_log_line_escapes_control_characters_in_client_fields() {
        let line = request_log_line(
            "GE\nT",
            "/1.0/identifiers/\x1b[31mX\x07",
            None,
            Some("text/\u{7}plain"),
            400,
            Duration::ZERO,
            None,
            0,
            None,
        );
        assert!(
            line.bytes().all(|b| b >= 0x20),
            "a control byte reached the line: {line:?}"
        );
        let map = parse_line(&line);
        assert_eq!(map["path"], json!("/1.0/identifiers/\\u{1b}[31mX\\u{7}"));
        assert_eq!(map["method"], json!("GE\\nT"));
        assert_eq!(map["accept"], json!("text/\\u{7}plain"));
    }

    #[test]
    fn request_log_line_cache_field_values() {
        for (outcome, label) in [
            (Some(CacheOutcome::Hit), "hit"),
            (Some(CacheOutcome::Miss), "miss"),
            (Some(CacheOutcome::Bypass), "bypass"),
            (None, "n/a"),
        ] {
            let line = request_log_line(
                "GET",
                "/x",
                None,
                None,
                200,
                Duration::ZERO,
                outcome,
                0,
                None,
            );
            assert_eq!(parse_line(&line)["cache"], json!(label), "{outcome:?}");
        }
    }

    /// `body_bytes` is always a number (`0` on a GET), `sidecar_updates` a
    /// number only when a sidecar reached the resolver — `0` for a sidecar
    /// with no updates, `null` otherwise.
    #[test]
    fn request_log_line_body_bytes_and_sidecar_updates() {
        let line = request_log_line("GET", "/x", None, None, 200, Duration::ZERO, None, 0, None);
        let map = parse_line(&line);
        assert_eq!(map["body_bytes"], json!(0));
        assert_eq!(map["sidecar_updates"], Value::Null);

        let line = request_log_line(
            "POST",
            "/x",
            None,
            None,
            200,
            Duration::ZERO,
            Some(CacheOutcome::Bypass),
            2048,
            Some(3),
        );
        let map = parse_line(&line);
        assert_eq!(map["body_bytes"], json!(2048));
        assert_eq!(map["sidecar_updates"], json!(3));
        assert_eq!(map["cache"], json!("bypass"));

        let line = request_log_line(
            "POST",
            "/x",
            None,
            None,
            200,
            Duration::ZERO,
            Some(CacheOutcome::Bypass),
            20,
            Some(0),
        );
        assert_eq!(parse_line(&line)["sidecar_updates"], json!(0));
    }

    /// `did` is the re-encoded parse result and `network` its network name;
    /// both are `null` when no DID was parsed, as is an absent `Accept`.
    #[test]
    fn request_log_line_did_and_network() {
        let did = did_on(Network::Mainnet);
        let line = request_log_line(
            "GET",
            "/x",
            Some(&did),
            None,
            200,
            Duration::ZERO,
            Some(CacheOutcome::Miss),
            0,
            None,
        );
        let map = parse_line(&line);
        assert_eq!(map["did"], json!(did.encode()));
        assert_eq!(map["network"], json!("mainnet"));
        assert_eq!(map["accept"], Value::Null);

        let line = request_log_line(
            "GET",
            "/health",
            None,
            None,
            200,
            Duration::ZERO,
            None,
            0,
            None,
        );
        let map = parse_line(&line);
        assert_eq!(map["did"], Value::Null);
        assert_eq!(map["network"], Value::Null);
    }

    /// Only the resolver path yields a DID, and only when its segment decodes
    /// and parses; everything else is `None` and the raw target stays in `path`.
    #[test]
    fn did_for_log_parses_only_the_resolver_path() {
        let did = did_on(Network::Mainnet);
        let encoded = did.encode();
        let plain = format!("/1.0/identifiers/{encoded}");
        assert_eq!(
            did_for_log(&plain).map(|d| d.encode().to_owned()),
            Some(encoded.to_owned())
        );
        let percent = format!("/1.0/identifiers/{}", encoded.replace(':', "%3A"));
        assert_ne!(percent, plain);
        assert_eq!(
            did_for_log(&percent).map(|d| d.encode().to_owned()),
            Some(encoded.to_owned())
        );
        for path in [
            "/1.0/identifiers/not-a-did",
            "/1.0/identifiers/",
            "/health",
            "/other",
            "/1.0/identifiers/did%3Aexample%3Aabc",
        ] {
            assert!(did_for_log(path).is_none(), "{path}");
        }
    }

    #[test]
    fn body_media_type_is_json_rows() {
        for json in [
            "application/json",
            "Application/JSON",
            "application/json; charset=utf-8",
            "application/ld+json",
            "application/did-resolution+json;q=1",
        ] {
            assert!(body_media_type_is_json(json), "{json}");
        }
        for other in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "+json",
            "application/jsonx",
            "application/json, text/plain",
            "",
        ] {
            assert!(!body_media_type_is_json(other), "{other:?}");
        }
    }

    /// The one predicate the shell (skip the read) and `prepare` (answer 415)
    /// share, over the header slice: absent accepted, JSON and `+json`
    /// accepted whatever the case or parameters, anything else refused, and a
    /// repeated header refused as a whole because its joined list is not JSON.
    #[test]
    fn refuses_post_body_rows() {
        let headers = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        for accepted in [
            headers(&[]),
            headers(&[("Content-Type", "application/json")]),
            headers(&[("content-type", "Application/JSON; charset=utf-8")]),
            headers(&[("Content-Type", "application/ld+json")]),
        ] {
            assert!(!refuses_post_body(&accepted), "{accepted:?}");
        }
        for refused in [
            headers(&[("Content-Type", "text/plain")]),
            headers(&[
                ("Content-Type", "application/json"),
                ("content-type", "text/plain"),
            ]),
        ] {
            assert!(refuses_post_body(&refused), "{refused:?}");
        }
    }

    /// The shell reads a body for exactly one shape of request: a `POST` on
    /// the resolver path whose media type is not refused. Method, route and
    /// media type each veto the read on their own.
    #[test]
    fn reads_body_rows() {
        let headers = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let json = headers(&[("Content-Type", "application/json")]);
        let none = headers(&[]);
        let text = headers(&[("Content-Type", "text/plain")]);
        let resolver = "/1.0/identifiers/did%3Abtcr2%3Ak1abc";
        assert!(reads_body("POST", resolver, &json));
        assert!(reads_body("POST", resolver, &none));
        // The route, not the DID: an empty or unparseable segment is still the
        // resolver path, and the handler answers those from the body-parsed
        // request as it does today.
        assert!(reads_body("POST", "/1.0/identifiers/", &json));
        assert!(reads_body("POST", "/1.0/identifiers/a/b", &json));
        for (method, path, headers) in [
            ("GET", resolver, &json),
            ("HEAD", resolver, &json),
            ("PUT", resolver, &json),
            ("post", resolver, &json),
            ("POST", HEALTH_PATH, &json),
            ("POST", HEALTH_PATH, &none),
            ("POST", "/nope", &json),
            ("POST", "/1.0/identifiers", &json),
            ("POST", resolver, &text),
        ] {
            assert!(
                !reads_body(method, path, headers),
                "{method} {path} {headers:?}"
            );
        }
    }

    // ---- the POST binding over the pure handler ----

    use std::num::NonZeroU64;
    use std::sync::Mutex;

    use did_btcr2::document::{Document, DocumentMetadata, InitialDocument, ResolutionMetadata};

    /// The initial document of a key-based DID as a resolution result.
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

    /// A resolver that answers every DID with its initial document and
    /// records the options it was handed, so a test can assert what reached
    /// it. It has no cache, so a traced `GET` reports `None`.
    #[derive(Default)]
    struct Answers {
        seen: Mutex<Vec<ResolutionOptions>>,
    }

    impl Resolve for Answers {
        fn resolve(
            &self,
            did: &Did,
            opts: ResolutionOptions,
        ) -> Result<ResolutionResult, did_btcr2_client::Error> {
            self.seen.lock().expect("seen lock").push(opts);
            Ok(ok_result(did))
        }
    }

    fn resolve_path(did: &Did) -> String {
        format!("/1.0/identifiers/{}", did.encode())
    }

    fn post(did: &Did, headers: &[(&str, &str)], body: &[u8]) -> Request {
        Request {
            method: "POST".to_string(),
            path: resolve_path(did),
            query: None,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_vec(),
        }
    }

    fn error_type(response: &Response) -> String {
        let body: Value = serde_json::from_slice(&response.body).expect("a JSON body");
        body["didResolutionMetadata"]["error"]["type"]
            .as_str()
            .expect("an error type")
            .to_string()
    }

    fn error_detail(response: &Response) -> String {
        let body: Value = serde_json::from_slice(&response.body).expect("a JSON body");
        body["didResolutionMetadata"]["error"]["detail"]
            .as_str()
            .expect("an error detail")
            .to_string()
    }

    const INVALID_OPTIONS: &str = "https://www.w3.org/ns/did#INVALID_OPTIONS";

    /// The method check precedes everything but the route: any method other
    /// than GET or POST on the resolver path is a bodiless 405 naming both,
    /// even for a segment that is not a DID. The liveness route keeps its own
    /// set.
    #[test]
    fn resolver_path_405_lists_get_and_post() {
        let did = did_on(Network::Mainnet);
        for method in ["HEAD", "PUT", "DELETE", "PATCH"] {
            let resp = handle(&request(method, &resolve_path(&did), None), &Untouchable);
            assert_eq!(resp.status, 405, "{method}");
            assert_eq!(
                resp.headers,
                vec![("Allow", "GET, POST".to_string())],
                "{method}"
            );
            assert!(resp.body.is_empty(), "{method}");
        }
        let resp = handle(
            &request("PUT", "/1.0/identifiers/not-a-did", None),
            &Untouchable,
        );
        assert_eq!(resp.status, 405);
        let resp = handle(&request("POST", "/health", None), &Untouchable);
        assert_eq!(resp.status, 405);
        assert_eq!(resp.headers, vec![("Allow", "GET, HEAD".to_string())]);
    }

    /// A `Content-Type` that is not JSON is refused before the DID is looked
    /// at: a bodiless 415 with no headers and no diagnostic. Two
    /// `Content-Type` headers join to a list, which is not a JSON type.
    #[test]
    fn post_with_non_json_content_type_is_bodiless_415() {
        let did = did_on(Network::Mainnet);
        let cases: [&[(&str, &str)]; 3] = [
            &[("Content-Type", "text/plain")],
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &[
                ("Content-Type", "application/json"),
                ("content-type", "text/plain"),
            ],
        ];
        for headers in cases {
            let resp = handle(&post(&did, headers, b"{}"), &Untouchable);
            assert_eq!(resp.status, 415, "{headers:?}");
            assert!(resp.headers.is_empty(), "{headers:?}");
            assert!(resp.body.is_empty(), "{headers:?}");
            assert!(resp.diagnostic.is_none(), "{headers:?}");
        }
        let mut not_a_did = post(&did, &[("Content-Type", "text/plain")], b"{}");
        not_a_did.path = "/1.0/identifiers/not-a-did".to_string();
        assert_eq!(
            handle(&not_a_did, &Untouchable).status,
            415,
            "the media type is checked before the DID"
        );
    }

    /// No `Content-Type`, `application/json` (any case, with parameters) and
    /// a `+json` structured syntax all reach the resolver, through the
    /// uncached path, with no sidecar reported.
    #[test]
    fn post_json_content_types_reach_the_resolver() {
        let did = did_on(Network::Mainnet);
        let cases: [&[(&str, &str)]; 4] = [
            &[],
            &[("Content-Type", "application/json")],
            &[("Content-Type", "Application/JSON; charset=utf-8")],
            &[("Content-Type", "application/ld+json")],
        ];
        for headers in cases {
            let answers = Answers::default();
            let handled = handle_traced(&post(&did, headers, b"{}"), &answers);
            assert_eq!(handled.response.status, 200, "{headers:?}");
            assert_eq!(handled.cache, Some(CacheOutcome::Bypass), "{headers:?}");
            assert_eq!(handled.sidecar_updates, None, "{headers:?}");
            assert_eq!(answers.seen.lock().expect("seen lock").len(), 1);
        }
    }

    /// Any query string on a POST — an option, a bare `?`, junk, or the
    /// specification's dereferencing example — is `INVALID_OPTIONS`, before
    /// the body is looked at and before the resolver.
    #[test]
    fn post_with_a_query_string_is_400_invalid_options() {
        let did = did_on(Network::Mainnet);
        for query in [
            "versionId=1",
            "",
            "x",
            "service=files&relativeRef=/resume.pdf",
        ] {
            let mut req = post(&did, &[], b"{}");
            req.query = Some(query.to_string());
            let resp = handle(&req, &Untouchable);
            assert_eq!(resp.status, 400, "{query:?}");
            assert_eq!(error_type(&resp), INVALID_OPTIONS, "{query:?}");
            assert!(
                error_detail(&resp).contains("query string"),
                "{query:?}: {}",
                error_detail(&resp)
            );
        }
    }

    /// An empty body and `{}` are the same request: a plain resolution
    /// through the uncached path, `Vary: Accept` on the 200 as for a GET.
    /// The GET path reports what the resolver reports (nothing, here); the
    /// POST path stamps the bypass itself.
    #[test]
    fn post_empty_body_and_empty_object_resolve_uncached() {
        let did = did_on(Network::Mainnet);
        let answers = Answers::default();
        for body in [&b""[..], b"{}"] {
            let handled = handle_traced(&post(&did, &[], body), &answers);
            assert_eq!(handled.response.status, 200, "{body:?}");
            assert!(
                handled
                    .response
                    .headers
                    .contains(&("Vary", "Accept".to_string())),
                "{body:?}"
            );
            assert_eq!(handled.cache, Some(CacheOutcome::Bypass), "{body:?}");
            assert_eq!(handled.sidecar_updates, None, "{body:?}");
        }
        let get = handle_traced(&request("GET", &resolve_path(&did), None), &answers);
        assert_eq!(get.response.status, 200);
        assert_eq!(get.cache, None);
        assert_eq!(get.sidecar_updates, None);
        for opts in answers.seen.lock().expect("seen lock").iter() {
            assert!(opts.sidecar_data.is_none());
            assert!(opts.version_id.is_none());
        }
    }

    /// The count of a sidecar's updates is what reached the resolver, `0`
    /// for an empty array and for a sidecar without one.
    #[test]
    fn post_sidecar_count_is_reported() {
        let did = did_on(Network::Mainnet);
        for body in [
            &br#"{"sidecar": {"updates": []}}"#[..],
            br#"{"sidecar": {}}"#,
        ] {
            let answers = Answers::default();
            let handled = handle_traced(&post(&did, &[], body), &answers);
            assert_eq!(handled.response.status, 200, "{body:?}");
            assert_eq!(handled.sidecar_updates, Some(0), "{body:?}");
            assert_eq!(handled.cache, Some(CacheOutcome::Bypass));
            let seen = answers.seen.lock().expect("seen lock");
            assert!(seen[0].sidecar_data.is_some(), "{body:?}");
        }
    }

    /// A body that is not a JSON object of options is `INVALID_OPTIONS`
    /// with the problem body; the resolver is never reached.
    #[test]
    fn post_malformed_body_is_400_invalid_options() {
        let did = did_on(Network::Mainnet);
        for body in [
            &b"["[..],
            b"[]",
            br#"{"versionId":"0"}"#,
            br#"{"versionId":"abc"}"#,
            br#"{"sidecar": 1}"#,
        ] {
            let resp = handle(&post(&did, &[], body), &Untouchable);
            assert_eq!(resp.status, 400, "{body:?}");
            assert_eq!(error_type(&resp), INVALID_OPTIONS, "{body:?}");
        }
    }

    /// The handler never reads `body` on a GET: a body the shell would not
    /// have read anyway changes nothing about the options.
    #[test]
    fn get_with_a_body_is_a_plain_get() {
        let did = did_on(Network::Mainnet);
        let answers = Answers::default();
        let mut req = request("GET", &resolve_path(&did), None);
        req.body = b"{\"versionId\": 2}".to_vec();
        let handled = handle_traced(&req, &answers);
        assert_eq!(handled.response.status, 200);
        assert_eq!(handled.cache, None);
        assert_eq!(handled.sidecar_updates, None);
        let seen = answers.seen.lock().expect("seen lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].version_id, None, "the body was ignored");
        assert!(seen[0].sidecar_data.is_none());
        drop(seen);
        // The shape the shell builds for every GET.
        let shell_get = Request {
            method: "GET".to_string(),
            path: resolve_path(&did),
            query: None,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert_eq!(handle(&shell_get, &answers).status, 200);
    }
}
