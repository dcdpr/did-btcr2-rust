//! `did-btcr2-resolver-http` — the W3C DID Resolution HTTP(S) GET binding over
//! the sans-I/O `did-btcr2` core and the `did-btcr2-client` facade.
//!
//! This crate owns no resolution logic. It turns `GET /1.0/identifiers/{did}`
//! into one call through the [`Resolve`] seam — in production
//! [`CachingResolver`] over [`ClientResolver`]: a miss builds a
//! `did_btcr2_client::Client` for the DID's own network, a hit is served from
//! memory for 60 s — and turns the typed result or error back into
//! an HTTP status, a `Content-Type`, and a resolution-result body. The request
//! handler is a pure function over plain structs so the conformance suite drives
//! it in-process with a scripted resolver; a thin `tiny_http` shell adapts it to
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
pub use options::{OptionsError, parse_options};
pub use path::{DecodeError, HEALTH_PATH, Route, percent_decode, route};
pub use problem::{
    Problem, RESOLUTION_RESULT, error_body, map_client_error, problem_response, status_for,
};
pub use resolve::{
    CACHE_CAPACITY, CACHE_TTL, CacheOutcome, CachingResolver, ClientResolver, Clock, Resolve,
    SystemClock,
};

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
/// those. Steps, in order: route (the liveness route answers here, for GET
/// and HEAD), method, decode once, empty, parse the DID (a DID URL is an
/// unsupported feature, another method is unsupported, anything else is an
/// invalid DID), options, `Accept`, resolve, map, body.
/// Only a request that reaches the resolution function gets a
/// resolution-result body; the route and method rejections are bodiless.
pub fn handle(req: &Request, resolver: &impl Resolve) -> Response {
    handle_traced(req, resolver).0
}

/// [`handle`], plus the cache outcome of the resolution it made: `None` when
/// the request was rejected before the resolver or the resolver has no cache.
/// The shell logs it; the outcome comes back with the response it belongs
/// to, so nothing is read from the resolver after the fact.
fn handle_traced(req: &Request, resolver: &impl Resolve) -> (Response, Option<CacheOutcome>) {
    let (did, opts, mode) = match prepare(req) {
        Ok(ready) => ready,
        Err(response) => return (response, None),
    };
    let (result, outcome) = resolver.resolve_traced(&did, opts);
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
    (response, outcome)
}

/// Everything [`handle`] does before the resolver: route, method, decode,
/// empty, parse the DID, options, `Accept`. `Ok` is what the resolution
/// call needs; `Err` is the response that ends the request here.
fn prepare(req: &Request) -> Result<(Did, ResolutionOptions, Mode), Response> {
    let encoded_did = match route(&req.path) {
        Route::NotFound => return Err(plain(404, vec![])),
        Route::Health if req.method == "GET" || req.method == "HEAD" => return Err(health()),
        Route::Health => return Err(plain(405, vec![("Allow", "GET, HEAD".to_string())])),
        Route::Resolve { encoded_did } => encoded_did,
    };
    if req.method != "GET" {
        return Err(plain(405, vec![("Allow", "GET".to_string())]));
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
    let mut opts =
        parse_options(req.query.as_deref()).map_err(|e| problem_response(e.details(), None))?;
    let accept = header_values(req, "accept");
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
    Ok((did, opts, mode))
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
/// (`hit`/`miss`/`n/a`), `network` — followed by the response's diagnostic
/// (the error chain behind a 500) when there is one. The diagnostic never
/// reaches the wire.
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
/// included: those never reach the resolver, so they carry `cache: "n/a"`.
fn serve_one(request: tiny_http::Request, resolver: &impl Resolve) {
    let started = Instant::now();
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
    let (response, cache) = match catch_unwind(AssertUnwindSafe(|| handle_traced(&plain, resolver)))
    {
        Ok(served) => served,
        Err(payload) => {
            eprintln!("handler panicked on {shown_target}; the worker continues");
            (
                problem_response(
                    problem::internal("the resolver failed internally"),
                    Some(format!("panic: {}", panic_message(payload.as_ref()))),
                ),
                None,
            )
        }
    };
    eprintln!(
        "{}",
        request_log_line(
            &plain.method,
            &target,
            did_for_log(&plain.path).as_ref(),
            header_values(&plain, "accept").as_deref(),
            response.status,
            started.elapsed(),
            cache,
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
/// terminal; `did` is the re-encoded parse result, never client bytes.
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
}

/// The `cache` field: `hit`, `miss`, or `n/a` when the resolver was not reached
/// (a rejected request, `/health`, or a panic) — or, for a resolver without a
/// cache, always (production wraps [`CachingResolver`], so never there).
fn cache_label(outcome: Option<CacheOutcome>) -> &'static str {
    match outcome {
        Some(CacheOutcome::Hit) => "hit",
        Some(CacheOutcome::Miss) => "miss",
        None => "n/a",
    }
}

/// Render the per-request log line. Pure, so it is tested without a socket.
fn request_log_line(
    method: &str,
    target: &str,
    did: Option<&Did>,
    accept: Option<&str>,
    status: u16,
    latency: Duration,
    cache: Option<CacheOutcome>,
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

    const FIELDS: [&str; 8] = [
        "method",
        "path",
        "did",
        "accept",
        "status",
        "latency_ms",
        "cache",
        "network",
    ];

    /// The line is one JSON object with exactly the eight fields, emitted in
    /// declaration order (not sorted), the numbers as numbers, on one line.
    #[test]
    fn request_log_line_has_the_eight_fields_in_declaration_order() {
        let line = request_log_line(
            "GET",
            "/1.0/identifiers/did:btcr2:k1abc?versionId=1",
            None,
            Some("application/did-resolution"),
            200,
            Duration::from_millis(1234),
            None,
        );
        assert!(!line.contains('\n'), "{line:?}");
        let map = parse_line(&line);
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        let mut expected: Vec<&str> = FIELDS.to_vec();
        expected.sort_unstable();
        let mut got = keys.clone();
        got.sort_unstable();
        assert_eq!(got, expected, "exactly the eight fields");
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
            (None, "n/a"),
        ] {
            let line = request_log_line("GET", "/x", None, None, 200, Duration::ZERO, outcome);
            assert_eq!(parse_line(&line)["cache"], json!(label), "{outcome:?}");
        }
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
        );
        let map = parse_line(&line);
        assert_eq!(map["did"], json!(did.encode()));
        assert_eq!(map["network"], json!("mainnet"));
        assert_eq!(map["accept"], Value::Null);

        let line = request_log_line("GET", "/health", None, None, 200, Duration::ZERO, None);
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
}
