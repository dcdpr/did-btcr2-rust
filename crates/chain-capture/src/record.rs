//! The recording seam: wrap any transport, drive a real resolve through it, and
//! keep every Esplora response body the resolve asked for.
//!
//! Recording sits at the HTTP boundary rather than inside the resolver, so the
//! captured bodies are exactly what a production resolve would have received —
//! and the replay harness later serves them back keyed by the same address the
//! resolver asked about.

use did_btcr2_client::{BtcTransport, TransportError};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

/// What one capture session observed.
#[derive(Debug, Default)]
pub struct Recording {
    /// `GET /address/{a}/txs` bodies, keyed by the address in the request path.
    ///
    /// A key present with an empty list is a captured-and-empty address; an
    /// absent key was never asked for.
    pub addresses: BTreeMap<String, Vec<Value>>,
    /// `GET /blocks/tip/height`.
    pub tip: Option<u32>,
}

/// A transport that delegates to `inner` and keeps the Esplora read traffic.
///
/// Only the two endpoint families a resolve reads are recorded: the per-address
/// transaction lists and the chain tip. Everything else — a broadcast, a UTXO
/// query, a fee estimate, a JSON-RPC call — passes through untouched and is
/// never persisted. That is deliberate: a fixture holds public chain data, and
/// an RPC request carries a credential.
pub struct RecordingTransport<T: BtcTransport> {
    inner: T,
    recording: Rc<RefCell<Recording>>,
}

impl<T: BtcTransport> RecordingTransport<T> {
    /// Wrap `inner`, recording what passes through it.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            recording: Rc::new(RefCell::new(Recording::default())),
        }
    }

    /// A shared handle on what has been recorded so far.
    ///
    /// The handle is shared, not owned, because a transport is consumed by value
    /// when a client is built and is never handed back. Clone the handle BEFORE
    /// moving the transport, and it keeps observing every later write.
    pub fn recording(&self) -> Rc<RefCell<Recording>> {
        Rc::clone(&self.recording)
    }
}

impl<T: BtcTransport> BtcTransport for RecordingTransport<T> {
    fn execute(
        &self,
        req: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, TransportError> {
        let path = req.uri().path().to_string();
        let resp = self.inner.execute(req)?;
        let status = resp.status().as_u16();

        if let Some(address) = address_from_txs_path(&path) {
            if !(200..300).contains(&status) {
                return Err(TransportError::Io(std::io::Error::other(format!(
                    "capture of `{address}` failed: HTTP {status} from {path} — \
                     a fixture must never record a failed response"
                ))));
            }
            let txs: Vec<Value> = serde_json::from_slice(resp.body()).map_err(|e| {
                std::io::Error::other(format!(
                    "capture of `{address}` failed: the response body is not a JSON array of \
                     transactions ({e}) — check that {path} points at an Esplora endpoint"
                ))
            })?;
            self.recording
                .borrow_mut()
                .addresses
                .insert(address.to_string(), txs);
        } else if path.ends_with("/blocks/tip/height") {
            if !(200..300).contains(&status) {
                return Err(TransportError::Io(std::io::Error::other(format!(
                    "chain-tip capture failed: HTTP {status} from {path} — \
                     every fixture pins the tip, so a missing one is fatal"
                ))));
            }
            // The body is a bare integer like `12345`; trim to tolerate the
            // trailing newline some endpoints emit.
            let text = std::str::from_utf8(resp.body()).map_err(|e| {
                std::io::Error::other(format!(
                    "chain-tip capture failed: {path} is not UTF-8 ({e})"
                ))
            })?;
            let tip: u32 = text.trim().parse().map_err(|e| {
                std::io::Error::other(format!(
                    "chain-tip capture failed: {path} returned `{}`, not a height ({e})",
                    text.trim()
                ))
            })?;
            self.recording.borrow_mut().tip = Some(tip);
        }

        Ok(resp)
    }
}

/// Extract the beacon address from an Esplora `/address/{a}/txs` request path.
///
/// Splits the query string off first, then requires the last three segments to
/// be `address`, `{address}`, `txs`. Used by BOTH the recorder here and the
/// replay harness's mirror, so capture and replay cannot disagree on the key.
///
/// A `/address/{a}/utxo` path, a broadcast, or a JSON-RPC path returns `None`.
pub fn address_from_txs_path(path: &str) -> Option<&str> {
    let path = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let n = segments.len();
    if n >= 3 && segments[n - 1] == "txs" && segments[n - 3] == "address" {
        Some(segments[n - 2])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const BASE: &str = "http://localhost:3000";
    const ADDR: &str = "bcrt1qexample";
    const OTHER: &str = "bcrt1qother";

    /// A transport that answers only the paths a test set up.
    ///
    /// Deliberately unlike the client crate's fake: an unrecognized path is a
    /// 404, not a permissive empty array, so the recorder's failure paths are
    /// actually reached.
    struct FakeInner {
        /// Address → response body for `/address/{a}/txs`.
        txs: BTreeMap<String, Vec<u8>>,
        /// Body for `/blocks/tip/height`.
        tip: Option<Vec<u8>>,
        /// Every path the fake was asked for, in order.
        seen: RefCell<Vec<String>>,
    }

    impl FakeInner {
        fn new() -> Self {
            Self {
                txs: BTreeMap::new(),
                tip: None,
                seen: RefCell::new(Vec::new()),
            }
        }

        fn with_txs(mut self, address: &str, body: &str) -> Self {
            self.txs
                .insert(address.to_string(), body.as_bytes().to_vec());
            self
        }

        fn with_tip(mut self, body: &str) -> Self {
            self.tip = Some(body.as_bytes().to_vec());
            self
        }
    }

    impl BtcTransport for FakeInner {
        fn execute(
            &self,
            req: http::Request<Vec<u8>>,
        ) -> Result<http::Response<Vec<u8>>, TransportError> {
            let path = req.uri().path().to_string();
            self.seen.borrow_mut().push(path.clone());

            let answer: Option<Vec<u8>> = if let Some(address) = address_from_txs_path(&path) {
                self.txs.get(address).cloned()
            } else if path.ends_with("/blocks/tip/height") {
                self.tip.clone()
            } else if path.ends_with("/utxo") {
                Some(b"[]".to_vec())
            } else if path.ends_with("/tx") {
                Some("00".repeat(32).into_bytes())
            } else if path == "/" {
                Some(br#"{"result":null,"error":null,"id":"1"}"#.to_vec())
            } else {
                None
            };

            let (status, body) = match answer {
                Some(body) => (200, body),
                None => (404, b"not found".to_vec()),
            };
            http::Response::builder()
                .status(status)
                .body(body)
                .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))
        }
    }

    /// The whole error chain as one string.
    ///
    /// `TransportError::Io`'s own `Display` is a fixed sentence; the detail the
    /// recorder builds lives on the wrapped source, which is what `main` prints
    /// as `Caused by:`. Asserting on the chain is therefore asserting on what
    /// the operator actually reads.
    fn chain(error: &TransportError) -> String {
        let mut out = error.to_string();
        let mut source = std::error::Error::source(error);
        while let Some(e) = source {
            out.push_str(" | ");
            out.push_str(&e.to_string());
            source = e.source();
        }
        out
    }

    fn get(transport: &impl BtcTransport, uri: &str) -> Result<Vec<u8>, TransportError> {
        let req = http::Request::get(uri)
            .body(Vec::new())
            .expect("a static URI is valid");
        Ok(transport.execute(req)?.body().clone())
    }

    fn one_tx_body() -> String {
        json!([{
            "txid": "aa".repeat(32),
            "version": 2,
            "locktime": 0,
            "vin": [],
            "vout": [{ "scriptpubkey": "6a20".to_string() + &"11".repeat(32), "value": 0 }],
            "size": 0,
            "weight": 0,
            "fee": 0,
            "status": {
                "confirmed": true,
                "block_height": 120,
                "block_hash": "00".repeat(32),
                "block_time": 1_700_000_000i64,
            },
        }])
        .to_string()
    }

    #[test]
    fn a_txs_body_is_recorded_under_its_address() {
        let inner = FakeInner::new().with_txs(ADDR, &one_tx_body());
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        get(&transport, &format!("{BASE}/address/{ADDR}/txs")).expect("the fetch succeeds");

        let recording = handle.borrow();
        let txs = recording
            .addresses
            .get(ADDR)
            .expect("the address was recorded");
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0]["status"]["block_height"], json!(120));
        assert_eq!(recording.tip, None);
    }

    #[test]
    fn an_empty_body_is_recorded_as_a_captured_empty_address() {
        let inner = FakeInner::new().with_txs(ADDR, "[]");
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        get(&transport, &format!("{BASE}/address/{ADDR}/txs")).expect("the fetch succeeds");

        let recording = handle.borrow();
        assert_eq!(
            recording.addresses.get(ADDR).map(Vec::len),
            Some(0),
            "an address that returned no transactions is captured-and-empty, not absent"
        );
        assert!(!recording.addresses.contains_key(OTHER));
    }

    #[test]
    fn the_chain_tip_is_recorded_and_is_not_an_address() {
        let inner = FakeInner::new().with_tip("212\n");
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        get(&transport, &format!("{BASE}/blocks/tip/height")).expect("the fetch succeeds");

        let recording = handle.borrow();
        assert_eq!(recording.tip, Some(212));
        assert!(
            recording.addresses.is_empty(),
            "the tip request must not appear as a beacon address"
        );
    }

    #[test]
    fn a_non_success_txs_response_is_an_error_and_records_nothing() {
        let inner = FakeInner::new();
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        let error = get(&transport, &format!("{BASE}/address/{ADDR}/txs"))
            .expect_err("an unanswered address must fail loud");
        let message = chain(&error);
        assert!(
            message.contains(ADDR) && message.contains("404"),
            "the failure must name the address and the status: {message}"
        );
        assert!(handle.borrow().addresses.is_empty());
    }

    #[test]
    fn a_non_success_tip_response_is_an_error() {
        let inner = FakeInner::new();
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        let error = get(&transport, &format!("{BASE}/blocks/tip/height"))
            .expect_err("an unanswered tip must fail loud");
        let message = chain(&error);
        assert!(
            message.contains("404"),
            "the failure must name the status: {message}"
        );
        assert_eq!(handle.borrow().tip, None);
    }

    #[test]
    fn a_body_that_is_not_a_transaction_array_is_an_error() {
        let inner = FakeInner::new().with_txs(ADDR, "<html>rate limited</html>");
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        let error = get(&transport, &format!("{BASE}/address/{ADDR}/txs"))
            .expect_err("a non-array body must not be stored as an opaque blob");
        let message = chain(&error);
        assert!(
            message.contains(ADDR) && message.contains("JSON array"),
            "the failure must name the address and the fault: {message}"
        );
        assert!(handle.borrow().addresses.is_empty());
    }

    #[test]
    fn a_non_numeric_tip_body_is_an_error() {
        let inner = FakeInner::new().with_tip("not a height");
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        let error = get(&transport, &format!("{BASE}/blocks/tip/height"))
            .expect_err("a non-numeric tip must fail loud");
        let message = chain(&error);
        assert!(
            message.contains("not a height"),
            "the failure must quote what came back: {message}"
        );
        assert_eq!(handle.borrow().tip, None);
    }

    #[test]
    fn two_requests_for_one_address_record_a_single_entry() {
        let inner = FakeInner::new().with_txs(ADDR, &one_tx_body());
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        get(&transport, &format!("{BASE}/address/{ADDR}/txs")).expect("the first fetch succeeds");
        get(&transport, &format!("{BASE}/address/{ADDR}/txs")).expect("the second fetch succeeds");

        let recording = handle.borrow();
        assert_eq!(recording.addresses.len(), 1);
        assert_eq!(
            recording.addresses.get(ADDR).map(Vec::len),
            Some(1),
            "the second body replaces the first rather than appending to it"
        );
    }

    #[test]
    fn a_cloned_handle_observes_writes_made_after_the_transport_moves() {
        let inner = FakeInner::new()
            .with_txs(ADDR, &one_tx_body())
            .with_tip("212");
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        // Move the transport somewhere that never gives it back, exactly as
        // building a client does.
        fn consume(transport: impl BtcTransport, uris: &[String]) {
            for uri in uris {
                get(&transport, uri).expect("the fetch succeeds");
            }
        }
        consume(
            transport,
            &[
                format!("{BASE}/address/{ADDR}/txs"),
                format!("{BASE}/blocks/tip/height"),
            ],
        );

        let recording = handle.borrow();
        assert_eq!(recording.addresses.len(), 1);
        assert_eq!(recording.tip, Some(212));
    }

    #[test]
    fn non_esplora_read_traffic_passes_through_unrecorded() {
        let transport = RecordingTransport::new(FakeInner::new());
        let handle = transport.recording();

        for uri in [
            format!("{BASE}/tx"),
            format!("{BASE}/address/{ADDR}/utxo"),
            "http://127.0.0.1:18443/".to_string(),
        ] {
            get(&transport, &uri).unwrap_or_else(|e| panic!("{uri} must pass through: {e}"));
        }

        let recording = handle.borrow();
        assert!(
            recording.addresses.is_empty(),
            "only /address/{{a}}/txs bodies are recorded, got {:?}",
            recording.addresses.keys().collect::<Vec<_>>()
        );
        assert_eq!(recording.tip, None);
    }

    #[test]
    fn every_request_still_reaches_the_wrapped_transport() {
        let transport = RecordingTransport::new(FakeInner::new().with_txs(ADDR, "[]"));

        get(&transport, &format!("{BASE}/address/{ADDR}/txs")).expect("the fetch succeeds");
        get(&transport, &format!("{BASE}/address/{ADDR}/utxo")).expect("the fetch succeeds");

        assert_eq!(
            *transport.inner.seen.borrow(),
            vec![
                format!("/address/{ADDR}/txs"),
                format!("/address/{ADDR}/utxo"),
            ],
            "the recorder observes traffic, it does not intercept or reorder it"
        );
    }

    #[test]
    fn address_extraction_ignores_a_query_string() {
        assert_eq!(
            address_from_txs_path("/address/bcrt1qexample/txs?limit=50"),
            Some("bcrt1qexample")
        );
        assert_eq!(
            address_from_txs_path("http://host:3000/address/bcrt1qexample/txs"),
            Some("bcrt1qexample")
        );
    }

    #[test]
    fn address_extraction_rejects_every_other_path() {
        for path in [
            "/address/bcrt1qexample/utxo",
            "/address/bcrt1qexample",
            "/blocks/tip/height",
            "/txs",
            "/tx",
            "/",
            "",
        ] {
            assert_eq!(
                address_from_txs_path(path),
                None,
                "`{path}` is not a beacon transaction-list path"
            );
        }
    }

    #[test]
    fn a_query_string_never_leaks_into_the_recorded_key() {
        let inner = FakeInner::new().with_txs(ADDR, "[]");
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        get(&transport, &format!("{BASE}/address/{ADDR}/txs?limit=50"))
            .expect("the fetch succeeds");

        assert_eq!(
            handle.borrow().addresses.keys().collect::<Vec<_>>(),
            vec![ADDR],
            "the key is the bare address, never the address plus a query"
        );
    }
}
