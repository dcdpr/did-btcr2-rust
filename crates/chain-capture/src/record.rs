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
    /// `GET /address/{a}/txs` bodies, keyed by the address in the request path,
    /// with every `GET /address/{a}/txs/chain/{last_seen_txid}` continuation
    /// page the client fetched appended in order — so an address's entry is
    /// its complete history as the resolver saw it, not Esplora's first page.
    ///
    /// A key present with an empty list is a captured-and-empty address; an
    /// absent key was never asked for.
    pub addresses: BTreeMap<String, Vec<Value>>,
    /// `GET /blocks/tip/height`.
    pub tip: Option<u32>,
    /// `GET /block/{hash}` bodies keyed by the hash in the request path.
    ///
    /// Invariant: each body's `id` equals its key. The recorder refuses a body
    /// whose `id` is absent, not a string, or a different hash, because the
    /// replay harness keys the served-back `mediantime` by the body's `id` and
    /// a mismatched body would silently never be found.
    ///
    /// Present only when the resolver asked for a block (an update proof
    /// carrying `expires` needs the confirming block's `mediantime`).
    pub blocks: BTreeMap<String, Value>,
}

/// A transport that delegates to `inner` and keeps the Esplora read traffic.
///
/// Only the three endpoint families a resolve reads are recorded: the
/// per-address transaction lists, the chain tip, and block headers (`GET
/// /block/{hash}`, asked for only when an update proof carries `expires`).
/// Everything else — a broadcast, a UTXO
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
        Self::sharing(inner, Rc::new(RefCell::new(Recording::default())))
    }

    /// Wrap `inner`, writing into an existing `recording`. Two transports over
    /// one recording is how a capture keeps a handle after the first has been
    /// moved into a client: what the client fetched and what the capture
    /// fetches afterwards land in the same fixture.
    pub fn sharing(inner: T, recording: Rc<RefCell<Recording>>) -> Self {
        Self { inner, recording }
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

        if let Some(page) = txs_page_from_path(&path) {
            let address = page.address();
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
            let mut recording = self.recording.borrow_mut();
            match page {
                // The first page starts the address's entry (and restarts it
                // on a re-fetch); a continuation extends it, so the entry
                // holds the whole history in the order the client walked it.
                TxsPage::First(address) => {
                    recording.addresses.insert(address.to_string(), txs);
                }
                TxsPage::Continuation { address, .. } => {
                    recording
                        .addresses
                        .entry(address.to_string())
                        .or_default()
                        .extend(txs);
                }
            }
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
        } else if let Some(hash) = block_hash_from_path(&path) {
            if !(200..300).contains(&status) {
                return Err(TransportError::Io(std::io::Error::other(format!(
                    "capture of block `{hash}` failed: HTTP {status} from {path} — \
                     a fixture must never record a failed response"
                ))));
            }
            let body: Value = serde_json::from_slice(resp.body()).map_err(|e| {
                TransportError::Malformed(format!(
                    "capture of block `{hash}` failed: the response body is not a JSON \
                     object ({e}) — check that {path} points at an Esplora endpoint"
                ))
            })?;
            if !body.is_object() {
                return Err(TransportError::Malformed(format!(
                    "capture of block `{hash}` failed: the response body is not a JSON \
                     object (got {}) — check that {path} points at an Esplora endpoint",
                    json_kind(&body)
                )));
            }
            // Exact comparison, no case folding: the resolver requests
            // `/block/{hash}` in lowercase hex, Esplora echoes the same lowercase
            // hex in `id`, and replay looks the body up by that same string — a
            // key differing only in case would never be served back anyway.
            match body.get("id").and_then(Value::as_str) {
                Some(id) if id == hash => {}
                Some(id) => {
                    return Err(TransportError::Malformed(format!(
                        "capture of block `{hash}` failed: the response body's `id` is `{id}`, \
                         not the hash in the request path — replay keys the block's mediantime \
                         by the body's `id`, so a mismatched body would never be served back"
                    )));
                }
                None => {
                    return Err(TransportError::Malformed(format!(
                        "capture of block `{hash}` failed: the response body has no string \
                         `id` — check that {path} points at an Esplora endpoint"
                    )));
                }
            }
            let mut recording = self.recording.borrow_mut();
            recording.blocks.insert(hash.to_string(), body);
        }

        Ok(resp)
    }
}

/// Fetch `GET {base_url}/block/{hash}` through `transport` for the block of
/// every confirmed announcement-shaped transaction — last output `OP_RETURN
/// <32-byte push>` — in `addresses`, one request per distinct block. Over a
/// [`RecordingTransport`] the bodies land in the recording's `blocks`, so a
/// fixture carries each announcement's `mediantime` whether or not the
/// resolve that produced it happened to ask: a replay under a `versionTime`
/// bound compares against it, and a capture without it cannot host that
/// probe. Returns the hashes fetched, in order.
pub fn capture_announcement_blocks<T: BtcTransport>(
    transport: &T,
    base_url: &str,
    addresses: &BTreeMap<String, Vec<Value>>,
) -> Result<Vec<String>, TransportError> {
    let mut hashes: Vec<String> = Vec::new();
    for tx in addresses.values().flatten() {
        let announces = tx["vout"]
            .as_array()
            .and_then(|vout| vout.last())
            .and_then(|out| out["scriptpubkey"].as_str())
            .is_some_and(is_announcement_script);
        let confirmed = tx["status"]["confirmed"].as_bool() == Some(true);
        let Some(hash) = tx["status"]["block_hash"].as_str() else {
            continue;
        };
        if announces && confirmed && is_block_hash(hash) && !hashes.iter().any(|h| h == hash) {
            hashes.push(hash.to_string());
        }
    }
    for hash in &hashes {
        let request = http::Request::get(format!("{base_url}/block/{hash}"))
            .body(Vec::new())
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
        transport.execute(request)?;
    }
    Ok(hashes)
}

/// `OP_RETURN OP_PUSHBYTES_32 <32 bytes>` as lowercase hex: `6a20` and 64
/// hex digits, the shape of every beacon announcement's signal output.
fn is_announcement_script(hex: &str) -> bool {
    hex.len() == 68 && hex.starts_with("6a20") && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// The JSON type name of a value, for an error an operator has to read.
fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Which page of an address history a request path asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum TxsPage<'a> {
    /// `/address/{a}/txs`: mempool entries plus the first confirmed page.
    First(&'a str),
    /// `/address/{a}/txs/chain/{last_seen_txid}`: the confirmed page after
    /// `last_seen`.
    Continuation {
        /// The address whose history is being paged.
        address: &'a str,
        /// The txid the page continues from.
        last_seen: &'a str,
    },
}

impl<'a> TxsPage<'a> {
    /// The address the page belongs to.
    pub fn address(&self) -> &'a str {
        match self {
            Self::First(address) | Self::Continuation { address, .. } => address,
        }
    }
}

/// Classify an Esplora address-history request path: the first page
/// ([`address_from_txs_path`]) or a continuation page
/// `/address/{a}/txs/chain/{last_seen_txid}`. Anything else is `None`.
pub fn txs_page_from_path(path: &str) -> Option<TxsPage<'_>> {
    if let Some(address) = address_from_txs_path(path) {
        return Some(TxsPage::First(address));
    }
    let path = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let n = segments.len();
    if n >= 5
        && segments[n - 5] == "address"
        && segments[n - 3] == "txs"
        && segments[n - 2] == "chain"
    {
        Some(TxsPage::Continuation {
            address: segments[n - 4],
            last_seen: segments[n - 1],
        })
    } else {
        None
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

/// Extract the block hash from an Esplora `/block/{hash}` request path.
///
/// Splits the query string off first, then requires the last two segments to be
/// `block`, `{hash}` with the hash exactly 64 hex characters. Mirrors the replay
/// harness's route in the core crate, so capture and replay key a block on the
/// same string: the hash as it appears in the request path.
///
/// A block sub-resource (`/block/{hash}/txids`, `/block/{hash}/status`), the tip
/// (`/blocks/tip/height`), and a height lookup (`/block-height/{n}`) all return
/// `None`.
pub fn block_hash_from_path(path: &str) -> Option<&str> {
    let path = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let n = segments.len();
    if n >= 2 && segments[n - 2] == "block" && is_block_hash(segments[n - 1]) {
        Some(segments[n - 1])
    } else {
        None
    }
}

/// Exactly 64 ASCII hex digits: the display form of a block hash.
fn is_block_hash(segment: &str) -> bool {
    segment.len() == 64 && segment.chars().all(|c| c.is_ascii_hexdigit())
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
        /// `last_seen_txid` → response body for `/address/{a}/txs/chain/{txid}`.
        pages: BTreeMap<String, Vec<u8>>,
        /// Body for `/blocks/tip/height`.
        tip: Option<Vec<u8>>,
        /// Block hash → response body for `/block/{hash}`.
        blocks: BTreeMap<String, Vec<u8>>,
        /// Every path the fake was asked for, in order.
        seen: RefCell<Vec<String>>,
    }

    impl FakeInner {
        fn new() -> Self {
            Self {
                txs: BTreeMap::new(),
                pages: BTreeMap::new(),
                tip: None,
                blocks: BTreeMap::new(),
                seen: RefCell::new(Vec::new()),
            }
        }

        fn with_txs(mut self, address: &str, body: &str) -> Self {
            self.txs
                .insert(address.to_string(), body.as_bytes().to_vec());
            self
        }

        fn with_page(mut self, last_seen: &str, body: &str) -> Self {
            self.pages
                .insert(last_seen.to_string(), body.as_bytes().to_vec());
            self
        }

        fn with_tip(mut self, body: &str) -> Self {
            self.tip = Some(body.as_bytes().to_vec());
            self
        }

        fn with_block(mut self, hash: &str, body: &str) -> Self {
            self.blocks
                .insert(hash.to_string(), body.as_bytes().to_vec());
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
            } else if let Some(TxsPage::Continuation { last_seen, .. }) = txs_page_from_path(&path)
            {
                self.pages.get(last_seen).cloned()
            } else if path.ends_with("/blocks/tip/height") {
                self.tip.clone()
            } else if let Some(hash) = block_hash_from_path(&path) {
                self.blocks.get(hash).cloned()
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

    /// A block hash as Esplora prints it: 64 lowercase hex characters.
    fn block_hash() -> String {
        "0a".repeat(32)
    }

    fn one_block_body(hash: &str) -> String {
        json!({
            "id": hash,
            "height": 1,
            "timestamp": 1_700_000_000i64,
            "mediantime": 1_699_996_400i64,
        })
        .to_string()
    }

    #[test]
    fn a_block_body_is_recorded_under_its_hash() {
        let hash = block_hash();
        let inner = FakeInner::new().with_block(&hash, &one_block_body(&hash));
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        get(&transport, &format!("{BASE}/block/{hash}")).expect("the fetch succeeds");

        let recording = handle.borrow();
        let block = recording
            .blocks
            .get(&hash)
            .expect("the block was recorded under its hash");
        assert_eq!(block["mediantime"], json!(1_699_996_400i64));
        assert_eq!(block["id"], json!(hash));
        assert!(
            recording.addresses.is_empty() && recording.tip.is_none(),
            "a block request must not appear as an address or the tip"
        );
    }

    #[test]
    fn a_block_subresource_is_not_recorded() {
        let hash = block_hash();
        let transport = RecordingTransport::new(FakeInner::new());
        let handle = transport.recording();

        // The fake answers 404 for a sub-resource; the recorder must not treat
        // that as a failed block capture either, since it is not a block request.
        get(&transport, &format!("{BASE}/block/{hash}/txids"))
            .expect("a sub-resource passes through unrecorded, whatever it returns");

        assert!(
            handle.borrow().blocks.is_empty(),
            "only /block/{{hash}} bodies are recorded, got {:?}",
            handle.borrow().blocks.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_non_success_block_response_is_an_error_and_records_nothing() {
        let hash = block_hash();
        let transport = RecordingTransport::new(FakeInner::new());
        let handle = transport.recording();

        let error = get(&transport, &format!("{BASE}/block/{hash}"))
            .expect_err("an unanswered block must fail loud");
        let message = chain(&error);
        assert!(
            message.contains(&hash) && message.contains("404"),
            "the failure must name the block and the status: {message}"
        );
        assert!(
            matches!(error, TransportError::Io(_)),
            "a failed response is an I/O-class capture failure, got {error:?}"
        );
        assert!(handle.borrow().blocks.is_empty());
    }

    #[test]
    fn a_block_body_that_is_not_an_object_is_an_error() {
        let hash = block_hash();
        for (body, fault) in [
            ("<html>rate limited</html>", "not JSON"),
            ("[1, 2, 3]", "a JSON array"),
            ("\"a string\"", "a JSON string"),
        ] {
            let inner = FakeInner::new().with_block(&hash, body);
            let transport = RecordingTransport::new(inner);
            let handle = transport.recording();

            let error = get(&transport, &format!("{BASE}/block/{hash}"))
                .err()
                .unwrap_or_else(|| panic!("{fault} must not be stored as a block"));
            assert!(
                matches!(error, TransportError::Malformed(_)),
                "{fault} is a malformed body, not an I/O failure, got {error:?}"
            );
            let message = chain(&error);
            assert!(
                message.contains(&hash) && message.contains("JSON object"),
                "the failure must name the block and the fault: {message}"
            );
            assert!(handle.borrow().blocks.is_empty());
        }
    }

    #[test]
    fn a_block_body_whose_id_is_not_the_path_hash_is_an_error() {
        let hash = block_hash();
        let other = "0b".repeat(32);
        let inner = FakeInner::new().with_block(&hash, &one_block_body(&other));
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        let error = get(&transport, &format!("{BASE}/block/{hash}"))
            .expect_err("a body for a different block must not be stored under this hash");
        assert!(
            matches!(error, TransportError::Malformed(_)),
            "a contradicting body is a malformed body, got {error:?}"
        );
        let message = chain(&error);
        assert!(
            message.contains(&hash) && message.contains(&other) && message.contains("id"),
            "the failure must name both hashes and the `id` field: {message}"
        );
        assert!(handle.borrow().blocks.is_empty());
    }

    #[test]
    fn a_block_body_without_a_string_id_is_an_error() {
        let hash = block_hash();
        for (body, fault) in [
            (
                r#"{"height":1,"mediantime":1699996400}"#,
                "a body with no id",
            ),
            (r#"{"id":5,"mediantime":1699996400}"#, "a non-string id"),
        ] {
            let inner = FakeInner::new().with_block(&hash, body);
            let transport = RecordingTransport::new(inner);
            let handle = transport.recording();

            let error = get(&transport, &format!("{BASE}/block/{hash}"))
                .err()
                .unwrap_or_else(|| panic!("{fault} must not be stored as a block"));
            assert!(
                matches!(error, TransportError::Malformed(_)),
                "{fault} is a malformed body, got {error:?}"
            );
            let message = chain(&error);
            assert!(
                message.contains(&hash) && message.contains("id"),
                "the failure must name the block and the `id` field: {message}"
            );
            assert!(handle.borrow().blocks.is_empty());
        }
    }

    #[test]
    fn block_hash_from_path_accepts_only_a_64_hex_last_segment() {
        let hash = block_hash();
        let upper = hash.to_uppercase();
        assert_eq!(
            block_hash_from_path(&format!("/block/{hash}")),
            Some(hash.as_str())
        );
        assert_eq!(
            block_hash_from_path(&format!("http://host:3000/block/{hash}?x=1")),
            Some(hash.as_str()),
            "the base and a query string are not part of the key"
        );
        assert_eq!(
            block_hash_from_path(&format!("/block/{upper}")),
            Some(upper.as_str()),
            "hex case is not the recorder's concern; the key is the path segment verbatim"
        );
        for path in [
            format!("/block/{hash}/txids"),
            format!("/block/{hash}/status"),
            "/blocks/tip/height".to_string(),
            "/block-height/120".to_string(),
            "/block/abc".to_string(),
            format!("/block/{}", "zz".repeat(32)),
            format!("/block/{hash}0"),
            "/block".to_string(),
            format!("/{hash}"),
            "".to_string(),
        ] {
            assert_eq!(
                block_hash_from_path(&path),
                None,
                "`{path}` is not a block-header path"
            );
        }
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
    fn announcement_blocks_are_fetched_once_each_and_recorded() {
        // Two announcements in block A (one request, not two), one
        // non-announcing transaction in block B (not fetched), and one
        // unconfirmed announcement (no block to fetch).
        let hash_a = "aa".repeat(32);
        let hash_b = "bb".repeat(32);
        let announcement = |txid: &str, hash: &str| {
            json!({
                "txid": txid,
                "version": 2, "locktime": 0, "vin": [],
                "vout": [{ "scriptpubkey": format!("6a20{}", "11".repeat(32)), "value": 0 }],
                "size": 0, "weight": 0, "fee": 0,
                "status": { "confirmed": true, "block_height": 120, "block_hash": hash, "block_time": 1_700_000_000 },
            })
        };
        let mut pending = announcement(&"04".repeat(32), &hash_b);
        pending["status"] = json!({ "confirmed": false });
        let mut payment = announcement(&"03".repeat(32), &hash_b);
        payment["vout"] =
            json!([{ "scriptpubkey": "0014".to_string() + &"ab".repeat(20), "value": 1 }]);
        let addresses = BTreeMap::from([
            (
                ADDR.to_string(),
                vec![
                    announcement(&"01".repeat(32), &hash_a),
                    announcement(&"02".repeat(32), &hash_a),
                ],
            ),
            (OTHER.to_string(), vec![payment, pending]),
        ]);

        let inner = FakeInner::new().with_block(&hash_a, &one_block_body(&hash_a));
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        let fetched = capture_announcement_blocks(&transport, BASE, &addresses)
            .expect("the announcement's block is fetched");
        assert_eq!(fetched, vec![hash_a.clone()], "one block, fetched once");
        let recording = handle.borrow();
        assert_eq!(
            recording.blocks.keys().collect::<Vec<_>>(),
            vec![&hash_a],
            "the body is recorded under its hash; the payment's block is not fetched"
        );
    }

    #[test]
    fn a_shared_recording_sees_both_transports_traffic() {
        let recording = Rc::new(RefCell::new(Recording::default()));
        let first =
            RecordingTransport::sharing(FakeInner::new().with_tip("212"), Rc::clone(&recording));
        let second = RecordingTransport::sharing(
            FakeInner::new().with_txs(ADDR, &one_tx_body()),
            Rc::clone(&recording),
        );
        get(&first, &format!("{BASE}/blocks/tip/height")).expect("the tip fetches");
        get(&second, &format!("{BASE}/address/{ADDR}/txs")).expect("the txs fetch");
        let recording = recording.borrow();
        assert_eq!(recording.tip, Some(212));
        assert!(recording.addresses.contains_key(ADDR));
    }

    #[test]
    fn a_continuation_page_extends_the_address_entry_in_order() {
        let first = one_tx_body();
        let older = json!([{
            "txid": "22".repeat(32),
            "version": 2, "locktime": 0, "vin": [], "vout": [], "size": 0, "weight": 0, "fee": 0,
            "status": { "confirmed": true, "block_height": 90, "block_hash": "00".repeat(32), "block_time": 1_700_000_000 },
        }])
        .to_string();
        let inner = FakeInner::new()
            .with_txs(ADDR, &first)
            .with_page(&"11".repeat(32), &older);
        let transport = RecordingTransport::new(inner);
        let handle = transport.recording();

        get(&transport, &format!("{BASE}/address/{ADDR}/txs")).expect("the first page fetches");
        get(
            &transport,
            &format!("{BASE}/address/{ADDR}/txs/chain/{}", "11".repeat(32)),
        )
        .expect("the continuation fetches");

        let recording = handle.borrow();
        let txs = recording
            .addresses
            .get(ADDR)
            .expect("the address was recorded");
        assert_eq!(
            txs.iter()
                .map(|tx| tx["status"]["block_height"].as_u64())
                .collect::<Vec<_>>(),
            vec![Some(120), Some(90)],
            "the continuation's transactions follow the first page's, under ONE key"
        );
        assert_eq!(
            recording.addresses.len(),
            1,
            "a continuation is not a second address"
        );
    }

    #[test]
    fn txs_page_from_path_classifies_first_and_continuation_pages() {
        assert_eq!(
            txs_page_from_path("/address/bcrt1qa/txs"),
            Some(TxsPage::First("bcrt1qa"))
        );
        assert_eq!(
            txs_page_from_path("/api/address/bcrt1qa/txs/chain/abcd?x=1"),
            Some(TxsPage::Continuation {
                address: "bcrt1qa",
                last_seen: "abcd"
            })
        );
        for other in [
            "/address/bcrt1qa/utxo",
            "/address/bcrt1qa/txs/mempool",
            "/address/bcrt1qa/txs/chain",
            "/blocks/tip/height",
            "/tx",
        ] {
            assert_eq!(txs_page_from_path(other), None, "{other}");
        }
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
        assert!(recording.blocks.is_empty());
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
