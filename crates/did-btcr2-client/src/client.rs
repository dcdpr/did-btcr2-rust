//! The four-operation facade `Client`.
//!
//! Composes the sans-I/O core with the injected [`BtcTransport`](crate::transport::BtcTransport)
//! seam. `create` (no I/O), `resolve` (drives the resolver FSM through the
//! transport), and `update`/`deactivate` (construct → fund → announce →
//! broadcast, split into a build half [`Client::build_update_tx`] and a broadcast
//! half so a `--dry-run` / offline path can stop after build).

use std::collections::HashMap;
use std::num::NonZeroU64;

use did_btcr2::document::{
    Document, InitialDocument, IntermediateDocument, ResolutionOptions, ResolutionResult,
};
use did_btcr2::identifier::{Did, DidComponents, DidVersion, IdType, Network};
use did_btcr2::key::PublicKey;
use did_btcr2::resolver::ResolverState;
use did_btcr2::{SignedBeaconTx, Update};
use esploda::bitcoin::{Address, Txid};
use esploda::esplora::Transaction;
use json_patch::Patch;
use secp256k1::SecretKey;

use crate::error::{Error, TransportError};
use crate::esplora;
use crate::funding::{self, Fee};
use crate::transport::BtcTransport;
use crate::url::resolve_base_url;

/// The `did:btcr2` client facade.
///
/// Holds the Esplora base URL and an injected [`BtcTransport`]. The transport is
/// a type parameter so a production [`UreqTransport`](crate::transport::UreqTransport)
/// and an in-process fake share one code path.
pub struct Client<T: BtcTransport> {
    base_url: String,
    transport: T,
}

impl<T: BtcTransport> Client<T> {
    /// Create a client against an explicit Esplora base URL.
    pub fn new(base_url: String, transport: T) -> Self {
        Self {
            base_url,
            transport,
        }
    }

    /// Create a client by selecting the Esplora base URL from a network name,
    /// with an optional `--esplora-url` override (see
    /// [`resolve_base_url`](crate::resolve_base_url)).
    pub fn with_network(
        network: &str,
        esplora_url: Option<String>,
        transport: T,
    ) -> Result<Self, Error> {
        let base_url = resolve_base_url(Some(network), esplora_url)?;
        Ok(Self::new(base_url, transport))
    }

    /// Create a key-based singleton DID document from a public key.
    ///
    /// This is pure composition over the sans-I/O core — it makes ZERO transport
    /// calls. It takes `&self` only to keep the facade's entry surface
    /// uniform; no field is read. The DID is fixed to version 1
    /// ([`DidVersion::One`]) per the spec.
    pub fn create(&self, public_key: &PublicKey, network: Network) -> Result<Document, Error> {
        let id_type = IdType::from(*public_key);
        let components = DidComponents::new(DidVersion::One, network, id_type);
        let did = Did::try_from(components)?;
        let initial = InitialDocument::from_did(&did, &ResolutionOptions::default())?;
        Ok(Document::from(initial))
    }

    /// Create an external (`x1`) DID + initial document from an externally-authored
    /// intermediate document.
    ///
    /// Pure composition over the sans-I/O core — it makes ZERO transport calls,
    /// and takes `&self` only to keep the facade's entry surface uniform with
    /// [`Client::create`]; no field is read. The DID is fixed to version 1
    /// ([`DidVersion::One`]) per the spec. Returns `Result` for signature
    /// uniformity with `create`; the underlying core call is infallible.
    ///
    /// The resulting `x1` DID is NOT deterministically resolvable: resolving it
    /// requires the genesis (intermediate) document to be supplied as sidecar
    /// data (`resolve --sidecar <file>`).
    pub fn create_external(
        &self,
        intermediate_document: IntermediateDocument,
        network: Network,
    ) -> Result<(Did, Document), Error> {
        let (did, initial) = InitialDocument::from_external_intermediate(
            intermediate_document,
            Some(DidVersion::One),
            Some(network),
        );
        Ok((did, Document::from(initial)))
    }

    /// Resolve a `did:btcr2` identifier to the spec resolution triple.
    ///
    /// Fetches the chain-tip height (a hard, propagated fetch — a None tip
    /// silently weakens confirmation reporting), then drives the sans-I/O
    /// resolver FSM to completion, issuing each beacon request through the
    /// injected transport.
    pub fn resolve(
        &self,
        did: &Did,
        mut opts: ResolutionOptions,
    ) -> Result<ResolutionResult, Error> {
        // Chain-tip GET — confirmations depend on a reliable tip, so this is a
        // hard `?`-propagated fetch (CLI main.rs:255-260 precedent).
        let tip = esplora::chain_tip_height(&self.transport, &self.base_url)?;
        if opts.chain_tip_height.is_none() {
            opts.chain_tip_height = Some(tip);
        }
        if opts.esplora_url.is_none() {
            opts.esplora_url = Some(self.base_url.clone());
        }

        // Drive the sans-I/O resolver FSM. The core returns the beacon requests
        // to issue; the facade runs them through the transport and feeds the
        // typed responses back.
        let mut fsm = Document::resolve(did, opts)?;
        let result = loop {
            match fsm.resolve()? {
                ResolverState::Requests(next_state, beacons) => {
                    let mut responses = HashMap::new();
                    for (beacon_type, requests) in beacons {
                        for req in requests {
                            let resp = self.transport.execute(req.map(|()| Vec::new()))?;
                            let status = resp.status().as_u16();
                            if !(200..300).contains(&status) {
                                return Err(Error::Transport(TransportError::Status {
                                    status,
                                    body: String::from_utf8_lossy(resp.body()).into_owned(),
                                }));
                            }
                            let txs: Vec<Transaction> = serde_json::from_slice(resp.body())?;
                            let entry: &mut Vec<Transaction> =
                                responses.entry(beacon_type).or_default();
                            entry.extend(txs);
                        }
                    }
                    fsm = next_state.process_responses(responses);
                }
                ResolverState::Resolved(result) => break result,
            }
        };

        Ok(result)
    }

    /// Build (but do NOT broadcast) the singleton-beacon announcement
    /// transaction for an already-constructed signed [`Update`] (build
    /// half). This is the `--dry-run` / offline-test entry point: it makes the
    /// `/utxo` (and, for a rate fee, `/fee-estimates`) GETs but issues NO
    /// `POST /tx`.
    ///
    /// Reads the beacon at `beacon_idx` via its accessor, fetches its own
    /// UTXOs, defaults the change address back to the beacon address
    /// resolves the [`Fee`] and selects funding inputs per the bounded
    /// single-input contract, and feeds the result to the core
    /// [`announce_singleton`](did_btcr2::Update::announce_singleton). For a rate
    /// fee the transaction is built twice: once with a provisional fee to measure
    /// the real vsize, then again with the exact `ceil(rate * vsize)` fee on the
    /// SAME single prevout (no divergence between the measured and broadcast tx).
    pub fn build_update_tx(
        &self,
        doc: &Document,
        signed: Update,
        beacon_idx: usize,
        fee: Fee,
        change: Option<Address>,
        beacon_sk: SecretKey,
    ) -> Result<SignedBeaconTx, Error> {
        let beacon = doc.beacons().nth(beacon_idx).ok_or(Error::NoBeacon)?;
        let addr = beacon.address().clone();
        let spk = addr.script_pubkey();
        let change_addr = change.unwrap_or_else(|| addr.clone());

        let utxos = funding::fetch_utxos(&self.transport, &self.base_url, &addr)?;

        match fee {
            Fee::Absolute(n) => {
                let prevouts = funding::select(&utxos, &spk, n)?;
                let signed_tx =
                    signed.announce_singleton(&addr, &prevouts, n, &change_addr, beacon_sk)?;
                Ok(signed_tx)
            }
            Fee::Rate(r) => {
                // Bootstrap with a provisional fee from a pessimistic vsize.
                let provisional = funding::resolve_fee(Fee::Rate(r), funding::provisional_vsize());
                let prevouts = funding::select(&utxos, &spk, provisional)?;
                // Bounded single-input contract: a rate fee MUST fund from one
                // input (so the rebuild vsize is stable). Multi-input under a
                // rate fee is deferred.
                if prevouts.len() > 1 {
                    return Err(Error::RateFeeRequiresMultipleInputs);
                }
                // First build measures the real vsize.
                let provisional_tx = signed.announce_singleton(
                    &addr,
                    &prevouts,
                    provisional,
                    &change_addr,
                    beacon_sk,
                )?;
                let vsize = provisional_tx.as_tx().vsize() as u64;
                let abs_fee = funding::resolve_fee(Fee::Rate(r), vsize);
                // The provisional selection only guaranteed coverage of
                // `provisional` (= rate * PROVISIONAL_VSIZE). Correctness of
                // reusing that prevout for `abs_fee` depends on the implicit
                // invariant `measured_vsize <= PROVISIONAL_VSIZE`. Re-validate
                // explicitly so a future output/script change that pushes the
                // measured vsize past the ceiling fails with a precise error
                // rather than a confusing InsufficientFunds from the rebuild
                let inputs_total: u64 = prevouts.iter().map(|p| p.value).sum();
                if inputs_total < abs_fee {
                    return Err(Error::NoSpendableUtxo);
                }
                // Rebuild with the exact fee on the SAME single prevout: input/
                // output count is unchanged, so the rebuilt vsize equals the
                // measured vsize and the fee is exact.
                let signed_tx = signed.announce_singleton(
                    &addr,
                    &prevouts,
                    abs_fee,
                    &change_addr,
                    beacon_sk,
                )?;
                Ok(signed_tx)
            }
        }
    }

    /// Broadcast an already-built [`SignedBeaconTx`] via `POST {base}/tx` and
    /// return the broadcast txid. A non-2xx response, or a 2xx whose body is not
    /// the locally computed txid, is a typed [`Error::BroadcastRejected`] (the
    /// response is inspected, never panicked).
    ///
    /// Public so a caller that builds the tx with [`Client::build_update_tx`],
    /// shows it for confirmation, and then broadcasts THAT EXACT tx can do so
    /// without a second build/fund pass (the confirmed bytes and the
    /// broadcast bytes are identical).
    pub fn broadcast(&self, tx: &SignedBeaconTx) -> Result<Txid, Error> {
        let raw = esploda::bitcoin::consensus::encode::serialize(tx.as_tx());
        let hex = hex_encode(&raw);

        let req = http::Request::post(format!("{}/tx", self.base_url))
            .body(hex.into_bytes())
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;

        let resp = self.transport.execute(req)?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::BroadcastRejected {
                body: String::from_utf8_lossy(resp.body()).into_owned(),
            });
        }
        // Esplora's POST /tx returns the broadcast txid as text. Cross-check it
        // against the locally computed txid so a 200 with an empty body, an error
        // page, or a *different* txid cannot masquerade as a successful broadcast
        // (a false success would tell the caller the DID update landed when it did
        // not). A mismatch or unparseable body is a typed BroadcastRejected.
        let local = tx.as_tx().txid();
        let body = String::from_utf8_lossy(resp.body());
        let returned: Txid = body.trim().parse().map_err(|_| Error::BroadcastRejected {
            body: body.clone().into_owned(),
        })?;
        if returned != local {
            return Err(Error::BroadcastRejected {
                body: format!("endpoint returned txid {returned}, expected {local}"),
            });
        }
        Ok(local)
    }

    /// Update the DID document: construct a signed update against `doc`, fund and
    /// build the beacon announcement, broadcast it, and return the broadcast
    /// txid.
    ///
    /// `current_version_id` is the version of `doc` (the resolved document the
    /// update is built against); the update targets `current + 1`. It is an
    /// explicit parameter (matching [`Client::deactivate`]) — the facade does not
    /// silently infer it. `update_sk` signs the update proof; `beacon_sk` signs
    /// the announcement inputs (for the default singleton path the same key backs
    /// both, but a rotated beacon key is expressible).
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &self,
        doc: &Document,
        patch: Patch,
        vm_id: &str,
        update_sk: SecretKey,
        beacon_sk: SecretKey,
        current_version_id: NonZeroU64,
        beacon_idx: usize,
        fee: Fee,
        change: Option<Address>,
    ) -> Result<Txid, Error> {
        let target = current_version_id
            .checked_add(1)
            .expect("a DID version_id never reaches u64::MAX in practice");
        let signed = doc.construct_signed_update(patch, target, vm_id, update_sk)?;
        let tx = self.build_update_tx(doc, signed, beacon_idx, fee, change, beacon_sk)?;
        self.broadcast(&tx)
    }

    /// Deactivate the DID document: construct the deactivate update against
    /// `doc`, fund and build the beacon announcement, broadcast it, and return
    /// the broadcast txid.
    ///
    /// Same shape as [`Client::update`]; the update is the `/deactivated true`
    /// patch and targets `current_version_id + 1`. The core's Guard 0 rejects a
    /// deactivate on an already-deactivated document before any broadcast.
    #[allow(clippy::too_many_arguments)]
    pub fn deactivate(
        &self,
        doc: &Document,
        vm_id: &str,
        update_sk: SecretKey,
        beacon_sk: SecretKey,
        current_version_id: NonZeroU64,
        beacon_idx: usize,
        fee: Fee,
        change: Option<Address>,
    ) -> Result<Txid, Error> {
        let target = current_version_id
            .checked_add(1)
            .expect("a DID version_id never reaches u64::MAX in practice");
        let signed = doc.deactivate(vm_id, update_sk, target)?;
        let tx = self.build_update_tx(doc, signed, beacon_idx, fee, change, beacon_sk)?;
        self.broadcast(&tx)
    }
}

/// Lowercase-hex encode a byte slice (the `POST /tx` body is raw tx hex). Kept
/// local so the facade carries no extra hex dependency for this single use.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("writing to a String never fails");
    }
    s
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use did_btcr2::identifier::Network;
    use did_btcr2::key::PublicKey;
    use secp256k1::{Secp256k1, SecretKey};

    use super::*;
    use crate::transport::BtcTransport;

    /// An in-process fake transport. Routes by request path + method and records
    /// both the total `execute` count and the `POST /tx` count. Each test owns
    /// its own instance, so `RefCell`/`Cell` are sufficient (no cross-thread
    /// sharing).
    struct FakeTransport {
        calls: RefCell<usize>,
        post_tx_calls: std::cell::Cell<usize>,
        /// Body served for `GET /address/{a}/txs` (a JSON tx array).
        txs_body: Vec<u8>,
        /// Chain-tip height served as a bare integer.
        tip: u32,
        /// A funding UTXO value (sats) served for `GET /address/{a}/utxo`.
        utxo_value: u64,
        /// HTTP status returned for `POST /tx` (200 by default; set non-2xx to
        /// exercise the broadcast-rejection path).
        broadcast_status: u16,
        /// If set, EVERY request returns this HTTP status (for the resolve error
        /// test).
        force_status: Option<u16>,
        /// If set, `POST /tx` returns 200 with a txid that does NOT match the
        /// posted transaction (exercises the broadcast txid cross-check).
        echo_wrong_txid: bool,
    }

    impl FakeTransport {
        fn new(txs_body: &str) -> Self {
            Self {
                calls: RefCell::new(0),
                post_tx_calls: std::cell::Cell::new(0),
                txs_body: txs_body.as_bytes().to_vec(),
                tip: 100,
                utxo_value: 100_000,
                broadcast_status: 200,
                force_status: None,
                echo_wrong_txid: false,
            }
        }

        fn with_status(status: u16) -> Self {
            Self {
                force_status: Some(status),
                ..Self::new("[]")
            }
        }

        fn with_broadcast_status(status: u16) -> Self {
            Self {
                broadcast_status: status,
                ..Self::new("[]")
            }
        }

        fn with_wrong_txid() -> Self {
            Self {
                echo_wrong_txid: true,
                ..Self::new("[]")
            }
        }

        /// Serve a single confirmed funding UTXO of exactly `value` sats. Used to
        /// drive the rate-fee coverage guard to its boundary.
        fn with_utxo_value(value: u64) -> Self {
            Self {
                utxo_value: value,
                ..Self::new("[]")
            }
        }

        fn call_count(&self) -> usize {
            *self.calls.borrow()
        }

        fn post_tx_count(&self) -> usize {
            self.post_tx_calls.get()
        }

        /// A synthetic confirmed `/utxo` array funding the announce.
        fn utxo_body(&self) -> Vec<u8> {
            serde_json::json!([{
                "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "vout": 0,
                "value": self.utxo_value,
                "status": { "confirmed": true, "block_height": 90 }
            }])
            .to_string()
            .into_bytes()
        }
    }

    impl BtcTransport for FakeTransport {
        fn execute(
            &self,
            req: http::Request<Vec<u8>>,
        ) -> Result<http::Response<Vec<u8>>, TransportError> {
            *self.calls.borrow_mut() += 1;

            if let Some(status) = self.force_status {
                return Ok(http::Response::builder()
                    .status(status)
                    .body(b"server error".to_vec())
                    .expect("static status is valid"));
            }

            let method = req.method().clone();
            let path = req.uri().path();

            if method == http::Method::POST && path.ends_with("/tx") {
                self.post_tx_calls.set(self.post_tx_calls.get() + 1);
                if !(200..300).contains(&self.broadcast_status) {
                    return Ok(http::Response::builder()
                        .status(self.broadcast_status)
                        .body(b"rejected".to_vec())
                        .expect("static status is valid"));
                }
                // Recover the broadcast tx from the posted hex and echo its real
                // txid: the facade cross-checks the response body against the
                // locally computed txid, so a wrong/empty body would (correctly)
                // be rejected. When `echo_wrong_txid` is set, deliberately return a
                // different txid to exercise that rejection path.
                let body = if self.echo_wrong_txid {
                    "00".repeat(32)
                } else {
                    let raw = hex_decode(req.body());
                    let tx: esploda::bitcoin::Transaction =
                        esploda::bitcoin::consensus::encode::deserialize(&raw)
                            .expect("the facade posts a consensus-encoded tx");
                    tx.txid().to_string()
                };
                return Ok(http::Response::builder()
                    .status(200)
                    .body(body.into_bytes())
                    .expect("static status is valid"));
            }

            let body: Vec<u8> = if path.ends_with("/blocks/tip/height") {
                self.tip.to_string().into_bytes()
            } else if path.contains("/address/") && path.ends_with("/txs") {
                self.txs_body.clone()
            } else if path.contains("/address/") && path.ends_with("/utxo") {
                self.utxo_body()
            } else if path.ends_with("/fee-estimates") {
                br#"{"6":1.0}"#.to_vec()
            } else {
                // Unknown route: an empty array is a safe default for any other
                // tx-list endpoint the FSM might probe.
                b"[]".to_vec()
            };

            Ok(http::Response::builder()
                .status(200)
                .body(body)
                .expect("static status is valid"))
        }
    }

    fn test_public_key() -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret key");
        sk.public_key(&secp)
    }

    /// Decode an ASCII-hex `POST /tx` body back into raw bytes (the fake's
    /// inverse of the facade's `hex_encode`).
    fn hex_decode(hex: &[u8]) -> Vec<u8> {
        let s = std::str::from_utf8(hex).expect("the posted body is ASCII hex");
        assert!(s.len().is_multiple_of(2), "hex body has an even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit pair"))
            .collect()
    }

    #[test]
    fn create_does_no_io() {
        let transport = FakeTransport::new("[]");
        let client = Client::new("http://unused".to_string(), transport);
        let pk = test_public_key();

        let doc = client
            .create(&pk, Network::Signet)
            .expect("create succeeds");

        // The document derives its beacons from the public key.
        assert_eq!(
            doc.beacons().count(),
            3,
            "key DID has three default beacons"
        );
        // create makes ZERO transport calls.
        assert_eq!(client.transport.call_count(), 0, "create performs no I/O");
    }

    /// A self-contained x1 intermediate (placeholder-DID) document. Mirrors the
    /// spec `did:btcr2:_` genesis-document shape (cf. the x1 q26jeds9 test
    /// vector); inlined so the client-crate test does not depend on the
    /// `did-btcr2` crate's test-suite submodule.
    fn x1_intermediate_document() -> IntermediateDocument {
        let json = serde_json::json!({
            "id": "did:btcr2:_",
            "@context": [
                "https://www.w3.org/ns/did/v1.1",
                "https://btcr2.dev/context/v1"
            ],
            "verificationMethod": [{
                "id": "did:btcr2:_#key-0",
                "type": "Multikey",
                "controller": "did:btcr2:_",
                "publicKeyMultibase": "zQ3shTHn9hZ1BHtoZayz4VmPAZT97p2v8swmuPEUwBKHCanTL"
            }],
            "authentication": ["did:btcr2:_#key-0"],
            "assertionMethod": ["did:btcr2:_#key-0"],
            "capabilityInvocation": ["did:btcr2:_#key-0"],
            "capabilityDelegation": ["did:btcr2:_#key-0"],
            "service": [{
                "id": "did:btcr2:_#service-0",
                "serviceEndpoint": "bitcoin:mnDXvNsFTf9cs4hWigPkENCBDp9eJpfyxF",
                "type": "SingletonBeacon"
            }]
        });
        IntermediateDocument::from_json_value(json, Network::Regtest)
            .expect("the inline intermediate document is structurally valid")
    }

    #[test]
    fn create_external_does_no_io() {
        let transport = FakeTransport::new("[]");
        let client = Client::new("http://unused".to_string(), transport);

        let (did, doc) = client
            .create_external(x1_intermediate_document(), Network::Regtest)
            .expect("create_external succeeds");

        // The minted DID is an external (x1) identifier.
        assert!(
            did.encode().starts_with("did:btcr2:x1"),
            "external create must mint an x1 DID, got: {}",
            did.encode()
        );
        assert!(
            matches!(did.components().id_type(), IdType::External(_)),
            "id type must be External"
        );
        // The returned document is bound to the minted DID (its `id` is the
        // substituted x1 DID, not the `did:btcr2:_` placeholder).
        assert_eq!(
            doc.as_ref().get("id").and_then(|v| v.as_str()),
            Some(did.encode())
        );
        // create_external makes ZERO transport calls.
        assert_eq!(
            client.transport.call_count(),
            0,
            "create_external performs no I/O"
        );
    }

    #[test]
    fn resolve_returns_triple() {
        // A freshly created DID has announced NO updates, so the beacon /txs
        // returns an empty array and the DID resolves to genesis version 1.
        let transport = FakeTransport::new("[]");
        let client = Client::new("http://fake".to_string(), transport);
        let pk = test_public_key();

        let doc = client
            .create(&pk, Network::Signet)
            .expect("create succeeds");
        let did: Did = doc.as_ref()["id"]
            .as_str()
            .expect("document has a string id")
            .parse()
            .expect("document id parses as a Did");

        let result = client
            .resolve(&did, ResolutionOptions::default())
            .expect("resolve succeeds");

        assert_eq!(
            result.document_metadata.version_id,
            std::num::NonZeroU64::new(1).expect("1 is non-zero"),
            "genesis resolves to version 1",
        );
        assert!(
            !result.document_metadata.deactivated,
            "genesis is not deactivated",
        );
    }

    #[test]
    fn transport_non_2xx_is_typed_error() {
        let transport = FakeTransport::with_status(500);
        let client = Client::new("http://fake".to_string(), transport);
        let pk = test_public_key();

        let doc = client
            .create(&pk, Network::Signet)
            .expect("create succeeds");
        let did: Did = doc.as_ref()["id"]
            .as_str()
            .expect("document has a string id")
            .parse()
            .expect("document id parses as a Did");

        let err = client
            .resolve(&did, ResolutionOptions::default())
            .expect_err("a 500 response is an error, not a panic");

        match err {
            Error::Transport(TransportError::Status { status, .. }) => {
                assert_eq!(status, 500);
            }
            other => panic!("expected a typed Status transport error, got {other:?}"),
        }
    }

    // ── Task 2: update / deactivate + build/broadcast split ──────────────────

    const TEST_SK_BYTES: [u8; 32] = [0x07; 32];

    fn test_secret_key() -> SecretKey {
        SecretKey::from_slice(&TEST_SK_BYTES).expect("[7u8; 32] is a valid secret key")
    }

    fn test_keyed_sk_pk() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = test_secret_key();
        let pk = sk.public_key(&secp);
        (sk, pk)
    }

    /// A benign update patch that appends the vm id to `assertionMethod` (keeps
    /// the document conformant; matches the core's `benign_patch`).
    fn benign_patch(vm_id: &str) -> Patch {
        serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/assertionMethod/-", "value": vm_id}
        ]))
        .expect("benign patch is valid RFC-6902")
    }

    /// Build a created genesis document + its DID + the `#initialKey` vm id.
    fn created_doc<T: BtcTransport>(client: &Client<T>) -> (Document, Did, String) {
        let (_sk, pk) = test_keyed_sk_pk();
        let doc = client
            .create(&pk, Network::Mutinynet)
            .expect("create succeeds");
        let did: Did = doc.as_ref()["id"]
            .as_str()
            .expect("document has a string id")
            .parse()
            .expect("document id parses as a Did");
        let vm_id = format!("{}#initialKey", did.encode());
        (doc, did, vm_id)
    }

    #[test]
    fn update_broadcasts_returns_txid() {
        let transport = FakeTransport::new("[]");
        let client = Client::new("http://fake".to_string(), transport);
        let (doc, _did, vm_id) = created_doc(&client);
        let sk = test_secret_key();
        let v1 = NonZeroU64::new(1).expect("1 is non-zero");

        let txid = client
            .update(
                &doc,
                benign_patch(&vm_id),
                &vm_id,
                sk,
                sk,
                v1,
                1, // the P2WPKH default beacon (spendable by the DID key)
                Fee::Absolute(1_000),
                None,
            )
            .expect("update broadcasts and returns a txid");

        // A txid is returned and exactly one POST /tx was issued.
        assert_eq!(
            client.transport.post_tx_count(),
            1,
            "update broadcasts once"
        );
        assert!(!txid.to_string().is_empty(), "a txid is returned");
    }

    #[test]
    fn broadcast_rejects_txid_mismatch() {
        // a 200 response whose body is a DIFFERENT txid must NOT be
        // reported as success. Without the cross-check the facade would return
        // the locally computed txid and treat the broadcast as landed; the fake
        // echoes an all-zero txid, so a correct facade rejects it.
        let transport = FakeTransport::with_wrong_txid();
        let client = Client::new("http://fake".to_string(), transport);
        let (doc, _did, vm_id) = created_doc(&client);
        let sk = test_secret_key();
        let v1 = NonZeroU64::new(1).expect("1 is non-zero");

        let err = client
            .update(
                &doc,
                benign_patch(&vm_id),
                &vm_id,
                sk,
                sk,
                v1,
                1,
                Fee::Absolute(1_000),
                None,
            )
            .expect_err("a 200 with a mismatched txid is not a successful broadcast");

        match err {
            Error::BroadcastRejected { .. } => {}
            other => panic!("expected BroadcastRejected on txid mismatch, got {other:?}"),
        }
        // The POST was issued (we reached broadcast), but it was rejected.
        assert_eq!(
            client.transport.post_tx_count(),
            1,
            "the broadcast was attempted before rejection"
        );
    }

    #[test]
    fn build_update_tx_is_dry() {
        let transport = FakeTransport::new("[]");
        let client = Client::new("http://fake".to_string(), transport);
        let (doc, _did, vm_id) = created_doc(&client);
        let sk = test_secret_key();
        let v2 = NonZeroU64::new(2).expect("2 is non-zero");

        let signed = doc
            .construct_signed_update(benign_patch(&vm_id), v2, &vm_id, sk)
            .expect("a signed update constructs against the genesis document");
        let tx = client
            .build_update_tx(&doc, signed, 1, Fee::Absolute(1_000), None, sk)
            .expect("build_update_tx produces a signed beacon tx");

        // The build half issues ZERO POST /tx calls (the --dry-run entry point).
        assert_eq!(
            client.transport.post_tx_count(),
            0,
            "build_update_tx broadcasts nothing"
        );
        // The built tx's last output is OP_RETURN <32 bytes> (the beacon signal).
        let last = tx
            .as_tx()
            .output
            .last()
            .expect("the announce tx has at least one output");
        assert!(
            last.script_pubkey.is_op_return(),
            "last output is OP_RETURN"
        );
    }

    #[test]
    fn rate_fee_measured_vsize_within_provisional_ceiling() {
        // the rate-fee path reuses the provisional single-input selection
        // for the exact `ceil(rate * measured_vsize)` fee. That reuse is only
        // sound while the measured vsize stays at or below the provisional
        // ceiling. Pin that invariant for the default P2WPKH beacon so a future
        // output/script change that breaks it is caught here.
        let transport = FakeTransport::new("[]");
        let client = Client::new("http://fake".to_string(), transport);
        let (doc, _did, vm_id) = created_doc(&client);
        let sk = test_secret_key();
        let v2 = NonZeroU64::new(2).expect("2 is non-zero");

        let signed = doc
            .construct_signed_update(benign_patch(&vm_id), v2, &vm_id, sk)
            .expect("a signed update constructs against the genesis document");
        // A rate fee drives the two-build measure-then-rebuild path.
        let tx = client
            .build_update_tx(&doc, signed, 1, Fee::Rate(1.0), None, sk)
            .expect("a rate-fee build succeeds within the provisional ceiling");

        let measured = tx.as_tx().vsize() as u64;
        assert!(
            measured <= funding::provisional_vsize(),
            "measured vsize {measured} exceeds the provisional ceiling {} — the \
             rate-fee single-input reuse is no longer sound",
            funding::provisional_vsize(),
        );
    }

    #[test]
    fn rate_fee_rejects_when_measured_fee_exceeds_inputs() {
        // Failure mode (the converse of the invariant test above): the rate
        // path selects a single input covering only the PROVISIONAL fee
        // (rate * PROVISIONAL_VSIZE), then rebuilds at the EXACT fee derived from
        // the MEASURED vsize. The legacy-P2PKH beacon (idx 0) has a ~148 vB input,
        // so its 1-in/2-out announce tx measures well past the 200 vB provisional
        // ceiling — making the exact fee larger than the provisionally-selected
        // input can cover. The coverage guard MUST reject this with
        // NoSpendableUtxo rather than silently rebuild an under-funded tx.
        //
        // rate = 100 sat/vB → provisional fee = 100 * 200 = 20_000. A 21_000-sat
        // input covers it (leaving a 1_000-sat, above-dust change output, so the
        // measured tx keeps both outputs and measures ~235 vB). The exact fee is
        // then 100 * ~235 ≈ 23_500 > 21_000, so the guard fires. The 100 sat/vB
        // rate amplifies the (measured − provisional) vsize gap into a multi-
        // thousand-sat fee gap, keeping the assertion robust to the ±1 vB jitter
        // of ECDSA signature lengths.
        let transport = FakeTransport::with_utxo_value(21_000);
        let client = Client::new("http://fake".to_string(), transport);
        let (doc, _did, vm_id) = created_doc(&client);
        let sk = test_secret_key();
        let v2 = NonZeroU64::new(2).expect("2 is non-zero");

        let signed = doc
            .construct_signed_update(benign_patch(&vm_id), v2, &vm_id, sk)
            .expect("a signed update constructs against the genesis document");

        let err = client
            .build_update_tx(
                &doc,
                signed,
                0, // the legacy-P2PKH beacon: its larger input inflates the vsize past 200
                Fee::Rate(100.0),
                None,
                sk,
            )
            .expect_err("the exact rate fee exceeds the provisionally-selected input");

        assert!(
            matches!(err, Error::NoSpendableUtxo),
            "expected NoSpendableUtxo from the coverage guard, got {err:?}",
        );
    }

    #[test]
    fn update_on_deactivated_rejected() {
        let transport = FakeTransport::new("[]");
        let client = Client::new("http://fake".to_string(), transport);
        let (genesis, _did, vm_id) = created_doc(&client);
        let sk = test_secret_key();

        // Build a deactivated document by applying the deactivate patch in JSON.
        let mut json = genesis.as_ref().clone();
        json.as_object_mut()
            .expect("document is an object")
            .insert("deactivated".to_string(), serde_json::json!(true));
        let deactivated =
            Document::from_json_value(json).expect("a deactivated document is still conformant");

        let v1 = NonZeroU64::new(1).expect("1 is non-zero");
        let err = client
            .update(
                &deactivated,
                benign_patch(&vm_id),
                &vm_id,
                sk,
                sk,
                v1,
                1,
                Fee::Absolute(1_000),
                None,
            )
            .expect_err("update on a deactivated document is rejected before broadcast");

        // The core Guard 0 surfaces as Error::Btcr2; no broadcast occurred.
        assert!(matches!(err, Error::Btcr2(_)), "got {err:?}");
        assert_eq!(
            client.transport.post_tx_count(),
            0,
            "a rejected update broadcasts nothing"
        );
    }

    #[test]
    fn broadcast_rejection_is_typed() {
        let transport = FakeTransport::with_broadcast_status(400);
        let client = Client::new("http://fake".to_string(), transport);
        let (doc, _did, vm_id) = created_doc(&client);
        let sk = test_secret_key();
        let v1 = NonZeroU64::new(1).expect("1 is non-zero");

        let err = client
            .update(
                &doc,
                benign_patch(&vm_id),
                &vm_id,
                sk,
                sk,
                v1,
                1,
                Fee::Absolute(1_000),
                None,
            )
            .expect_err("a non-2xx POST /tx is an error, not a panic");

        match err {
            Error::BroadcastRejected { .. } => {}
            other => panic!("expected BroadcastRejected, got {other:?}"),
        }
    }
}
