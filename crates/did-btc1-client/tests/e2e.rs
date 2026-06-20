//! Keystone offline end-to-end test for the four-operation facade.
//!
//! Drives create → resolve → update → mid-sequence re-resolve → deactivate →
//! final re-resolve entirely through `Client` against an in-process
//! [`FakeTransport`], with NO network. It proves the facade composes all four
//! operations: the genesis resolve reaches version 1, the update broadcast +
//! sidecar-fed re-resolve reaches version 2, and the deactivate broadcast +
//! sidecar-fed re-resolve reaches version 3 with `deactivated == true`.
//!
//! Sidecar threading (the JSON-Document-Hash plumbing): `update()`/`deactivate()`
//! return only a `Txid`, so the test CONSTRUCTS the two `Update` bodies directly
//! against the same documents the facade signs (the deactivate against the
//! version-2 document obtained from a mid-sequence facade re-resolve — the only
//! way to reach the post-update document, since the core's in-crate update
//! application is crate-private) and threads them into each re-resolve via
//! `SidecarData::new`. The captured `Update` and the facade-announced update share
//! the SAME deterministic hash, so the sidecar table (keyed by that hash) matches
//! the broadcast tx's OP_RETURN signal.
//!
//! Transport fake (the two HIGH review fixes):
//! - `POST /tx` recovers the broadcast `bitcoin::Transaction` from the hex, then
//!   BUILDS the Esplora JSON-API shape via `esplora_tx_from_bitcoin` and pushes it
//!   into the served `/txs` state. It does NOT wire-decode the hex into the
//!   JSON-API type (that type is the Esplora HTTP shape, not consensus wire).
//! - `/txs` returns a growing snapshot of confirmed announce txs: `[]` before any
//!   broadcast (version 1), `[update1]` after the update broadcast (version 2),
//!   `[update1, deactivate]` after the deactivate broadcast (version 3).

use std::cell::{Cell, RefCell};
use std::num::NonZeroU64;
use std::rc::Rc;

use did_btc1::document::{Document, ResolutionOptions, SidecarData};
use did_btc1::identifier::{Did, Network};
use did_btc1::key::PublicKey;
use did_btc1_client::{BtcTransport, Client, Fee, Patch, TransportError};
use esploda::bitcoin::Transaction as BitcoinTx;
use esploda::bitcoin::consensus::encode::deserialize;
use secp256k1::{Secp256k1, SecretKey};

/// The deterministic test secret key backing the DID key, the update proofs, and
/// the beacon-announce inputs (the default singleton path: one key for all).
const TEST_SK_BYTES: [u8; 32] = [0x07; 32];

fn test_secret_key() -> SecretKey {
    SecretKey::from_slice(&TEST_SK_BYTES).expect("[7u8; 32] is a valid secret key")
}

fn test_public_key() -> PublicKey {
    let secp = Secp256k1::new();
    test_secret_key().public_key(&secp)
}

/// A benign update patch (appends the vm id to `assertionMethod`; keeps the
/// document conformant).
fn benign_patch(vm_id: &str) -> Patch {
    serde_json::from_value(serde_json::json!([
        {"op": "add", "path": "/assertionMethod/-", "value": vm_id}
    ]))
    .expect("benign patch is valid RFC-6902")
}

/// Build the served Esplora JSON-API transaction from a recovered broadcast
/// `bitcoin::Transaction` (the verified `bridge_to_esplora` recipe). The resolver
/// reads only the LAST output's scriptPubKey, the status, and the txid, so only
/// those carry real data. `status.confirmed` MUST be true or the re-resolve hits
/// an unconfirmed-beacon-tx error.
fn esplora_tx_from_bitcoin(
    tx: &BitcoinTx,
    block_height: u32,
    block_time: i64,
) -> serde_json::Value {
    let vout: Vec<serde_json::Value> = tx
        .output
        .iter()
        .map(|o| {
            serde_json::json!({
                "scriptpubkey": o.script_pubkey.to_hex_string(),
                "value": o.value,
            })
        })
        .collect();
    serde_json::json!({
        "txid": tx.txid().to_string(),
        "version": tx.version,
        "locktime": 0,
        "vin": [],
        "vout": vout,
        "size": 0,
        "weight": 0,
        "fee": 0,
        "status": {
            "confirmed": true,
            "block_height": block_height,
            "block_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "block_time": block_time,
        },
    })
}

/// Shared, interior-mutable transport state. Held behind an `Rc` so the test
/// retains a handle (to inspect counters) after the transport is moved into the
/// `Client`. Each test owns its own instance, so `RefCell`/`Cell` are correct
/// (no cross-thread sharing).
#[derive(Default)]
struct FakeState {
    /// The confirmed beacon announce txs served by `/txs`, as Esplora JSON-API
    /// values. Starts empty and grows by one on each `POST /tx`.
    served_txs: RefCell<Vec<serde_json::Value>>,
    /// A monotonically increasing counter so each `/utxo` call hands back a
    /// distinct funding UTXO (never starves a second announce build).
    utxo_seq: Cell<u32>,
    /// Count of `POST /tx` calls (broadcasts).
    post_tx_calls: Cell<usize>,
    /// Count of all `execute` calls (any endpoint).
    all_calls: Cell<usize>,
}

/// A stateful in-process transport wrapping a shared [`FakeState`].
struct FakeTransport {
    state: Rc<FakeState>,
    /// The chain-tip height (must be >= each announce tx's block_height).
    tip: u32,
}

impl FakeTransport {
    fn new() -> (Self, Rc<FakeState>) {
        let state = Rc::new(FakeState::default());
        (
            Self {
                state: Rc::clone(&state),
                tip: 200,
            },
            state,
        )
    }

    /// A fresh confirmed funding UTXO (distinct outpoint per call) covering the
    /// 1_000-sat fee, so both the update and deactivate announce builds are
    /// funded even though the fake does not track spentness.
    fn utxo_body(&self) -> Vec<u8> {
        let n = self.state.utxo_seq.get();
        self.state.utxo_seq.set(n + 1);
        // A distinct synthetic txid per call.
        let txid = format!("{n:064x}");
        serde_json::json!([{
            "txid": txid,
            "vout": 0,
            "value": 100_000,
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
        self.state.all_calls.set(self.state.all_calls.get() + 1);
        let method = req.method().clone();
        let path = req.uri().path();

        // POST /tx: recover the broadcast tx from hex, BUILD the Esplora JSON-API
        // shape (NOT consensus-decode into it), push it into the served /txs.
        if method == http::Method::POST && path.ends_with("/tx") {
            self.state
                .post_tx_calls
                .set(self.state.post_tx_calls.get() + 1);
            let hex_body = String::from_utf8(req.body().clone()).expect("the tx hex body is UTF-8");
            let raw = hex::decode(hex_body.trim()).expect("the tx hex body decodes");
            let tx: BitcoinTx =
                deserialize(&raw).expect("the posted hex deserializes as a bitcoin transaction");
            let esplora = esplora_tx_from_bitcoin(&tx, 100, 1_700_000_000);
            self.state.served_txs.borrow_mut().push(esplora);
            return Ok(http::Response::builder()
                .status(200)
                .body(tx.txid().to_string().into_bytes())
                .expect("static status is valid"));
        }

        let body: Vec<u8> = if path.ends_with("/blocks/tip/height") {
            self.tip.to_string().into_bytes()
        } else if path.contains("/address/") && path.ends_with("/txs") {
            // The current snapshot of confirmed announce txs (Phase A/B/C).
            serde_json::Value::Array(self.state.served_txs.borrow().clone())
                .to_string()
                .into_bytes()
        } else if path.contains("/address/") && path.ends_with("/utxo") {
            self.utxo_body()
        } else if path.ends_with("/fee-estimates") {
            br#"{"6":1.0}"#.to_vec()
        } else {
            b"[]".to_vec()
        };

        Ok(http::Response::builder()
            .status(200)
            .body(body)
            .expect("static status is valid"))
    }
}

#[test]
fn e2e_four_operations_roundtrip() {
    let (transport, state) = FakeTransport::new();
    let client = Client::new("http://fake".to_string(), transport);
    let sk = test_secret_key();
    let pk = test_public_key();

    // 1. Create: a key-based singleton DID. ZERO transport calls during create.
    let genesis_doc = client
        .create(&pk, Network::Mutinynet)
        .expect("create succeeds");
    assert_eq!(
        state.all_calls.get(),
        0,
        "create performs no I/O (zero transport calls)",
    );
    let did: Did = genesis_doc.as_ref()["id"]
        .as_str()
        .expect("document has a string id")
        .parse()
        .expect("document id parses as a Did");
    let vm_id = format!("{}#initialKey", did.encode());

    let v1 = NonZeroU64::new(1).expect("1 is non-zero");
    let v2 = NonZeroU64::new(2).expect("2 is non-zero");
    let v3 = NonZeroU64::new(3).expect("3 is non-zero");

    // 2. First resolve → genesis triple (version 1, not deactivated). /txs empty.
    let first = client
        .resolve(&did, ResolutionOptions::default())
        .expect("genesis resolve succeeds");
    assert_eq!(
        first.document_metadata.version_id, v1,
        "genesis resolves to version 1",
    );
    assert!(
        !first.document_metadata.deactivated,
        "genesis is not deactivated",
    );

    // 3. Capture the update body against the GENESIS document (source_hash chains
    //    from it), then drive the broadcast through the facade.
    let update = first
        .document
        .construct_signed_update(benign_patch(&vm_id), v2, &vm_id, sk)
        .expect("the update constructs against the genesis document");
    let _txid = client
        .update(
            &first.document,
            benign_patch(&vm_id),
            &vm_id,
            sk,
            sk,
            v1,
            1, // the P2WPKH default beacon (spendable by the DID key)
            Fee::Absolute(1_000),
            None,
        )
        .expect("the update broadcasts");

    // The broadcast tx's last output is OP_RETURN <32 bytes> (the beacon signal).
    // (Asserted indirectly: the re-resolve below only reaches version 2 if the
    // announce tx carries the matching 32-byte signal.)

    // 4. Mid-sequence re-resolve → the version-2 document (via re-resolution, not
    //    in-crate update application). /txs now serves [update1]; the sidecar
    //    carries update1.
    let mid_opts = ResolutionOptions {
        sidecar_data: Some(SidecarData::new(None, vec![update.clone()], None, None)),
        ..Default::default()
    };
    let mid = client
        .resolve(&did, mid_opts)
        .expect("the mid-sequence re-resolve succeeds");
    assert_eq!(
        mid.document_metadata.version_id, v2,
        "the update + sidecar drive the re-resolve to version 2",
    );
    let doc_v2: Document = mid.document;

    // Capture the deactivate body against the version-2 document (its source_hash
    // chains to update1's target_hash — building it against genesis would not
    // chain), then drive the broadcast through the facade.
    let deactivate = doc_v2
        .deactivate(&vm_id, sk, v3)
        .expect("the deactivate constructs against the version-2 document");
    let _txid2 = client
        .deactivate(&doc_v2, &vm_id, sk, sk, v2, 1, Fee::Absolute(1_000), None)
        .expect("the deactivate broadcasts");

    // 5. Final re-resolve with BOTH updates in the sidecar → version 3,
    //    deactivated. /txs now serves [update1, deactivate].
    let sidecar = SidecarData::new(None, vec![update, deactivate], None, None);
    let opts = ResolutionOptions {
        sidecar_data: Some(sidecar),
        ..Default::default()
    };
    let result = client
        .resolve(&did, opts)
        .expect("the final re-resolve succeeds");

    assert!(
        result.document_metadata.deactivated,
        "the final document is deactivated",
    );
    assert_eq!(
        result.document_metadata.version_id, v3,
        "the final document is at version 3 (genesis 1 → update 2 → deactivate 3)",
    );

    // Exactly two broadcasts crossed the transport (the update and the
    // deactivate); each resolve only reads, never broadcasts.
    assert_eq!(
        state.post_tx_calls.get(),
        2,
        "the facade broadcast exactly once per write operation",
    );
}
