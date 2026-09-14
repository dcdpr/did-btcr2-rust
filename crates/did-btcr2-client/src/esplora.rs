//! Hand-built Esplora endpoint helpers used by the facade.
//!
//! Each helper builds a typed `http::Request<Vec<u8>>`, runs it through the
//! injected [`BtcTransport`], inspects the status, and parses the body. Only the
//! endpoints this plan needs live here; `/address/{a}/utxo`, `/fee-estimates`,
//! and `POST /tx` land in a later plan.

use chrono::{DateTime, Utc};
use esploda::bitcoin::{BlockHash, Txid};
use esploda::esplora::{Status, Transaction};

use crate::error::{Error, TransportError};
use crate::transport::BtcTransport;

/// Confirmed transactions per page of an Esplora address history. Esplora's
/// own number: `GET /address/{a}/txs` returns up to 50 mempool transactions
/// plus the first 25 confirmed ones, newest first, and each
/// `GET /address/{a}/txs/chain/{last_seen_txid}` returns the next 25
/// confirmed ones.
pub const ESPLORA_PAGE_SIZE: usize = 25;

/// Execute a `GET` for a JSON transaction list, mapping a non-2xx status to
/// [`TransportError::Status`].
fn fetch_txs<T: BtcTransport>(
    transport: &T,
    req: http::Request<Vec<u8>>,
) -> Result<Vec<Transaction>, Error> {
    let resp = transport.execute(req)?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(Error::Transport(TransportError::Status {
            status,
            body: String::from_utf8_lossy(resp.body()).into_owned(),
        }));
    }
    Ok(serde_json::from_slice(resp.body())?)
}

/// Fetch the COMPLETE confirmed history behind a core `GET
/// {base}/address/{a}/txs` request, following Esplora's pagination.
///
/// The sans-I/O core asks for an address once and treats the answer as the
/// whole history; Esplora answers the first page only. A beacon address that
/// is also the funding and change address gathers two transactions per
/// update, so after a dozen updates — or any unrelated traffic — the oldest
/// announcements fall off that page, and a resolver that stopped there would
/// see only the newest signals and raise `LATE_PUBLISHING` for a valid
/// history, or resolve to the genesis document. So: page on
/// `/txs/chain/{last_seen_txid}` from the oldest confirmed transaction of each
/// page until a page carries fewer than [`ESPLORA_PAGE_SIZE`] confirmed
/// transactions. Mempool entries (first page only) are carried through
/// unchanged; the core skips them itself. A continuation whose oldest
/// confirmed transaction is the very txid it was keyed on re-serves its own
/// page: that is a malformed history, reported as
/// [`TransportError::Malformed`], not an infinite walk.
pub fn address_history<T: BtcTransport>(
    transport: &T,
    first: http::Request<Vec<u8>>,
) -> Result<Vec<Transaction>, Error> {
    let txs_uri = first.uri().to_string();
    let mut page = fetch_txs(transport, first)?;
    let mut history = Vec::new();
    let mut previous_last_seen: Option<Txid> = None;
    loop {
        let confirmed = page
            .iter()
            .filter(|tx| matches!(tx.status, Status::Confirmed { .. }))
            .count();
        let last_seen = page
            .iter()
            .rev()
            .find(|tx| matches!(tx.status, Status::Confirmed { .. }))
            .map(|tx| tx.txid);
        if let Some(txid) = last_seen
            && Some(txid) == previous_last_seen
        {
            return Err(Error::Transport(TransportError::Malformed(format!(
                "address history continuation from {txid} returned the same page again"
            ))));
        }
        history.append(&mut page);
        let (Some(last_seen), true) = (last_seen, confirmed >= ESPLORA_PAGE_SIZE) else {
            return Ok(history);
        };
        previous_last_seen = Some(last_seen);
        let next = http::Request::get(format!("{txs_uri}/chain/{last_seen}"))
            .body(Vec::new())
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
        page = fetch_txs(transport, next)?;
    }
}

/// Fetch the current chain-tip height via `GET {base}/blocks/tip/height`.
///
/// The Esplora response body is a bare ASCII integer. A non-2xx status is mapped
/// to [`TransportError::Status`]; the body is parsed as a `u32`.
pub fn chain_tip_height<T: BtcTransport>(transport: &T, base_url: &str) -> Result<u32, Error> {
    let req = http::Request::get(format!("{base_url}/blocks/tip/height"))
        .body(Vec::new())
        .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;

    let resp = transport.execute(req)?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(Error::Transport(TransportError::Status {
            status,
            body: String::from_utf8_lossy(resp.body()).into_owned(),
        }));
    }

    // The body is a bare integer like `12345`. Trim to tolerate a trailing
    // newline some endpoints emit.
    let text = std::str::from_utf8(resp.body())
        .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
    let height: u32 = text.trim().parse().map_err(|e: std::num::ParseIntError| {
        TransportError::Io(std::io::Error::other(e.to_string()))
    })?;
    Ok(height)
}

/// The two fields of an Esplora `GET /block/{hash}` body the resolver needs.
#[derive(serde::Deserialize)]
struct EsploraBlock {
    id: String,
    mediantime: i64,
}

/// Parse the block hash and `mediantime` out of an Esplora `GET /block/{hash}`
/// body. Only those two fields are read; the rest of the block header is
/// ignored. A body that is not JSON, lacks either field, or carries a
/// non-hex `id` or an out-of-range `mediantime` is a typed error: a non-JSON
/// body or a missing field is [`Error::Json`], a present-but-wrong field is
/// [`TransportError::Malformed`].
pub fn block_mediantime_from_body(body: &[u8]) -> Result<(BlockHash, DateTime<Utc>), Error> {
    let block: EsploraBlock = serde_json::from_slice(body)?;
    let hash = block.id.parse::<BlockHash>().map_err(|e| {
        TransportError::Malformed(format!("block body `id` is not a block hash: {e}"))
    })?;
    let mediantime = DateTime::from_timestamp(block.mediantime, 0).ok_or_else(|| {
        TransportError::Malformed(format!(
            "block body `mediantime` {} is out of range",
            block.mediantime
        ))
    })?;
    Ok((hash, mediantime))
}

/// A `GET /block/{hash}` body with every field blockstream's Esplora emits:
/// the all-zero block hash, header time 1_700_000_000, mediantime
/// 1_699_996_400. Shared with the client's fake transport.
#[cfg(test)]
pub(crate) const BLOCK_BODY: &str = r#"{"id":"0000000000000000000000000000000000000000000000000000000000000000","height":100,"version":536870912,"timestamp":1700000000,"tx_count":1,"size":285,"weight":1140,"merkle_root":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b","previousblockhash":"000000000000000000000000000000000000000000000000000000000000ffff","mediantime":1699996400,"nonce":0,"bits":486604799,"difficulty":1.0}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_mediantime_parses_an_esplora_block_body() {
        let (hash, mediantime) =
            block_mediantime_from_body(BLOCK_BODY.as_bytes()).expect("a full block body parses");
        assert_eq!(
            hash.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(mediantime.timestamp(), 1_699_996_400);
    }

    #[test]
    fn block_mediantime_rejects_a_body_without_mediantime() {
        let body = br#"{"id":"0000000000000000000000000000000000000000000000000000000000000000","height":100,"timestamp":1700000000}"#;
        let err =
            block_mediantime_from_body(body).expect_err("a body without mediantime is rejected");
        assert!(
            matches!(err, Error::Json(_)),
            "expected Error::Json, got {err:?}"
        );
    }

    #[test]
    fn block_mediantime_rejects_a_non_hex_id() {
        let body = br#"{"id":"not-a-block-hash","mediantime":1699996400}"#;
        let err = block_mediantime_from_body(body).expect_err("a non-hex id is rejected");
        assert!(
            matches!(&err, Error::Transport(TransportError::Malformed(msg)) if msg.contains("not a block hash")),
            "expected Transport(Malformed), got {err:?}"
        );
    }

    #[test]
    fn block_mediantime_rejects_an_out_of_range_mediantime() {
        let body = br#"{"id":"0000000000000000000000000000000000000000000000000000000000000000","mediantime":9223372036854775807}"#;
        let err =
            block_mediantime_from_body(body).expect_err("an out-of-range mediantime is rejected");
        assert!(
            matches!(&err, Error::Transport(TransportError::Malformed(msg)) if msg.contains("out of range")),
            "expected Transport(Malformed), got {err:?}"
        );
    }

    #[test]
    fn a_malformed_transport_error_displays_its_message() {
        assert_eq!(
            TransportError::Malformed("x".to_string()).to_string(),
            "malformed response body: x"
        );
    }

    #[test]
    fn block_mediantime_rejects_a_non_json_body() {
        let err = block_mediantime_from_body(b"not json").expect_err("a non-JSON body is rejected");
        assert!(
            matches!(err, Error::Json(_)),
            "expected Error::Json, got {err:?}"
        );
    }
}
