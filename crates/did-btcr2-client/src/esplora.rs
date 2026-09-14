//! Hand-built Esplora endpoint helpers used by the facade.
//!
//! Each helper builds a typed `http::Request<Vec<u8>>`, runs it through the
//! injected [`BtcTransport`], inspects the status, and parses the body. Only the
//! endpoints this plan needs live here; `/address/{a}/utxo`, `/fee-estimates`,
//! and `POST /tx` land in a later plan.

use chrono::{DateTime, Utc};
use esploda::bitcoin::BlockHash;

use crate::error::{Error, TransportError};
use crate::transport::BtcTransport;

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
