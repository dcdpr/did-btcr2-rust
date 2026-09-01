//! Hand-built Esplora endpoint helpers used by the facade.
//!
//! Each helper builds a typed `http::Request<Vec<u8>>`, runs it through the
//! injected [`BtcTransport`], inspects the status, and parses the body. Only the
//! endpoints this plan needs live here; `/address/{a}/utxo`, `/fee-estimates`,
//! and `POST /tx` land in a later plan.

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
