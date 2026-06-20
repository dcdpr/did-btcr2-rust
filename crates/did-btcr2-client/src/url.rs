//! Esplora base-URL selection.
//!
//! Owns the mapping from a `--network` string to a confirmed Esplora base URL,
//! plus the `--esplora-url` override. Hoisted out of the CLI so the facade — and
//! any future HTTP front-end — share one source of truth for endpoint selection.

use crate::error::Error;

/// Map a `network` value to its confirmed Esplora base URL (no trailing slash).
///
/// All four URLs were live-checked (each `/blocks/tip/height` returned a bare
/// integer over https).
pub fn network_base_url(network: &str) -> Option<&'static str> {
    match network {
        "testnet" => Some("https://blockstream.info/testnet/api"),
        "signet" => Some("https://blockstream.info/signet/api"),
        "mainnet" => Some("https://blockstream.info/api"),
        "mutinynet" => Some("https://mutinynet.com/api"),
        _ => None,
    }
}

/// Resolve the Esplora base URL. `esplora_url` wins verbatim (with any trailing
/// slash trimmed); otherwise `network` maps to a confirmed URL; the default is
/// `testnet`. An unrecognized `network` is a clean [`Error::UnknownNetwork`],
/// not a silent fallback.
pub fn resolve_base_url(
    network: Option<&str>,
    esplora_url: Option<String>,
) -> Result<String, Error> {
    if let Some(mut url) = esplora_url {
        // Consumers concatenate with a leading slash (`{base}/blocks/tip/height`),
        // so a trailing slash here would yield a `//` in the path.
        if url.ends_with('/') {
            url.pop();
        }
        return Ok(url);
    }
    let net = network.unwrap_or("testnet");
    network_base_url(net)
        .map(str::to_string)
        .ok_or_else(|| Error::UnknownNetwork(net.to_string()))
}
