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
/// not a silent fallback. `regtest` is a recognized network with no hosted
/// Esplora endpoint: without an `--esplora-url` override it is a clean
/// [`Error::NoDefaultEndpoint`] (never a testnet fallback, never `UnknownNetwork`).
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
    if net == "regtest" {
        // regtest is a recognized network with no hosted Esplora endpoint;
        // it must NOT default to testnet and must NOT launder through UnknownNetwork.
        return Err(Error::NoDefaultEndpoint("regtest"));
    }
    network_base_url(net)
        .map(str::to_string)
        .ok_or_else(|| Error::UnknownNetwork(net.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regtest_without_url_has_no_default_endpoint() {
        // regtest is a recognized network with no hosted Esplora endpoint: it must
        // NOT fall back to a testnet URL and must NOT launder through UnknownNetwork.
        match resolve_base_url(Some("regtest"), None) {
            Err(Error::NoDefaultEndpoint(net)) => assert_eq!(net, "regtest"),
            other => panic!("expected NoDefaultEndpoint, got {other:?}"),
        }
        let msg = Error::NoDefaultEndpoint("regtest").to_string();
        assert!(
            msg.contains("no default Esplora endpoint"),
            "message should name the missing default, got: {msg}"
        );
        assert!(
            msg.contains("--esplora-url"),
            "message should point at the remediation, got: {msg}"
        );
    }

    #[test]
    fn regtest_with_url_uses_supplied_endpoint() {
        // A supplied --esplora-url wins for regtest (live resolve against a local node).
        assert_eq!(
            resolve_base_url(
                Some("regtest"),
                Some("http://localhost:3000/api".to_string())
            )
            .unwrap(),
            "http://localhost:3000/api"
        );
    }

    #[test]
    fn unknown_network_is_unchanged() {
        match resolve_base_url(Some("bogus"), None) {
            Err(Error::UnknownNetwork(net)) => assert_eq!(net, "bogus"),
            other => panic!("expected UnknownNetwork, got {other:?}"),
        }
    }

    #[test]
    fn default_network_is_testnet() {
        assert_eq!(
            resolve_base_url(None, None).unwrap(),
            "https://blockstream.info/testnet/api"
        );
    }
}
