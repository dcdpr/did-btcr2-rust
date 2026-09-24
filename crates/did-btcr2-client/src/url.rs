//! Esplora base-URL selection.
//!
//! Owns the mapping from a `--network` string to a confirmed Esplora base URL,
//! plus the `--esplora-url` override, and the one name <-> [`Network`] table
//! the flag and the endpoint lookup share. Hoisted out of the CLI so the
//! facade — and any future HTTP front-end — share one source of truth for
//! endpoint selection.

use did_btcr2::identifier::Network;

use crate::error::Error;

/// Map a `--network` name to the core [`Network`]. The six names the CLI
/// accepts (`testnet` is `TestnetV3`, `testnet4` is `TestnetV4`); anything
/// else is [`Error::UnknownNetwork`].
pub fn network_from_name(name: &str) -> Result<Network, Error> {
    match name {
        "testnet" => Ok(Network::TestnetV3),
        "testnet4" => Ok(Network::TestnetV4),
        "signet" => Ok(Network::Signet),
        "mainnet" => Ok(Network::Mainnet),
        "mutinynet" => Ok(Network::Mutinynet),
        "regtest" => Ok(Network::Regtest),
        other => Err(Error::UnknownNetwork(other.to_string())),
    }
}

/// The name the `--network` flag and the Esplora table use for a core
/// [`Network`]. Total: every named network round-trips through
/// [`network_from_name`]; only `Custom(_)` ("custom") has neither a
/// `--network` spelling nor a hosted endpoint, so it is not accepted back.
pub fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        Network::TestnetV3 => "testnet",
        Network::TestnetV4 => "testnet4",
        Network::Mutinynet => "mutinynet",
        Network::Custom(_) => "custom",
    }
}

/// Map a `network` value to its confirmed Esplora base URL (no trailing slash).
///
/// All five URLs were live-checked (each `/blocks/tip/height` returned a bare
/// integer over https; the mempool.space signet and testnet4 endpoints on
/// 2026-09-24). `regtest` and `custom` have no hosted endpoint.
pub fn network_base_url(network: &str) -> Option<&'static str> {
    match network {
        "testnet" => Some("https://blockstream.info/testnet/api"),
        "testnet4" => Some("https://mempool.space/testnet4/api"),
        "signet" => Some("https://mempool.space/signet/api"),
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

    /// The six `--network` spellings and the core `Network` variants they
    /// name round-trip through the one table; `Custom` still has a name (for
    /// error text and the endpoint lookup) but is not accepted as a flag
    /// value.
    #[test]
    fn network_names_round_trip() {
        for (name, net) in [
            ("mainnet", Network::Mainnet),
            ("signet", Network::Signet),
            ("testnet", Network::TestnetV3),
            ("testnet4", Network::TestnetV4),
            ("mutinynet", Network::Mutinynet),
            ("regtest", Network::Regtest),
        ] {
            assert_eq!(
                network_from_name(name).unwrap(),
                net,
                "{name} maps to {net:?}"
            );
            assert_eq!(network_name(net), name, "{net:?} is named {name}");
        }
        assert_eq!(network_name(Network::Custom(12)), "custom");
        for name in ["custom", "bogus"] {
            match network_from_name(name) {
                Err(Error::UnknownNetwork(n)) => assert_eq!(n, name),
                other => panic!("expected UnknownNetwork for {name}, got {other:?}"),
            }
        }
    }

    /// Every hosted network has its endpoint in the one table; signet and
    /// testnet4 are served by mempool.space, and regtest has none.
    #[test]
    fn hosted_endpoint_table() {
        for (name, url) in [
            ("mainnet", "https://blockstream.info/api"),
            ("testnet", "https://blockstream.info/testnet/api"),
            ("testnet4", "https://mempool.space/testnet4/api"),
            ("signet", "https://mempool.space/signet/api"),
            ("mutinynet", "https://mutinynet.com/api"),
        ] {
            assert_eq!(network_base_url(name), Some(url), "{name} endpoint");
            assert_eq!(resolve_base_url(Some(name), None).unwrap(), url);
        }
        assert_eq!(network_base_url("regtest"), None);
        assert_eq!(network_base_url("custom"), None);
    }

    #[test]
    fn default_network_is_testnet() {
        assert_eq!(
            resolve_base_url(None, None).unwrap(),
            "https://blockstream.info/testnet/api"
        );
    }
}
