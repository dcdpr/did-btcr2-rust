//! The one seam the binding composes: resolve a DID to a result, or fail.

use std::collections::HashMap;

use did_btcr2::document::{ResolutionOptions, ResolutionResult};
use did_btcr2::identifier::Did;
use did_btcr2_client::{Client, Error, UreqTransport, network_name};

/// Resolve a DID. Production is [`ClientResolver`]; the conformance suite
/// supplies a scripted implementation, so the handler is tested against the
/// exact type it composes in production.
pub trait Resolve {
    /// Resolve `did` under `opts`, or fail with the facade's error.
    fn resolve(&self, did: &Did, opts: ResolutionOptions) -> Result<ResolutionResult, Error>;
}

/// Production resolver: one `did-btcr2-client` per request, for the DID's own
/// network. Cloning shares the `ureq` agent (connection pool); the override
/// map is small and immutable, so cloning it per worker is fine.
#[derive(Clone, Debug)]
pub struct ClientResolver {
    /// `network_name()` string -> Esplora base URL, from `--esplora-url`.
    overrides: HashMap<String, String>,
    transport: UreqTransport,
}

impl ClientResolver {
    /// Build a resolver with the given per-network endpoint overrides. Keys
    /// are `did_btcr2_client::network_name` outputs: `mainnet`, `signet`,
    /// `regtest`, `testnet`, `testnet4`, `mutinynet`, `custom` (every custom
    /// network shares one override).
    pub fn new(overrides: HashMap<String, String>) -> Self {
        Self {
            overrides,
            transport: UreqTransport::new(),
        }
    }

    /// The override URL for the DID's network, if one was configured.
    pub fn override_for(&self, did: &Did) -> Option<&str> {
        self.overrides
            .get(network_name(did.components().network()))
            .map(String::as_str)
    }
}

impl Resolve for ClientResolver {
    fn resolve(&self, did: &Did, opts: ResolutionOptions) -> Result<ResolutionResult, Error> {
        let esplora_url = self.override_for(did).map(str::to_string);
        // `for_did` consults the hosted-endpoint table when no override is
        // given and fails with `NoDefaultEndpoint` for regtest / testnet4 /
        // custom. `resolve` fetches the chain tip on every call, so every
        // response reports current confirmations; nothing is cached here.
        Client::for_did(did, None, esplora_url, self.transport.clone())?.resolve(did, opts)
    }
}

// The FSM is built and consumed inside `Client::resolve`; nothing about the
// resolver crosses a thread except this handle, which workers clone.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ClientResolver>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use did_btcr2::identifier::{DidComponents, DidVersion, IdType, Network};

    /// A key-based DID anchored to `network`, re-parsed from its string form
    /// exactly as a request would carry it.
    fn did_on(network: Network) -> Did {
        let public_key = did_btcr2::KeyPair::generate().public_key;
        let components = DidComponents::new(DidVersion::One, network, IdType::from(public_key))
            .expect("the components are valid");
        Did::try_from(components)
            .expect("the DID encodes")
            .encode()
            .parse()
            .expect("the encoded DID parses back")
    }

    fn overrides(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn override_is_keyed_by_network_name() {
        let resolver = ClientResolver::new(overrides(&[
            ("testnet4", "http://h:1"),
            ("custom", "http://c:2"),
        ]));
        assert_eq!(
            resolver.override_for(&did_on(Network::TestnetV4)),
            Some("http://h:1")
        );
        assert_eq!(resolver.override_for(&did_on(Network::Regtest)), None);
        // Every custom network (nibble 12..=14) shares the one `custom` key.
        for nibble in 12..=14 {
            assert_eq!(
                resolver.override_for(&did_on(Network::Custom(nibble))),
                Some("http://c:2"),
                "custom nibble {nibble}"
            );
        }
        assert_eq!(resolver.override_for(&did_on(Network::Mainnet)), None);
    }

    /// With no override, `Client::for_did` fails before any request is made
    /// for a network with no hosted endpoint, so the test needs no socket.
    #[test]
    fn unconfigured_network_is_no_default_endpoint_before_any_io() {
        let resolver = ClientResolver::new(HashMap::new());
        for (network, name) in [
            (Network::Regtest, "regtest"),
            (Network::TestnetV4, "testnet4"),
        ] {
            let err = resolver
                .resolve(&did_on(network), ResolutionOptions::default())
                .expect_err("no hosted endpoint");
            match err {
                Error::NoDefaultEndpoint(n) => assert_eq!(n, name),
                other => panic!("expected NoDefaultEndpoint, got {other:?}"),
            }
        }
    }

    #[test]
    fn client_resolver_is_debug() {
        fn assert_send_sync<T: Send + Sync + Clone>() {}
        assert_send_sync::<ClientResolver>();
        let rendered = format!("{:?}", ClientResolver::new(HashMap::new()));
        assert!(rendered.contains("ClientResolver"), "{rendered}");
    }
}
