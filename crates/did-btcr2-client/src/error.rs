//! Error types for the `did-btcr2-client` facade.
//!
//! Two layers, mirroring the CLI's `CliRunError` shape: [`TransportError`] for
//! the HTTP seam (a genuine network failure, an I/O read error, a typed
//! non-2xx status, or a well-formed response whose body has the wrong shape),
//! and [`Error`] for the facade as a whole (transport, JSON parsing, the
//! sans-I/O core's resolver/document errors, and the endpoint-selection
//! rejections: an unknown network name, a network with no hosted endpoint,
//! or a `--network` that contradicts the DID).

use did_btcr2::error::{Btcr2Error, ProblemDetails};
use onlyerror::Error;

/// An error crossing the HTTP transport seam.
///
/// A non-2xx HTTP response is NOT a [`TransportError::Http`]: the production
/// agent is configured with `http_status_as_error(false)`, so a non-2xx
/// response arrives as a `Response` the facade inspects and maps to
/// [`TransportError::Status`]. A [`TransportError::Http`] is reserved for a
/// genuine ureq failure (DNS, connect, timeout, TLS).
#[derive(Debug, Error)]
pub enum TransportError {
    /// A genuine ureq transport failure (DNS, connect, timeout, TLS).
    Http(#[from] ureq::Error),

    /// An I/O error reading the response body.
    Io(#[from] std::io::Error),

    /// A well-formed HTTP response whose body does not have the shape the
    /// client requires: JSON that parsed but carries a field that is not what
    /// it claims to be (a block `id` that is not a hex block hash, a
    /// `mediantime` outside the representable range), or a body that
    /// contradicts the request it answers. Nothing I/O-related happened, which
    /// is why this is not [`TransportError::Io`]; a body that is not JSON at
    /// all is the facade's `Error::Json`.
    #[error("malformed response body: {0}")]
    Malformed(String),

    /// A non-2xx HTTP response, carrying the status code and body for
    /// deterministic inspection by the caller.
    #[error("HTTP {status}: {body}")]
    Status {
        /// The HTTP status code.
        status: u16,
        /// The response body, as a lossy UTF-8 string.
        body: String,
    },
}

/// An error from any facade operation.
#[derive(Debug, Error)]
pub enum Error {
    /// An error crossing the HTTP transport seam.
    Transport(#[from] TransportError),

    /// A JSON (de)serialization error (response body parsing).
    Json(#[from] serde_json::Error),

    /// An error constructing the resolver or applying an update in the core.
    Core(#[from] did_btcr2::document::Error),

    /// A spec-level (`did:btcr2`) error from the core.
    Btcr2(#[from] did_btcr2::error::Btcr2Error),

    /// An error stepping the resolver FSM in the core.
    Resolver(#[from] did_btcr2::resolver::Error),

    /// An invalid DID identifier.
    Identifier(#[from] did_btcr2::identifier::Error),

    /// An unrecognized `--network` value.
    #[error(
        "unknown network '{0}'. Expected testnet, testnet4, signet, mainnet, mutinynet, or regtest"
    )]
    UnknownNetwork(String),

    /// A recognized network that has no hosted Esplora endpoint (regtest), used
    /// without an `--esplora-url` override. Regtest is a known network, so this is
    /// deliberately distinct from `UnknownNetwork`. Also raised for a DID
    /// anchored to regtest or a custom network when the endpoint is derived
    /// from the DID and no URL was given.
    #[error("{0} has no default Esplora endpoint; pass --esplora-url")]
    NoDefaultEndpoint(&'static str),

    /// `--network` named a chain other than the one the DID is anchored to.
    /// The DID's network is authoritative; the flag may only confirm it.
    #[error(
        "--network {flag} contradicts the DID, which is anchored to {did_network}; drop the flag or name the DID's network"
    )]
    NetworkMismatch {
        /// The chain the flag named.
        flag: String,
        /// The chain encoded in the DID.
        did_network: String,
    },

    /// An unrecognized `--beacon` type name.
    #[error("unknown beacon type '{0}'; expected P2PKH, P2WPKH, or P2TR")]
    UnknownBeaconType(String),

    /// The next `version_id` would overflow `u64` (the DID has been updated
    /// `u64::MAX` times — not reachable in practice).
    #[error("version_id overflow: the DID is already at the maximum version")]
    VersionIdOverflow,

    /// No confirmed beacon UTXO covers the required fee.
    #[error(
        "no confirmed UTXO at beacon address {address} covers the required fee of {required_fee_sats} sats (found {found_confirmed_sats} confirmed)"
    )]
    NoSpendableUtxo {
        /// The beacon address queried for spendable UTXOs (rendered form).
        address: String,
        /// The fee (sats) the funding needed to cover.
        required_fee_sats: u64,
        /// The confirmed sats that were weighed against the fee and fell short
        /// (sats): the full confirmed balance at `address` on the absolute-fee
        /// path, or the single funding input the single-input rate-fee path is
        /// bounded to. Reporting the address total on the rate path would be
        /// self-contradictory (it can exceed the fee the one usable input can't).
        found_confirmed_sats: u64,
    },

    /// The resolved document has no beacon at the requested index.
    NoBeacon,

    /// The core issued a beacon-signal request whose path is not
    /// `/address/{address}/txs`, so the client cannot tell which beacon
    /// address the history it fetches belongs to — and the core requires each
    /// history fed back under that address. A mismatch between the two crates,
    /// not a network fault.
    #[error(
        "the resolver requested `{0}`, which is not an /address/<address>/txs endpoint; the \
         client keys each history by the address in that path"
    )]
    UnroutableRequest(String),

    /// Building or signing the beacon announcement transaction failed.
    Announce(#[from] did_btcr2::beacon::AnnounceError),

    /// The `/fee-estimates` endpoint did not return a rate for the requested
    /// conf-target (A3 — error, do NOT silently low-ball with a default rate).
    #[error("no fee estimate for conf-target {target} blocks")]
    FeeEstimateUnavailable {
        /// The conf-target (in blocks) that had no estimate.
        target: u16,
    },

    /// A rate fee was requested but funding would need more than one input, which
    /// is unsupported. Multi-input under a rate fee is deferred to a later phase;
    /// the single-input bound keeps the measured-vsize fee exact.
    MultiInputRateFeeUnsupported,

    /// A fee rate was not a usable sat/vB value: it was negative, zero, `NaN`,
    /// or infinite; OR it exceeded the accepted maximum (see the client's
    /// `MAX_FEE_RATE_SAT_PER_VB` ceiling); OR its absolute fee (`ceil(rate *
    /// vsize)`) would overflow the `u64` fee range. Such rates arrive from a
    /// malformed/hostile `/fee-estimates` response or a bad CLI value and are
    /// rejected up front rather than coerced, clamped, or saturated by `as u64`
    /// into a zero-sat or non-relayable fee.
    #[error(
        "invalid fee rate {rate} sat/vB: expected a positive, finite value within the accepted maximum whose absolute fee fits in u64"
    )]
    InvalidFeeRate {
        /// The offending rate.
        rate: f64,
    },

    /// `POST /tx` was rejected (non-2xx) by the broadcast endpoint.
    #[error("broadcast rejected: {body}")]
    BroadcastRejected {
        /// The endpoint's response body.
        body: String,
    },

    /// A `/utxo` entry carried a txid that did not parse as a Bitcoin txid.
    #[error("invalid UTXO txid '{txid}'")]
    InvalidUtxoTxid {
        /// The unparseable txid string from the response.
        txid: String,
    },
}

/// The problem details of the core error this wraps, or `None` for a facade
/// failure that is not a resolution outcome (transport, JSON, endpoint
/// selection, funding).
impl ProblemDetails for Error {
    fn details(&self) -> Option<serde_json::Value> {
        match self {
            Error::Btcr2(e) => e.details(),
            Error::Core(e) => e.details(),
            Error::Resolver(e) => e.details(),
            Error::Identifier(e) => identifier_details(e),
            _ => None,
        }
    }
}

/// The core's identifier-to-resolution conversion (`Btcr2Error::from`),
/// restated by reference because the parse error is not `Clone`.
/// `identifier_codes_follow_the_core_conversion` fails if the two drift apart.
fn identifier_details(err: &did_btcr2::identifier::Error) -> Option<serde_json::Value> {
    match err {
        did_btcr2::identifier::Error::MethodNotSupported(method) => {
            Btcr2Error::MethodNotSupported(method.clone()).details()
        }
        other => Btcr2Error::InvalidDid(other.to_string()).details(),
    }
}

/// The code fragment of a problem `type`, e.g. `NOT_FOUND` from
/// `https://www.w3.org/ns/did#NOT_FOUND`.
fn code_of(details: &serde_json::Value) -> Option<String> {
    let (_, code) = details["type"].as_str()?.rsplit_once('#')?;
    (!code.is_empty()).then(|| code.to_string())
}

impl Error {
    /// The specification error code this error carries, or `None` when it is
    /// not a resolution outcome.
    pub fn spec_code(&self) -> Option<String> {
        code_of(&self.details()?)
    }
}

/// The specification error code of the first error in `err`'s source chain
/// (starting with `err` itself) that carries one, or `None` when none does.
///
/// Recognizes this crate's [`enum@Error`] and the core's spec-bearing errors
/// (`Btcr2Error`, `document::Error`, `resolver::Error`, and an identifier
/// parse error, which is an invalid DID or an unsupported method).
pub fn spec_code_in_chain(err: &(dyn std::error::Error + 'static)) -> Option<String> {
    std::iter::successors(Some(err), |e| e.source()).find_map(|e| {
        if let Some(e) = e.downcast_ref::<Error>() {
            e.spec_code()
        } else if let Some(e) = e.downcast_ref::<Btcr2Error>() {
            code_of(&e.details()?)
        } else if let Some(e) = e.downcast_ref::<did_btcr2::document::Error>() {
            code_of(&e.details()?)
        } else if let Some(e) = e.downcast_ref::<did_btcr2::resolver::Error>() {
            code_of(&e.details()?)
        } else if let Some(e) = e.downcast_ref::<did_btcr2::identifier::Error>() {
            code_of(&identifier_details(e)?)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_btcr2::identifier::{Did, Sha256Hash};
    use std::str::FromStr;

    fn parse_error(did: &str) -> did_btcr2::identifier::Error {
        Did::from_str(did).expect_err("not a did:btcr2 identifier")
    }

    #[test]
    fn missing_update_data_has_its_code() {
        let err = Error::Btcr2(Btcr2Error::MissingUpdateData {
            update_hash: Sha256Hash::from([0u8; 32]),
        });
        assert_eq!(err.spec_code().as_deref(), Some("MISSING_UPDATE_DATA"));
    }

    #[test]
    fn resolver_unit_variants_have_their_codes() {
        let late = Error::Resolver(did_btcr2::resolver::Error::LatePublishingError);
        assert_eq!(late.spec_code().as_deref(), Some("LATE_PUBLISHING"));
        let mismatch = Error::Resolver(did_btcr2::resolver::Error::UpdateHashMismatch);
        assert_eq!(mismatch.spec_code().as_deref(), Some("INVALID_DID_UPDATE"));
    }

    #[test]
    fn identifier_errors_are_invalid_did_or_method_not_supported() {
        let malformed = Error::Identifier(parse_error("did:btcr2:notbech32"));
        assert_eq!(malformed.spec_code().as_deref(), Some("INVALID_DID"));
        let other_method = Error::Identifier(parse_error("did:example:123"));
        assert_eq!(
            other_method.spec_code().as_deref(),
            Some("METHOD_NOT_SUPPORTED")
        );
    }

    #[test]
    fn identifier_codes_follow_the_core_conversion() {
        // Each identifier error, parsed twice: one copy goes through the core's
        // own conversion, the other through this crate's restatement of it.
        for did in ["did:btcr2:notbech32", "did:example:123", "not-a-did"] {
            let owned = parse_error(did);
            let borrowed = parse_error(did);
            let core = code_of(&Btcr2Error::from(owned).details().expect("details"));
            assert!(core.is_some(), "{did}");
            assert_eq!(Error::Identifier(borrowed).spec_code(), core, "{did}");
        }
    }

    #[test]
    fn facade_failures_have_no_code() {
        let transport = Error::Transport(TransportError::Malformed("x".to_string()));
        assert_eq!(transport.spec_code(), None);
        assert_eq!(Error::UnknownNetwork("x".to_string()).spec_code(), None);
        let mismatch = Error::NetworkMismatch {
            flag: "signet".to_string(),
            did_network: "mutinynet".to_string(),
        };
        assert_eq!(mismatch.spec_code(), None);
    }

    /// A caller's error that wraps a client error as its source.
    #[derive(Debug)]
    struct Wrapper(Error);

    impl std::fmt::Display for Wrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("the command failed")
        }
    }

    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn chain_lookup_finds_a_wrapped_client_code() {
        let wrapped = Wrapper(Error::Btcr2(Btcr2Error::MissingUpdateData {
            update_hash: Sha256Hash::from([0u8; 32]),
        }));
        assert_eq!(
            spec_code_in_chain(&wrapped).as_deref(),
            Some("MISSING_UPDATE_DATA")
        );
    }

    #[test]
    fn chain_lookup_skips_a_wrapper_whose_source_has_no_code() {
        let wrapped = Wrapper(Error::UnknownNetwork("x".to_string()));
        assert_eq!(spec_code_in_chain(&wrapped), None);
    }

    #[test]
    fn chain_lookup_returns_none_for_an_io_error() {
        assert_eq!(spec_code_in_chain(&std::io::Error::other("x")), None);
    }

    #[test]
    fn chain_lookup_reads_a_bare_identifier_error() {
        assert_eq!(
            spec_code_in_chain(&parse_error("did:btcr2:notbech32")).as_deref(),
            Some("INVALID_DID")
        );
        assert_eq!(
            spec_code_in_chain(&parse_error("did:example:123")).as_deref(),
            Some("METHOD_NOT_SUPPORTED")
        );
    }

    #[test]
    fn chain_lookup_reads_bare_core_errors() {
        let late = did_btcr2::resolver::Error::LatePublishingError;
        assert_eq!(
            spec_code_in_chain(&late).as_deref(),
            Some("LATE_PUBLISHING")
        );
        let btcr2 = Btcr2Error::InvalidDidUpdate("x".to_string());
        assert_eq!(
            spec_code_in_chain(&btcr2).as_deref(),
            Some("INVALID_DID_UPDATE")
        );
    }
}
