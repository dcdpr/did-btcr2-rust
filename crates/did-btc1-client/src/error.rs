//! Error types for the `did-btc1-client` facade.
//!
//! Two layers, mirroring the CLI's `CliRunError` shape: [`TransportError`] for
//! the HTTP seam (a genuine network failure, an I/O read error, or a typed
//! non-2xx status), and [`Error`] for the facade as a whole (transport, JSON
//! parsing, the sans-I/O core's resolver/document errors, and an
//! unknown-network rejection).

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
    Core(#[from] did_btc1::document::Error),

    /// A spec-level (`did:btc1`) error from the core.
    Btc1(#[from] did_btc1::error::Btc1Error),

    /// An error stepping the resolver FSM in the core.
    Resolver(#[from] did_btc1::resolver::Error),

    /// An invalid DID identifier.
    Identifier(#[from] did_btc1::identifier::Error),

    /// An unrecognized `--network` value.
    #[error("unknown network '{0}'. Expected testnet, signet, mainnet, or mutinynet")]
    UnknownNetwork(String),

    /// An unrecognized `--beacon` type name.
    #[error("unknown beacon type '{0}'; expected P2PKH, P2WPKH, or P2TR")]
    UnknownBeaconType(String),

    /// The next `version_id` would overflow `u64` (the DID has been updated
    /// `u64::MAX` times — not reachable in practice).
    #[error("version_id overflow: the DID is already at the maximum version")]
    VersionIdOverflow,

    /// No confirmed beacon UTXO covers the required fee (nothing to fund the
    /// announcement with).
    NoSpendableUtxo,

    /// The resolved document has no beacon at the requested index.
    NoBeacon,

    /// Building or signing the beacon announcement transaction failed.
    Announce(#[from] did_btc1::beacon::AnnounceError),

    /// The `/fee-estimates` endpoint did not return a rate for the requested
    /// conf-target (A3 — error, do NOT silently low-ball with a default rate).
    #[error("no fee estimate for conf-target {target} blocks")]
    FeeEstimateUnavailable {
        /// The conf-target (in blocks) that had no estimate.
        target: u16,
    },

    /// A rate fee would require spending more than one funding input. Multi-input
    /// under a rate fee is deferred to a later phase (the single-input bound keeps
    /// the measured-vsize fee exact).
    RateFeeRequiresMultipleInputs,

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
