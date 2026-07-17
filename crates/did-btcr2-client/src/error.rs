//! Error types for the `did-btcr2-client` facade.
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
    Core(#[from] did_btcr2::document::Error),

    /// A spec-level (`did:btcr2`) error from the core.
    Btcr2(#[from] did_btcr2::error::Btcr2Error),

    /// An error stepping the resolver FSM in the core.
    Resolver(#[from] did_btcr2::resolver::Error),

    /// An invalid DID identifier.
    Identifier(#[from] did_btcr2::identifier::Error),

    /// An unrecognized `--network` value.
    #[error("unknown network '{0}'. Expected testnet, signet, mainnet, or mutinynet")]
    UnknownNetwork(String),

    /// A recognized network that has no hosted Esplora endpoint (regtest), used
    /// without an `--esplora-url` override. Regtest is a known network, so this is
    /// deliberately distinct from `UnknownNetwork`.
    #[error("{0} has no default Esplora endpoint; pass --esplora-url")]
    NoDefaultEndpoint(&'static str),

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
