//! `did-btcr2-client` — the I/O-bearing four-operation facade over the sans-I/O
//! `did-btcr2` core.
//!
//! The core crate (`did-btcr2`) is sans-I/O: it never makes a network call. The
//! standard `did:btcr2` operations, however, imply I/O — `resolve` fetches beacon
//! signals from an Esplora endpoint, `update`/`deactivate` broadcast a beacon
//! announcement. This crate composes those operations on top of the core,
//! routing every HTTP call through the [`BtcTransport`] seam so the same
//! composition is shared by the CLI and a future HTTP front-end, and so offline
//! tests can inject an in-process fake transport.
//!
//! # The four operations
//!
//! - [`Client::create`] mints a DID from a public key, or from an intermediate
//!   document for the external (`x1`) form. Performs no I/O.
//! - [`Client::resolve`] drives the core resolver FSM, serving each round of
//!   beacon-signal requests through the transport.
//! - [`Client::update`] and [`Client::deactivate`] build a signed update, fund
//!   and construct its beacon announcement, then broadcast it.
//!
//! # Where the beacon key lives
//!
//! Announcement signing is split so the beacon secret never enters the core: the
//! core builds an unsigned transaction plus its sighashes, [`sign_beacon_tx`]
//! signs them here, and the core reassembles and re-validates the result. See
//! `docs/adr/0001-beacon-construct-sign-split.md`.
//!
//! # Funding
//!
//! [`resolve_fee`] settles an absolute or rate-based [`Fee`] against the fee
//! estimates the endpoint reports, and [`select`] picks the funding inputs under
//! the bounded single-input contract. [`network_base_url`] and
//! [`resolve_base_url`] map a network name to its Esplora endpoint; regtest has
//! no default and requires one to be supplied.

#![deny(missing_docs)]

mod client;
mod error;
mod esplora;
mod funding;
mod signing;
mod transport;
mod url;

pub use client::Client;
pub use error::{Error, TransportError};
pub use funding::{
    DEFAULT_CONF_TARGET, EsploraUtxo, Fee, UtxoStatus, confirmed_total, fetch_fee_estimates,
    fetch_utxos, rate_from_estimates, resolve_fee, select,
};
pub use signing::sign_beacon_tx;
pub use transport::{BtcTransport, UreqTransport};
pub use url::{network_base_url, resolve_base_url};

// Re-export the resolve option/result surface a facade caller needs, so callers
// do not depend on `did-btcr2` paths directly for the common case.
pub use did_btcr2::document::{ResolutionOptions, ResolutionResult};

// Re-export `Patch` (the RFC-6902 update patch type) so an `update` caller can
// name the parameter without depending on `json-patch` directly.
pub use json_patch::Patch;
