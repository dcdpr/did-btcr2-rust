//! `did-btc1-client` — the I/O-bearing four-operation facade over the sans-I/O
//! `did-btc1` core.
//!
//! The core crate (`did-btc1`) is sans-I/O: it never makes a network call. The
//! standard `did:btc1` operations, however, imply I/O — `resolve` fetches beacon
//! signals from an Esplora endpoint, `update`/`deactivate` broadcast a beacon
//! announcement. This crate composes those operations on top of the core,
//! routing every HTTP call through the [`BtcTransport`] seam so the same
//! composition is shared by the CLI and a future HTTP front-end, and so offline
//! tests can inject an in-process fake transport.
//!
//! This plan delivers the spine: the transport seam, [`Client::create`] (no
//! I/O), and [`Client::resolve`] (drives the resolver FSM through the transport).

mod client;
mod error;
mod esplora;
mod funding;
mod transport;
mod url;

pub use client::Client;
pub use error::{Error, TransportError};
pub use funding::{
    DEFAULT_CONF_TARGET, EsploraUtxo, Fee, fetch_fee_estimates, fetch_utxos, rate_from_estimates,
    resolve_fee, select,
};
pub use transport::{BtcTransport, UreqTransport};
pub use url::{network_base_url, resolve_base_url};

// Re-export the resolve option/result surface a facade caller needs, so callers
// do not depend on `did-btc1` paths directly for the common case.
pub use did_btc1::document::{ResolutionOptions, ResolutionResult};

// Re-export `Patch` (the RFC-6902 update patch type) so an `update` caller can
// name the parameter without depending on `json-patch` directly.
pub use json_patch::Patch;
