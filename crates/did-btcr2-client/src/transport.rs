//! The transport seam.
//!
//! [`BtcTransport`] abstracts the single HTTP operation the facade needs:
//! execute a request and return the response. The production [`UreqTransport`]
//! wraps a configured `ureq::Agent`; an in-process fake implementing the same
//! trait is injected for offline tests. No HTTP code lives in the sans-I/O core
//! — it all lives behind this trait.

use std::time::Duration;

use crate::error::TransportError;

/// Abstracts the facade's one HTTP operation: execute a request, get a response.
///
/// The request and response carry `Vec<u8>` bodies. `esploda::Req` is
/// `http::Request<()>`; normalize it via `req.map(|()| Vec::new())` before
/// calling [`BtcTransport::execute`].
pub trait BtcTransport {
    /// Execute an HTTP request and return the response.
    ///
    /// A non-2xx status is returned as a normal [`http::Response`] (not an
    /// error) so the caller can type it deterministically; a genuine network
    /// failure (DNS, connect, timeout) is a [`TransportError`].
    fn execute(
        &self,
        req: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, TransportError>;
}

/// Build a configured HTTP agent.
///
/// The User-Agent is REQUIRED — the mutinynet endpoint returns 403 to UA-less
/// requests — and a 30s global timeout bounds a slow or hostile server.
/// `http_status_as_error(false)` makes a non-2xx response surface as a
/// [`http::Response`] (status + body preserved) rather than a `ureq::Error`,
/// so the facade can type non-2xx deterministically.
fn build_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .http_status_as_error(false)
        .build()
        .into()
}

/// The production transport: a `ureq::Agent` configured per `build_agent`.
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    /// Create a production transport with the configured agent.
    pub fn new() -> Self {
        Self {
            agent: build_agent(),
        }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl BtcTransport for UreqTransport {
    fn execute(
        &self,
        req: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, TransportError> {
        // The agent is configured `http_status_as_error(false)`, so a non-2xx
        // response is returned here as a `Response` rather than an `Err`; only a
        // genuine network failure becomes `TransportError::Http`.
        let mut resp = self.agent.run(req)?;
        let status = resp.status();
        let body = resp.body_mut().read_to_vec()?;

        // The facade only inspects status + body; response headers are not
        // forwarded. A `Response::builder().status(<valid status>).body(_)` is
        // infallible, so this `expect` is statically justified.
        http::Response::builder()
            .status(status)
            .body(body)
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))
    }
}
