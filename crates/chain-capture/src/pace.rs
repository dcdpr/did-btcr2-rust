//! Request pacing and rate-limit retry for captures against a hosted indexer.
//!
//! The public Esplora indexers (mempool.space and its peers) rate-limit their
//! callers, and a capture session issues a burst of address, continuation-page
//! and block requests. Starting one request every 500 ms, and retrying an HTTP
//! 429 with a bounded exponential backoff, is what the generator of the test
//! vectors itself does against the same service, so a capture behaves no worse
//! than the tool that minted the data.
//!
//! [`PacedTransport`] sits *below* the recorder: the recorder refuses any
//! non-2xx answer to a transaction-list request, so a 429 has to be absorbed
//! here, and only the eventual successful body is ever passed up to be
//! recorded. Any other non-2xx status is passed up unchanged, where the
//! recorder still refuses it.
//!
//! Every wait goes through a [`Clock`], so the tests drive pacing and backoff
//! with a fake clock and never sleep for real.

use did_btcr2_client::{BtcTransport, TransportError};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

/// The HTTP status a rate-limiting indexer answers with.
const TOO_MANY_REQUESTS: u16 = 429;

/// A source of the current time and a way to wait.
pub trait Clock {
    /// The current instant.
    fn now(&self) -> Instant;
    /// Block for `duration`.
    fn sleep(&self, duration: Duration);
}

/// The real clock: [`Instant::now`] and a thread sleep.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// How requests are spaced and how a 429 is retried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacePolicy {
    /// The minimum gap between the starts of two requests in one session.
    pub spacing: Duration,
    /// How many times one request is sent before a run of 429s is a failure.
    /// At least one send always happens.
    pub max_attempts: u32,
    /// The wait after the first 429; each further 429 doubles it.
    pub first_backoff: Duration,
    /// The ceiling on any single backoff wait.
    pub max_backoff: Duration,
}

impl PacePolicy {
    /// One request every 500 ms; a 429 retried up to 5 attempts, backoff 1 s
    /// doubling to 16 s.
    pub const fn public_indexer() -> Self {
        Self {
            spacing: Duration::from_millis(500),
            max_attempts: 5,
            first_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(16),
        }
    }

    /// No spacing and no retry, for a local regtest indexer.
    pub const fn unpaced() -> Self {
        Self {
            spacing: Duration::ZERO,
            max_attempts: 1,
            first_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        }
    }

    /// The wait after the `attempt`-th consecutive 429 (1-based):
    /// `first_backoff * 2^(attempt-1)`, capped at `max_backoff`.
    fn backoff(&self, attempt: u32) -> Duration {
        1u32.checked_shl(attempt.saturating_sub(1))
            .and_then(|factor| self.first_backoff.checked_mul(factor))
            .map_or(self.max_backoff, |wait| wait.min(self.max_backoff))
    }
}

/// When the last request of a session started. Shared by every
/// [`PacedTransport`] handle of one session so they are spaced as one stream.
#[derive(Debug, Default)]
pub struct PaceState {
    last_start: Option<Instant>,
}

/// A transport that spaces request starts and retries a rate-limited answer.
pub struct PacedTransport<T: BtcTransport, C: Clock> {
    inner: T,
    clock: C,
    policy: PacePolicy,
    state: Rc<RefCell<PaceState>>,
}

impl<T: BtcTransport, C: Clock> PacedTransport<T, C> {
    /// Wrap `inner`, spacing its requests against the session-wide `state`.
    pub fn sharing(inner: T, clock: C, policy: PacePolicy, state: Rc<RefCell<PaceState>>) -> Self {
        Self {
            inner,
            clock,
            policy,
            state,
        }
    }

    /// Wait until the session's spacing allows another request to start, then
    /// mark it started.
    fn wait_turn(&self) {
        let last_start = self.state.borrow().last_start;
        if let Some(last) = last_start {
            let ready_at = last + self.policy.spacing;
            let now = self.clock.now();
            if ready_at > now {
                self.clock.sleep(ready_at - now);
            }
        }
        self.state.borrow_mut().last_start = Some(self.clock.now());
    }
}

impl<T: BtcTransport, C: Clock> BtcTransport for PacedTransport<T, C> {
    fn execute(
        &self,
        req: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, TransportError> {
        // `http::Request` is not `Clone`; a retry rebuilds it from its parts.
        let (parts, body) = req.into_parts();
        let rebuild = || {
            let mut again = http::Request::new(body.clone());
            *again.method_mut() = parts.method.clone();
            *again.uri_mut() = parts.uri.clone();
            *again.version_mut() = parts.version;
            *again.headers_mut() = parts.headers.clone();
            again
        };

        let attempts = self.policy.max_attempts.max(1);
        for attempt in 1..=attempts {
            self.wait_turn();
            // A network failure is not a rate limit: it is returned at once.
            let resp = self.inner.execute(rebuild())?;
            if resp.status().as_u16() != TOO_MANY_REQUESTS {
                return Ok(resp);
            }
            if attempt < attempts {
                self.clock.sleep(self.policy.backoff(attempt));
            }
        }
        Err(TransportError::Io(std::io::Error::other(format!(
            "HTTP 429 from {} after {attempts} attempts: the indexer is rate-limiting \
             this capture; wait and re-run the capture",
            parts.uri
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RecordingTransport;
    use std::collections::{BTreeMap, VecDeque};

    const BASE: &str = "https://indexer.example/api";
    const ADDR: &str = "tb1qpacedaddress";

    /// A clock that never waits: `sleep` records the duration and advances
    /// `now` by it, and a test can advance `now` by hand.
    #[derive(Clone)]
    struct FakeClock(Rc<RefCell<FakeClockState>>);

    struct FakeClockState {
        base: Instant,
        offset: Duration,
        sleeps: Vec<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self(Rc::new(RefCell::new(FakeClockState {
                base: Instant::now(),
                offset: Duration::ZERO,
                sleeps: Vec::new(),
            })))
        }

        fn advance(&self, by: Duration) {
            self.0.borrow_mut().offset += by;
        }

        fn sleeps(&self) -> Vec<Duration> {
            self.0.borrow().sleeps.clone()
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            let state = self.0.borrow();
            state.base + state.offset
        }

        fn sleep(&self, duration: Duration) {
            let mut state = self.0.borrow_mut();
            state.sleeps.push(duration);
            state.offset += duration;
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Seen {
        method: String,
        uri: String,
        body: Vec<u8>,
    }

    /// Queued `(status, body)` replies per request path; the last one repeats.
    #[derive(Clone, Default)]
    struct ScriptedTransport {
        canned: Rc<RefCell<BTreeMap<String, VecDeque<(u16, String)>>>>,
        seen: Rc<RefCell<Vec<Seen>>>,
    }

    impl ScriptedTransport {
        fn reply(&self, path: &str, status: u16, body: &str) -> &Self {
            self.canned
                .borrow_mut()
                .entry(path.to_string())
                .or_default()
                .push_back((status, body.to_string()));
            self
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.borrow().clone()
        }
    }

    impl BtcTransport for ScriptedTransport {
        fn execute(
            &self,
            req: http::Request<Vec<u8>>,
        ) -> Result<http::Response<Vec<u8>>, TransportError> {
            let path = req.uri().path().to_string();
            self.seen.borrow_mut().push(Seen {
                method: req.method().to_string(),
                uri: req.uri().to_string(),
                body: req.body().clone(),
            });
            let (status, body) = {
                let mut canned = self.canned.borrow_mut();
                let queue = canned
                    .get_mut(&path)
                    .unwrap_or_else(|| panic!("no canned reply for `{path}`"));
                if queue.len() > 1 {
                    queue.pop_front().expect("a non-empty queue")
                } else {
                    queue.front().cloned().expect("a non-empty queue")
                }
            };
            Ok(http::Response::builder()
                .status(status)
                .body(body.into_bytes())
                .expect("a valid status and body build a response"))
        }
    }

    fn get(path: &str) -> http::Request<Vec<u8>> {
        http::Request::get(format!("{BASE}{path}"))
            .body(Vec::new())
            .expect("a valid request")
    }

    fn paced(
        inner: ScriptedTransport,
        clock: &FakeClock,
        policy: PacePolicy,
    ) -> PacedTransport<ScriptedTransport, FakeClock> {
        PacedTransport::sharing(
            inner,
            clock.clone(),
            policy,
            Rc::new(RefCell::new(PaceState::default())),
        )
    }

    /// The operator-facing message: `TransportError::Io` displays a fixed
    /// sentence, and the detail lives on its source, which `main` prints as
    /// `Caused by:`.
    fn chain(error: &TransportError) -> String {
        let mut out = error.to_string();
        let mut source = std::error::Error::source(error);
        while let Some(e) = source {
            out.push_str(" | ");
            out.push_str(&e.to_string());
            source = e.source();
        }
        out
    }

    fn secs(s: &[u64]) -> Vec<Duration> {
        s.iter().copied().map(Duration::from_secs).collect()
    }

    #[test]
    fn paced_requests_through_one_handle_start_500_ms_apart() {
        let inner = ScriptedTransport::default();
        inner.reply("/api/blocks/tip/height", 200, "100");
        let clock = FakeClock::new();
        let transport = paced(inner, &clock, PacePolicy::public_indexer());

        transport.execute(get("/blocks/tip/height")).unwrap();
        assert!(
            clock.sleeps().is_empty(),
            "the first request waits for nothing"
        );
        transport.execute(get("/blocks/tip/height")).unwrap();
        assert_eq!(clock.sleeps(), vec![Duration::from_millis(500)]);
    }

    #[test]
    fn paced_handles_sharing_one_state_are_spaced_as_one_stream() {
        let inner = ScriptedTransport::default();
        inner.reply("/api/blocks/tip/height", 200, "100");
        let clock = FakeClock::new();
        let state = Rc::new(RefCell::new(PaceState::default()));
        let policy = PacePolicy::public_indexer();
        let first =
            PacedTransport::sharing(inner.clone(), clock.clone(), policy, Rc::clone(&state));
        let second = PacedTransport::sharing(inner, clock.clone(), policy, Rc::clone(&state));

        first.execute(get("/blocks/tip/height")).unwrap();
        second.execute(get("/blocks/tip/height")).unwrap();
        assert_eq!(clock.sleeps(), vec![Duration::from_millis(500)]);
    }

    #[test]
    fn paced_request_after_the_spacing_has_elapsed_does_not_wait() {
        let inner = ScriptedTransport::default();
        inner.reply("/api/blocks/tip/height", 200, "100");
        let clock = FakeClock::new();
        let transport = paced(inner, &clock, PacePolicy::public_indexer());

        transport.execute(get("/blocks/tip/height")).unwrap();
        clock.advance(Duration::from_millis(600));
        transport.execute(get("/blocks/tip/height")).unwrap();
        assert!(clock.sleeps().is_empty());
    }

    #[test]
    fn rate_limited_request_is_retried_until_it_succeeds() {
        let inner = ScriptedTransport::default();
        let path = format!("/api/address/{ADDR}/txs");
        inner
            .reply(&path, 429, "slow down")
            .reply(&path, 429, "slow down")
            .reply(&path, 200, "[]");
        let clock = FakeClock::new();
        let transport = paced(inner.clone(), &clock, PacePolicy::public_indexer());

        let request = http::Request::post(format!("{BASE}/address/{ADDR}/txs"))
            .body(b"payload".to_vec())
            .unwrap();
        let resp = transport.execute(request).unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.body(), b"[]");

        let seen = inner.seen();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|s| *s == seen[0]), "{seen:?}");
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].uri, format!("{BASE}/address/{ADDR}/txs"));
        assert_eq!(seen[0].body, b"payload");
        assert_eq!(clock.sleeps(), secs(&[1, 2]));
    }

    #[test]
    fn rate_limited_five_times_fails_naming_the_uri_and_attempts() {
        let inner = ScriptedTransport::default();
        inner.reply("/api/blocks/tip/height", 429, "slow down");
        let clock = FakeClock::new();
        let transport = paced(inner.clone(), &clock, PacePolicy::public_indexer());

        let err = transport
            .execute(get("/blocks/tip/height"))
            .expect_err("five 429s are a failure");
        let message = chain(&err);
        assert!(
            message.contains(&format!("{BASE}/blocks/tip/height")),
            "{message}"
        );
        assert!(message.contains("5 attempts"), "{message}");
        assert!(!message.contains("slow down"), "{message}");
        assert_eq!(inner.seen().len(), 5);
        assert_eq!(clock.sleeps(), secs(&[1, 2, 4, 8]));
    }

    #[test]
    fn rate_limited_backoff_doubles_and_caps_at_16_seconds() {
        let inner = ScriptedTransport::default();
        inner.reply("/api/blocks/tip/height", 429, "");
        let clock = FakeClock::new();
        let policy = PacePolicy {
            max_attempts: 7,
            ..PacePolicy::public_indexer()
        };
        let transport = paced(inner.clone(), &clock, policy);

        let err = transport.execute(get("/blocks/tip/height")).unwrap_err();
        assert!(chain(&err).contains("7 attempts"), "{err}");
        assert_eq!(inner.seen().len(), 7);
        assert_eq!(clock.sleeps(), secs(&[1, 2, 4, 8, 16, 16]));
    }

    #[test]
    fn rate_limited_backoff_survives_an_overflowing_attempt_count() {
        let policy = PacePolicy::public_indexer();
        assert_eq!(policy.backoff(40), Duration::from_secs(16));
        assert_eq!(policy.backoff(u32::MAX), Duration::from_secs(16));
    }

    #[test]
    fn unpaced_policy_never_waits_and_does_not_retry() {
        let inner = ScriptedTransport::default();
        inner
            .reply("/api/blocks/tip/height", 200, "100")
            .reply("/api/tx/abc", 429, "");
        let clock = FakeClock::new();
        let transport = paced(inner.clone(), &clock, PacePolicy::unpaced());

        transport.execute(get("/blocks/tip/height")).unwrap();
        transport.execute(get("/blocks/tip/height")).unwrap();
        let err = transport.execute(get("/tx/abc")).unwrap_err();
        assert!(chain(&err).contains("1 attempts"), "{err}");
        assert!(clock.sleeps().is_empty());
        assert_eq!(inner.seen().len(), 3);
    }

    #[test]
    fn paced_transport_passes_other_failures_up_unretried() {
        for status in [404u16, 500] {
            let inner = ScriptedTransport::default();
            inner.reply("/api/tx/abc", status, "nope");
            let clock = FakeClock::new();
            let transport = paced(inner.clone(), &clock, PacePolicy::public_indexer());

            let resp = transport.execute(get("/tx/abc")).unwrap();
            assert_eq!(resp.status().as_u16(), status);
            assert_eq!(resp.body(), b"nope");
            assert_eq!(inner.seen().len(), 1);
            assert!(clock.sleeps().is_empty());
        }
    }

    #[test]
    fn paced_transport_propagates_a_network_failure_without_retrying() {
        struct Unreachable(Rc<RefCell<u32>>);
        impl BtcTransport for Unreachable {
            fn execute(
                &self,
                _req: http::Request<Vec<u8>>,
            ) -> Result<http::Response<Vec<u8>>, TransportError> {
                *self.0.borrow_mut() += 1;
                Err(TransportError::Io(std::io::Error::other(
                    "connection refused",
                )))
            }
        }
        let calls = Rc::new(RefCell::new(0));
        let clock = FakeClock::new();
        let transport = PacedTransport::sharing(
            Unreachable(Rc::clone(&calls)),
            clock.clone(),
            PacePolicy::public_indexer(),
            Rc::new(RefCell::new(PaceState::default())),
        );
        let err = transport.execute(get("/tx/abc")).unwrap_err();
        assert!(chain(&err).contains("connection refused"), "{err}");
        assert_eq!(*calls.borrow(), 1);
        assert!(clock.sleeps().is_empty());
    }

    #[test]
    fn rate_limited_answer_never_reaches_the_recorder() {
        let inner = ScriptedTransport::default();
        let path = format!("/api/address/{ADDR}/txs");
        let tx = r#"[{"txid":"aa"}]"#;
        inner.reply(&path, 429, "slow down").reply(&path, 200, tx);
        let clock = FakeClock::new();
        let recorder =
            RecordingTransport::new(paced(inner.clone(), &clock, PacePolicy::public_indexer()));
        let recording = recorder.recording();

        recorder
            .execute(get(&format!("/address/{ADDR}/txs")))
            .unwrap();
        let recorded = recording.borrow();
        assert_eq!(recorded.addresses.len(), 1);
        assert_eq!(
            recorded.addresses[ADDR],
            serde_json::from_str::<Vec<serde_json::Value>>(tx).unwrap()
        );
        assert_eq!(inner.seen().len(), 2);
    }
}
