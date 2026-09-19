//! The one seam the binding composes: resolve a DID to a result, or fail.
//! Production composes [`CachingResolver`] over [`ClientResolver`]: a miss
//! costs one `did-btcr2-client` resolution including the chain-tip fetch, a
//! hit costs a map lookup and a clone.

use std::collections::HashMap;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use did_btcr2::document::{ResolutionOptions, ResolutionResult};
use did_btcr2::identifier::Did;
use did_btcr2_client::{Client, Error, UreqTransport, network_name};

// The cache is not yet re-exported from the crate root, so the lib target has
// no path to its constants and constructors (`new` is the root the clock and
// `with_clock` are reached through). `expect` (not `allow`) becomes an error
// the moment the export lands, so the markers cannot outlive their reason.

/// How long a successful result is served from memory before the next request
/// for it resolves again: one block interval, so `confirmations` and a freshly
/// confirmed update are at most a minute stale.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reachable once the crate root re-exports the cache"
    )
)]
pub const CACHE_TTL: Duration = Duration::from_secs(60);

/// The most entries the cache holds; past it, expired entries go first and
/// then the oldest.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reachable once the crate root re-exports the cache"
    )
)]
pub const CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).expect("1024 is non-zero");

/// Resolve a DID. Production is [`ClientResolver`]; the conformance suite
/// supplies a scripted implementation, so the handler is tested against the
/// exact type it composes in production.
pub trait Resolve {
    /// Resolve `did` under `opts`, or fail with the facade's error.
    fn resolve(&self, did: &Did, opts: ResolutionOptions) -> Result<ResolutionResult, Error>;

    /// The cache outcome of the most recent `resolve` on this handle, taken so
    /// the next request starts clean; `None` for a resolver without a cache or
    /// when `resolve` has not run since the last take. The shell reads it once
    /// per request for the log line; a handle serves one request at a time.
    fn take_cache_outcome(&self) -> Option<CacheOutcome> {
        None
    }
}

/// A source of monotonic time, so the cache's expiry is testable without
/// waiting.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The process clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Whether a resolver answered the most recent request from its cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheOutcome {
    /// Served from memory; the upstream resolver was not called.
    Hit,
    /// The upstream resolver was called (whatever it answered).
    Miss,
}

/// `(did, versionId, versionTime, minConf)` — the projection of the options
/// that selects a result. `accept` is deliberately absent: representation is
/// chosen after the result exists, so one resolution serves every `Accept`.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct CacheKey {
    did: String,
    version_id: Option<NonZeroU64>,
    version_time: Option<DateTime<Utc>>,
    min_conf: Option<NonZeroU32>,
}

struct Entry {
    inserted: Instant,
    result: ResolutionResult,
}

/// A response cache over any [`Resolve`]: successful results for `ttl`, at
/// most `capacity` of them, keyed by DID and the three scalar options. Errors
/// are passed through and never stored (`Error` is not `Clone`, so they cannot
/// be). Cloning shares the cache — every `serve` worker sees the same entries —
/// and gives the clone its own cache-outcome slot.
pub struct CachingResolver<R> {
    inner: R,
    ttl: Duration,
    capacity: NonZeroUsize,
    clock: Arc<dyn Clock>,
    entries: Arc<Mutex<HashMap<CacheKey, Entry>>>,
    last: Mutex<Option<CacheOutcome>>,
}

impl<R> CachingResolver<R> {
    /// Wrap `inner` with the process clock.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "reachable once the crate root re-exports the cache"
        )
    )]
    pub fn new(inner: R, ttl: Duration, capacity: NonZeroUsize) -> Self {
        Self::with_clock(inner, ttl, capacity, Arc::new(SystemClock))
    }

    /// Wrap `inner` with an explicit clock (tests).
    pub fn with_clock(
        inner: R,
        ttl: Duration,
        capacity: NonZeroUsize,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner,
            ttl,
            capacity,
            clock,
            entries: Arc::new(Mutex::new(HashMap::new())),
            last: Mutex::new(None),
        }
    }

    /// Entries currently held, expired ones included until the next insert or
    /// lookup touches them.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// `true` when no entry is held.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "reachable once the crate root re-exports the cache"
        )
    )]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The map holds plain data, so a panic in another worker mid-operation
    /// leaves at worst a missing entry; the poison flag carries no meaning.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A live entry's result, or `None` — removing the entry if it has expired.
    fn lookup(&self, key: &CacheKey, now: Instant) -> Option<ResolutionResult> {
        let mut map = self.lock();
        match map.get(key) {
            Some(entry) if now.duration_since(entry.inserted) < self.ttl => {
                Some(entry.result.clone())
            }
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    /// Insert, making room first: expired entries go, then the oldest.
    fn insert(&self, key: CacheKey, now: Instant, result: ResolutionResult) {
        let mut map = self.lock();
        if map.len() >= self.capacity.get() {
            map.retain(|_, e| now.duration_since(e.inserted) < self.ttl);
        }
        if map.len() >= self.capacity.get() {
            let oldest = map
                .iter()
                .min_by_key(|(_, e)| e.inserted)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                map.remove(&k);
            }
        }
        map.insert(
            key,
            Entry {
                inserted: now,
                result,
            },
        );
    }

    fn record(&self, outcome: CacheOutcome) {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
    }
}

impl<R: Clone> Clone for CachingResolver<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            ttl: self.ttl,
            capacity: self.capacity,
            clock: Arc::clone(&self.clock),
            entries: Arc::clone(&self.entries),
            last: Mutex::new(None),
        }
    }
}

impl<R> fmt::Debug for CachingResolver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachingResolver")
            .field("ttl", &self.ttl)
            .field("capacity", &self.capacity)
            .field("entries", &self.len())
            .finish_non_exhaustive()
    }
}

impl<R: Resolve> Resolve for CachingResolver<R> {
    fn resolve(&self, did: &Did, opts: ResolutionOptions) -> Result<ResolutionResult, Error> {
        let key = CacheKey {
            did: did.encode().to_owned(),
            version_id: opts.version_id,
            version_time: opts.version_time,
            min_conf: opts.min_conf,
        };
        let now = self.clock.now();
        if let Some(result) = self.lookup(&key, now) {
            self.record(CacheOutcome::Hit);
            return Ok(result);
        }
        self.record(CacheOutcome::Miss);
        // An `Err` leaves here; nothing is inserted.
        let result = self.inner.resolve(did, opts)?;
        self.insert(key, self.clock.now(), result.clone());
        Ok(result)
    }

    fn take_cache_outcome(&self) -> Option<CacheOutcome> {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
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
        // response reports current confirmations; nothing is cached here —
        // the cache is [`CachingResolver`], which wraps this type in
        // production.
        Client::for_did(did, None, esplora_url, self.transport.clone())?.resolve(did, opts)
    }
}

// The FSM is built and consumed inside `Client::resolve`; nothing about the
// resolver crosses a thread except this handle, which workers clone. The
// cache's `Arc<dyn Clock>` is Send + Sync because `Clock` requires both, and
// its outcome slot is a `Mutex`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ClientResolver>();
    assert_send_sync::<CachingResolver<ClientResolver>>();
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

    // ---- the response cache ----

    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::Utc;
    use did_btcr2::document::{Document, DocumentMetadata, InitialDocument, ResolutionMetadata};
    use serde_json::Value;

    use crate::{Request, handle};

    /// A clock the test advances by hand.
    struct ManualClock(Mutex<Instant>);

    impl ManualClock {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Instant::now())))
        }

        fn advance(&self, by: Duration) {
            let mut now = self.0.lock().expect("clock lock");
            *now += by;
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            *self.0.lock().expect("clock lock")
        }
    }

    type ResolveFn =
        dyn Fn(&Did, ResolutionOptions) -> Result<ResolutionResult, Error> + Send + Sync;

    /// A scripted resolver: the closure IS the script.
    #[derive(Clone)]
    struct Scripted(Arc<ResolveFn>);

    impl Resolve for Scripted {
        fn resolve(&self, did: &Did, opts: ResolutionOptions) -> Result<ResolutionResult, Error> {
            (self.0)(did, opts)
        }
    }

    /// Wrap `script` so every call is counted before it runs.
    fn counting(
        script: impl Fn(&Did, ResolutionOptions) -> Result<ResolutionResult, Error>
        + Send
        + Sync
        + 'static,
    ) -> (Scripted, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let scripted = Scripted(Arc::new(move |did, opts| {
            counter.fetch_add(1, Ordering::SeqCst);
            script(did, opts)
        }));
        (scripted, calls)
    }

    /// The initial document of a key-based DID as a resolution result, with
    /// the core's `contentType` and a version-1 metadata triple.
    fn ok_result(did: &Did, deactivated: bool) -> ResolutionResult {
        let document = Document::from(
            InitialDocument::from_did(did, &ResolutionOptions::default())
                .expect("a k1 DID generates its initial document"),
        );
        let mut resolution_metadata = ResolutionMetadata::default();
        resolution_metadata.content_type = Some("application/did".to_string());
        ResolutionResult {
            resolution_metadata,
            document,
            document_metadata: DocumentMetadata {
                version_id: NonZeroU64::MIN,
                confirmations: Some(0),
                deactivated,
                updated: None,
            },
        }
    }

    /// The core's own stamp (`Resolver::new`): `opts.accept`, or the default
    /// representation when the caller supplied none.
    fn stamped_like_the_core(
        did: &Did,
        opts: &ResolutionOptions,
        deactivated: bool,
    ) -> ResolutionResult {
        let mut result = ok_result(did, deactivated);
        result.resolution_metadata.content_type = Some(
            opts.accept
                .clone()
                .unwrap_or_else(|| "application/did".to_string()),
        );
        result
    }

    fn ok_counting() -> (Scripted, Arc<AtomicUsize>) {
        counting(|did, _| Ok(ok_result(did, false)))
    }

    fn cache<R>(inner: R, clock: &Arc<ManualClock>) -> CachingResolver<R> {
        CachingResolver::with_clock(
            inner,
            CACHE_TTL,
            CACHE_CAPACITY,
            Arc::clone(clock) as Arc<dyn Clock>,
        )
    }

    fn with_version_id(n: u64) -> ResolutionOptions {
        ResolutionOptions {
            version_id: Some(NonZeroU64::new(n).expect("non-zero")),
            ..Default::default()
        }
    }

    fn with_version_time(rfc3339: &str) -> ResolutionOptions {
        ResolutionOptions {
            version_time: Some(
                chrono::DateTime::parse_from_rfc3339(rfc3339)
                    .expect("a valid timestamp")
                    .with_timezone(&Utc),
            ),
            ..Default::default()
        }
    }

    fn with_min_conf(n: u32) -> ResolutionOptions {
        ResolutionOptions {
            min_conf: Some(NonZeroU32::new(n).expect("non-zero")),
            ..Default::default()
        }
    }

    fn get(did: &Did, accept: Option<&str>) -> Request {
        Request {
            method: "GET".into(),
            path: format!("/1.0/identifiers/{}", did.encode()),
            query: None,
            headers: accept
                .map(|a| vec![("Accept".to_string(), a.to_string())])
                .unwrap_or_default(),
        }
    }

    fn header<'a>(response: &'a crate::Response, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn body_json(response: &crate::Response) -> Value {
        serde_json::from_slice(&response.body).expect("the body is JSON")
    }

    #[test]
    fn second_call_within_ttl_is_a_hit_and_reaches_upstream_once() {
        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        let first = resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("first call resolves");
        let second = resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("second call resolves");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(second.document, first.document);
        assert_eq!(
            second.document_metadata.version_id,
            first.document_metadata.version_id
        );
    }

    #[test]
    fn call_at_ttl_reaches_upstream_again() {
        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");
        clock.advance(CACHE_TTL);
        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn call_just_under_ttl_is_still_a_hit() {
        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");
        clock.advance(CACHE_TTL - Duration::from_secs(1));
        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn errors_are_never_cached() {
        let clock = ManualClock::new();
        let attempt = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::clone(&attempt);
        let (inner, calls) = counting(move |did, _| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(Error::NoDefaultEndpoint("regtest"))
            } else {
                Ok(ok_result(did, false))
            }
        });
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        let err = resolver
            .resolve(&did, ResolutionOptions::default())
            .expect_err("the first call fails");
        assert!(matches!(err, Error::NoDefaultEndpoint(_)), "{err:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolver.len(), 0);
        assert!(resolver.is_empty());

        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("the second call resolves");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resolver.len(), 1);

        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("the third call is a hit");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn distinct_options_are_distinct_entries() {
        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);
        let variants = || {
            [
                with_version_id(1),
                with_version_id(2),
                with_version_time("2026-01-01T00:00:00Z"),
                with_min_conf(6),
                ResolutionOptions::default(),
            ]
        };

        for opts in variants() {
            resolver.resolve(&did, opts).expect("resolves");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert_eq!(resolver.len(), 5);

        for opts in variants() {
            resolver.resolve(&did, opts).expect("resolves");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert_eq!(resolver.len(), 5);
    }

    #[test]
    fn version_time_key_is_the_utc_instant() {
        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        resolver
            .resolve(&did, with_version_time("2026-01-01T02:00:00+02:00"))
            .expect("resolves");
        resolver
            .resolve(&did, with_version_time("2026-01-01T00:00:00Z"))
            .expect("resolves");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolver.len(), 1);
    }

    #[test]
    fn distinct_dids_are_distinct_entries() {
        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);

        resolver
            .resolve(&did_on(Network::Mainnet), ResolutionOptions::default())
            .expect("resolves");
        resolver
            .resolve(&did_on(Network::Mainnet), ResolutionOptions::default())
            .expect("resolves");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resolver.len(), 2);
    }

    /// One resolution serves every `Accept`, and each full body reports the
    /// content type its own request negotiated — whichever request populated
    /// the entry. The bare request goes first because that is the order that
    /// exposes a stale stamp: the entry holds `application/did+json`.
    #[test]
    fn accept_is_not_part_of_the_key() {
        let clock = ManualClock::new();
        let (inner, calls) = counting(|did, opts| Ok(stamped_like_the_core(did, &opts, false)));
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        let bare = handle(&get(&did, Some("application/did+json")), &resolver);
        let full = handle(&get(&did, Some("application/did-resolution")), &resolver);
        let default = handle(&get(&did, None), &resolver);

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for response in [&bare, &full, &default] {
            assert_eq!(response.status, 200, "{response:?}");
        }

        assert!(bare.body.starts_with(b"{\"@context\""), "{bare:?}");
        assert_eq!(header(&bare, "Content-Type"), Some("application/did+json"));

        for response in [&full, &default] {
            assert!(
                response.body.starts_with(b"{\"didDocument\""),
                "{response:?}"
            );
            assert_eq!(
                body_json(response)["didResolutionMetadata"]["contentType"],
                "application/did",
                "{response:?}"
            );
        }
    }

    #[test]
    fn deactivated_results_are_cached() {
        let clock = ManualClock::new();
        let (inner, calls) = counting(|did, _| Ok(ok_result(did, true)));
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");
        let second = resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(second.document_metadata.deactivated);
    }

    /// The cached 410 is re-stamped too: each full body reports the content
    /// type its own request negotiated.
    #[test]
    fn deactivated_hit_reports_the_negotiated_content_type() {
        let clock = ManualClock::new();
        let (inner, calls) = counting(|did, opts| Ok(stamped_like_the_core(did, &opts, true)));
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        let first = handle(&get(&did, Some("application/did+json")), &resolver);
        let second = handle(&get(&did, Some("application/did-resolution")), &resolver);

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for response in [&first, &second] {
            assert_eq!(response.status, 410, "{response:?}");
            assert_eq!(
                header(response, "Content-Type"),
                Some("application/did-resolution")
            );
            assert!(
                response.body.starts_with(b"{\"didDocument\""),
                "{response:?}"
            );
        }
        assert_eq!(
            body_json(&first)["didResolutionMetadata"]["contentType"],
            "application/did+json"
        );
        assert_eq!(
            body_json(&second)["didResolutionMetadata"]["contentType"],
            "application/did"
        );
    }

    #[test]
    fn capacity_evicts_expired_first_then_oldest() {
        let two = NonZeroUsize::new(2).expect("non-zero");
        let (a, b, c) = (
            did_on(Network::Mainnet),
            did_on(Network::Mainnet),
            did_on(Network::Mainnet),
        );

        // Expired entries go first: at capacity with both entries past the
        // TTL, the insert clears them and holds only the newcomer.
        let clock = ManualClock::new();
        let (inner, _) = ok_counting();
        let resolver = CachingResolver::with_clock(
            inner,
            CACHE_TTL,
            two,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        resolver
            .resolve(&a, ResolutionOptions::default())
            .expect("resolves");
        resolver
            .resolve(&b, ResolutionOptions::default())
            .expect("resolves");
        assert_eq!(resolver.len(), 2);
        clock.advance(CACHE_TTL + Duration::from_secs(1));
        resolver
            .resolve(&c, ResolutionOptions::default())
            .expect("resolves");
        assert_eq!(resolver.len(), 1);

        // Then the oldest: nothing expired, so the first-inserted entry goes.
        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = CachingResolver::with_clock(
            inner,
            CACHE_TTL,
            two,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        resolver
            .resolve(&a, ResolutionOptions::default())
            .expect("resolves");
        clock.advance(Duration::from_secs(1));
        resolver
            .resolve(&b, ResolutionOptions::default())
            .expect("resolves");
        clock.advance(Duration::from_secs(1));
        resolver
            .resolve(&c, ResolutionOptions::default())
            .expect("resolves");
        assert_eq!(resolver.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // B is still held (a hit), checked before A so re-requesting A cannot
        // evict B first.
        resolver
            .resolve(&b, ResolutionOptions::default())
            .expect("resolves");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        // A was the one evicted: it reaches upstream again.
        resolver
            .resolve(&a, ResolutionOptions::default())
            .expect("resolves");
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn take_cache_outcome_is_per_handle_and_taken_once() {
        let clock = ManualClock::new();
        let (inner, _) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        assert_eq!(resolver.take_cache_outcome(), None);

        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");
        assert_eq!(resolver.take_cache_outcome(), Some(CacheOutcome::Miss));
        assert_eq!(resolver.take_cache_outcome(), None);

        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");
        assert_eq!(resolver.take_cache_outcome(), Some(CacheOutcome::Hit));
        assert_eq!(resolver.take_cache_outcome(), None);

        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");
        let other_handle = resolver.clone();
        assert_eq!(other_handle.take_cache_outcome(), None);
        assert_eq!(resolver.take_cache_outcome(), Some(CacheOutcome::Hit));

        assert_eq!(
            ClientResolver::new(HashMap::new()).take_cache_outcome(),
            None
        );
    }

    #[test]
    fn caching_resolver_is_send_sync_clone_and_debug_hides_entries() {
        fn assert<T: Send + Sync + Clone>() {}
        assert::<CachingResolver<ClientResolver>>();

        // The production constructor, on the process clock.
        let (inner, calls) = ok_counting();
        let resolver = CachingResolver::new(inner, CACHE_TTL, CACHE_CAPACITY);
        let did = did_on(Network::Mainnet);
        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");
        resolver
            .resolve(&did, ResolutionOptions::default())
            .expect("resolves");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let rendered = format!("{resolver:?}");
        assert!(rendered.contains("CachingResolver"), "{rendered}");
        assert!(rendered.contains("ttl"), "{rendered}");
        assert!(rendered.contains("entries"), "{rendered}");
        assert!(!rendered.contains("did:btcr2:"), "{rendered}");
        assert!(!rendered.contains(did.encode()), "{rendered}");
    }
}
