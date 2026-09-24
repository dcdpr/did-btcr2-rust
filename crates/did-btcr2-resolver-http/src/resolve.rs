//! The one seam the binding composes: resolve a DID to a result, or fail.
//! Production composes [`CachingResolver`] over [`ClientResolver`]: a miss
//! costs one `did-btcr2-client` resolution including the chain-tip fetch, a
//! hit costs a map lookup and a clone. A `POST` resolution bypasses the cache
//! entirely (`resolve_uncached`).

use std::collections::HashMap;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use did_btcr2::document::{ResolutionOptions, ResolutionResult};
use did_btcr2::identifier::Did;
use did_btcr2_client::{Client, Error, UreqTransport, network_name};

/// How long a successful result is served from memory before the next request
/// for it resolves again: one block interval, so `confirmations` and a freshly
/// confirmed update are at most a minute stale. The age is counted from the
/// instant the lookup missed — before the upstream call, whose chain tip the
/// result reflects — not from the instant the result arrived, so a slow or
/// rate-limited Esplora does not extend the bound by its latency.
pub const CACHE_TTL: Duration = Duration::from_secs(60);

/// The most entries the cache holds; past it, expired entries go first and
/// then the oldest.
pub const CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).expect("1024 is non-zero");

/// Resolve a DID. Production is [`ClientResolver`]; the conformance suite
/// supplies a scripted implementation, so the handler is tested against the
/// exact type it composes in production.
pub trait Resolve {
    /// Resolve `did` under `opts`, or fail with the facade's error.
    fn resolve(&self, did: &Did, opts: ResolutionOptions) -> Result<ResolutionResult, Error>;

    /// Resolve and report whether a cache answered: `Some(Hit)` or
    /// `Some(Miss)` from a caching resolver, `None` from one without a cache.
    /// The outcome travels with the result it describes, so it belongs to the
    /// call that produced it however many threads share the handle. The shell
    /// uses it for the log line.
    fn resolve_traced(
        &self,
        did: &Did,
        opts: ResolutionOptions,
    ) -> (Result<ResolutionResult, Error>, Option<CacheOutcome>) {
        (self.resolve(did, opts), None)
    }

    /// Resolve without consulting or filling any cache. The `POST` binding's
    /// path, and the only one on which `opts.sidecar_data` may be set: a
    /// sidecar-resolved result must never be served to a later request that
    /// carried no sidecar, so it never enters a cache. Default: [`Resolve::resolve`].
    fn resolve_uncached(
        &self,
        did: &Did,
        opts: ResolutionOptions,
    ) -> Result<ResolutionResult, Error> {
        self.resolve(did, opts)
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

/// Whether a resolver answered a request from its cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheOutcome {
    /// Served from memory; the upstream resolver was not called.
    Hit,
    /// The upstream resolver was called (whatever it answered).
    Miss,
    /// The cache was neither read nor written: the request was a `POST`,
    /// served through [`Resolve::resolve_uncached`]. Stamped by the handler,
    /// never returned by [`Resolve::resolve_traced`].
    Bypass,
}

/// `(did, versionId, versionTime, minConf)` — the projection of the options
/// that selects a result. `accept` is deliberately absent: representation is
/// chosen after the result exists, so one resolution serves every `Accept`.
/// `minConf` is stored as the value in force, so an absent option and an
/// explicit [`ResolutionOptions::DEFAULT_MIN_CONF`] — which the core resolves
/// identically — share one entry.
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
/// be). Cloning shares the cache — every `serve` worker sees the same entries.
/// The hit/miss outcome is returned from [`Resolve::resolve_traced`], never
/// stored on the handle, so one handle may serve any number of threads.
///
/// # Contract
///
/// The key is `(did, versionId, versionTime, minConf)` and nothing else. The
/// other [`ResolutionOptions`] fields — `sidecar_data`, `chain_tip_height`,
/// `expand_relative_urls` and `esplora_url` — are not part of it, so a caller
/// must not vary them across requests for one DID: a request carrying sidecar
/// data could otherwise be answered by an entry computed without it. Callers
/// must leave all four at their defaults; the layer below the cache fills
/// what it needs (`Client::resolve` fetches the chain tip and picks the
/// Esplora URL for the DID's network). This binding never sets any of them
/// — `parse_options` yields only the three scalars and `handle` adds
/// `accept`, which is not in the key by design — and `resolve_traced` checks
/// the contract with a `debug_assert!`, so a test shell that broke it would
/// fail loudly rather than serve a mismatched hit. (`accept` is excluded
/// because representation is chosen after the result exists: one resolution
/// serves every `Accept`.) A sidecar travels only through
/// [`Resolve::resolve_uncached`], which forwards to the inner resolver without
/// touching the map; `resolve_traced` still asserts that `sidecar_data` is
/// unset.
pub struct CachingResolver<R> {
    inner: R,
    ttl: Duration,
    capacity: NonZeroUsize,
    clock: Arc<dyn Clock>,
    entries: Arc<Mutex<HashMap<CacheKey, Entry>>>,
}

impl<R> CachingResolver<R> {
    /// Wrap `inner` with the process clock.
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
        }
    }

    /// Entries currently held, expired ones included until the next insert or
    /// lookup touches them.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// `true` when no entry is held.
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
}

impl<R: Clone> Clone for CachingResolver<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            ttl: self.ttl,
            capacity: self.capacity,
            clock: Arc::clone(&self.clock),
            entries: Arc::clone(&self.entries),
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
        self.resolve_traced(did, opts).0
    }

    fn resolve_traced(
        &self,
        did: &Did,
        opts: ResolutionOptions,
    ) -> (Result<ResolutionResult, Error>, Option<CacheOutcome>) {
        // The contract on the type: only the keyed options may vary. Anything
        // else set here would be invisible to the lookup.
        debug_assert!(
            opts.sidecar_data.is_none()
                && opts.chain_tip_height.is_none()
                && !opts.expand_relative_urls
                && opts.esplora_url.is_none(),
            "CachingResolver: an option outside the cache key was set (sidecar_data, \
             chain_tip_height, expand_relative_urls or esplora_url); the layer below \
             the cache owns those"
        );
        let key = CacheKey {
            did: did.encode().to_owned(),
            version_id: opts.version_id,
            version_time: opts.version_time,
            // The key holds the value in force; `opts` goes upstream as given.
            min_conf: opts.min_conf.or(Some(ResolutionOptions::DEFAULT_MIN_CONF)),
        };
        let now = self.clock.now();
        if let Some(result) = self.lookup(&key, now) {
            return (Ok(result), Some(CacheOutcome::Hit));
        }
        let result = match self.inner.resolve(did, opts) {
            Ok(result) => result,
            // An `Err` leaves here; nothing is inserted.
            Err(e) => return (Err(e), Some(CacheOutcome::Miss)),
        };
        // Stamped with the instant before the upstream call, so the TTL bounds
        // the age of the data (the chain tip it reflects), not of the entry.
        self.insert(key, now, result.clone());
        (Ok(result), Some(CacheOutcome::Miss))
    }

    /// Straight to the inner resolver: no key, no lookup, no insert.
    fn resolve_uncached(
        &self,
        did: &Did,
        opts: ResolutionOptions,
    ) -> Result<ResolutionResult, Error> {
        self.inner.resolve(did, opts)
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
        // given and fails with `NoDefaultEndpoint` for regtest / custom. `resolve` fetches the chain tip on every call, so every
        // response reports current confirmations; nothing is cached here —
        // the cache is [`CachingResolver`], which wraps this type in
        // production.
        Client::for_did(did, None, esplora_url, self.transport.clone())?.resolve(did, opts)
    }
}

// The FSM is built and consumed inside `Client::resolve`; nothing about the
// resolver crosses a thread except this handle, which workers clone. The
// cache's `Arc<dyn Clock>` is Send + Sync because `Clock` requires both, and
// the entry map is behind a `Mutex`; there is no other per-handle state.
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
        // Every custom network (nibble 12..=15) shares the one `custom` key.
        for nibble in 12..=15 {
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
    /// testnet4 has a hosted endpoint, so only regtest and custom remain.
    #[test]
    fn unconfigured_network_is_no_default_endpoint_before_any_io() {
        let resolver = ClientResolver::new(HashMap::new());
        for (network, name) in [
            (Network::Regtest, "regtest"),
            (Network::Custom(12), "custom"),
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
            body: Vec::new(),
        }
    }

    /// A POST asking for the full result with a JSON body.
    fn post(did: &Did, body: &[u8]) -> Request {
        Request {
            method: "POST".into(),
            path: format!("/1.0/identifiers/{}", did.encode()),
            query: None,
            headers: vec![
                (
                    "Accept".to_string(),
                    "application/did-resolution".to_string(),
                ),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body: body.to_vec(),
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
                with_min_conf(ResolutionOptions::DEFAULT_MIN_CONF.get() + 1),
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

    /// An absent `minConf` and an explicit `DEFAULT_MIN_CONF` resolve
    /// identically in the core, so they are one entry in either order; any
    /// other value is its own entry. The options go upstream as given — the
    /// normalisation is in the key only.
    #[test]
    fn min_conf_absent_and_explicit_default_are_one_entry() {
        let default = ResolutionOptions::DEFAULT_MIN_CONF;
        let clock = ManualClock::new();
        let seen: Arc<Mutex<Vec<Option<NonZeroU32>>>> = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let (inner, calls) = counting(move |did, opts| {
            record.lock().expect("seen lock").push(opts.min_conf);
            Ok(ok_result(did, false))
        });
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        let (_, outcome) = resolver.resolve_traced(&did, ResolutionOptions::default());
        assert_eq!(outcome, Some(CacheOutcome::Miss));
        let (_, outcome) = resolver.resolve_traced(&did, with_min_conf(default.get()));
        assert_eq!(
            outcome,
            Some(CacheOutcome::Hit),
            "explicit default after absent"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolver.len(), 1);

        let (_, outcome) = resolver.resolve_traced(&did, with_min_conf(default.get() + 1));
        assert_eq!(
            outcome,
            Some(CacheOutcome::Miss),
            "another value is its own entry"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resolver.len(), 2);

        // The reverse order on a fresh DID: explicit default populates, absent hits.
        let other = did_on(Network::Mainnet);
        let (_, outcome) = resolver.resolve_traced(&other, with_min_conf(default.get()));
        assert_eq!(outcome, Some(CacheOutcome::Miss));
        let (_, outcome) = resolver.resolve_traced(&other, ResolutionOptions::default());
        assert_eq!(
            outcome,
            Some(CacheOutcome::Hit),
            "absent after explicit default"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(resolver.len(), 3);

        // Upstream received the options as the caller gave them.
        assert_eq!(
            *seen.lock().expect("seen lock"),
            vec![
                None,
                Some(NonZeroU32::new(default.get() + 1).expect("non-zero")),
                Some(default),
            ]
        );
    }

    /// The contract on the type, checked in debug builds: an option the key
    /// does not cover trips the assertion before anything is looked up or
    /// resolved, for each of the four; the binding's own request path — the
    /// three query options plus `Accept` — sets none of them, so a served
    /// request passes.
    #[cfg(debug_assertions)]
    #[test]
    fn options_outside_the_key_fail_the_debug_assertion() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        use did_btcr2::document::SidecarData;

        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        let offending = [
            (
                "sidecar_data",
                ResolutionOptions {
                    sidecar_data: Some(SidecarData::default()),
                    ..Default::default()
                },
            ),
            (
                "chain_tip_height",
                ResolutionOptions {
                    chain_tip_height: Some(1),
                    ..Default::default()
                },
            ),
            (
                "expand_relative_urls",
                ResolutionOptions {
                    expand_relative_urls: true,
                    ..Default::default()
                },
            ),
            (
                "esplora_url",
                ResolutionOptions {
                    esplora_url: Some("http://h:1".to_string()),
                    ..Default::default()
                },
            ),
        ];
        for (name, opts) in offending {
            let tripped = catch_unwind(AssertUnwindSafe(|| resolver.resolve_traced(&did, opts)));
            assert!(tripped.is_err(), "{name} must trip the assertion");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the upstream was never reached"
        );
        assert!(resolver.is_empty(), "nothing was inserted");

        // The binding's own path passes: `Accept` and every query option.
        let mut request = get(&did, Some("application/did-resolution"));
        request.query = Some("versionId=1&minConf=3&noCache=false".to_string());
        let crate::Handled {
            response,
            cache: outcome,
            ..
        } = crate::handle_traced(&request, &resolver);
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(outcome, Some(CacheOutcome::Miss));
        let mut request = get(&did, None);
        request.query = Some("versionTime=2026-01-01T00:00:00Z".to_string());
        let crate::Handled {
            response,
            cache: outcome,
            ..
        } = crate::handle_traced(&request, &resolver);
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(outcome, Some(CacheOutcome::Miss));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// The uncached path forwards every call to the inner resolver and
    /// leaves the map alone: a sidecar goes through without tripping the
    /// contract assertion, nothing is looked up, nothing is stored, and a
    /// later traced call still misses. The trait default forwards to
    /// `resolve`.
    #[test]
    fn resolve_uncached_forwards_to_the_inner_resolver_and_stores_nothing() {
        use did_btcr2::document::SidecarData;

        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);
        let with_sidecar = || ResolutionOptions {
            sidecar_data: Some(SidecarData::default()),
            ..Default::default()
        };

        resolver
            .resolve_uncached(&did, with_sidecar())
            .expect("resolves through the inner resolver");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(resolver.is_empty(), "nothing was inserted");

        resolver
            .resolve_uncached(&did, with_sidecar())
            .expect("resolves again");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "nothing was served from memory"
        );
        assert!(resolver.is_empty());

        let (_, outcome) = resolver.resolve_traced(&did, ResolutionOptions::default());
        assert_eq!(
            outcome,
            Some(CacheOutcome::Miss),
            "the uncached calls filled nothing"
        );
        let (_, outcome) = resolver.resolve_traced(&did, ResolutionOptions::default());
        assert_eq!(outcome, Some(CacheOutcome::Hit));
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // The trait default: a resolver without a cache forwards to `resolve`.
        let plain = Scripted(Arc::new(|did, _| Ok(ok_result(did, false))));
        assert!(plain.resolve_uncached(&did, with_sidecar()).is_ok());
    }

    /// A POST never reads from or writes to the cache, in either direction,
    /// through the handler over a real `CachingResolver`. Not gated on
    /// `debug_assertions`: the test profile has them on, and the point is
    /// that the cache's sidecar assertion is never reached by a POST — the
    /// handler takes the uncached path, not a path around the assertion.
    /// Writes: after a POST the map is empty. Reads: a POST after a GET
    /// filled the map still reaches upstream, even with a body whose options
    /// key the cached entry exactly. A rejected POST reports no outcome.
    #[test]
    fn post_bypasses_the_cache_in_both_directions() {
        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);
        let with_sidecar = br#"{"sidecar": {"updates": []}}"#;

        let crate::Handled {
            response,
            cache: outcome,
            sidecar_updates,
        } = crate::handle_traced(&post(&did, with_sidecar), &resolver);
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(outcome, Some(CacheOutcome::Bypass));
        assert_eq!(sidecar_updates, Some(0));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(resolver.is_empty(), "the POST wrote nothing");

        let crate::Handled {
            response,
            cache: outcome,
            sidecar_updates,
        } = crate::handle_traced(&get(&did, Some("application/did-resolution")), &resolver);
        assert_eq!(response.status, 200);
        assert_eq!(outcome, Some(CacheOutcome::Miss), "the POST cached nothing");
        assert_eq!(sidecar_updates, None);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resolver.len(), 1, "the GET cached its result");

        let crate::Handled {
            response,
            cache: outcome,
            sidecar_updates,
        } = crate::handle_traced(&post(&did, b""), &resolver);
        assert_eq!(response.status, 200);
        assert_eq!(outcome, Some(CacheOutcome::Bypass));
        assert_eq!(sidecar_updates, None);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "the fresh GET entry was not served to the POST"
        );
        assert_eq!(resolver.len(), 1, "the empty POST wrote nothing either");

        let crate::Handled {
            response,
            cache: outcome,
            ..
        } = crate::handle_traced(&get(&did, Some("application/did-resolution")), &resolver);
        assert_eq!(response.status, 200);
        assert_eq!(outcome, Some(CacheOutcome::Hit));
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // The strongest form of "never read": the GET entry is keyed on
        // `versionId: 1`, and a POST naming exactly that still goes upstream.
        let crate::Handled {
            response,
            cache: outcome,
            sidecar_updates,
        } = crate::handle_traced(
            &post(&did, br#"{"sidecar": {"updates": []}, "versionId": 1}"#),
            &resolver,
        );
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(outcome, Some(CacheOutcome::Bypass));
        assert_eq!(sidecar_updates, Some(0));
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(resolver.len(), 1);

        let mut rejected = post(&did, b"{}");
        rejected.query = Some("versionId=1".to_string());
        let crate::Handled {
            response,
            cache: outcome,
            sidecar_updates,
        } = crate::handle_traced(&rejected, &resolver);
        assert_eq!(response.status, 400);
        assert_eq!(outcome, None, "the resolver was not reached");
        assert_eq!(sidecar_updates, None);
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(resolver.len(), 1);
    }

    /// The entry's age is counted from the instant the lookup missed, not
    /// from the instant the upstream answered: with a resolution that takes
    /// `latency`, the entry expires at `miss + TTL`, so a call at
    /// `miss + TTL - 1 s` is still a hit and a call at `miss + TTL` is not.
    /// Stamping on completion would keep it until `miss + latency + TTL`.
    #[test]
    fn entry_age_is_measured_from_before_the_upstream_call() {
        let latency = Duration::from_secs(10);
        let clock = ManualClock::new();
        let slow_clock = Arc::clone(&clock);
        let (inner, calls) = counting(move |did, _| {
            slow_clock.advance(latency);
            Ok(ok_result(did, false))
        });
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        let (_, outcome) = resolver.resolve_traced(&did, ResolutionOptions::default());
        assert_eq!(outcome, Some(CacheOutcome::Miss));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The clock now reads miss + latency.

        clock.advance(CACHE_TTL - latency - Duration::from_secs(1));
        let (_, outcome) = resolver.resolve_traced(&did, ResolutionOptions::default());
        assert_eq!(
            outcome,
            Some(CacheOutcome::Hit),
            "at miss + TTL - 1 s the entry is live"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(1));
        let (_, outcome) = resolver.resolve_traced(&did, ResolutionOptions::default());
        assert_eq!(
            outcome,
            Some(CacheOutcome::Miss),
            "at miss + TTL the entry has expired, whatever the latency was"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
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

    /// Each call carries its own outcome: the first is a miss, the second a
    /// hit, an error is a miss (the upstream was called), a call past the TTL
    /// is a miss again, and a clone sharing the entries reports a hit for what
    /// the original populated. Nothing is read back from the handle.
    #[test]
    fn resolve_traced_returns_the_outcome_of_that_call() {
        let clock = ManualClock::new();
        let attempt = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::clone(&attempt);
        let (inner, calls) = counting(move |did, _| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 1 {
                Err(Error::NoDefaultEndpoint("regtest"))
            } else {
                Ok(ok_result(did, false))
            }
        });
        let resolver = cache(inner, &clock);
        let (a, b) = (did_on(Network::Mainnet), did_on(Network::Mainnet));

        let (first, outcome) = resolver.resolve_traced(&a, ResolutionOptions::default());
        assert!(first.is_ok());
        assert_eq!(outcome, Some(CacheOutcome::Miss));

        let (second, outcome) = resolver.resolve_traced(&a, ResolutionOptions::default());
        assert!(second.is_ok());
        assert_eq!(outcome, Some(CacheOutcome::Hit));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // The second upstream call fails: a miss, and the error comes back
        // with it.
        let (failed, outcome) = resolver.resolve_traced(&b, ResolutionOptions::default());
        assert!(
            matches!(failed, Err(Error::NoDefaultEndpoint(_))),
            "{failed:?}"
        );
        assert_eq!(outcome, Some(CacheOutcome::Miss));
        assert_eq!(resolver.len(), 1, "the error was not stored");

        let other_handle = resolver.clone();
        let (_, outcome) = other_handle.resolve_traced(&a, ResolutionOptions::default());
        assert_eq!(
            outcome,
            Some(CacheOutcome::Hit),
            "a clone shares the entries"
        );

        clock.advance(CACHE_TTL);
        let (_, outcome) = resolver.resolve_traced(&a, ResolutionOptions::default());
        assert_eq!(outcome, Some(CacheOutcome::Miss), "expired: upstream again");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// One handle shared by several threads: every thread gets the outcome of
    /// its own call, not a neighbour's. Each thread misses on its own DID and
    /// then hits it; with a shared slot, a thread could read another's miss as
    /// its hit or find the slot empty.
    #[test]
    fn resolve_traced_outcomes_are_attributed_per_call_across_threads() {
        let clock = ManualClock::new();
        let (inner, calls) = ok_counting();
        let resolver = cache(inner, &clock);
        let dids: Vec<Did> = (0..8).map(|_| did_on(Network::Mainnet)).collect();

        std::thread::scope(|scope| {
            for did in &dids {
                scope.spawn(|| {
                    let (first, outcome) =
                        resolver.resolve_traced(did, ResolutionOptions::default());
                    assert!(first.is_ok());
                    assert_eq!(outcome, Some(CacheOutcome::Miss), "{}", did.encode());
                    let (second, outcome) =
                        resolver.resolve_traced(did, ResolutionOptions::default());
                    assert!(second.is_ok());
                    assert_eq!(outcome, Some(CacheOutcome::Hit), "{}", did.encode());
                });
            }
        });

        assert_eq!(calls.load(Ordering::SeqCst), dids.len());
        assert_eq!(resolver.len(), dids.len());
    }

    /// A resolver without a cache reports no outcome, and `handle` attributes
    /// the outcome to the request it served: a rejected request never reaches
    /// the resolver and carries `None`; the two that do carry their own. A
    /// POST carries `Bypass` whatever resolver sits behind the handler — the
    /// label is the handler's, not the cache's.
    #[test]
    fn resolvers_without_a_cache_report_none_and_handle_carries_the_outcome() {
        // `Client::for_did` fails before any I/O for a network with no hosted
        // endpoint, so the bare production resolver is exercised offline.
        let bare = ClientResolver::new(HashMap::new());
        let (result, outcome) =
            bare.resolve_traced(&did_on(Network::Regtest), ResolutionOptions::default());
        assert!(matches!(result, Err(Error::NoDefaultEndpoint(_))));
        assert_eq!(outcome, None);
        let plain = Scripted(Arc::new(|did, _| Ok(ok_result(did, false))));
        let (result, outcome) =
            plain.resolve_traced(&did_on(Network::Mainnet), ResolutionOptions::default());
        assert!(result.is_ok());
        assert_eq!(outcome, None);
        let crate::Handled {
            response,
            cache: outcome,
            ..
        } = crate::handle_traced(&post(&did_on(Network::Mainnet), b"{}"), &plain);
        assert_eq!(response.status, 200);
        assert_eq!(
            outcome,
            Some(CacheOutcome::Bypass),
            "the handler stamps the bypass, not the resolver"
        );

        let clock = ManualClock::new();
        let (inner, _) = ok_counting();
        let resolver = cache(inner, &clock);
        let did = did_on(Network::Mainnet);

        let mut rejected = get(&did, Some("application/did-resolution"));
        rejected.query = Some("versionId=abc".to_string());
        let crate::Handled {
            response,
            cache: outcome,
            ..
        } = crate::handle_traced(&rejected, &resolver);
        assert_eq!(response.status, 400);
        assert_eq!(outcome, None, "the resolver was not reached");

        let crate::Handled {
            response,
            cache: outcome,
            ..
        } = crate::handle_traced(&get(&did, Some("application/did-resolution")), &resolver);
        assert_eq!(response.status, 200);
        assert_eq!(outcome, Some(CacheOutcome::Miss));
        let crate::Handled {
            response,
            cache: outcome,
            ..
        } = crate::handle_traced(&get(&did, None), &resolver);
        assert_eq!(response.status, 200);
        assert_eq!(outcome, Some(CacheOutcome::Hit));
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
