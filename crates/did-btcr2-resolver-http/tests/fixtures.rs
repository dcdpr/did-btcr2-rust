//! The guard for the two mainnet fixtures the W3C suite is pointed at.
//!
//! `w3c/localConfig.cjs` names the deployed host and two identifiers; `FIXTURES.md`
//! is their provenance record. Neither file is compiled, so a typo in either would
//! surface only when the weekly interop report runs — as a red row with no local
//! reproduction. This guard pins what the two files say at build time:
//!
//! - the config names exactly two `did:btcr2:` identifiers, both of which parse;
//! - the `valid` one is key-based (`k1`) and the `notFound` one external (`x1`);
//! - both are mainnet, version 1 (the layout byte is `0x00` under either nibble
//!   ordering, so no identifier-layout change can reach them);
//! - `notFound` is a bare string, because the pinned suite reads it as a scalar
//!   and would request `/1.0/identifiers/[object Object]` for the README's array;
//! - the `endpoint` has the resolver-path shape (`https://…/1.0/identifiers`, no
//!   trailing slash) — the shape, not a literal host, so a host move is a config
//!   edit with nothing to change here. The config is compiled in (`include_str!`),
//!   so the test binary does carry whatever host the config names;
//! - the record names both identifiers verbatim, carries the two custody
//!   statements and the exact `NOT_FOUND` type URI, and holds no 64-hex token
//!   above the `## 7.` heading; below it (the funded mutinynet demo DIDs) a
//!   64-hex token is a transaction id and must sit on a line that says `txid`.
//!
//! The token extractors have their own negative cases below, so the guard cannot
//! pass by extracting nothing.

use did_btcr2::identifier::{Did, DidVersion, IdType, Network};

const CONFIG: &str = include_str!("../w3c/localConfig.cjs");
const RECORD: &str = include_str!("../FIXTURES.md");
// No host constant: the guard asserts the endpoint's SHAPE, not a literal host, so a host move
// is a config edit with nothing to change here. The host is still in the binary — `CONFIG`
// above embeds the whole file — so when the droplet is destroyed, the config is what to update
// (`DEPLOY.md`, "Cleanup").

/// The heading that separates the unfunded, secret-free mainnet fixtures from the funded
/// mutinynet demo DIDs whose records legitimately carry transaction ids.
const DEMO_HEADING: &str = "\n## 7. mutinynet demo DIDs";

/// The first 64-hex token in `text`, labelled or not.
fn any_hex64(text: &str) -> Option<&str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .find(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The first 64-hex token in `text` that does not sit on a line naming `txid`.
fn unlabelled_hex64(text: &str) -> Option<&str> {
    text.lines()
        .filter(|line| !line.contains("txid"))
        .find_map(any_hex64)
}

/// Every token that starts with `did:btcr2:` in `source`, split on the characters
/// that cannot appear in a DID: `"`, `'`, `,`, whitespace.
fn btcr2_dids(source: &str) -> Vec<&str> {
    source
        .split(|c: char| c == '"' || c == '\'' || c == ',' || c.is_whitespace())
        .filter(|t| t.starts_with("did:btcr2:"))
        .collect()
}

/// The text of `source` after the first occurrence of `key`, or a panic naming it.
fn after<'a>(source: &'a str, key: &str) -> &'a str {
    let at = source
        .find(key)
        .unwrap_or_else(|| panic!("`{key}` is present"));
    &source[at + key.len()..]
}

/// The string value of the first `"endpoint":` entry in `source` (the text between the
/// opening and closing double quotes after the key), or a panic if it is not a string.
fn endpoint(source: &str) -> &str {
    let rest = after(source, "\"endpoint\":").trim_start();
    let rest = rest.strip_prefix('"').expect("endpoint is a string");
    &rest[..rest.find('"').expect("endpoint string closes")]
}

/// The two config tokens as `(k1, x1)`, each parsed and round-tripped.
fn fixtures() -> ((&'static str, Did), (&'static str, Did)) {
    let tokens = btcr2_dids(CONFIG);
    assert_eq!(
        tokens.len(),
        2,
        "the config names exactly two DIDs: {tokens:?}"
    );
    let parsed: Vec<(&str, Did)> = tokens
        .iter()
        .map(|t| {
            let did: Did = t.parse().unwrap_or_else(|e| panic!("`{t}` parses: {e}"));
            assert_eq!(did.encode(), *t, "`{t}` round-trips through Did");
            (*t, did)
        })
        .collect();
    let k1 = parsed
        .iter()
        .find(|(_, d)| matches!(d.components().id_type(), IdType::Key(_)))
        .cloned()
        .expect("one key-based DID");
    let x1 = parsed
        .iter()
        .find(|(_, d)| matches!(d.components().id_type(), IdType::External(_)))
        .cloned()
        .expect("one external DID");
    (k1, x1)
}

#[test]
fn config_names_exactly_two_dids_one_k1_one_x1() {
    let tokens = btcr2_dids(CONFIG);
    assert_eq!(
        tokens.len(),
        2,
        "exactly two DIDs in the config: {tokens:?}"
    );
    let parsed: Vec<Did> = tokens
        .iter()
        .map(|t| {
            t.parse::<Did>()
                .unwrap_or_else(|e| panic!("`{t}` parses: {e}"))
        })
        .collect();
    let keyed = parsed
        .iter()
        .filter(|d| matches!(d.components().id_type(), IdType::Key(_)))
        .count();
    let external = parsed
        .iter()
        .filter(|d| matches!(d.components().id_type(), IdType::External(_)))
        .count();
    assert_eq!(keyed, 1, "exactly one k1");
    assert_eq!(external, 1, "exactly one x1");
    for (token, did) in tokens.iter().zip(&parsed) {
        assert_eq!(did.encode(), *token, "`{token}` round-trips");
    }
}

#[test]
fn both_fixtures_are_mainnet_version_one() {
    let ((k1_token, k1), (x1_token, x1)) = fixtures();
    for (token, did) in [(k1_token, &k1), (x1_token, &x1)] {
        let c = did.components();
        assert_eq!(c.version(), DidVersion::One, "`{token}` is version 1");
        assert_eq!(c.network(), Network::Mainnet, "`{token}` is mainnet");
    }
    assert!(k1.public_key().is_some(), "the k1 carries its genesis key");
    assert!(x1.public_key().is_none(), "the x1 carries no key");
    assert_eq!(k1.components().id_type().hrp(), "k");
    assert_eq!(x1.components().id_type().hrp(), "x");
}

#[test]
fn valid_is_the_k1_and_not_found_is_the_x1() {
    let ((k1_token, _), (x1_token, _)) = fixtures();
    let valid_at = CONFIG.find("\"valid\"").expect("`valid` key");
    let not_found_at = CONFIG.find("\"notFound\"").expect("`notFound` key");
    let k1_at = CONFIG.find(k1_token).expect("the k1 token");
    let x1_at = CONFIG.find(x1_token).expect("the x1 token");
    assert!(valid_at < not_found_at, "`valid` precedes `notFound`");
    assert!(
        valid_at < k1_at && k1_at < not_found_at,
        "the k1 lies between `valid` and `notFound`"
    );
    assert!(not_found_at < x1_at, "the x1 lies after `notFound`");
}

#[test]
fn not_found_is_a_bare_string_not_an_array() {
    let (_, (x1_token, _)) = fixtures();
    let rest = after(CONFIG, "\"notFound\":").trim_start();
    assert!(
        rest.starts_with('"'),
        "`notFound` is a string, not an array or object: {:?}",
        &rest[..rest.len().min(20)]
    );
    let next = btcr2_dids(rest)
        .first()
        .copied()
        .expect("a DID after `notFound`");
    assert_eq!(next, x1_token, "the token right after `notFound` is the x1");
    // Between `"notFound"` and the closing brace of `supportedDids` there is no `[`.
    let supported = after(CONFIG, "\"notFound\"");
    let close = supported.find('}').expect("`supportedDids` closes");
    assert!(
        !supported[..close].contains('['),
        "no array between `notFound` and the end of `supportedDids`"
    );
}

#[test]
fn endpoint_is_the_resolver_path_without_a_trailing_slash() {
    let e = endpoint(CONFIG);
    assert!(e.starts_with("https://"), "endpoint is https: {e}");
    assert!(
        e.ends_with("/1.0/identifiers"),
        "endpoint is the resolver path: {e}"
    );
    assert!(!e.ends_with('/'), "no trailing slash: {e}");
    assert!(
        e.len() > "https:///1.0/identifiers".len(),
        "there is a host between the scheme and the path: {e}"
    );
    assert!(
        !CONFIG.contains("identifiers/\""),
        "no endpoint string ends in a slash"
    );
    assert!(CONFIG.contains("\"tags\": [\"did-resolution\"]"));
    for absent in ["deactivated", "derefUrls", "serviceDerefUrls"] {
        assert!(
            !CONFIG.contains(absent),
            "`{absent}` is left out so its rows are not generated"
        );
    }
}

#[test]
fn record_names_both_dids_verbatim() {
    let ((k1_token, _), (x1_token, _)) = fixtures();
    for token in [k1_token, x1_token] {
        let count = RECORD.matches(token).count();
        assert!(
            count >= 3,
            "`{token}` appears in the record {count} times, want >= 3"
        );
    }
    for needle in [
        "https://www.w3.org/ns/did#NOT_FOUND",
        "Nobody holds this secret",
        "Nobody holds the genesis document",
    ] {
        assert!(RECORD.contains(needle), "the record contains `{needle}`");
    }
    let (above, below) = RECORD
        .split_once(DEMO_HEADING)
        .expect("the demo heading is present");
    assert_eq!(
        any_hex64(above),
        None,
        "the mainnet part of the record holds no 64-hex token (a secret)"
    );
    assert_eq!(
        unlabelled_hex64(below),
        None,
        "a 64-hex token in the demo section must be a labelled txid"
    );
}

#[test]
fn extractor_negative_cases() {
    let mixed = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK 'did:btcr2:k1abc',\"did:btcr2:x1def\"";
    assert_eq!(
        btcr2_dids(mixed),
        vec!["did:btcr2:k1abc", "did:btcr2:x1def"]
    );
    assert!(btcr2_dids("").is_empty());

    // The prefix alone is a token the extractor returns; it is the parse step that guards.
    let bare = btcr2_dids("did:btcr2: x");
    assert_eq!(bare, vec!["did:btcr2:"]);
    assert!(
        bare[0].parse::<Did>().is_err(),
        "the bare prefix is not a DID"
    );

    assert_eq!(
        endpoint("x \"endpoint\": \"https://h/1.0/identifiers\", y"),
        "https://h/1.0/identifiers"
    );

    // The two hex extractors find tokens, so the record checks cannot pass by
    // scanning nothing: 64 hex digits are found, 63 are not, and a label of
    // `txid` on the same line is the only thing that excuses one.
    let a64 = "a".repeat(64);
    let z64 = "0".repeat(64);
    assert_eq!(any_hex64(&z64), Some(z64.as_str()));
    assert_eq!(
        any_hex64(&format!("a {}", &a64[..63])),
        None,
        "63 hex is not a token"
    );
    assert_eq!(
        any_hex64(&format!("txid: {a64}")),
        Some(a64.as_str()),
        "any_hex64 ignores labels"
    );
    assert_eq!(unlabelled_hex64(&format!("txid: {a64}")), None);
    assert_eq!(
        unlabelled_hex64(&format!("secret {a64}")),
        Some(a64.as_str())
    );
    assert_eq!(
        unlabelled_hex64(&format!("funding txid {a64}\nkey {z64}")),
        Some(z64.as_str()),
        "the label excuses its own line only"
    );
    assert!(
        RECORD.contains(DEMO_HEADING),
        "the record has the demo heading"
    );
    assert!(
        RECORD.matches(DEMO_HEADING).count() == 1,
        "the demo heading occurs once, so the split is unambiguous"
    );
}
