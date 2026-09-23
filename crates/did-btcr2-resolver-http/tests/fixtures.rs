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
//! - `notFound` is the README's array of `{did, resolutionOptions}` objects, the
//!   shape the pinned suite iterates; the guard holds it to one entry, carrying
//!   the x1 under a `did` key, so a dropped key or a swapped identifier fails here;
//! - the `endpoint` has the resolver-path shape (`https://…/1.0/identifiers`, no
//!   trailing slash) — the shape, not a literal host, so a host move is a config
//!   edit with nothing to change here. The config is compiled in (`include_str!`),
//!   so the test binary does carry whatever host the config names;
//! - the record names both identifiers verbatim, carries the two custody
//!   statements and the exact `NOT_FOUND` type URI, and holds no 64-hex token
//!   above the `## 7.` heading; below it (the funded mutinynet demo DIDs) a
//!   64-hex token is a transaction id and must sit on a line that says `txid`;
//! - the demo section records exactly two DIDs, both mutinynet / version 1 / `k1`,
//!   under an `updated` and a `deactivated` subsection with their custody
//!   statements, with at least six labelled txids and no txid bullet that
//!   quotes anything but a 64-hex token;
//! - the committed sidecar `demo/updated-v2.sidecar.json` parses as the core's
//!   `SidecarData`, holds one update, and names the updated DID;
//! - the minted fixture `fixtures/chain/minted/clean-rotating-beacons.json` holds
//!   the DID the `deactivated` record names, on the network, at the tip, with the
//!   signal txids and heights and the end state (`versionId "4"`, deactivated)
//!   the record describes, and the `chain-capture` RUNBOOK's "The minted DIDs"
//!   entry names the same DID. The fixture is re-minted under a fresh key after
//!   every mutinynet reset, and the regtest recipe writes to the same path, so
//!   without this the record would keep naming a DID the file no longer holds
//!   while every replay test — which reads the DID from the file — stayed green.
//!
//! The token extractors have their own negative cases below, so the guard cannot
//! pass by extracting nothing.

use did_btcr2::document::SidecarData;
use did_btcr2::identifier::{Did, DidVersion, IdType, Network};

const CONFIG: &str = include_str!("../w3c/localConfig.cjs");
const RECORD: &str = include_str!("../FIXTURES.md");
const DEMO_SIDECAR: &str = include_str!("../demo/updated-v2.sidecar.json");
const CLEAN_FIXTURE: &str =
    include_str!("../../../fixtures/chain/minted/clean-rotating-beacons.json");
const CAPTURE_RUNBOOK: &str = include_str!("../../chain-capture/RUNBOOK.md");
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
/// that cannot appear in a DID: `"`, `'`, `` ` ``, `,`, whitespace.
fn btcr2_dids(source: &str) -> Vec<&str> {
    source
        .split(|c: char| c == '"' || c == '\'' || c == '`' || c == ',' || c.is_whitespace())
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

/// A drift guard on the `notFound` entry's identifier and shape, not a JSON-syntax
/// check: the suite iterates the entry and destructures `{did, resolutionOptions}`,
/// so dropping the `did` key, adding a second entry or swapping in the k1 would each
/// change which DID the 404 row requests while leaving the file valid JavaScript.
#[test]
fn not_found_is_the_readme_array_of_did_objects() {
    let (_, (x1_token, _)) = fixtures();
    let rest = after(CONFIG, "\"notFound\":").trim_start();
    assert!(
        rest.starts_with('['),
        "`notFound` is the README's array, not a bare string: {:?}",
        &rest[..rest.len().min(20)]
    );
    let entries = &rest[1..rest.find(']').expect("the `notFound` array closes")];

    let dids = btcr2_dids(entries);
    assert_eq!(
        dids,
        vec![x1_token],
        "the `notFound` array holds exactly one DID, the x1"
    );
    assert_eq!(
        entries.matches("\"did\":").count(),
        1,
        "the `notFound` array holds exactly one entry"
    );

    let value = after(entries, "\"did\":").trim_start();
    let value = value
        .strip_prefix('"')
        .expect("the entry's `did` value is a string");
    assert!(
        value.starts_with(x1_token) && value[x1_token.len()..].starts_with('"'),
        "the x1 is the entry's `did` value, not some other field: {:?}",
        &value[..value.len().min(80)]
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

/// The demo section of the record (everything below `DEMO_HEADING`).
fn demo_section() -> &'static str {
    RECORD
        .split_once(DEMO_HEADING)
        .expect("the demo heading is present")
        .1
}

/// The two demo DIDs, sorted and deduplicated, each parsed and round-tripped.
fn demo_dids() -> Vec<(&'static str, Did)> {
    let mut dids = btcr2_dids(demo_section());
    dids.sort_unstable();
    dids.dedup();
    dids.into_iter()
        .map(|t| {
            let did: Did = t.parse().unwrap_or_else(|e| panic!("`{t}` parses: {e}"));
            assert_eq!(did.encode(), t, "`{t}` round-trips through Did");
            (t, did)
        })
        .collect()
}

/// The DID named on the heading line that starts with `heading`, in the demo section.
fn heading_did(heading: &str) -> &'static str {
    let rest = after(demo_section(), heading);
    let line = rest.lines().next().expect("the heading has a line");
    btcr2_dids(line)
        .first()
        .copied()
        .unwrap_or_else(|| panic!("the `{heading}` heading names a DID: {line:?}"))
}

/// The DID named in the `### 7.1 updated` heading.
fn updated_did() -> &'static str {
    heading_did("### 7.1 updated")
}

/// The DID named in the `### 7.2 deactivated` heading.
fn deactivated_did() -> &'static str {
    heading_did("### 7.2 deactivated")
}

/// The `### 7.2 deactivated` record: from its heading to the next `### ` heading or the
/// end of the file.
fn deactivated_record() -> &'static str {
    let rest = after(demo_section(), "### 7.2 deactivated");
    match rest.find("\n### ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

#[test]
fn demo_section_records_two_mutinynet_k1_dids_with_labelled_txids() {
    let below = demo_section();
    let dids = demo_dids();
    assert_eq!(
        dids.len(),
        2,
        "the demo section names exactly two DIDs: {:?}",
        dids.iter().map(|(t, _)| *t).collect::<Vec<_>>()
    );
    for (token, did) in &dids {
        let c = did.components();
        assert_eq!(c.network(), Network::Mutinynet, "`{token}` is mutinynet");
        assert_eq!(c.version(), DidVersion::One, "`{token}` is version 1");
        assert!(
            matches!(c.id_type(), IdType::Key(_)),
            "`{token}` is key-based"
        );
        assert!(did.public_key().is_some(), "`{token}` carries its key");
    }
    let txid_lines: Vec<&str> = below.lines().filter(|l| l.contains("txid")).collect();
    let labelled = txid_lines.iter().filter(|l| any_hex64(l).is_some()).count();
    assert!(
        labelled >= 6,
        "at least six txid lines carry a 64-hex token (one funding + one update for the updated \
         DID, three funding + two updates + one deactivate for the deactivated one), got {labelled}"
    );
    // A bullet that labels a txid and quotes a value (backticks) must quote a real one; the
    // §7 intro and a bullet that only introduces a list may say `txid` without a token.
    for line in txid_lines
        .iter()
        .filter(|l| l.trim_start().starts_with("- ") && l.contains('`'))
    {
        assert!(
            any_hex64(line).is_some(),
            "a txid bullet that quotes a value quotes a 64-hex token: {line:?}"
        );
    }
    for needle in [
        "### 7.1 updated",
        "### 7.2 deactivated",
        "The secret is kept",
        "The key is a throwaway",
    ] {
        assert!(
            below.contains(needle),
            "the demo section contains `{needle}`"
        );
    }
    let updated_at = below.find("### 7.1 updated").expect("7.1");
    let deactivated_at = below.find("### 7.2 deactivated").expect("7.2");
    assert!(updated_at < deactivated_at, "7.1 precedes 7.2");
}

#[test]
fn demo_sidecar_parses_and_names_the_updated_did() {
    let parsed = serde_json::from_str::<SidecarData>(DEMO_SIDECAR);
    assert!(
        parsed.is_ok(),
        "the demo sidecar parses: {:?}",
        parsed.err()
    );
    let raw: serde_json::Value =
        serde_json::from_str(DEMO_SIDECAR).expect("the demo sidecar is JSON");
    assert_eq!(
        raw["updates"].as_array().map(Vec::len),
        Some(1),
        "the demo sidecar holds exactly one update"
    );
    let updated = updated_did();
    let did: Did = updated
        .parse()
        .unwrap_or_else(|e| panic!("`{updated}` parses: {e}"));
    assert_eq!(did.components().network(), Network::Mutinynet);
    assert!(
        DEMO_SIDECAR.contains(updated),
        "the demo sidecar names the updated DID `{updated}`"
    );
    assert!(
        demo_dids().iter().any(|(t, _)| *t == updated),
        "the updated DID is one of the demo section's DIDs"
    );
    assert_eq!(
        any_hex64(DEMO_SIDECAR),
        None,
        "the sidecar holds no 64-hex token (a secret)"
    );
}

/// The minted fixture is the DID the `deactivated` record describes, and the record
/// describes the fixture: the same DID, on mutinynet, captured at the tip the record
/// states, every signal's txid and block height on a labelled line of the record, three
/// sidecar updates, and the end state the `DEPLOY.md` §10 row promises — `versionId "4"`,
/// deactivated. The RUNBOOK's "The minted DIDs" entry names the same DID. A re-mint (or
/// the regtest recipe run as written, which writes to the same path) that is not followed
/// by a new record fails here, not in front of the operator.
#[test]
fn minted_fixture_is_the_deactivated_demo_did() {
    let fixture: serde_json::Value =
        serde_json::from_str(CLEAN_FIXTURE).expect("the minted fixture is JSON");
    let deactivated = deactivated_did();
    let did: Did = deactivated
        .parse()
        .unwrap_or_else(|e| panic!("`{deactivated}` parses: {e}"));
    assert_eq!(did.components().network(), Network::Mutinynet);
    assert_ne!(deactivated, updated_did(), "the two demo DIDs differ");
    assert!(
        demo_dids().iter().any(|(t, _)| *t == deactivated),
        "the deactivated DID is one of the demo section's DIDs"
    );

    assert_eq!(
        fixture["did"], deactivated,
        "the fixture holds the DID the 7.2 record names"
    );
    assert_eq!(fixture["network"], "mutinynet", "the record says mutinynet");
    let metadata = &fixture["expected"]["didDocumentMetadata"];
    assert_eq!(
        metadata["versionId"], "4",
        "the record says versionId \"4\""
    );
    assert_eq!(metadata["deactivated"], true, "the record says deactivated");
    assert_eq!(
        fixture["sidecar"]["updates"].as_array().map(Vec::len),
        Some(3),
        "the record says three sidecar updates"
    );

    let record = deactivated_record();
    let tip = fixture["tip_height"]
        .as_u64()
        .expect("the fixture records its tip height");
    assert!(
        record.contains(&format!("tip {tip}")),
        "the record states the capture tip {tip}"
    );
    let signals = fixture["signals"]
        .as_array()
        .expect("the fixture records its signals");
    assert_eq!(signals.len(), 3, "one signal per update");
    for signal in signals {
        let txid = signal["txid"].as_str().expect("a signal has a txid");
        let height = signal["block_height"]
            .as_u64()
            .expect("a signal has a block height");
        let line = record
            .lines()
            .find(|l| l.contains(txid))
            .unwrap_or_else(|| panic!("the record names signal txid {txid}"));
        assert!(
            line.contains("txid"),
            "the signal txid sits on a line that labels it: {line:?}"
        );
        assert!(
            record.contains(&format!("block {height}")),
            "the record states block {height} for txid {txid}"
        );
    }

    // The RUNBOOK's entry for the scenario names the DID the fixture holds; the first
    // DID after the scenario's label is the current mint (the replaced one follows).
    let entry = after(
        after(CAPTURE_RUNBOOK, "### The minted DIDs"),
        "`clean-rotating-beacons`:",
    );
    let runbook_did = btcr2_dids(entry)
        .first()
        .copied()
        .expect("the RUNBOOK entry for clean-rotating-beacons names a DID");
    assert_eq!(
        runbook_did, deactivated,
        "the RUNBOOK's minted-DIDs entry names the fixture's DID"
    );
}

#[test]
fn extractor_negative_cases() {
    let mixed = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK 'did:btcr2:k1abc',\"did:btcr2:x1def\" `did:btcr2:k1ghi`";
    assert_eq!(
        btcr2_dids(mixed),
        vec!["did:btcr2:k1abc", "did:btcr2:x1def", "did:btcr2:k1ghi"]
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
