//! Executable, self-checking Singleton conformance matrix.
//!
//! This integration test is the single source of truth for which did:btcr2
//! method-spec MUST/SHALL requirements the Singleton-only milestone covers. It
//! has four interlocking guards so the matrix cannot silently rot:
//!
//! 1. [`index_guard`] parses the vendored method-spec INDEX snapshot and FAILS
//!    if any MUST/SHALL row is not accounted for in the curated table. A new
//!    spec MUST therefore breaks CI until a human triages it.
//! 2. [`curated_len_matches_parsed_must_rows`] asserts the curated table has
//!    exactly as many rows as the snapshot's MUST/SHALL universe — catching a
//!    typo'd join key that `index_guard` might otherwise accept as a "different"
//!    row (an off-by-one with no obvious miss).
//! 3. [`every_covered_row_names_a_real_test`] asserts every `Covered(test)` row
//!    names a test enumerated in the hand-maintained `KNOWN_TESTS` allow-list.
//!    NOTE: this proves only that the referenced *string* appears in
//!    `KNOWN_TESTS` — NOT that a `#[test]` of that name actually exists in the
//!    suite. A pure-string integration test cannot introspect the libtest
//!    registry, so a test renamed AND simultaneously dropped from `KNOWN_TESTS`
//!    slips past this guard (caught only by the green suite breaking elsewhere).
//!    This is an accepted, documented residual — see the `KNOWN_TESTS` doc and the
//!    "Self-Check Scope (residual)" section emitted into `CONFORMANCE.md`. A
//!    stronger fix would generate `KNOWN_TESTS` from `cargo test -- --list`.
//! 4. [`conformance_md_matches_golden`] renders the matrix + gap list to a
//!    committed `CONFORMANCE.md` golden and asserts they match (BLESS to refresh).
//!
//! Hermeticity: the snapshot is VENDORED at
//! `specs-snapshot/method-spec-index.md` inside the crate, not read from the
//! parent repo's `../../specs/INDEX.md`. A `../../specs/` path escapes the crate
//! root and breaks under `cargo package` / a standalone checkout. The test runs
//! offline in default `cargo test` with no I/O.

use std::collections::HashSet;

/// The vendored method-spec INDEX section (the `## did:btcr2 method spec` block
/// of the parent `specs/INDEX.md`), embedded at compile time so the test is
/// hermetic and packageable.
const INDEX_SNAPSHOT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/specs-snapshot/method-spec-index.md"
));

// ---------------------------------------------------------------------------
// INDEX cross-check guard
// ---------------------------------------------------------------------------

/// Normalize an INDEX snippet into the stable join key (the first ~80 chars).
///
/// `.build-method-index.py` truncates each snippet to 120 chars after
/// `line.strip()`, so the curated key compares on the first 80 normalized chars
/// to stay inside both the curated text and the truncated INDEX text. The
/// normalization is intentionally identical to the curated table's stored
/// prefixes (computed by the same rules):
///
/// - strip `{{#cite X}}` mdBook citation macros
/// - strip markdown links `[text](url)` -> `text`
/// - lowercase; collapse all whitespace to single spaces
/// - strip a trailing truncation ellipsis
/// - take the first 80 chars
fn normalize_prefix(snippet: &str) -> String {
    // strip {{#cite ...}}
    let mut s = strip_braced_cites(snippet);
    // strip markdown links [text](url) -> text
    s = strip_md_links(&s);
    // lowercase + collapse whitespace
    let lowered = s.to_lowercase();
    let collapsed = lowered.split_whitespace().collect::<Vec<_>>().join(" ");
    // strip trailing ellipsis / truncation marks
    let trimmed = collapsed.trim_end_matches('…').trim_end();
    // take the first 80 chars, then trim again so a slice landing on a space
    // boundary does not leave a fragile trailing space in the join key.
    let prefix: String = trimmed.chars().take(80).collect();
    prefix.trim_end().to_string()
}

/// Remove `{{#cite ...}}` macros from `s`.
fn strip_braced_cites(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if s[i..].starts_with("{{#cite") {
            // skip to the closing "}}"
            if let Some(end) = s[i..].find("}}") {
                i += end + 2;
                continue;
            } else {
                break;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Replace markdown links `[text](url)` with just `text`.
fn strip_md_links(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '[' {
            // find matching ']'
            if let Some(close) = chars[i + 1..].iter().position(|&c| c == ']') {
                let close = i + 1 + close;
                // require an immediately-following "(...)"
                if close + 1 < chars.len()
                    && chars[close + 1] == '('
                    && let Some(paren) = chars[close + 2..].iter().position(|&c| c == ')')
                {
                    let paren = close + 2 + paren;
                    // emit the link text only
                    out.extend(chars[i + 1..close].iter());
                    i = paren + 1;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Parse one INDEX row `- <file>:<line> **KW** — <snippet>` into
/// `(file, normalized_prefix)`. The `:LINE` is deliberately ignored — it shifts
/// on every `python3 .build-method-index.py` regeneration; the normalized text
/// prefix is the stable key.
fn parse_index_row(line: &str) -> (String, String) {
    // strip leading "- "
    let rest = line.strip_prefix("- ").unwrap_or(line);
    // file is up to the first ':'
    let colon = rest.find(':').expect("INDEX row has file:line");
    let file = rest[..colon].to_string();
    // snippet is after the " — " em-dash separator
    let snippet = rest.split_once(" — ").map(|(_, s)| s).unwrap_or("");
    (file, normalize_prefix(snippet))
}

/// Scan the method-spec section of the INDEX snapshot for every MUST-family row.
///
/// Scope is MUST + MUST NOT + SHALL + SHALL NOT only. SHOULD / MAY /
/// RECOMMENDED / OPTIONAL / REQUIRED are out of scope. Multi-word negatives are
/// emitted by `.build-method-index.py` as a unit (`**MUST NOT**`), so they are
/// matched distinctly. Only lines at/after the `## did:btcr2 method spec` marker
/// are scanned.
///
/// The third tuple field is the **occurrence index** of `(file, prefix)` within
/// parse order: 0 for the first row carrying a given `(file, prefix)` key, 1 for
/// the second, etc.. It disambiguates rows whose normalized text prefix
/// is byte-identical (e.g. the encode-side and decode-side `INVALID_DID` rows in
/// `algorithms.md`, which both normalize to the same key but are structurally
/// distinct requirements). Without this discriminator the two rows would collapse
/// to a single `HashSet` entry and the INDEX guard could no longer prove both are
/// independently curated. The occurrence index is derived from parse order rather
/// than the `:line` field so it does not churn on every INDEX regeneration.
fn method_spec_must_rows(index_md: &str) -> Vec<(String, String, usize)> {
    let mut seen: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    index_md
        .lines()
        .skip_while(|l| *l != "## did:btcr2 method spec")
        .filter(|l| l.starts_with("- did-btcr2/src/"))
        .filter(|l| {
            l.contains("**MUST**")
                || l.contains("**SHALL**")
                || l.contains("**MUST NOT**")
                || l.contains("**SHALL NOT**")
        })
        .map(parse_index_row)
        .map(|(file, prefix)| {
            let occ = seen.entry((file.clone(), prefix.clone())).or_insert(0);
            let idx = *occ;
            *occ += 1;
            (file, prefix, idx)
        })
        .collect()
}

/// Build the curated join keys as `(file, prefix, occurrence_index)`, mirroring
/// [`method_spec_must_rows`]: the Nth curated row carrying a given `(file, prefix)`
/// pair (in CURATED declaration order) gets occurrence index N. The
/// CURATED array is ordered so that, for the duplicated-text pair, the encode-side
/// row precedes the decode-side row — matching the parse order of the snapshot.
fn curated_join_keys() -> Vec<(String, String, usize)> {
    let mut seen: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    CURATED
        .iter()
        .map(|r| {
            let key = (r.file.to_string(), r.prefix.to_string());
            let occ = seen.entry(key.clone()).or_insert(0);
            let idx = *occ;
            *occ += 1;
            (key.0, key.1, idx)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Curated requirement table (human-judged Singleton applicability)
// ---------------------------------------------------------------------------

/// Coverage status of a single method-spec MUST/SHALL row for the Singleton-only
/// milestone.
#[derive(Clone, Copy)]
enum Status {
    /// Exercised by a real, currently-asserting `#[test]` (path enumerated in
    /// [`KNOWN_TESTS`]).
    Covered(&'static str),
    /// Applies only to CAS / SMT / aggregation beacons, deferred to a future
    /// milestone. Not a gap for the Singleton scope.
    DeferredAggregation,
    /// Out of scope for this method implementation, with a reason.
    NotApplicable(&'static str),
}

/// One curated conformance row.
struct ConformanceRow {
    /// Stable ID: `<file-stem>:<slug>`. The slug disambiguates rows that share a
    /// normalized text prefix (e.g. the two identical INVALID_DID error rows).
    id: &'static str,
    /// Source method-spec file (matches the INDEX `did-btcr2/src/<file>` field).
    file: &'static str,
    /// Keyword (`MUST` / `MUST NOT`).
    keyword: &'static str,
    /// Normalized statement-text prefix — the join key against the INDEX guard.
    /// MUST equal `normalize_prefix(<the INDEX snippet>)` exactly.
    prefix: &'static str,
    /// Coverage disposition.
    status: Status,
}

/// The curated Singleton conformance table.
///
/// One row per method-spec MUST/SHALL line in the vendored snapshot (63 rows).
/// `prefix` values are the normalized 80-char join keys; they MUST match the
/// INDEX guard's `normalize_prefix` output for the corresponding snippet (the
/// `index_guard` + `curated_len_matches_parsed_must_rows` tests enforce this).
const CURATED: &[ConformanceRow] = &[
    // ---- algorithms.md (identifier encode/decode) --------------------------
    ConformanceRow {
        id: "algorithms.md:encode-invalid-did-on-error",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "any errors encountered during this algorithm must raise an `invalid_did` error.",
        status: Status::Covered("identifier::tests::test_invalid_prefix"),
    },
    ConformanceRow {
        id: "algorithms.md:key-or-hash-genesis-bytes-variant",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "`key_or_hash` must be one of the supported [genesis bytes] variants defined in t",
        status: Status::Covered("identifier::tests::test_id_type_hrps"),
    },
    ConformanceRow {
        id: "algorithms.md:version-number-must-be-1",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "the `version_number` value must be `1`, declaring the encoding follows this spec",
        status: Status::Covered("identifier::tests::test_encode_decode_key_based"),
    },
    ConformanceRow {
        id: "algorithms.md:decode-invalid-did-on-error",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "any errors encountered during this algorithm must raise an `invalid_did` error.",
        status: Status::Covered("identifier::tests::test_invalid_genesis_length"),
    },
    ConformanceRow {
        id: "algorithms.md:identifier-processed-per-resolution",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "a **did:btcr2** identifier must be processed according to the did resolution alg",
        status: Status::Covered("identifier::tests::test_encode_decode_key_based"),
    },
    ConformanceRow {
        id: "algorithms.md:btcr2-version-zero-version-number",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "* `btcr2_version` must be `0`. introduce `version_number` as `btcr2_version + 1`",
        status: Status::Covered("identifier::tests::test_encode_decode_key_based"),
    },
    ConformanceRow {
        id: "algorithms.md:network-value-in-table",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "* `network_value` must be one of the values in table 1: network values. `network",
        status: Status::Covered("identifier::tests::test_network_conversion"),
    },
    ConformanceRow {
        id: "algorithms.md:hrp-k-or-x",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "* the `hrp` must be either `\"k\"` or `\"x\"`.",
        status: Status::Covered("identifier::tests::test_id_type_hrps"),
    },
    ConformanceRow {
        id: "algorithms.md:hrp-k-genesis-bytes-33-byte",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "if the `hrp` is `\"k\"` (key-based **btcr2:did** identifier), `key_or_hash` must b",
        status: Status::Covered("identifier::tests::test_encode_decode_key_based"),
    },
    ConformanceRow {
        id: "algorithms.md:hrp-x-genesis-bytes",
        file: "did-btcr2/src/algorithms.md",
        keyword: "MUST",
        prefix: "if the `hrp` is `\"x\"` ([genesis document]-based **btcr2:did** identifier), `key_",
        status: Status::Covered("identifier::tests::test_encode_decode_external"),
    },
    // ---- appendix/privacy-considerations.md --------------------------------
    ConformanceRow {
        id: "privacy-considerations.md:test-suite-consensus-splits",
        file: "did-btcr2/src/appendix/privacy-considerations.md",
        keyword: "MUST",
        prefix: "in order to prevent consensus splits, **did:btcr2** needs a particularly good te",
        status: Status::NotApplicable(
            "non-normative test-suite design guidance, not an implementable method behavior",
        ),
    },
    ConformanceRow {
        id: "privacy-considerations.md:smt-aggregation-service-path",
        file: "did-btcr2/src/appendix/privacy-considerations.md",
        keyword: "MUST",
        prefix: "within [smt beacons][smt beacon], the did is used as a path to an [smt] leaf nod",
        status: Status::DeferredAggregation,
    },
    // ---- appendix/security-considerations.md -------------------------------
    ConformanceRow {
        id: "security-considerations.md:avoid-late-publishing",
        file: "did-btcr2/src/appendix/security-considerations.md",
        keyword: "MUST",
        prefix: "**did:btcr2** was designed to avoid [late publishing] such that, independent of",
        status: Status::Covered("resolver::tests::unknown_signal_hash_raises_missing_update_data"),
    },
    ConformanceRow {
        id: "security-considerations.md:invalidation-attacks",
        file: "did-btcr2/src/appendix/security-considerations.md",
        keyword: "MUST",
        prefix: "invalidation attacks are where adversaries are able to publish [beacon signals][",
        status: Status::Covered("resolver::tests::unknown_signal_hash_raises_missing_update_data"),
    },
    ConformanceRow {
        id: "security-considerations.md:updates-available-at-resolution",
        file: "did-btcr2/src/appendix/security-considerations.md",
        keyword: "MUST",
        prefix: "[btcr2 updates][btcr2 update] must be available to resolver at the time of resol",
        status: Status::Covered("resolver::tests::unknown_signal_hash_raises_missing_update_data"),
    },
    // ---- beacons/aggregate-beacons.md (aggregation, deferred) -------------
    ConformanceRow {
        id: "aggregate-beacons.md:participants-persist-nonce",
        file: "did-btcr2/src/beacons/aggregate-beacons.md",
        keyword: "MUST",
        prefix: "* participants must persist their `nonce` values.",
        status: Status::DeferredAggregation,
    },
    ConformanceRow {
        id: "aggregate-beacons.md:service-received-responses",
        file: "did-btcr2/src/beacons/aggregate-beacons.md",
        keyword: "MUST",
        prefix: "once the [aggregation service] has received responses to an update opportunity f",
        status: Status::DeferredAggregation,
    },
    ConformanceRow {
        id: "aggregate-beacons.md:smt-service-constructs-tree",
        file: "did-btcr2/src/beacons/aggregate-beacons.md",
        keyword: "MUST",
        prefix: "* for [smt beacons][smt beacon], the [aggregation service] constructs a [sparse",
        status: Status::DeferredAggregation,
    },
    ConformanceRow {
        id: "aggregate-beacons.md:cas-participant-checks-index",
        file: "did-btcr2/src/beacons/aggregate-beacons.md",
        keyword: "MUST",
        prefix: "* for a [cas beacon], the [aggregation participant] checks that every registered",
        status: Status::DeferredAggregation,
    },
    ConformanceRow {
        id: "aggregate-beacons.md:smt-participant-validates-index",
        file: "did-btcr2/src/beacons/aggregate-beacons.md",
        keyword: "MUST",
        prefix: "* for an [smt beacon], the [aggregation participant] validates that all the inde",
        status: Status::DeferredAggregation,
    },
    // ---- beacons.md --------------------------------------------------------
    ConformanceRow {
        id: "beacons.md:all-signals-processed",
        file: "did-btcr2/src/beacons.md",
        keyword: "MUST",
        prefix: "all beacon signals broadcast from a [btcr2 beacon] in the [current did document]",
        status: Status::Covered("resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash"),
    },
    ConformanceRow {
        id: "beacons.md:active-beacons-in-service",
        file: "did-btcr2/src/beacons.md",
        keyword: "MUST",
        prefix: "the current, active, [btcr2 beacons][btcr2 beacon] of a did document are specifi",
        status: Status::Covered("document::tests::beacons_accessor"),
    },
    ConformanceRow {
        id: "beacons.md:resolvers-support-beacon-types",
        file: "did-btcr2/src/beacons.md",
        keyword: "MUST",
        prefix: "all **did:btcr2** did resolvers must support the [beacon types][beacon type] def",
        status: Status::Covered("beacon::tests::beacon_type_serde_round_trips_spec_strings"),
    },
    // ---- conformance.md ----------------------------------------------------
    ConformanceRow {
        id: "conformance.md:conformant-to-did-core",
        file: "did-btcr2/src/conformance.md",
        keyword: "MUST",
        prefix: "implementations must be conformant to all normative statements in decentralized",
        status: Status::NotApplicable(
            "umbrella conformance statement over DID-Core/Resolution; covered transitively by \
             the specific rows below, not a single testable behavior",
        ),
    },
    // ---- data-structures.md ------------------------------------------------
    ConformanceRow {
        id: "data-structures.md:json-ld-conformance",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "concrete representations of these data structures must conform to the json-ld 1.",
        status: Status::NotApplicable(
            "JSON-LD 1.1 layer is out of scope (see PROJECT.md Out of Scope); JCS hashing needs \
             are met without a general JSON-LD conformance layer",
        ),
    },
    ConformanceRow {
        id: "data-structures.md:base64url-no-pad-encoding",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "must be encoded as a string using `\"base64url\"` encoding without padding.",
        status: Status::Covered("update::tests::unsigned_update_hashes_are_base64url_no_pad"),
    },
    ConformanceRow {
        id: "data-structures.md:did-doc-required-properties",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "the following properties must be included:",
        status: Status::Covered("document::tests::test_document_validation_missing_elements"),
    },
    ConformanceRow {
        id: "data-structures.md:source-target-hash-json-document-hashing",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "sha-256 hashes (`targethash` and `sourcehash`) must be produced using the [json",
        status: Status::Covered("document::tests::golden_signed_update_bytes"),
    },
    ConformanceRow {
        id: "data-structures.md:patch-result-conformant-doc",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "applied to a did document. the result of applying the patch must be a conformant",
        status: Status::Covered("document::tests::construct_signed_update_round_trips"),
    },
    ConformanceRow {
        id: "data-structures.md:target-version-id-plus-one",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "targetversionid must be one more than the `versionid` of the did document being",
        status: Status::Covered("resolver::tests::metadata_version_id_is_an_ascii_string"),
    },
    ConformanceRow {
        id: "data-structures.md:source-hash-applied-to",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "- `sourcehash`: sha-256 hash of the did document that the patch must be applied",
        status: Status::Covered("document::tests::construct_signed_update_round_trips"),
    },
    ConformanceRow {
        id: "data-structures.md:target-hash-result-of-patch",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "- `targethash`: sha-256 hash of the did document that results from applying the",
        status: Status::Covered("document::tests::construct_signed_update_round_trips"),
    },
    ConformanceRow {
        id: "data-structures.md:data-integrity-config-properties",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "the following properties must be included in the data integrity config:",
        status: Status::Covered("document::tests::data_integrity_config_shape"),
    },
    ConformanceRow {
        id: "data-structures.md:capability-action-write",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "string must be set to `\"write\"`.",
        status: Status::Covered("document::tests::data_integrity_config_shape"),
    },
    ConformanceRow {
        id: "data-structures.md:proof-purpose-capability-invocation",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "a [data integrity proof] with the `proofpurpose` set to `\"capabilityinvocation\"`",
        status: Status::Covered("document::tests::construct_signed_update_round_trips"),
    },
    ConformanceRow {
        id: "data-structures.md:proof-value-detached-schnorr",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "- `proofvalue`: must be a detached schnorr signature produced according to schno",
        status: Status::Covered("document::tests::proof_value_is_base58btc_64_bytes"),
    },
    ConformanceRow {
        id: "data-structures.md:cas-announcement-hashes-base64url",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "sha-256 hashes (`id`, `updateid`, `hashes`) must be `\"base64url\"` encoded withou",
        status: Status::DeferredAggregation,
    },
    ConformanceRow {
        id: "data-structures.md:sidecar-maps-dids-to-update-hashes",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "a data structure that maps dids to [btcr2 signed update] hashes. all [btcr2 sign",
        status: Status::Covered("resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash"),
    },
    ConformanceRow {
        id: "data-structures.md:root-capability-map-only-properties",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "the root capability must be a map containing only the following properties:",
        status: Status::Covered("zcap::tests::test_round_trip"),
    },
    ConformanceRow {
        id: "data-structures.md:root-capability-context",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "- `@context`: must be the context string `\"https://w3id.org/zcap/v1\"`",
        status: Status::Covered("zcap::tests::test_round_trip"),
    },
    ConformanceRow {
        id: "data-structures.md:root-capability-id-urn",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "- `id`: must be a urn of the following format: `urn:zcap:root:${encodeuricompone",
        status: Status::Covered("zcap::tests::test_dereference_root_capability"),
    },
    ConformanceRow {
        id: "data-structures.md:root-capability-invocation-target",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "- `invocationtarget`: must be the `did`.",
        status: Status::Covered("zcap::tests::test_dereference_root_capability"),
    },
    ConformanceRow {
        id: "data-structures.md:root-capability-controller",
        file: "did-btcr2/src/data-structures.md",
        keyword: "MUST",
        prefix: "- `controller`: must be the `did`.",
        status: Status::Covered("zcap::tests::test_dereference_root_capability"),
    },
    // ---- operations/create.md ----------------------------------------------
    ConformanceRow {
        id: "create.md:secp256k1-pubkey-genesis-bytes",
        file: "did-btcr2/src/operations/create.md",
        keyword: "MUST",
        prefix: "an secp256k1 public key can be used as the [genesis bytes]. the key must be",
        status: Status::Covered("document::tests::deterministically_generate"),
    },
    ConformanceRow {
        id: "create.md:genesis-document-hashed",
        file: "did-btcr2/src/operations/create.md",
        keyword: "MUST",
        prefix: "a [genesis document] can be used as the [genesis bytes], but must be hashed",
        status: Status::Covered("document::tests::test_from_external_intermediate"),
    },
    // ---- operations/deactivate.md ------------------------------------------
    ConformanceRow {
        id: "deactivate.md:add-deactivated-true",
        file: "did-btcr2/src/operations/deactivate.md",
        keyword: "MUST",
        prefix: "to deactivate a **did:btcr2**, the did controller must add the property `deactiv",
        status: Status::Covered("resolver::tests::metadata_deactivated_follows_the_document"),
    },
    // ---- operations/resolve.md ---------------------------------------------
    ConformanceRow {
        id: "resolve.md:input-through-decode-and-sidecar",
        file: "did-btcr2/src/operations/resolve.md",
        keyword: "MUST",
        prefix: "input values must first go through decoding the did and [processing sidecar data",
        status: Status::Covered("resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash"),
    },
    ConformanceRow {
        id: "resolve.md:parse-did-with-decoding-algorithm",
        file: "did-btcr2/src/operations/resolve.md",
        keyword: "MUST",
        prefix: "the `did` must be parsed with the [did-btcr2 identifier decoding] algorithm to r",
        status: Status::Covered("identifier::tests::test_encode_decode_key_based"),
    },
    ConformanceRow {
        id: "resolve.md:invalid-did-on-decode-error",
        file: "did-btcr2/src/operations/resolve.md",
        keyword: "MUST",
        prefix: "`network`, and `genesis_bytes`. an [`invalid_did`] error must be raised in respo",
        status: Status::Covered("identifier::tests::test_invalid_prefix"),
    },
    ConformanceRow {
        id: "resolve.md:process-genesis-document-placeholder",
        file: "did-btcr2/src/operations/resolve.md",
        keyword: "MUST",
        prefix: "process the [genesis document] provided in `sidecar.genesisdocument` by replacin",
        status: Status::Covered("document::tests::test_from_external_intermediate"),
    },
    ConformanceRow {
        id: "resolve.md:render-initial-did-document-bitcoin-uri",
        file: "did-btcr2/src/operations/resolve.md",
        keyword: "MUST",
        prefix: "render the [initial did document] template with these values (bitcoin addresses",
        status: Status::Covered("beacon::tests::from_bip21"),
    },
    ConformanceRow {
        id: "resolve.md:parse-rendered-template-conformant-doc",
        file: "did-btcr2/src/operations/resolve.md",
        keyword: "MUST",
        prefix: "parse the rendered template as json to form `current_document`. the resulting [d",
        status: Status::Covered("document::tests::test_document_parse"),
    },
    ConformanceRow {
        id: "resolve.md:late-publishing-raised",
        file: "did-btcr2/src/operations/resolve.md",
        keyword: "MUST",
        prefix: "* [`late_publishing`] error must be raised.",
        status: Status::Covered(
            "update::tests::confirm_duplicate_in_range_mismatch_is_late_publishing",
        ),
    },
    // ---- operations/update.md ----------------------------------------------
    ConformanceRow {
        id: "update.md:apply-patches-target-conformant",
        file: "did-btcr2/src/operations/update.md",
        keyword: "MUST",
        prefix: "apply all json patches in `jsonpatches` to `didsourcedocument` to create `didtar",
        status: Status::Covered("document::tests::construct_signed_update_round_trips"),
    },
    ConformanceRow {
        id: "update.md:unsigned-update-conformant",
        file: "did-btcr2/src/operations/update.md",
        keyword: "MUST",
        prefix: "resulting [btcr2 unsigned update (data structure)] must be conformant to this sp",
        status: Status::Covered("update::tests::unsigned_update_has_four_contexts"),
    },
    ConformanceRow {
        id: "update.md:invalid-did-update-vm-set-lacks-id",
        file: "did-btcr2/src/operations/update.md",
        keyword: "MUST",
        prefix: "an [`invalid_did_update`] error must be raised if the `didsourcedocument.verific",
        status: Status::Covered("document::tests::update_rejects_unknown_vm"),
    },
    ConformanceRow {
        id: "update.md:invalid-did-update-capability-invocation-lacks-id",
        file: "did-btcr2/src/operations/update.md",
        keyword: "MUST",
        prefix: "an [`invalid_did_update`] error must be raised if the `didsourcedocument.capabil",
        status: Status::Covered("document::tests::update_rejects_vm_not_in_capability_invocation"),
    },
    ConformanceRow {
        id: "update.md:data-integrity-config-conformant",
        file: "did-btcr2/src/operations/update.md",
        keyword: "MUST",
        prefix: "resulting [data integrity config (data structure)] must be conformant to verifia",
        status: Status::Covered("document::tests::data_integrity_config_shape"),
    },
    // ---- terminology.md ----------------------------------------------------
    ConformanceRow {
        id: "terminology.md:beacon-is-singleton-smt-or-cas",
        file: "did-btcr2/src/terminology.md",
        keyword: "MUST",
        prefix: "did. it must be either a [singleton beacon], [smt beacon], or a [cas beacon].",
        status: Status::Covered("beacon::tests::beacon_type_serde_round_trips_spec_strings"),
    },
    ConformanceRow {
        id: "terminology.md:must-not-complete-resolution-if-data-missing",
        file: "did-btcr2/src/terminology.md",
        keyword: "MUST NOT",
        prefix: "if some data is needed but not available, the did method must not allow did reso",
        status: Status::Covered("resolver::tests::unknown_signal_hash_raises_missing_update_data"),
    },
    ConformanceRow {
        id: "terminology.md:history-changes-detected",
        file: "did-btcr2/src/terminology.md",
        keyword: "MUST",
        prefix: "any changes to the history, such as may occur if a website edits a file, must be",
        status: Status::Covered("document::tests::wrong_target_version_id_fails_round_trip"),
    },
    ConformanceRow {
        id: "terminology.md:carry-did-document-history",
        file: "did-btcr2/src/terminology.md",
        keyword: "MUST",
        prefix: "vehicle, the same way the did controller must bring along the did document histo",
        status: Status::Covered("resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash"),
    },
    // ---- update-data-distribution.md (CAS/IPFS, deferred) -----------------
    ConformanceRow {
        id: "update-data-distribution.md:ipfs-chunking",
        file: "did-btcr2/src/update-data-distribution.md",
        keyword: "MUST",
        prefix: "for **did:btcr2** identifiers, files stored in ipfs must override the default ch",
        status: Status::DeferredAggregation,
    },
];

/// Every test path a `Covered` row may reference.
///
/// This is a string allow-list. It catches a `Covered` row pointing at a
/// name not listed here. RESIDUAL (review concern #10): a `#[test]` that is
/// deleted or renamed AND simultaneously dropped from this list is NOT caught by
/// the matrix — only by the green suite failing elsewhere. CONFORMANCE.md states
/// this honestly (`render_matrix` emits the self-check-residual note).
const KNOWN_TESTS: &[&str] = &[
    "beacon::tests::beacon_type_serde_round_trips_spec_strings",
    "beacon::tests::from_bip21",
    "document::tests::beacons_accessor",
    "document::tests::construct_signed_update_round_trips",
    "document::tests::data_integrity_config_shape",
    "document::tests::deterministically_generate",
    "document::tests::golden_signed_update_bytes",
    "document::tests::proof_value_is_base58btc_64_bytes",
    "document::tests::test_document_parse",
    "document::tests::test_document_validation_missing_elements",
    "document::tests::test_from_external_intermediate",
    "document::tests::update_rejects_unknown_vm",
    "document::tests::update_rejects_vm_not_in_capability_invocation",
    "document::tests::wrong_target_version_id_fails_round_trip",
    "identifier::tests::test_encode_decode_external",
    "identifier::tests::test_encode_decode_key_based",
    "identifier::tests::test_id_type_hrps",
    "identifier::tests::test_invalid_genesis_length",
    "identifier::tests::test_invalid_prefix",
    "identifier::tests::test_network_conversion",
    "resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash",
    "resolver::tests::metadata_version_id_is_an_ascii_string",
    "resolver::tests::metadata_deactivated_follows_the_document",
    "resolver::tests::unknown_signal_hash_raises_missing_update_data",
    "update::tests::confirm_duplicate_in_range_mismatch_is_late_publishing",
    "update::tests::unsigned_update_has_four_contexts",
    "update::tests::unsigned_update_hashes_are_base64url_no_pad",
    "zcap::tests::test_dereference_root_capability",
    "zcap::tests::test_round_trip",
];

// ---------------------------------------------------------------------------
// BLESS golden helper
// ---------------------------------------------------------------------------

/// Assert `produced` equals the committed golden at `golden_path`, or WRITE the
/// golden when `BLESS=1`.
///
/// INTENTIONALLY DUPLICATED from the `bless_or_assert` in
/// `src/document.rs`: Rust test helpers cannot be shared across
/// the unit-test / integration-test crate boundary (review concern #11). Both
/// copies use runtime `std::fs` on read AND write so the path the writer wrote
/// is the path the asserter reads (never `include_str!` for a blessed file).
fn bless_or_assert(produced: &str, golden_path: &str) {
    if std::env::var("BLESS").as_deref() == Ok("1") {
        std::fs::write(golden_path, produced)
            .unwrap_or_else(|e| panic!("BLESS write {golden_path}: {e}"));
        return;
    }
    let golden = std::fs::read_to_string(golden_path)
        .unwrap_or_else(|e| panic!("read golden {golden_path} (run BLESS=1 to create): {e}"));
    assert_eq!(
        produced,
        golden.trim_end_matches('\n'),
        "{golden_path} drift — re-run `BLESS=1 cargo test --test conformance` if intended"
    );
}

// ---------------------------------------------------------------------------
// Matrix render
// ---------------------------------------------------------------------------

/// Render the curated table into the `CONFORMANCE.md` markdown document: a
/// status matrix, a gap list, and the honest self-check-residual note.
fn render_matrix() -> String {
    let mut out = String::new();
    out.push_str("# did:btcr2 Singleton Conformance Matrix\n\n");
    out.push_str(
        "This document is rendered from `tests/conformance.rs` (the curated table is the single\n\
         source of truth). Regenerate with `BLESS=1 cargo test --test conformance \
         conformance_md_matches_golden`.\n\n",
    );
    out.push_str(
        "It enumerates every did:btcr2 method-spec **MUST** / **SHALL** requirement (from the\n\
         vendored `specs-snapshot/method-spec-index.md`) and tags each with its Singleton-milestone\n\
         coverage status:\n\n",
    );
    out.push_str(
        "- **Covered** — exercised by a named, currently-asserting `#[test]` in the suite.\n\
         - **DeferredAggregation** — applies only to CAS / SMT / aggregation beacons; deferred to a future\n  \
         milestone (not a Singleton gap).\n\
         - **NotApplicable** — out of scope for this method implementation, with a reason.\n\n",
    );

    // Counts
    let (mut covered, mut deferred, mut na) = (0usize, 0usize, 0usize);
    for row in CURATED {
        match row.status {
            Status::Covered(_) => covered += 1,
            Status::DeferredAggregation => deferred += 1,
            Status::NotApplicable(_) => na += 1,
        }
    }
    out.push_str(&format!(
        "**Totals:** {} requirements — {} Covered, {} DeferredAggregation, {} NotApplicable.\n\n",
        CURATED.len(),
        covered,
        deferred,
        na,
    ));

    // Matrix table
    out.push_str("## Requirement Matrix\n\n");
    out.push_str("| ID | Keyword | Status | Test / Reason |\n");
    out.push_str("|----|---------|--------|---------------|\n");
    for row in CURATED {
        let (status, detail) = match row.status {
            Status::Covered(t) => ("Covered", format!("`{t}`")),
            Status::DeferredAggregation => (
                "DeferredAggregation",
                String::from("CAS/SMT/aggregation — future milestone"),
            ),
            Status::NotApplicable(r) => ("NotApplicable", r.to_string()),
        };
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            row.id, row.keyword, status, detail,
        ));
    }
    out.push('\n');

    // Gap list: Covered rows are not gaps; DeferredAggregation/NotApplicable are
    // explicitly-justified non-gaps. A genuine gap would be a MUST that is
    // neither Covered nor justified — by construction there are none (every row
    // carries a status), so this section lists the deferred/NA justifications.
    out.push_str("## Gap List\n\n");
    out.push_str(
        "No Singleton-applicable MUST/SHALL is left uncovered: every requirement above is either\n\
         Covered by a test or explicitly justified as DeferredAggregation / NotApplicable. The justified\n\
         non-gaps are:\n\n",
    );
    for row in CURATED {
        match row.status {
            Status::DeferredAggregation => {
                out.push_str(&format!(
                    "- `{}` ({}) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.\n",
                    row.id, row.keyword,
                ));
            }
            Status::NotApplicable(r) => {
                out.push_str(&format!(
                    "- `{}` ({}) — NotApplicable: {}\n",
                    row.id, row.keyword, r,
                ));
            }
            Status::Covered(_) => {}
        }
    }
    out.push('\n');

    // Self-check residual note (review concern #10).
    out.push_str("## Self-Check Scope (residual)\n\n");
    out.push_str(
        "This matrix auto-detects NEW spec MUST/SHALL rows — the INDEX cross-check guard\n\
         (`index_guard`) fails CI on any unaccounted row, and `curated_len_matches_parsed_must_rows`\n\
         fails on a row-count drift. However, a DELETED or RENAMED referenced test is caught only by\n\
         the green test suite failing elsewhere — NOT by this matrix. `every_covered_row_names_a_real_test`\n\
         only verifies that each Covered row names a test in the `KNOWN_TESTS` allow-list; a test that\n\
         is renamed AND simultaneously dropped from that list would slip past this matrix until the\n\
         suite breaks. This residual is accepted and documented (no-half-implementations constraint).\n",
    );

    out.trim_end().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// every MUST/SHALL row parsed from the vendored INDEX snapshot is
/// accounted for in the curated table, matched by `(file, normalized-prefix)`.
/// FAILS (listing the unaccounted rows) if a new spec MUST slips in.
#[test]
fn index_guard() {
    let curated_keys: HashSet<(String, String, usize)> = curated_join_keys().into_iter().collect();

    let mut unaccounted = Vec::new();
    for (file, prefix, occ) in method_spec_must_rows(INDEX_SNAPSHOT) {
        if !curated_keys.contains(&(file.clone(), prefix.clone(), occ)) {
            let occ_note = if occ > 0 {
                format!(" (occurrence #{occ})")
            } else {
                String::new()
            };
            unaccounted.push(format!("  {file} :: {prefix}{occ_note}"));
        }
    }

    assert!(
        unaccounted.is_empty(),
        "{} method-spec MUST/SHALL row(s) are unaccounted for in CURATED \
         (add each with a Singleton applicability judgment):\n{}",
        unaccounted.len(),
        unaccounted.join("\n"),
    );
}

/// Review concern #9: the curated table has EXACTLY as many rows as the
/// snapshot's MUST/SHALL universe. Catches a typo'd join-key prefix that
/// `index_guard` might accept as a "different" row — an off-by-one with no clear
/// miss.
#[test]
fn curated_len_matches_parsed_must_rows() {
    let parsed = method_spec_must_rows(INDEX_SNAPSHOT).len();
    assert_eq!(
        CURATED.len(),
        parsed,
        "curated table has {} rows but the INDEX snapshot parses {} MUST/SHALL rows — \
         a join-key typo or a missing/extra curated row",
        CURATED.len(),
        parsed,
    );
}

/// every `Covered(test)` row names a test enumerated in the hand-maintained
/// `KNOWN_TESTS` allow-list.
///
/// Exact property: this proves the referenced *string* is present in
/// `KNOWN_TESTS`, NOT that a `#[test]` of that name compiles or exists. The two
/// hand-edited sides (the `Covered(...)` reference and `KNOWN_TESTS`) can drift
/// together past this guard if a test is renamed and dropped from the list at the
/// same time — caught only by the suite breaking elsewhere. Accepted residual
/// (see the module doc and the `CONFORMANCE.md` "Self-Check Scope" note); a
/// stronger fix generates `KNOWN_TESTS` from `cargo test -- --list`.
#[test]
fn every_covered_row_names_a_real_test() {
    let known: HashSet<&str> = KNOWN_TESTS.iter().copied().collect();
    // Sanity: the allow-list is non-trivial (guards against a degenerate
    // `== 0`-on-an-empty-list assertion that would always pass).
    assert!(
        known.len() >= 20,
        "KNOWN_TESTS shrank unexpectedly to {} entries",
        known.len(),
    );

    let mut missing = Vec::new();
    for row in CURATED {
        if let Status::Covered(test) = row.status
            && !known.contains(test)
        {
            missing.push(format!("  row `{}` -> `{}`", row.id, test));
        }
    }
    assert!(
        missing.is_empty(),
        "{} Covered row(s) name a test not in KNOWN_TESTS \
         (add the test to KNOWN_TESTS, or fix the reference):\n{}",
        missing.len(),
        missing.join("\n"),
    );
}

/// the rendered matrix + gap list match the committed `CONFORMANCE.md`
/// golden. Run `BLESS=1 cargo test --test conformance conformance_md_matches_golden`
/// to regenerate the golden after an intended change.
#[test]
fn conformance_md_matches_golden() {
    let rendered = render_matrix();
    bless_or_assert(
        &rendered,
        concat!(env!("CARGO_MANIFEST_DIR"), "/CONFORMANCE.md"),
    );
}
