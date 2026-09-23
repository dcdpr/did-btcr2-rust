//! The traceability guard for the W3C DID Resolution test suite.
//!
//! `CURATED` maps every `it()` in the vendored suite's `4-did-resolution.js`
//! and `10-bindings.js`, and the three exported helpers of `assertions.js`, to
//! a named Rust test or a stated reason. The ledger discipline:
//!
//! - a row may only claim a test that exists (`#[test]` above `fn name(` in
//!   `tests/conformance.rs` or `tests/schema.rs`, proven with `include_str!`);
//! - every `it()` title the vendored files contain must be a row, and the
//!   per-file counts must match the pin;
//! - the submodule's `HEAD` must be the recorded pin;
//! - an absent or unpopulated submodule is a failure naming the fix, never a
//!   skip;
//! - the POST binding note names every `#[test]` in `tests/post.rs` and only
//!   those (both directions are checked);
//! - `CONFORMANCE.md` is rendered from the table and compared to the
//!   checked-in golden (`BLESS=1` rewrites it).
//!
//! The title extractor and the existence check have their own negative tests
//! below, so the guard cannot pass vacuously.

use std::path::Path;
use std::process::Command;

/// The vendored `w3c/did-resolution-test-suite` commit.
const PIN: &str = "c3fb2a88585da1dd6167dccd59a84700fa2383ed";
const SUITE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../w3c-resolution-suite");
const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/CONFORMANCE.md");

const RESOLUTION_JS: &str = "4-did-resolution.js";
const BINDINGS_JS: &str = "10-bindings.js";
const ASSERTIONS_JS: &str = "assertions.js";

/// `it()` blocks per file at the pin; a second tripwire beside the pin check.
const RESOLUTION_IT_COUNT: usize = 13;
const BINDINGS_IT_COUNT: usize = 21;
const ASSERTIONS_HELPER_COUNT: usize = 3;

#[derive(Clone, Copy)]
enum Status {
    /// A named `#[test]` in `tests/conformance.rs` or `tests/schema.rs`.
    Covered(&'static str),
    /// The assertion is outside what the binding implements; the reason says why.
    NotApplicable(&'static str),
    /// The upstream block asserts nothing about resolver behaviour.
    NoAssertion(&'static str),
}

struct Row {
    file: &'static str,
    line: u32,
    title: &'static str,
    status: Status,
}

const DEREFERENCING: &str = "DID URL dereferencing is not implemented; a DID URL on the resolver \
                             path answers 501 FEATURE_NOT_SUPPORTED (test \
                             did_url_segment_is_501_feature_not_supported)";

const CURATED: &[Row] = &[
    // --- 4-did-resolution.js ---
    Row {
        file: RESOLUTION_JS,
        line: 24,
        title: "Implementation has at least one valid DID to test",
        status: Status::NoAssertion(
            "manifest-level check (validDids.length > 0); no resolver behaviour",
        ),
    },
    Row {
        file: RESOLUTION_JS,
        line: 32,
        title: "All conformant DID resolvers MUST implement the DID resolution function for at least one DID method",
        status: Status::Covered("get_with_accept_did_resolution_returns_200_and_the_result_triple"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 44,
        title: "The resolutionOptions input is REQUIRED, but the structure MAY be empty.",
        status: Status::NoAssertion("empty test body (`// TODO` at 4-did-resolution.js:48)"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 52,
        title: "The didResolutionMetadata structure is REQUIRED.",
        status: Status::Covered("result_has_did_resolution_metadata"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 62,
        title: "If resolution is successful, the didDocument MUST be a conformant DID document",
        status: Status::Covered("successful_result_carries_a_did_document"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 72,
        title: "The value of id in the resolved DID document MUST match the DID that was resolved",
        status: Status::Covered(
            "did_document_id_equals_the_requested_did_for_raw_and_encoded_forms",
        ),
    },
    Row {
        file: RESOLUTION_JS,
        line: 83,
        title: "If the resolution is successful, the `didDocumentMetadata` MUST be a metadata structure",
        status: Status::Covered("successful_result_has_did_document_metadata_object"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 95,
        title: "The did input to the resolve function is REQUIRED",
        status: Status::Covered("empty_did_segment_is_400_invalid_did"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 108,
        title: "The did input value MUST be a conformant DID as defined in Decentralized Identifiers (DIDs) v1.0.",
        status: Status::Covered("not_a_did_and_did_example_are_rejected"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 116,
        title: "Produces a INVALID_DID error and conformant resolution result",
        status: Status::Covered("bad_dids_produce_invalid_did_error_resolution_result"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 126,
        title: "The error property in DID Document Metadata is REQUIRED when there is an error in the resolution process.",
        status: Status::Covered("error_result_carries_the_error_property"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 139,
        title: "If the resolution is unsuccessful, the `didDocumentMetadata` output MUST be an empty metadata structure",
        status: Status::Covered("error_result_did_document_metadata_is_an_empty_object"),
    },
    Row {
        file: RESOLUTION_JS,
        line: 154,
        title: "If the DID method is not supported, produces a METHOD_NOT_SUPPORTED error and conformant resolution result",
        status: Status::Covered("unsupported_method_produces_method_not_supported_501"),
    },
    // --- 10-bindings.js ---
    Row {
        file: BINDINGS_JS,
        line: 50,
        title: "All HTTPS bindings MUST use TLS",
        status: Status::NotApplicable(
            "TLS is a property of the deployed host, not of the handler; DEPLOY.md §6 terminates TLS at the reverse proxy in front of the loopback-bound binary",
        ),
    },
    Row {
        file: BINDINGS_JS,
        line: 66,
        title: "All conforming DID resolvers MUST implement the GET version of the HTTPS binding",
        status: Status::Covered("explicit_get_returns_200"),
    },
    Row {
        file: BINDINGS_JS,
        line: 80,
        title: "If Accept is application/did-resolution, HTTP body MUST contain a DID resolution result",
        status: Status::Covered("accept_did_resolution_body_is_a_resolution_result"),
    },
    Row {
        file: BINDINGS_JS,
        line: 94,
        title: "If function is successful and returns a didDocument, HTTP response status code MUST be 200",
        status: Status::Covered("successful_resolution_status_is_200"),
    },
    Row {
        file: BINDINGS_JS,
        line: 107,
        title: "HTTP response MUST contain a Content-Type header whose value MUST equal contentType in didResolutionMetadata",
        status: Status::Covered(
            "content_type_header_contains_did_resolution_metadata_content_type",
        ),
    },
    Row {
        file: BINDINGS_JS,
        line: 130,
        title: "HTTP response body MUST contain the didDocument result of the DID resolution function",
        status: Status::Covered("full_result_body_contains_the_did_document"),
    },
    Row {
        file: BINDINGS_JS,
        line: 146,
        title: "If Accept is set to a DID representation media type, response body MUST contain only the didDocument (not the full resolution result)",
        status: Status::Covered("did_representation_accept_returns_only_the_document"),
    },
    Row {
        file: BINDINGS_JS,
        line: 178,
        title: "GET binding: resolver MUST accept URL-encoded DIDs (required because clients MUST URL-encode when resolution options other than accept are provided)",
        status: Status::Covered("percent_encoded_did_resolves_like_the_raw_form"),
    },
    Row {
        file: BINDINGS_JS,
        line: 200,
        title: "INVALID_DID error MUST map to HTTP status 400 (input: \"${badDid}\")",
        status: Status::Covered("invalid_did_maps_to_400"),
    },
    Row {
        file: BINDINGS_JS,
        line: 213,
        title: "METHOD_NOT_SUPPORTED error MUST map to HTTP status 501",
        status: Status::Covered("method_not_supported_maps_to_501"),
    },
    Row {
        file: BINDINGS_JS,
        line: 232,
        title: "NOT_FOUND error MUST map to HTTP status 404",
        status: Status::Covered("not_found_maps_to_404"),
    },
    Row {
        file: BINDINGS_JS,
        line: 246,
        title: "REPRESENTATION_NOT_SUPPORTED error MUST map to HTTP status 406",
        status: Status::Covered("unsupported_representation_maps_to_406"),
    },
    Row {
        file: BINDINGS_JS,
        line: 276,
        title: "If deactivated metadata property is true, HTTP response status MUST be 410",
        status: Status::Covered("deactivated_document_maps_to_410"),
    },
    Row {
        file: BINDINGS_JS,
        line: 306,
        title: "If Accept is application/did-url-dereferencing, HTTP body MUST contain a DID URL dereferencing result (${didUrl})",
        status: Status::NotApplicable(DEREFERENCING),
    },
    Row {
        file: BINDINGS_JS,
        line: 326,
        title: "If DID URL dereferencing returns a non-uri-list contentStream, HTTP status MUST be 200 (${didUrl})",
        status: Status::NotApplicable(DEREFERENCING),
    },
    Row {
        file: BINDINGS_JS,
        line: 343,
        title: "If DID URL dereferencing succeeds, Content-Type MUST equal contentType in dereferencingMetadata (${didUrl})",
        status: Status::NotApplicable(DEREFERENCING),
    },
    Row {
        file: BINDINGS_JS,
        line: 368,
        title: "HTTP response body MUST contain the contentStream from DID URL dereferencing (${didUrl})",
        status: Status::NotApplicable(DEREFERENCING),
    },
    Row {
        file: BINDINGS_JS,
        line: 385,
        title: "If Accept is set to a content media type, response body MUST contain only the contentStream (not the full dereferencing result) (${didUrl})",
        status: Status::NotApplicable(DEREFERENCING),
    },
    Row {
        file: BINDINGS_JS,
        line: 419,
        title: "If contentType is text/uri-list, HTTP response status MUST be 303 (${didUrl})",
        status: Status::NotApplicable(DEREFERENCING),
    },
    Row {
        file: BINDINGS_JS,
        line: 433,
        title: "If 303 response, HTTP response MUST contain a Location header with the selected DID service endpoint URL (${didUrl})",
        status: Status::NotApplicable(DEREFERENCING),
    },
    Row {
        file: BINDINGS_JS,
        line: 449,
        title: "If 303 response, HTTP response body MUST be empty (${didUrl})",
        status: Status::NotApplicable(DEREFERENCING),
    },
    // --- assertions.js ---
    Row {
        file: ASSERTIONS_JS,
        line: 9,
        title: "checkSuccessfulResolutionResult",
        status: Status::Covered("success_result_shape_matches_check_successful_resolution_result"),
    },
    Row {
        file: ASSERTIONS_JS,
        line: 20,
        title: "checkErrorResolutionResult",
        status: Status::Covered("error_result_shape_matches_check_error_resolution_result"),
    },
    Row {
        file: ASSERTIONS_JS,
        line: 39,
        title: "checkConformantDidDocument",
        status: Status::Covered("resolved_document_validates_against_did_schema"),
    },
];

// ---------------------------------------------------------------------------
// The vendored files
// ---------------------------------------------------------------------------

/// Read `tests/<name>` from the vendored suite; an absent submodule is a
/// failure that names the fix.
fn read_suite_file(name: &str) -> String {
    let path = format!("{SUITE_DIR}/tests/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{path} is absent or unreadable ({e}); the w3c-resolution-suite submodule is not \
             populated — run `git submodule update --init w3c-resolution-suite`"
        )
    })
}

fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// Every `it(` call in a mocha source with its 1-based line and its title.
///
/// The title is the string-literal expression the file passes: each `'…'`,
/// `"…"` or `` `…` `` literal is taken verbatim (template placeholders such as
/// `${didUrl}` stay as written) and consecutive literals joined with `+` are
/// concatenated. `xit(`, `fit(` and `it.skip(` do not match: the `it` must not
/// be preceded by an identifier character or a `.`, and `it.skip(` has `.skip`
/// between `it` and `(`. An `it(` whose first argument is not a literal yields
/// an empty title, so the row check reports it instead of losing it.
fn it_titles(src: &str) -> Vec<(u32, String)> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let preceded_by_identifier = i > 0 && {
            let prev = bytes[i - 1] as char;
            is_identifier_char(prev) || prev == '.'
        };
        if !preceded_by_identifier && bytes[i..].starts_with(b"it(") {
            let mut title = String::new();
            let mut j = i + 3;
            loop {
                j = skip_whitespace(bytes, j);
                let Some(&quote) = bytes.get(j) else { break };
                if quote != b'\'' && quote != b'"' && quote != b'`' {
                    break;
                }
                j += 1;
                let start = j;
                while j < bytes.len() && bytes[j] != quote {
                    if bytes[j] == b'\\' {
                        j += 1;
                    }
                    j += 1;
                }
                let end = j.min(bytes.len());
                title.push_str(&src[start..end]);
                j = skip_whitespace(bytes, end + 1);
                if bytes.get(j) == Some(&b'+') {
                    j += 1;
                    continue;
                }
                break;
            }
            out.push((line_of(src, i), title));
            i += 3;
            continue;
        }
        i += 1;
    }
    out
}

fn skip_whitespace(bytes: &[u8], mut j: usize) -> usize {
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    j
}

/// 1-based line of byte offset `at`.
fn line_of(src: &str, at: usize) -> u32 {
    1 + src.as_bytes()[..at].iter().filter(|&&b| b == b'\n').count() as u32
}

// ---------------------------------------------------------------------------
// The Rust tests a row may claim
// ---------------------------------------------------------------------------

/// The `fn` names declared with `#[test]` within the three preceding non-blank
/// lines (a `#[should_panic]` between them is allowed), in document order.
fn test_fn_names(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter_map(|(idx, l)| {
            let name = l.trim_start().strip_prefix("fn ")?.split('(').next()?;
            lines[..idx]
                .iter()
                .rev()
                .filter(|p| !p.trim().is_empty())
                .take(3)
                .any(|p| p.trim() == "#[test]")
                .then(|| name.to_string())
        })
        .collect()
}

/// True when some source declares `fn {name}(` with `#[test]` within the three
/// preceding non-blank lines.
fn test_exists_in(sources: &[&str], name: &str) -> bool {
    sources
        .iter()
        .any(|src| test_fn_names(src).iter().any(|n| n == name))
}

fn test_exists(name: &str) -> bool {
    test_exists_in(
        &[include_str!("conformance.rs"), include_str!("schema.rs")],
        name,
    )
}

// ---------------------------------------------------------------------------
// CONFORMANCE.md
// ---------------------------------------------------------------------------

fn status_cells(status: Status) -> (&'static str, String) {
    match status {
        Status::Covered(test) => ("Covered", format!("`{test}`")),
        Status::NotApplicable(reason) => ("Not applicable", reason.to_string()),
        Status::NoAssertion(reason) => ("No assertion", reason.to_string()),
    }
}

/// The binding's own POST rows in `tests/post.rs`, named by the third binding note.
/// `binding_note_names_existing_post_tests` fails when one is renamed away;
/// `every_post_test_is_in_the_binding_note` fails when a POST test is added
/// without being named here.
const POST_TESTS: &[&str] = &[
    "sidecar_body_reaches_the_resolver_typed",
    "post_percent_encoded_did_matches_raw",
    "post_rejections_are_400_or_501_before_the_resolver",
    "sidecar_in_a_get_query_is_400_invalid_options",
    "post_content_type_gate_is_bodiless_415",
    "post_with_query_string_is_400_invalid_options",
    "post_empty_body_resolves_like_get",
    "post_deactivated_result_is_410",
    "post_accept_negotiation_applies",
    "clean_fixture_sidecar_resolves_through_the_binding",
    "post_error_from_the_resolver_keeps_the_get_mapping",
];

/// The 405 row in `tests/conformance.rs` the note points at.
const POST_ALLOW_TEST: &str = "other_methods_on_resolver_path_are_405_with_allow_get_post";

/// The cache-bypass invariant in `src/resolve.rs` the note points at.
const POST_BYPASS_TEST: &str = "post_bypasses_the_cache_in_both_directions";

/// The third binding note: why the POST binding adds no suite rows and where its
/// own tests live. One line, no trailing newline.
fn post_binding_note() -> String {
    let names = POST_TESTS
        .iter()
        .map(|t| format!("`{t}`"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "- `POST /1.0/identifiers/{{did}}` (DID Resolution §12.1, a MAY) adds no suite rows: the \
         pinned suite issues GET only. The binding's own POST rows live in `tests/post.rs` — \
         {names} — beside the 405 row `{POST_ALLOW_TEST}` in `tests/conformance.rs` \
         (`Allow: GET, POST`); the cache-bypass invariant is `{POST_BYPASS_TEST}` in \
         `src/resolve.rs`."
    )
}

/// Render the curated table as the `CONFORMANCE.md` document. Deterministic,
/// `\n` line ends, no trailing whitespace.
fn render() -> String {
    let mut out = String::new();
    out.push_str("# did-btcr2-resolver-http conformance to the W3C DID Resolution test suite\n\n");
    out.push_str(&format!(
        "This document is rendered from the curated table in `tests/guard.rs` against \
         `w3c/did-resolution-test-suite @ {PIN}`, vendored as the `w3c-resolution-suite` \
         submodule. Regenerate with `BLESS=1 cargo test -p did-btcr2-resolver-http --test guard`.\n\n"
    ));
    out.push_str(
        "Every `it()` in `tests/4-did-resolution.js` and `tests/10-bindings.js`, and each exported \
         helper of `tests/assertions.js`, is a row. The guard fails when a Covered row names a test \
         that does not exist, when an upstream `it()` has no row, when the per-file counts drift, \
         when the submodule is not at the pin, or when the submodule is not checked out.\n\n",
    );
    out.push_str(
        "- **Covered** — a named `#[test]` in `tests/conformance.rs` or `tests/schema.rs` \
         asserts the behaviour in-process.\n\
         - **Not applicable** — outside what the binding implements, with the reason.\n\
         - **No assertion** — the upstream block asserts nothing about resolver behaviour.\n\n",
    );

    out.push_str("## Binding notes\n\n");
    out.push_str(
        "- A non-ASCII request line is answered 400 by `tiny_http` before the handler runs, so no \
         problem body exists for it.\n",
    );
    out.push_str(
        "- A raw `?` in the request-target starts the query string (an unknown name answers 400 \
         `INVALID_OPTIONS`, test `raw_query_on_the_resolver_path_is_options_not_a_did_url`); only \
         the percent-encoded `%3F` form is a DID URL and answers 501 `FEATURE_NOT_SUPPORTED` (test \
         `did_url_segment_is_501_feature_not_supported`).\n",
    );
    out.push_str(&post_binding_note());
    out.push_str("\n\n");

    let (mut covered, mut na, mut none) = (0usize, 0usize, 0usize);
    for row in CURATED {
        match row.status {
            Status::Covered(_) => covered += 1,
            Status::NotApplicable(_) => na += 1,
            Status::NoAssertion(_) => none += 1,
        }
    }
    out.push_str(&format!(
        "**Totals:** {} rows — Covered {covered} · Not applicable {na} · No assertion {none}\n\n",
        CURATED.len()
    ));

    out.push_str("## Traceability\n\n");
    for (file, subject) in [
        (RESOLUTION_JS, "it() title"),
        (BINDINGS_JS, "it() title"),
        (ASSERTIONS_JS, "Exported helper"),
    ] {
        out.push_str(&format!("### `tests/{file}`\n\n"));
        out.push_str(&format!(
            "| Line (at pin) | {subject} | Status | Rust test / reason |\n|---|---|---|---|\n"
        ));
        for row in CURATED.iter().filter(|r| r.file == file) {
            let (status, detail) = status_cells(row.status);
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                row.line, row.title, status, detail
            ));
        }
        out.push('\n');
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

/// Assert `produced` equals the committed golden at `golden_path`, or write the
/// golden when `BLESS=1`. Runtime `std::fs` on both sides so the path written is
/// the path compared (never `include_str!` for a blessed file).
fn bless_or_assert(produced: &str, golden_path: &str) {
    if std::env::var("BLESS").as_deref() == Ok("1") {
        std::fs::write(golden_path, produced)
            .unwrap_or_else(|e| panic!("BLESS write {golden_path}: {e}"));
        return;
    }
    let golden = std::fs::read_to_string(golden_path)
        .unwrap_or_else(|e| panic!("read golden {golden_path} (run BLESS=1 to create): {e}"));
    assert_eq!(
        produced, golden,
        "{golden_path} drift — re-run `BLESS=1 cargo test -p did-btcr2-resolver-http --test guard` if intended"
    );
}

fn rows_for(file: &str) -> Vec<&'static Row> {
    CURATED.iter().filter(|r| r.file == file).collect()
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

#[test]
fn every_upstream_it_title_is_a_curated_row() {
    for file in [RESOLUTION_JS, BINDINGS_JS] {
        let rows = rows_for(file);
        let missing: Vec<String> = it_titles(&read_suite_file(file))
            .into_iter()
            .filter(|(line, title)| !rows.iter().any(|r| r.title == title && r.line == *line))
            .map(|(line, title)| format!("{file}:{line} {title:?}"))
            .collect();
        assert!(
            missing.is_empty(),
            "it() blocks in the vendored {file} with no curated row (title and line must match): \
             {missing:#?}"
        );
    }
}

#[test]
fn curated_row_counts_match_the_suite() {
    for (file, expected) in [
        (RESOLUTION_JS, RESOLUTION_IT_COUNT),
        (BINDINGS_JS, BINDINGS_IT_COUNT),
    ] {
        let extracted = it_titles(&read_suite_file(file)).len();
        let curated = rows_for(file).len();
        assert_eq!(extracted, expected, "{file}: it() blocks at the pin");
        assert_eq!(curated, expected, "{file}: curated rows");
    }
    let assertions = read_suite_file(ASSERTIONS_JS);
    let helpers = rows_for(ASSERTIONS_JS);
    assert_eq!(
        helpers.len(),
        ASSERTIONS_HELPER_COUNT,
        "{ASSERTIONS_JS}: curated rows"
    );
    for row in helpers {
        let decl = format!("export function {}(", row.title);
        assert!(
            assertions.contains(&decl),
            "{ASSERTIONS_JS} does not export `{}`",
            row.title
        );
    }
}

#[test]
fn every_covered_row_names_a_real_test() {
    let bogus: Vec<String> = CURATED
        .iter()
        .filter_map(|r| match r.status {
            Status::Covered(test) if !test_exists(test) => {
                Some(format!("{}:{} -> {test}", r.file, r.line))
            }
            _ => None,
        })
        .collect();
    assert!(
        bogus.is_empty(),
        "Covered rows naming a test that is not a `#[test] fn` in tests/conformance.rs or \
         tests/schema.rs: {bogus:#?}"
    );
}

#[test]
fn curated_titles_are_unique_and_lines_ascend_within_a_file() {
    for file in [RESOLUTION_JS, BINDINGS_JS, ASSERTIONS_JS] {
        let rows = rows_for(file);
        for (a, b) in rows.iter().zip(rows.iter().skip(1)) {
            assert!(
                a.line < b.line,
                "{file}: line {} is not before line {}",
                a.line,
                b.line
            );
        }
        for (idx, row) in rows.iter().enumerate() {
            assert!(
                !rows[..idx].iter().any(|p| p.title == row.title),
                "{file}: duplicate title {:?}",
                row.title
            );
        }
    }
}

#[test]
fn submodule_is_at_the_recorded_pin() {
    if !Path::new(SUITE_DIR).join(".git").exists() {
        eprintln!(
            "{SUITE_DIR} has no .git (exported tree); pin check skipped, the file checks still run"
        );
        return;
    }
    let output = Command::new("git")
        .args(["-C", SUITE_DIR, "rev-parse", "HEAD"])
        .output()
        .expect("git is on PATH");
    assert!(
        output.status.success(),
        "git rev-parse failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let head = String::from_utf8(output.stdout).expect("a hex commit id");
    assert_eq!(
        head.trim(),
        PIN,
        "the w3c-resolution-suite submodule is not at the recorded pin; bump PIN and regenerate \
         the line column"
    );
}

#[test]
fn conformance_md_matches_golden() {
    bless_or_assert(&render(), GOLDEN);
}

#[test]
fn binding_note_names_existing_post_tests() {
    let post_rs = include_str!("post.rs");
    let resolve_rs = include_str!("../src/resolve.rs");
    let missing: Vec<&str> = POST_TESTS
        .iter()
        .copied()
        .filter(|name| !test_exists_in(&[post_rs], name))
        .collect();
    assert!(
        missing.is_empty(),
        "the POST binding note names tests that are not `#[test] fn`s in tests/post.rs: \
         {missing:#?}"
    );
    assert!(
        test_exists(POST_ALLOW_TEST),
        "`{POST_ALLOW_TEST}` is a `#[test] fn` in tests/conformance.rs"
    );
    assert!(
        test_exists_in(&[resolve_rs], POST_BYPASS_TEST),
        "`{POST_BYPASS_TEST}` is a `#[test] fn` in src/resolve.rs"
    );
    // The rendered note carries every name it is built from, backticked.
    let note = post_binding_note();
    for name in POST_TESTS
        .iter()
        .copied()
        .chain([POST_ALLOW_TEST, POST_BYPASS_TEST])
    {
        assert!(note.contains(&format!("`{name}`")), "note names `{name}`");
    }
    assert!(note.starts_with("- `POST /1.0/identifiers/{did}`"));
    assert!(!note.ends_with('\n'), "render() supplies the line ends");
    assert!(
        render().contains(&format!("{note}\n\n**Totals:**")),
        "the note is the last binding note, right before the Totals line"
    );
}

#[test]
fn every_post_test_is_in_the_binding_note() {
    let declared = test_fn_names(include_str!("post.rs"));
    let unlisted: Vec<&String> = declared
        .iter()
        .filter(|n| !POST_TESTS.contains(&n.as_str()))
        .collect();
    assert!(
        unlisted.is_empty(),
        "`#[test] fn`s in tests/post.rs the POST binding note does not name — add them to \
         POST_TESTS and re-bless CONFORMANCE.md: {unlisted:#?}"
    );
    assert_eq!(
        POST_TESTS.len(),
        declared.len(),
        "POST_TESTS and tests/post.rs list the same tests"
    );
}

// ---------------------------------------------------------------------------
// The guard's own negatives
// ---------------------------------------------------------------------------

#[test]
fn it_titles_joins_concatenated_literals_and_skips_non_it_calls() {
    let snippet = "describe('x', function () {\n  it('a' + 'b', async function () {});\n  it.skip('never', async function () {});\n  xit(\"nor this\", function () {});\n  it(`template ${v}`, function () {});\n});\n";
    assert_eq!(
        it_titles(snippet),
        vec![(2, "ab".to_string()), (5, "template ${v}".to_string())]
    );

    // The vendored files carry non-ASCII text in comments (`→`); the scanner
    // must step through multi-byte characters without slicing inside one.
    let multibyte = "// INVALID_DID → 400\nit('after an arrow', function () {});\n";
    assert_eq!(
        it_titles(multibyte),
        vec![(2, "after an arrow".to_string())]
    );
}

#[test]
fn test_exists_rejects_a_bogus_name_and_accepts_a_real_one() {
    assert!(!test_exists("nonexistent_test_xyz"));
    assert!(test_exists("deactivated_document_maps_to_410"));
    let src = "fn helper() {}\n#[test]\nfn real() {}\n";
    assert!(test_exists_in(&[src], "real"));
    assert!(!test_exists_in(&[src], "helper"), "no #[test] above helper");
}

#[test]
fn test_fn_names_takes_annotated_fns_in_order() {
    let src = "fn helper() {}\n#[test]\nfn real() {}\n\n#[test]\n#[should_panic(expected = \"x\")]\nfn panics() {}\npub fn not_a_test() {}\n";
    assert_eq!(test_fn_names(src), ["real", "panics"]);
    assert!(test_fn_names("fn a() {}\nfn b() {}\n").is_empty());
}

#[test]
#[should_panic(expected = "git submodule update --init w3c-resolution-suite")]
fn missing_suite_file_fails_loudly_naming_the_submodule_command() {
    read_suite_file("does-not-exist.js");
}
