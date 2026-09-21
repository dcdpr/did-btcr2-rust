# did-btcr2-resolver-http conformance to the W3C DID Resolution test suite

This document is rendered from the curated table in `tests/guard.rs` against `w3c/did-resolution-test-suite @ 2649fdf719beadbd3c684d358eea23c3c2e514fe`, vendored as the `w3c-resolution-suite` submodule. Regenerate with `BLESS=1 cargo test -p did-btcr2-resolver-http --test guard`.

Every `it()` in `tests/4-did-resolution.js` and `tests/10-bindings.js`, and each exported helper of `tests/assertions.js`, is a row. The guard fails when a Covered row names a test that does not exist, when an upstream `it()` has no row, when the per-file counts drift, when the submodule is not at the pin, or when the submodule is not checked out.

- **Covered** — a named `#[test]` in `tests/conformance.rs` or `tests/schema.rs` asserts the behaviour in-process.
- **Not applicable** — outside what the binding implements, with the reason.
- **No assertion** — the upstream block asserts nothing about resolver behaviour.

## Binding notes

- A non-ASCII request line is answered 400 by `tiny_http` before the handler runs, so no problem body exists for it.
- A raw `?` in the request-target starts the query string (an unknown name answers 400 `INVALID_OPTIONS`, test `raw_query_on_the_resolver_path_is_options_not_a_did_url`); only the percent-encoded `%3F` form is a DID URL and answers 501 `FEATURE_NOT_SUPPORTED` (test `did_url_segment_is_501_feature_not_supported`).
- `POST /1.0/identifiers/{did}` (DID Resolution §12.1, a MAY) adds no suite rows: the pinned suite issues GET only. The binding's own POST rows live in `tests/post.rs` — `sidecar_body_reaches_the_resolver_typed`, `post_rejections_are_400_or_501_before_the_resolver`, `post_content_type_gate_is_bodiless_415`, `post_with_query_string_is_400_invalid_options`, `post_empty_body_resolves_like_get`, `post_deactivated_result_is_410`, `post_accept_negotiation_applies`, `clean_fixture_sidecar_resolves_through_the_binding` — beside the 405 row `other_methods_on_resolver_path_are_405_with_allow_get_post` in `tests/conformance.rs` (`Allow: GET, POST`); the cache-bypass invariant is `post_bypasses_the_cache_in_both_directions` in `src/resolve.rs`.

**Totals:** 37 rows — Covered 26 · Not applicable 9 · No assertion 2

## Traceability

### `tests/4-did-resolution.js`

| Line (at pin) | it() title | Status | Rust test / reason |
|---|---|---|---|
| 24 | Implementation has at least one valid DID to test | No assertion | manifest-level check (validDids.length > 0); no resolver behaviour |
| 32 | All conformant DID resolvers MUST implement the DID resolution function for at least one DID method | Covered | `get_with_accept_did_resolution_returns_200_and_the_result_triple` |
| 44 | The resolutionOptions input is REQUIRED, but the structure MAY be empty. | No assertion | empty test body (`// TODO` at 4-did-resolution.js:48) |
| 52 | The didResolutionMetadata structure is REQUIRED. | Covered | `result_has_did_resolution_metadata` |
| 62 | If resolution is successful, the didDocument MUST be a conformant DID document | Covered | `successful_result_carries_a_did_document` |
| 72 | The value of id in the resolved DID document MUST match the DID that was resolved | Covered | `did_document_id_equals_the_requested_did_for_raw_and_encoded_forms` |
| 83 | If the resolution is successful, the `didDocumentMetadata` MUST be a metadata structure | Covered | `successful_result_has_did_document_metadata_object` |
| 95 | The did input to the resolve function is REQUIRED | Covered | `empty_did_segment_is_400_invalid_did` |
| 108 | The did input value MUST be a conformant DID as defined in Decentralized Identifiers (DIDs) v1.0. | Covered | `not_a_did_and_did_example_are_rejected` |
| 116 | Produces a INVALID_DID error and conformant resolution result | Covered | `bad_dids_produce_invalid_did_error_resolution_result` |
| 126 | The error property in DID Document Metadata is REQUIRED when there is an error in the resolution process. | Covered | `error_result_carries_the_error_property` |
| 139 | If the resolution is unsuccessful, the `didDocumentMetadata` output MUST be an empty metadata structure | Covered | `error_result_did_document_metadata_is_an_empty_object` |
| 154 | If the DID method is not supported, produces a METHOD_NOT_SUPPORTED error and conformant resolution result | Covered | `unsupported_method_produces_method_not_supported_501` |

### `tests/10-bindings.js`

| Line (at pin) | it() title | Status | Rust test / reason |
|---|---|---|---|
| 50 | All HTTPS bindings MUST use TLS | Not applicable | TLS is a property of the deployed host, not of the handler; DEPLOY.md §6 terminates TLS at the reverse proxy in front of the loopback-bound binary |
| 66 | All conforming DID resolvers MUST implement the GET version of the HTTPS binding | Covered | `explicit_get_returns_200` |
| 80 | If Accept is application/did-resolution, HTTP body MUST contain a DID resolution result | Covered | `accept_did_resolution_body_is_a_resolution_result` |
| 94 | If function is successful and returns a didDocument, HTTP response status code MUST be 200 | Covered | `successful_resolution_status_is_200` |
| 107 | HTTP response MUST contain a Content-Type header whose value MUST equal contentType in didResolutionMetadata | Covered | `content_type_header_contains_did_resolution_metadata_content_type` |
| 130 | HTTP response body MUST contain the didDocument result of the DID resolution function | Covered | `full_result_body_contains_the_did_document` |
| 146 | If Accept is set to a DID representation media type, response body MUST contain only the didDocument (not the full resolution result) | Covered | `did_representation_accept_returns_only_the_document` |
| 178 | GET binding: resolver MUST accept URL-encoded DIDs (required because clients MUST URL-encode when resolution options other than accept are provided) | Covered | `percent_encoded_did_resolves_like_the_raw_form` |
| 200 | INVALID_DID error MUST map to HTTP status 400 (input: "${badDid}") | Covered | `invalid_did_maps_to_400` |
| 213 | METHOD_NOT_SUPPORTED error MUST map to HTTP status 501 | Covered | `method_not_supported_maps_to_501` |
| 228 | NOT_FOUND error MUST map to HTTP status 404 | Covered | `not_found_maps_to_404` |
| 243 | REPRESENTATION_NOT_SUPPORTED error MUST map to HTTP status 406 | Covered | `unsupported_representation_maps_to_406` |
| 269 | If deactivated metadata property is true, HTTP response status MUST be 410 | Covered | `deactivated_document_maps_to_410` |
| 300 | If Accept is application/did-url-dereferencing, HTTP body MUST contain a DID URL dereferencing result (${didUrl}) | Not applicable | DID URL dereferencing is not implemented; a DID URL on the resolver path answers 501 FEATURE_NOT_SUPPORTED (test did_url_segment_is_501_feature_not_supported) |
| 320 | If DID URL dereferencing returns a non-uri-list contentStream, HTTP status MUST be 200 (${didUrl}) | Not applicable | DID URL dereferencing is not implemented; a DID URL on the resolver path answers 501 FEATURE_NOT_SUPPORTED (test did_url_segment_is_501_feature_not_supported) |
| 337 | If DID URL dereferencing succeeds, Content-Type MUST equal contentType in dereferencingMetadata (${didUrl}) | Not applicable | DID URL dereferencing is not implemented; a DID URL on the resolver path answers 501 FEATURE_NOT_SUPPORTED (test did_url_segment_is_501_feature_not_supported) |
| 362 | HTTP response body MUST contain the contentStream from DID URL dereferencing (${didUrl}) | Not applicable | DID URL dereferencing is not implemented; a DID URL on the resolver path answers 501 FEATURE_NOT_SUPPORTED (test did_url_segment_is_501_feature_not_supported) |
| 379 | If Accept is set to a content media type, response body MUST contain only the contentStream (not the full dereferencing result) (${didUrl}) | Not applicable | DID URL dereferencing is not implemented; a DID URL on the resolver path answers 501 FEATURE_NOT_SUPPORTED (test did_url_segment_is_501_feature_not_supported) |
| 413 | If contentType is text/uri-list, HTTP response status MUST be 303 (${didUrl}) | Not applicable | DID URL dereferencing is not implemented; a DID URL on the resolver path answers 501 FEATURE_NOT_SUPPORTED (test did_url_segment_is_501_feature_not_supported) |
| 427 | If 303 response, HTTP response MUST contain a Location header with the selected DID service endpoint URL (${didUrl}) | Not applicable | DID URL dereferencing is not implemented; a DID URL on the resolver path answers 501 FEATURE_NOT_SUPPORTED (test did_url_segment_is_501_feature_not_supported) |
| 443 | If 303 response, HTTP response body MUST be empty (${didUrl}) | Not applicable | DID URL dereferencing is not implemented; a DID URL on the resolver path answers 501 FEATURE_NOT_SUPPORTED (test did_url_segment_is_501_feature_not_supported) |

### `tests/assertions.js`

| Line (at pin) | Exported helper | Status | Rust test / reason |
|---|---|---|---|
| 9 | checkSuccessfulResolutionResult | Covered | `success_result_shape_matches_check_successful_resolution_result` |
| 20 | checkErrorResolutionResult | Covered | `error_result_shape_matches_check_error_resolution_result` |
| 39 | checkConformantDidDocument | Covered | `resolved_document_validates_against_did_schema` |
