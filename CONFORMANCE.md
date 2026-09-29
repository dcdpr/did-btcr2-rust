# did:btcr2 Singleton Conformance Matrix

This document is rendered from `tests/conformance.rs` (the curated table is the single
source of truth). Regenerate with `BLESS=1 cargo test --test conformance conformance_md_matches_golden`.

It enumerates every did:btcr2 method-spec **MUST** / **SHALL** requirement (from the
vendored `specs-snapshot/method-spec-index.md`) and tags each with its Singleton-milestone
coverage status:

- **Covered** — exercised by one or more named, currently-asserting `#[test]`s in the crate.
- **DeferredAggregation** — applies only to CAS / SMT / aggregation beacons; deferred to a future
  milestone (not a Singleton gap).
- **NotApplicable** — out of scope for this method implementation, with a reason.
- **Gap** — applies to the Singleton scope and is not implemented; the reason names what is
  missing.

**Totals:** 88 requirements — 65 Covered, 16 DeferredAggregation, 6 NotApplicable, 1 Gap.

## Requirement Matrix

| ID | Keyword | Status | Test / Reason |
|----|---------|--------|---------------|
| `algorithms.md:encode-invalid-did-on-error` | MUST | Covered | `identifier::tests::test_invalid_prefix` |
| `algorithms.md:key-or-hash-genesis-bytes-variant` | MUST | Covered | `identifier::tests::test_id_type_hrps` |
| `algorithms.md:version-number-must-be-1` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `algorithms.md:reserved-network-values-not-encoded` | MUST NOT | Covered | `identifier::tests::did_components_new_rejects_out_of_range_custom_network` |
| `algorithms.md:encode-method-specific-id-lowercase` | MUST | Covered | `identifier::pinned_mutinynet_vector_tests::encode_reproduces_spec_string` |
| `algorithms.md:method-specific-id-bech32m-conformant` | MUST | Covered | `identifier::tests::test_from_str_rejects_malformed_bech32` |
| `algorithms.md:decode-invalid-did-on-error` | MUST | Covered | `identifier::tests::test_invalid_genesis_length` |
| `algorithms.md:identifier-processed-per-resolution` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `algorithms.md:decode-method-specific-id-lowercase` | MUST | Covered | `identifier::tests::parse_did_identifier_rejects_uppercase_method_specific_id` |
| `algorithms.md:btcr2-version-zero-version-number` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `algorithms.md:network-name-integer-representable` | MUST | Covered | `identifier::tests::test_network_conversion` |
| `algorithms.md:network-value-handled-per-table` | MUST | Covered | `identifier::tests::test_network_conversion` |
| `algorithms.md:reserved-network-value-rejected-on-decode` | MUST | Covered | `identifier::tests::test_custom_network` |
| `algorithms.md:hrp-k-or-x` | MUST | Covered | `identifier::tests::test_id_type_hrps` |
| `algorithms.md:hrp-k-genesis-bytes-33-byte` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `algorithms.md:hrp-x-genesis-bytes` | MUST | Covered | `identifier::tests::test_encode_decode_external` |
| `algorithms.md:decoding-inverts-encoding` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `algorithms.md:smt-proof-fields-decoded-before-hashing` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `algorithms.md:smt-proof-verification-false-conditions` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `optimized-smt.md:smt-proof-fields-decoded-before-hashing` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `privacy-considerations.md:test-suite-consensus-splits` | MUST | NotApplicable | non-normative test-suite design guidance, not an implementable method behavior |
| `privacy-considerations.md:smt-aggregation-service-path` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `security-considerations.md:avoid-late-publishing` | MUST | Covered | `resolver::tests::unknown_signal_hash_raises_missing_update_data` |
| `security-considerations.md:invalidation-attacks` | MUST | Covered | `resolver::tests::unknown_signal_hash_raises_missing_update_data` |
| `security-considerations.md:updates-available-at-resolution` | MUST | Covered | `resolver::tests::unknown_signal_hash_raises_missing_update_data` |
| `aggregate-beacons.md:participants-persist-nonce` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `aggregate-beacons.md:service-received-responses` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `aggregate-beacons.md:smt-service-constructs-tree` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `aggregate-beacons.md:cas-participant-checks-index` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `aggregate-beacons.md:smt-participant-validates-index` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `beacons.md:process-each-found-signal` | MUST | Covered | `resolver::tests::a_later_update_at_the_introducing_height_is_found_and_applied`, `resolver::tests::a_conflicting_announcement_below_the_current_height_is_not_found`, `resolver::tests::find_next_signals_skips_transactions_below_the_current_block_height` |
| `beacons.md:active-beacons-in-service` | MUST | Covered | `document::tests::beacons_accessor` |
| `beacons.md:resolvers-support-beacon-types` | MUST | Covered | `beacon::tests::beacon_type_serde_round_trips_spec_strings` |
| `conformance.md:bcp14-keyword-interpretation` | MUST NOT | NotApplicable | BCP 14 boilerplate: names the RFC 2119 keywords and how to read them; imposes no requirement on an implementation |
| `conformance.md:conformant-to-did-core` | MUST | NotApplicable | umbrella conformance statement over DID-Core/Resolution; covered transitively by the specific rows below, not a single testable behavior |
| `data-structures.md:json-ld-conformance` | MUST | NotApplicable | JSON-LD 1.1 layer is out of scope (see PROJECT.md Out of Scope); JCS hashing needs are met without a general JSON-LD conformance layer |
| `data-structures.md:base64url-no-pad-encoding` | MUST | Covered | `update::tests::unsigned_update_hashes_are_base64url_no_pad` |
| `data-structures.md:did-doc-required-properties` | MUST | Covered | `document::tests::test_document_validation_missing_elements` |
| `data-structures.md:relative-did-url-resolved-against-id` | MUST | Covered | `document::tests::apply_update_resolves_relative_did_url` |
| `data-structures.md:source-target-hash-json-document-hashing` | MUST | Covered | `document::tests::golden_signed_update_bytes` |
| `data-structures.md:update-context-pinned-array` | MUST | Covered | `document::tests::apply_update_rejects_unpinned_context` |
| `data-structures.md:patch-result-conformant-doc` | MUST | Covered | `document::tests::construct_signed_update_round_trips` |
| `data-structures.md:target-version-id-plus-one` | MUST | Covered | `resolver::tests::metadata_version_id_is_an_ascii_string` |
| `data-structures.md:source-hash-applied-to` | MUST | Covered | `document::tests::construct_signed_update_round_trips` |
| `data-structures.md:target-hash-result-of-patch` | MUST | Covered | `document::tests::construct_signed_update_round_trips` |
| `data-structures.md:data-integrity-config-properties` | MUST | Covered | `document::tests::data_integrity_config_shape` |
| `data-structures.md:proof-context-equals-update-context` | MUST | Covered | `document::tests::apply_update_rejects_proof_context_mismatch` |
| `data-structures.md:capability-action-write` | MUST | Covered | `document::tests::data_integrity_config_shape` |
| `data-structures.md:proof-purpose-capability-invocation` | MUST | Covered | `document::tests::construct_signed_update_round_trips` |
| `data-structures.md:proof-value-detached-schnorr` | MUST | Covered | `document::tests::proof_value_is_base58btc_64_bytes` |
| `data-structures.md:smt-proofs-one-per-smt-signal` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `data-structures.md:cas-announcement-hashes-base64url` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `data-structures.md:smt-proof-nonce-base64url` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `data-structures.md:smt-proof-collapsed-bitmap` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `data-structures.md:smt-proof-hashes-sibling-nodes` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `data-structures.md:resolver-media-types` | MUST | NotApplicable | media types are a property of the HTTP DID Resolution binding; this crate returns typed Rust values, not media-typed bytes, so there is no surface to test until the binding exists |
| `data-structures.md:sidecar-maps-dids-to-update-hashes` | MUST | Covered | `resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash` |
| `data-structures.md:root-capability-map-only-properties` | MUST | Covered | `zcap::tests::test_round_trip` |
| `data-structures.md:root-capability-context` | MUST | Covered | `zcap::tests::test_round_trip` |
| `data-structures.md:root-capability-id-urn` | MUST | Covered | `zcap::tests::test_dereference_root_capability` |
| `data-structures.md:root-capability-invocation-target` | MUST | Covered | `zcap::tests::test_dereference_root_capability` |
| `data-structures.md:root-capability-controller` | MUST | Covered | `zcap::tests::test_dereference_root_capability` |
| `create.md:secp256k1-pubkey-genesis-bytes` | MUST | Covered | `document::tests::deterministically_generate` |
| `create.md:genesis-document-hashed` | MUST | Covered | `document::tests::test_from_external_intermediate` |
| `deactivate.md:add-deactivated-true` | MUST | Covered | `resolver::tests::metadata_deactivated_follows_the_document` |
| `resolve.md:input-through-decode-and-sidecar` | MUST | Covered | `resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash` |
| `resolve.md:version-id-parsed-as-integer-invalid-options` | MUST | Gap | the parse half is not exercised: the core takes typed `version_id: Option<NonZeroU64>` / `version_time: Option<DateTime>` values and the CLI accepts neither, so no shipped front end parses a string `versionId` and raises `INVALID_OPTIONS` on an unparseable value; that lands with the HTTP binding. The companion rule — `versionId` and `versionTime` together are `INVALID_OPTIONS` — is modelled (`Btcr2Error::InvalidOptions`) and covered by `resolver::tests::version_id_and_version_time_together_are_invalid_options` |
| `resolve.md:parse-did-with-decoding-algorithm` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `resolve.md:invalid-did-on-decode-error` | MUST | Covered | `identifier::tests::test_invalid_prefix` |
| `resolve.md:process-genesis-document-placeholder` | MUST | Covered | `document::tests::test_from_external_intermediate` |
| `resolve.md:render-initial-did-document-bitcoin-uri` | MUST | Covered | `document::tests::beacons_accessor` |
| `resolve.md:parse-rendered-template-conformant-doc` | MUST | Covered | `document::tests::test_document_parse` |
| `resolve.md:signal-confirmed-min-conf` | MUST NOT | Covered | `resolver::tests::signal_below_min_conf_is_skipped_and_at_min_conf_applies`, `resolver::tests::min_conf_one_applies_a_one_confirmation_signal`, `resolver::tests::unconfirmed_needed_signal_is_skipped`, `resolver::tests::pending_announcement_resolves_to_the_confirmed_version` |
| `resolve.md:update-hash-compared-to-signal` | MUST | Covered | `resolver::tests::a_sidecar_update_not_hashing_to_the_signal_bytes_is_missing_update_data` |
| `resolve.md:late-publishing-raised` | MUST | Covered | `update::tests::confirm_duplicate_in_range_mismatch_is_late_publishing` |
| `resolve.md:capability-invocation-entry-identifies-proof-vm` | MUST | Covered | `document::tests::apply_update_accepts_embedded_capability_invocation` |
| `update.md:apply-patch-invalid-did-update-on-failure` | MUST | Covered | `document::tests::construct_signed_update_rejects_failing_patch` |
| `update.md:target-version-id-from-fresh-resolution` | MUST | NotApplicable | a DID-controller operating rule: the library takes the current `versionId` as an explicit argument (`construct_signed_update`, the client's `update`/`deactivate`) and cannot observe whether the caller obtained it from a fresh resolution |
| `update.md:unsigned-update-conformant` | MUST | Covered | `update::tests::unsigned_update_has_four_contexts` |
| `update.md:invalid-did-update-capability-invocation-lacks-id` | MUST | Covered | `document::tests::update_rejects_vm_not_in_capability_invocation` |
| `update.md:invalid-did-update-referenced-vm-missing` | MUST | Covered | `document::tests::construct_signed_update_rejects_reference_to_missing_verification_method` |
| `update.md:data-integrity-config-conformant` | MUST | Covered | `document::tests::data_integrity_config_shape` |
| `terminology.md:beacon-is-singleton-smt-or-cas` | MUST | Covered | `beacon::tests::beacon_type_serde_round_trips_spec_strings` |
| `terminology.md:must-not-complete-resolution-if-data-missing` | MUST NOT | Covered | `resolver::tests::unknown_signal_hash_raises_missing_update_data` |
| `terminology.md:history-changes-detected` | MUST | Covered | `document::tests::wrong_target_version_id_fails_round_trip` |
| `terminology.md:carry-did-document-history` | MUST | Covered | `resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash` |
| `update-data-distribution.md:cas-retrieval-hash-verified` | MUST NOT | DeferredAggregation | CAS/SMT/aggregation — future milestone |
| `update-data-distribution.md:ipfs-chunking` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |

## Gap List

1 Singleton-applicable MUST/SHALL row(s) are not implemented and are listed here so
this matrix does not overstate conformance:

- `resolve.md:version-id-parsed-as-integer-invalid-options` (MUST) — Gap: the parse half is not exercised: the core takes typed `version_id: Option<NonZeroU64>` / `version_time: Option<DateTime>` values and the CLI accepts neither, so no shipped front end parses a string `versionId` and raises `INVALID_OPTIONS` on an unparseable value; that lands with the HTTP binding. The companion rule — `versionId` and `versionTime` together are `INVALID_OPTIONS` — is modelled (`Btcr2Error::InvalidOptions`) and covered by `resolver::tests::version_id_and_version_time_together_are_invalid_options`

The justified non-gaps are:

- `algorithms.md:smt-proof-fields-decoded-before-hashing` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `algorithms.md:smt-proof-verification-false-conditions` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `optimized-smt.md:smt-proof-fields-decoded-before-hashing` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `privacy-considerations.md:test-suite-consensus-splits` (MUST) — NotApplicable: non-normative test-suite design guidance, not an implementable method behavior
- `privacy-considerations.md:smt-aggregation-service-path` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:participants-persist-nonce` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:service-received-responses` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:smt-service-constructs-tree` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:cas-participant-checks-index` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:smt-participant-validates-index` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `conformance.md:bcp14-keyword-interpretation` (MUST NOT) — NotApplicable: BCP 14 boilerplate: names the RFC 2119 keywords and how to read them; imposes no requirement on an implementation
- `conformance.md:conformant-to-did-core` (MUST) — NotApplicable: umbrella conformance statement over DID-Core/Resolution; covered transitively by the specific rows below, not a single testable behavior
- `data-structures.md:json-ld-conformance` (MUST) — NotApplicable: JSON-LD 1.1 layer is out of scope (see PROJECT.md Out of Scope); JCS hashing needs are met without a general JSON-LD conformance layer
- `data-structures.md:smt-proofs-one-per-smt-signal` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `data-structures.md:cas-announcement-hashes-base64url` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `data-structures.md:smt-proof-nonce-base64url` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `data-structures.md:smt-proof-collapsed-bitmap` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `data-structures.md:smt-proof-hashes-sibling-nodes` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `data-structures.md:resolver-media-types` (MUST) — NotApplicable: media types are a property of the HTTP DID Resolution binding; this crate returns typed Rust values, not media-typed bytes, so there is no surface to test until the binding exists
- `update.md:target-version-id-from-fresh-resolution` (MUST) — NotApplicable: a DID-controller operating rule: the library takes the current `versionId` as an explicit argument (`construct_signed_update`, the client's `update`/`deactivate`) and cannot observe whether the caller obtained it from a fresh resolution
- `update-data-distribution.md:cas-retrieval-hash-verified` (MUST NOT) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `update-data-distribution.md:ipfs-chunking` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.

## Self-Check Scope

This matrix detects NEW or drifted spec MUST/SHALL rows: the INDEX cross-check guard
(`index_guard`) fails CI on any unaccounted row, and `curated_len_matches_parsed_must_rows`
fails on a row-count drift. `every_covered_row_names_a_real_test` reads the library source and
fails on any Covered citation that names no `#[test] fn` at that module path, or one that is
`#[ignore]`d, so a deleted, renamed or ignored test fails the matrix itself. Its limit:
citations must be library unit tests in inline modules (`<module>::<inline mod>::<fn>`); any
other form fails the check rather than passing it.