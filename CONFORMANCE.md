# did:btcr2 Singleton Conformance Matrix

This document is rendered from `tests/conformance.rs` (the curated table is the single
source of truth). Regenerate with `BLESS=1 cargo test --test conformance conformance_md_matches_golden`.

It enumerates every did:btcr2 method-spec **MUST** / **SHALL** requirement (from the
vendored `specs-snapshot/method-spec-index.md`) and tags each with its Singleton-milestone
coverage status:

- **Covered** — exercised by a named, currently-asserting `#[test]` in the suite.
- **DeferredAggregation** — applies only to CAS / SMT / aggregation beacons; deferred to a future
  milestone (not a Singleton gap).
- **NotApplicable** — out of scope for this method implementation, with a reason.

**Totals:** 63 requirements — 52 Covered, 8 DeferredAggregation, 3 NotApplicable.

## Requirement Matrix

| ID | Keyword | Status | Test / Reason |
|----|---------|--------|---------------|
| `algorithms.md:encode-invalid-did-on-error` | MUST | Covered | `identifier::tests::test_invalid_prefix` |
| `algorithms.md:key-or-hash-genesis-bytes-variant` | MUST | Covered | `identifier::tests::test_id_type_hrps` |
| `algorithms.md:version-number-must-be-1` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `algorithms.md:decode-invalid-did-on-error` | MUST | Covered | `identifier::tests::test_invalid_genesis_length` |
| `algorithms.md:identifier-processed-per-resolution` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `algorithms.md:btcr2-version-zero-version-number` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `algorithms.md:network-value-in-table` | MUST | Covered | `identifier::tests::test_network_conversion` |
| `algorithms.md:hrp-k-or-x` | MUST | Covered | `identifier::tests::test_id_type_hrps` |
| `algorithms.md:hrp-k-genesis-bytes-33-byte` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `algorithms.md:hrp-x-genesis-bytes` | MUST | Covered | `identifier::tests::test_encode_decode_external` |
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
| `beacons.md:all-signals-processed` | MUST | Covered | `resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash` |
| `beacons.md:active-beacons-in-service` | MUST | Covered | `document::tests::beacons_accessor` |
| `beacons.md:resolvers-support-beacon-types` | MUST | Covered | `beacon::tests::beacon_type_serde_round_trips_spec_strings` |
| `conformance.md:conformant-to-did-core` | MUST | NotApplicable | umbrella conformance statement over DID-Core/Resolution; covered transitively by the specific rows below, not a single testable behavior |
| `data-structures.md:json-ld-conformance` | MUST | NotApplicable | JSON-LD 1.1 layer is out of scope (see PROJECT.md Out of Scope); JCS hashing needs are met without a general JSON-LD conformance layer |
| `data-structures.md:base64url-no-pad-encoding` | MUST | Covered | `update::tests::unsigned_update_hashes_are_base64url_no_pad` |
| `data-structures.md:did-doc-required-properties` | MUST | Covered | `document::tests::test_document_validation_missing_elements` |
| `data-structures.md:source-target-hash-json-document-hashing` | MUST | Covered | `document::tests::golden_signed_update_bytes` |
| `data-structures.md:patch-result-conformant-doc` | MUST | Covered | `document::tests::construct_signed_update_round_trips` |
| `data-structures.md:target-version-id-plus-one` | MUST | Covered | `resolver::tests::metadata_version_id_is_an_ascii_string` |
| `data-structures.md:source-hash-applied-to` | MUST | Covered | `document::tests::construct_signed_update_round_trips` |
| `data-structures.md:target-hash-result-of-patch` | MUST | Covered | `document::tests::construct_signed_update_round_trips` |
| `data-structures.md:data-integrity-config-properties` | MUST | Covered | `document::tests::data_integrity_config_shape` |
| `data-structures.md:capability-action-write` | MUST | Covered | `document::tests::data_integrity_config_shape` |
| `data-structures.md:proof-purpose-capability-invocation` | MUST | Covered | `document::tests::construct_signed_update_round_trips` |
| `data-structures.md:proof-value-detached-schnorr` | MUST | Covered | `document::tests::proof_value_is_base58btc_64_bytes` |
| `data-structures.md:cas-announcement-hashes-base64url` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |
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
| `resolve.md:parse-did-with-decoding-algorithm` | MUST | Covered | `identifier::tests::test_encode_decode_key_based` |
| `resolve.md:invalid-did-on-decode-error` | MUST | Covered | `identifier::tests::test_invalid_prefix` |
| `resolve.md:process-genesis-document-placeholder` | MUST | Covered | `document::tests::test_from_external_intermediate` |
| `resolve.md:render-initial-did-document-bitcoin-uri` | MUST | Covered | `beacon::tests::from_bip21` |
| `resolve.md:parse-rendered-template-conformant-doc` | MUST | Covered | `document::tests::test_document_parse` |
| `resolve.md:late-publishing-raised` | MUST | Covered | `update::tests::confirm_duplicate_in_range_mismatch_is_late_publishing` |
| `update.md:apply-patches-target-conformant` | MUST | Covered | `document::tests::construct_signed_update_round_trips` |
| `update.md:unsigned-update-conformant` | MUST | Covered | `update::tests::unsigned_update_has_four_contexts` |
| `update.md:invalid-did-update-vm-set-lacks-id` | MUST | Covered | `document::tests::update_rejects_unknown_vm` |
| `update.md:invalid-did-update-capability-invocation-lacks-id` | MUST | Covered | `document::tests::update_rejects_vm_not_in_capability_invocation` |
| `update.md:data-integrity-config-conformant` | MUST | Covered | `document::tests::data_integrity_config_shape` |
| `terminology.md:beacon-is-singleton-smt-or-cas` | MUST | Covered | `beacon::tests::beacon_type_serde_round_trips_spec_strings` |
| `terminology.md:must-not-complete-resolution-if-data-missing` | MUST NOT | Covered | `resolver::tests::unknown_signal_hash_raises_missing_update_data` |
| `terminology.md:history-changes-detected` | MUST | Covered | `document::tests::wrong_target_version_id_fails_round_trip` |
| `terminology.md:carry-did-document-history` | MUST | Covered | `resolver::tests::sidecar_lookup_table_keyed_by_jcs_hash` |
| `update-data-distribution.md:ipfs-chunking` | MUST | DeferredAggregation | CAS/SMT/aggregation — future milestone |

## Gap List

No Singleton-applicable MUST/SHALL is left uncovered: every requirement above is either
Covered by a test or explicitly justified as DeferredAggregation / NotApplicable. The justified
non-gaps are:

- `privacy-considerations.md:test-suite-consensus-splits` (MUST) — NotApplicable: non-normative test-suite design guidance, not an implementable method behavior
- `privacy-considerations.md:smt-aggregation-service-path` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:participants-persist-nonce` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:service-received-responses` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:smt-service-constructs-tree` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:cas-participant-checks-index` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `aggregate-beacons.md:smt-participant-validates-index` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `conformance.md:conformant-to-did-core` (MUST) — NotApplicable: umbrella conformance statement over DID-Core/Resolution; covered transitively by the specific rows below, not a single testable behavior
- `data-structures.md:json-ld-conformance` (MUST) — NotApplicable: JSON-LD 1.1 layer is out of scope (see PROJECT.md Out of Scope); JCS hashing needs are met without a general JSON-LD conformance layer
- `data-structures.md:cas-announcement-hashes-base64url` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.
- `update-data-distribution.md:ipfs-chunking` (MUST) — DeferredAggregation: CAS/SMT/aggregation, out of the Singleton scope.

## Self-Check Scope (residual)

This matrix auto-detects NEW spec MUST/SHALL rows — the INDEX cross-check guard
(`index_guard`) fails CI on any unaccounted row, and `curated_len_matches_parsed_must_rows`
fails on a row-count drift. However, a DELETED or RENAMED referenced test is caught only by
the green test suite failing elsewhere — NOT by this matrix. `every_covered_row_names_a_real_test`
only verifies that each Covered row names a test in the `KNOWN_TESTS` allow-list; a test that
is renamed AND simultaneously dropped from that list would slip past this matrix until the
suite breaks. This residual is accepted and documented (no-half-implementations constraint).