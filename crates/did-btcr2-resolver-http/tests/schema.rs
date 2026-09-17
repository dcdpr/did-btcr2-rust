//! Validates the document the binding returns against the W3C suite's
//! `did-schema.json`, the draft-04 schema `checkConformantDidDocument` in
//! `tests/assertions.js` feeds to Ajv.
//!
//! The schema is read at runtime from the vendored `w3c-resolution-suite`
//! submodule, so an absent or unpopulated submodule fails these tests loudly
//! rather than skipping them.

use did_btcr2::document::{Document, InitialDocument, ResolutionOptions};
use did_btcr2::identifier::Did;
use serde_json::{Value, json};

/// A regtest key-based DID; generating its initial document needs no network.
const VALID_DID: &str = "did:btcr2:k1qgpakaw4lwemekywf0lyth9hf6j8r2td7gqtrs4aztqfky50jnx7s8gfapup6";

const SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../w3c-resolution-suite/tests/did-schema.json"
);

fn schema_text() -> String {
    std::fs::read_to_string(SCHEMA_PATH).unwrap_or_else(|e| {
        panic!(
            "{SCHEMA_PATH} is absent or unreadable ({e}); the w3c-resolution-suite submodule \
             is not populated — run `git submodule update --init w3c-resolution-suite`"
        )
    })
}

fn schema() -> jsonschema::Validator {
    let value: Value = serde_json::from_str(&schema_text()).expect("did-schema.json is JSON");
    jsonschema::validator_for(&value).expect("did-schema.json compiles under its declared draft-04")
}

/// The initial document of the key-based DID, as the binding would return it.
fn resolved_document() -> Value {
    let did: Did = VALID_DID.parse().expect("a valid did:btcr2 DID");
    let document = Document::from(
        InitialDocument::from_did(&did, &ResolutionOptions::default())
            .expect("a k1 DID generates its initial document"),
    );
    document.as_ref().clone()
}

fn errors(v: &jsonschema::Validator, doc: &Value) -> Vec<String> {
    v.iter_errors(doc).map(|e| e.to_string()).collect()
}

#[test]
fn resolved_document_validates_against_did_schema() {
    let validator = schema();
    let doc = resolved_document();
    assert!(validator.is_valid(&doc), "{:?}", errors(&validator, &doc));
}

#[test]
fn document_without_id_fails_the_schema() {
    let validator = schema();
    let mut doc = resolved_document();
    doc.as_object_mut()
        .expect("a document is an object")
        .remove("id")
        .expect("the document has an id");
    assert!(!validator.is_valid(&doc));
    let errs = errors(&validator, &doc);
    assert!(
        errs.iter().any(|e| e.contains("id")),
        "an error names the missing id: {errs:?}"
    );
}

#[test]
fn verification_method_without_controller_fails_the_schema() {
    let validator = schema();
    let mut doc = resolved_document();
    doc["verificationMethod"][0]
        .as_object_mut()
        .expect("the first verification method is an object")
        .remove("controller")
        .expect("the verification method has a controller");
    assert!(!validator.is_valid(&doc), "{doc}");
}

#[test]
fn numeric_id_fails_the_schema() {
    let validator = schema();
    let mut doc = resolved_document();
    doc["id"] = json!(5);
    assert!(!validator.is_valid(&doc), "{doc}");
}

#[test]
fn schema_is_draft_04_as_the_suite_declares() {
    let value: Value = serde_json::from_str(&schema_text()).expect("did-schema.json is JSON");
    assert_eq!(
        value["$schema"],
        json!("http://json-schema.org/draft-04/schema#"),
        "the pinned suite's schema declares another draft; re-check the validator's behaviour"
    );
}
