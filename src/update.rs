#![warn(clippy::unwrap_used)]

use crate::zcap::proof::Proof;
use crate::{canonical_hash::CanonicalHash, error::Btc1Error, identifier::Sha256Hash, json_tools};
use json_patch::Patch;
use onlyerror::Error;
use serde_json::Value;
use std::{fs, num::NonZeroU64, path::Path};

#[derive(Debug, Error)]
pub enum Error {
    /// I/O error
    Io(#[from] std::io::Error),

    /// JSON parse error
    Json(#[from] serde_json::Error),

    /// JSON value parse error
    JsonValue(#[from] json_tools::JsonError),

    /// Invalid targetVersionId
    InvalidTargetVersionId,
}

#[derive(Clone, Debug)]
pub struct Update {
    pub(crate) source_hash: Sha256Hash,
    pub(crate) target_hash: Sha256Hash,
    pub(crate) target_version_id: NonZeroU64,
    pub(crate) proof: Proof,
    pub(crate) patch: Patch,

    pub(crate) json: Value,
}

impl Update {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let json = fs::read_to_string(path)?;

        Self::from_json_string(&json)
    }

    pub fn from_json_string(json: &str) -> Result<Self, Error> {
        let json = serde_json::from_str(json)?;

        Self::from_json_value(json)
    }

    pub fn from_json_value(json: Value) -> Result<Self, Error> {
        use json_tools::*;

        // TODO: Can we replace this with serde?
        let source_hash = hash_from_object(&json, "sourceHash")?;
        let target_hash = hash_from_object(&json, "targetHash")?;
        // `targetVersionId` is a JSON *number*, intentionally NOT the string form
        // used by the sibling `versionId` field in DocumentMetadata
        // (`version_id_serde`). The spec carries it unquoted
        // (did-btcr2/src/data-structures.md:105-106,
        // did-btcr2/src/example-data/btcr2-signed-update.json:29) and does integer
        // arithmetic/comparison on it during resolve
        // (did-btcr2/src/operations/resolve.md:160-176: `targetVersionId - 2`,
        // `== current_version_id + 1`). Do NOT "fix" this asymmetry by accepting a
        // string here — a string-form value must be rejected as UnexpectedJsonType.
        let target_version_id = u64::try_from(int_from_object(&json, "targetVersionId")?)
            .map_err(|_| Error::InvalidTargetVersionId)?
            .try_into()
            .map_err(|_| Error::InvalidTargetVersionId)?;
        // TODO: Check whether "proof" and "path" exists as a key.
        // TODO: Remove these clones
        let proof = serde_json::from_value(json["proof"].clone())?;
        let patch = serde_json::from_value(json["patch"].clone())?;

        Ok(Self {
            source_hash,
            target_hash,
            target_version_id,
            proof,
            patch,
            json,
        })
    }

    // Spec section 7.2.2.4
    pub(crate) fn confirm_duplicate(&self, hash_history: &[Sha256Hash]) -> Result<(), Btc1Error> {
        let update_hash = UnsecuredUpdate::from(self).hash();
        // target_version_id is u64; on 32-bit hosts a sufficiently long update
        // history would overflow usize. Legitimately fallible -> Result.
        // Btc1Error::InvalidDidUpdate is the closest existing variant; we do
        // not introduce a new error variant here.
        //
        // checked_sub(2) also defends against the prior u64 underflow when
        // target_version_id == 1 (NonZeroU64 enforces non-zero, not >= 2);
        // without checked_sub, 1u64 - 2 would wrap to 0xFFFF_FFFF_FFFF_FFFF in
        // release mode and the index would then go out of bounds on hash_history.
        let update_hash_index = u64::from(self.target_version_id)
            .checked_sub(2)
            .ok_or_else(|| {
                Btc1Error::InvalidDidUpdate(
                    "target_version_id must be >= 2 for duplicate-check; got 1".into(),
                )
            })?;
        let update_hash_index = usize::try_from(update_hash_index).map_err(|_| {
            Btc1Error::InvalidDidUpdate(
                "target_version_id overflows usize on this host (32-bit limit)".into(),
            )
        })?;
        let historical_update_hash = *hash_history.get(update_hash_index).ok_or_else(|| {
            Btc1Error::InvalidDidUpdate(
                "duplicate-check index past end of update hash history".into(),
            )
        })?;

        if historical_update_hash != update_hash {
            Err(Btc1Error::late_publishing(
                update_hash,
                historical_update_hash,
            ))
        } else {
            Ok(())
        }
    }
}

impl AsRef<Value> for Update {
    fn as_ref(&self) -> &Value {
        &self.json
    }
}

impl CanonicalHash for Update {}

#[derive(Clone, Debug)]
pub(crate) struct UnsecuredUpdate {
    pub(crate) json: Value,
}

impl UnsecuredUpdate {
    /// Build an unsigned BTCR2 update directly from its inputs (the spec's
    /// "Construct BTCR2 Unsigned Update" step), independent of signing.
    ///
    /// Assembles the canonical unsigned-update JSON: the four required
    /// `@context` URLs in spec order, the JSON Patch, the source/target hashes
    /// (emitted as base64url-no-pad strings via the `Sha256Hash` serializer),
    /// and the target version id. The resulting struct hashes identically to
    /// the same JSON produced by stripping the proof off a signed `Update`,
    /// so the signing/verify paths share one canonical shape.
    pub(crate) fn construct(
        patch: &Patch,
        source_hash: Sha256Hash,
        target_hash: Sha256Hash,
        target_version_id: NonZeroU64,
    ) -> Self {
        let json = serde_json::json!({
            "@context": [
                "https://w3id.org/security/v2",
                "https://w3id.org/zcap/v1",
                "https://w3id.org/json-ld-patch/v1",
                "https://btcr2.dev/context/v1"
            ],
            "patch": patch,
            "sourceHash": source_hash,
            "targetHash": target_hash,
            "targetVersionId": u64::from(target_version_id),
        });
        Self { json }
    }
}

impl From<&Update> for UnsecuredUpdate {
    fn from(update: &Update) -> Self {
        let mut json = update.json.clone();
        if let Value::Object(map) = &mut json {
            map.remove("proof");
        }

        Self { json }
    }
}

impl AsRef<Value> for UnsecuredUpdate {
    fn as_ref(&self) -> &Value {
        &self.json
    }
}

impl CanonicalHash for UnsecuredUpdate {}

#[cfg(test)]
mod tests {
    use super::*;

    /// `confirm_duplicate` must NOT panic when the
    /// caller-supplied sidecar drives a duplicate-check index past the end of the
    /// update hash history. With `target_version_id - 2 >= hash_history.len()` the
    /// old raw slice index by position panicked out-of-bounds; the fix
    /// uses `.get(idx).ok_or_else(InvalidDidUpdate)` so the resolve path returns a
    /// typed spec error instead.
    ///
    /// The first update in `sidecar-two-updates.json` carries
    /// `targetVersionId: 2` → index 0; an EMPTY `hash_history` makes `0 >= 0`, the
    /// out-of-range path. Must return `Err(Btc1Error::InvalidDidUpdate(_))`, never
    /// a panic and never `LatePublishingError` (which is only reachable once the
    /// index is in range).
    #[test]
    fn confirm_duplicate_index_past_end_returns_err() {
        let raw = include_str!("../fixtures/spec-form/sidecar-two-updates.json");
        let value: Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let first_update_json = value["updates"][0].clone();
        let update =
            Update::from_json_value(first_update_json).expect("first fixture update parses");
        assert_eq!(u64::from(update.target_version_id), 2);

        // Empty history → update_hash_index 0 is past the end (0 >= 0).
        let hash_history: Vec<Sha256Hash> = Vec::new();
        let err = update
            .confirm_duplicate(&hash_history)
            .expect_err("out-of-range index must error, not panic");

        match err {
            Btc1Error::InvalidDidUpdate(_) => {}
            other => panic!("expected InvalidDidUpdate, got {other:?}"),
        }
    }

    /// A small RFC 6902 patch used across the construct tests.
    fn sample_patch() -> Patch {
        serde_json::from_value(serde_json::json!([
            {"op": "add", "path": "/x", "value": 1}
        ]))
        .expect("sample patch is a valid RFC 6902 op array")
    }

    /// a constructed unsigned update carries exactly the four
    /// required `@context` URLs, in spec order. The verify path requires an
    /// exact `@context` match, so a wrong or short set would break interop
    /// This pins the canonical set at construction time.
    #[test]
    fn unsigned_update_has_four_contexts() {
        let patch = sample_patch();
        let src = Sha256Hash([0x11; 32]);
        let tgt = Sha256Hash([0x22; 32]);
        let ver = NonZeroU64::new(2).expect("2 is non-zero");

        let u = UnsecuredUpdate::construct(&patch, src, tgt, ver);

        assert_eq!(
            u.as_ref()["@context"],
            serde_json::json!([
                "https://w3id.org/security/v2",
                "https://w3id.org/zcap/v1",
                "https://w3id.org/json-ld-patch/v1",
                "https://btcr2.dev/context/v1"
            ])
        );
    }

    /// the constructed unsigned update carries the expected field
    /// set — `targetVersionId` as the numeric version, `patch` round-tripping
    /// back to the input, and the two hashes serialized as JSON strings.
    #[test]
    fn unsigned_update_field_set() {
        let patch = sample_patch();
        let src = Sha256Hash([0x11; 32]);
        let tgt = Sha256Hash([0x22; 32]);
        let ver = NonZeroU64::new(2).expect("2 is non-zero");

        let u = UnsecuredUpdate::construct(&patch, src, tgt, ver);
        let json = u.as_ref();

        assert_eq!(json["targetVersionId"], serde_json::json!(2));

        let round_tripped: Patch = serde_json::from_value(json["patch"].clone())
            .expect("patch field round-trips back to a Patch");
        assert_eq!(round_tripped, patch);

        assert!(
            json["sourceHash"].is_string(),
            "sourceHash must serialize as a JSON string"
        );
        assert!(
            json["targetHash"].is_string(),
            "targetHash must serialize as a JSON string"
        );
    }

    /// Wire form: the hash strings are base64url-no-pad — they contain
    /// none of the base64-standard `+`, `/`, or padding `=` characters. Pins
    /// that the `Sha256Hash` serializer's encoding is preserved through the
    /// constructor.
    #[test]
    fn unsigned_update_hashes_are_base64url_no_pad() {
        let patch = sample_patch();
        let src = Sha256Hash([0x11; 32]);
        let tgt = Sha256Hash([0x22; 32]);
        let ver = NonZeroU64::new(2).expect("2 is non-zero");

        let u = UnsecuredUpdate::construct(&patch, src, tgt, ver);
        let json = u.as_ref();

        let source_hash = json["sourceHash"]
            .as_str()
            .expect("sourceHash is a JSON string");
        assert!(
            !source_hash.contains(['+', '/', '=']),
            "sourceHash must be base64url-no-pad (no '+', '/', or '='): {source_hash}"
        );
    }
}
