//! Root Capability derivation and management for DID:BTCR2
//!
//! This module implements the algorithms specified in section 11.4 of the DID:BTCR2
//! specification for deriving and dereferencing root capabilities.

use crate::identifier::Did;

pub(crate) mod proof;

/// Derive a root capability from a DID:BTCR2 identifier
///
/// This implements the algorithm from section 9.4.1 of the DID:BTCR2 specification:
/// "Derive Root Capability from did:btcr2 Identifier"
///
/// # Arguments
///
/// * `did_identifier` - The DID:BTCR2 identifier (e.g., "did:btcr2:k1qqpuww...")
///
/// # Returns
///
/// * `Ok(RootCapability)` - The derived root capability
/// * `Err(Error)` - If the DID identifier is invalid
pub(crate) fn derive_root_capability(did_identifier: Did) -> String {
    // Step 3: URL encode the DID identifier
    let encoded_identifier = urlencoding::encode(did_identifier.encode());

    // Step 4: Construct capability ID
    format!("urn:zcap:root:{encoded_identifier}")
}

/// Why a root capability identifier failed to dereference. Test-only, like
/// the function that returns it: the resolve path never dereferences a
/// capability URN, it compares it by equality.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RootCapabilityError {
    /// The identifier does not start with `urn:zcap:root:`.
    MissingPrefix,
    /// The percent-encoded payload did not decode to UTF-8.
    Decode,
    /// The decoded payload is not a valid `did:btcr2` identifier.
    InvalidDid,
}

/// Dereference a root capability identifier to get the capability object
///
/// This implements the algorithm from section 11.4.2 of the DID:BTCR2 specification:
/// "Dereference Root Capability Identifier"
///
/// # Arguments
///
/// * `capability_id` - The capability identifier (e.g., "urn:zcap:root:did%3Abtc1%3A...")
///
/// # Returns
///
/// * `Ok(Did)` - The dereferenced root capability as a did
/// * `Err(RootCapabilityError)` - Which prefix/decode/parse step rejected the
///   identifier
///
/// The resolve path compares the URN by equality; this inverse is kept for
/// the tests that pin the URN format.
#[cfg(test)]
pub(crate) fn dereference_root_capability(capability_id: &str) -> Result<Did, RootCapabilityError> {
    let Some(did_identifier_str) = capability_id.strip_prefix("urn:zcap:root:") else {
        return Err(RootCapabilityError::MissingPrefix);
    };

    let did = urlencoding::decode(did_identifier_str).map_err(|_| RootCapabilityError::Decode)?;

    did.parse().map_err(|_| RootCapabilityError::InvalidDid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DID: &str =
        "did:btcr2:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
    const TEST_CAP_ID: &str = "urn:zcap:root:did%3Abtcr2%3Ak1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";

    #[test]
    fn test_dereference_root_capability() {
        let root_did = dereference_root_capability(TEST_CAP_ID).unwrap();
        assert_eq!(root_did.encode(), TEST_DID);
    }

    #[test]
    fn test_dereference_root_capability_invalid_id() {
        // Invalid capability ID formats
        assert!(dereference_root_capability("invalid").is_err());
        assert!(dereference_root_capability("urn:zcap:invalid:test").is_err());
        assert!(dereference_root_capability("urn:invalid:root:test").is_err());
        assert!(dereference_root_capability("invalid:zcap:root:test").is_err());
    }

    // ---- dereference bad-payload negative tests -----------------
    //
    // A `urn:zcap:root:` capability id is attacker-supplied; a crafted id must
    // NOT dereference to a bogus/authorized Did — it must fail closed. Each of
    // the three dereference failure paths (prefix, percent-decode, DID parse)
    // returns its own `RootCapabilityError` variant, so both tests pin which
    // step did the rejecting.

    /// A valid `urn:zcap:root:` prefix wrapping a percent-encoded
    /// NON-DID payload (`not%2Da%2Ddid` decodes to `not-a-did`) is rejected —
    /// the inner `did.parse()` fails -> `RootCapabilityError::InvalidDid`.
    #[test]
    fn test_dereference_rejects_non_did_payload() {
        let err = dereference_root_capability("urn:zcap:root:not%2Da%2Ddid")
            .expect_err("a non-DID payload must not dereference");
        assert_eq!(
            err,
            RootCapabilityError::InvalidDid,
            "a non-DID payload must be rejected by the DID parse step"
        );
    }

    /// A `urn:zcap:root:` prefix wrapping a bad percent-escape (`%ZZ`)
    /// is rejected. MECHANISM (verified): `urlencoding::decode`
    /// is LENIENT — on `%ZZ` it passes the literal `%` through and yields the
    /// valid-UTF-8 string `%ZZ`, returning `Ok` (it only errors on non-UTF-8
    /// bytes). So this input does NOT trip the decode-error arm; the
    /// rejection arrives one step later when the decoded string fails to parse as
    /// a Did. This test binds fail-closed REJECTION via the downstream
    /// DID-parse path — it does NOT exercise a percent-decode failure (so it does
    /// not overclaim the decode-failure mechanism).
    #[test]
    fn test_dereference_rejects_bad_percent_encoding() {
        let err = dereference_root_capability("urn:zcap:root:%ZZ")
            .expect_err("a bad-percent-encoding payload must not dereference");
        assert_eq!(
            err,
            RootCapabilityError::InvalidDid,
            "a lenient percent-decode must still be rejected by the DID parse step"
        );
    }

    #[test]
    fn test_round_trip() {
        // Derive capability from DID
        let root_capability_id = derive_root_capability(TEST_DID.parse().unwrap());

        // Dereference the capability ID
        let dereferenced_did = dereference_root_capability(&root_capability_id).unwrap();

        assert_eq!(TEST_DID, dereferenced_did.encode());
    }
}
