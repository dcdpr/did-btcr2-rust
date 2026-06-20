//! Root Capability derivation and management for DID:BTCR2
//!
//! This module implements the algorithms specified in section 11.4 of the DID:BTCR2
//! specification for deriving and dereferencing root capabilities.

use crate::error::Btcr2Error;
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
/// * `Err(Error)` - If the capability ID is invalid
pub(crate) fn dereference_root_capability(capability_id: &str) -> Result<Did, Btcr2Error> {
    let Some(did_identifier_str) = capability_id.strip_prefix("urn:zcap:root:") else {
        return Err(Btcr2Error::Zcap("invalid root capability".into()));
    };

    let did = urlencoding::decode(did_identifier_str)
        .map_err(|e| Btcr2Error::Zcap(format!("Failed to decode DID from capability ID: {e:?}")))?;

    did.parse()
        .map_err(|err| Btcr2Error::Zcap(format!("Invalid DID in root capability: {err}")))
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

    #[test]
    fn test_round_trip() {
        // Derive capability from DID
        let root_capability_id = derive_root_capability(TEST_DID.parse().unwrap());

        // Dereference the capability ID
        let dereferenced_did = dereference_root_capability(&root_capability_id).unwrap();

        assert_eq!(TEST_DID, dereferenced_did.encode());
    }
}
