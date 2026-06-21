#![warn(clippy::unwrap_used)]
//! # DID:BTCR2 Encoding
//!
//! This crate provides encoding and decoding functionality for DID:BTCR2 identifiers
//! as specified in the DID:BTCR2 DID Method Specification.
//!
//! ## DID:BTCR2 Identifier Format
//!
//! A DID:BTCR2 identifier consists of:
//! - `did:btcr2:` prefix
//! - Bech32m-encoded data containing:
//!   - Version (4 bits)
//!   - Network identifier (4 bits)
//!   - Genesis bytes (32 bytes for key-based, variable for external)
//!
//! ## Examples
//!
//! ```rust
//! use did_btcr2::identifier::{Network, IdType, Error, DidVersion, Did};
//! use did_btcr2::key::{PublicKeyExt};
//!
//! // Parse a DID identifier
//! let didstr = "did:btcr2:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
//!
//! let did: Did = didstr.parse()?;
//!
//! let components = did.components();
//!
//! assert_eq!(components.version(), DidVersion::One);
//! assert_eq!(components.network(), Network::Mainnet);
//! assert!(matches!(components.id_type(), IdType::Key(_)));
//!
//! if let Some(public_key) = did.public_key() {
//!     println!("{}", public_key.to_multikey());
//! }
//!
//! # Ok::<(), Error>(())
//! ```

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bech32_rust::{Bech32Error, DecodedResult, decode, encode};
use onlyerror::Error;
use secp256k1::{PublicKey, constants::PUBLIC_KEY_SIZE};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

/// The DID method prefix for BTCR2 identifiers
pub const DID_BTCR2_PREFIX: &str = "did:btcr2:";

/// Human-readable part for key-based DID identifiers
pub const HRP_KEY: &str = "k";

/// Human-readable part for external document-based DID identifiers
pub const HRP_EXTERNAL: &str = "x";

/// Expected length of a SHA-256 hash
pub const SHA256_HASH_LEN: usize = 32;

/// Errors that can occur during DID identifier encoding/decoding
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid DID format - missing or incorrect prefix
    #[error("Invalid DID format: {0}")]
    InvalidDidFormat(String),

    /// Invalid version number
    #[error("Invalid version: {0} (must be 1-16)")]
    InvalidVersion(u8),

    /// Invalid network identifier
    #[error("Invalid network identifier: {0}")]
    InvalidNetwork(u8),

    /// Invalid human-readable part
    #[error("Invalid HRP: {0} (must be 'k' or 'x')")]
    InvalidHrp(String),

    /// Invalid genesis bytes length
    #[error("Invalid genesis bytes length: {0} (expected {1})")]
    InvalidGenesisLength(usize, usize),

    /// Bech32 encoding/decoding error
    #[error("Bech32 error: {0}")]
    Bech32(#[from] Bech32Error),

    /// Invalid identifier type
    #[error("Invalid identifier type: {0}")]
    InvalidIdType(String),

    /// Invalid secp256k1 public key (length-correct but not a valid curve point)
    #[error("Invalid secp256k1 public key point: {0}")]
    InvalidPublicKeyPoint(secp256k1::Error),

    /// Error with key operations
    Key(#[from] crate::key::Error),

    /// Invalid hash length
    InvalidHashLength,
}

/// Extension trait for types that may carry a Bitcoin [`Network`] hint.
pub trait TryNetworkExt {
    /// The Bitcoin network this value designates, if any.
    fn try_network(&self) -> Option<Network> {
        None
    }
}

impl TryNetworkExt for String {}

/// A parsed and validated did:btcr2 identifier: the Bech32m-encoded string
/// together with its decoded [`DidComponents`] (version, network, id type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Did {
    encoded: String,
    components: DidComponents,
}

impl FromStr for Did {
    type Err = Error;

    fn from_str(did: &str) -> Result<Self, Self::Err> {
        let components = parse_did_identifier(did)?;

        Ok(Self {
            encoded: did.to_string(),
            components,
        })
    }
}

impl TryFrom<DidComponents> for Did {
    type Error = Error;

    fn try_from(components: DidComponents) -> Result<Self, Self::Error> {
        let encoded =
            encode_did_identifier(components.version, components.network, components.id_type)?;

        Ok(Self {
            encoded,
            components,
        })
    }
}

impl Did {
    /// The Bech32m-encoded `did:btcr2:...` string form of this identifier.
    pub fn encode(&self) -> &str {
        &self.encoded
    }

    /// The decoded components (version, network, id type) of this identifier.
    pub fn components(&self) -> &DidComponents {
        &self.components
    }

    /// The genesis public key for a key-based DID, or `None` for an
    /// external (`x`) identifier.
    pub fn public_key(&self) -> Option<PublicKey> {
        match self.components.id_type {
            IdType::Key(key) => PublicKey::from_slice(&key).ok(),
            IdType::External(_) => None,
        }
    }

    pub(crate) fn public_key_unchecked(&self) -> PublicKey {
        match self.components.id_type {
            IdType::Key(key) => PublicKey::from_slice(&key).expect(
                "IdType::Key bytes were validated as a valid secp256k1 point at parse time in IdType::try_from",
            ),
            IdType::External(_) => unreachable!(
                "public_key_unchecked called on an External id type — callers must check id_type first"
            ),
        }
    }
}

impl TryNetworkExt for Did {
    fn try_network(&self) -> Option<Network> {
        Some(self.components.network)
    }
}

/// DID:BTCR2 encoding version
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DidVersion {
    /// Version 1 — the only version defined by the current did:btcr2 spec.
    #[default]
    One = 1,
}

impl TryFrom<u8> for DidVersion {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::One),
            _ => Err(Error::InvalidVersion(value)),
        }
    }
}

impl From<DidVersion> for u8 {
    fn from(value: DidVersion) -> Self {
        value as u8
    }
}

/// Bitcoin networks supported by DID:BTCR2
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Network {
    /// Bitcoin mainnet
    #[default]
    Mainnet = 0,
    /// Bitcoin signet
    Signet = 1,
    /// Bitcoin regtest
    Regtest = 2,
    /// Bitcoin testnet v3
    TestnetV3 = 3,
    /// Bitcoin testnet v4
    TestnetV4 = 4,
    /// Mutinynet
    Mutinynet = 5,
    /// Custom test network (6-11)
    Custom(u8),
}

impl TryFrom<u8> for Network {
    type Error = Error;
    fn try_from(nibble: u8) -> Result<Self, Self::Error> {
        match nibble {
            0 => Ok(Network::Mainnet),
            1 => Ok(Network::Signet),
            2 => Ok(Network::Regtest),
            3 => Ok(Network::TestnetV3),
            4 => Ok(Network::TestnetV4),
            5 => Ok(Network::Mutinynet),
            6..=15 => Ok(Network::Custom(nibble)),
            _ => Err(Error::InvalidNetwork(nibble)),
        }
    }
}

impl From<Network> for u8 {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => 0,
            Network::Signet => 1,
            Network::Regtest => 2,
            Network::TestnetV3 => 3,
            Network::TestnetV4 => 4,
            Network::Mutinynet => 5,
            Network::Custom(n) => n,
        }
    }
}

impl TryFrom<Network> for esploda::bitcoin::Network {
    type Error = Error;

    fn try_from(value: Network) -> Result<Self, Error> {
        match value {
            Network::Mainnet => Ok(Self::Bitcoin),
            Network::TestnetV3 => Ok(Self::Testnet),
            Network::Regtest => Ok(Self::Regtest),
            Network::Signet | Network::Mutinynet => Ok(Self::Signet),
            _ => Err(Error::InvalidNetwork(u8::from(value))),
        }
    }
}

/// Type of DID identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdType {
    // TODO: Replace array with `PublicKey`
    /// Key-based identifier (secp256k1 public key)
    Key([u8; PUBLIC_KEY_SIZE]),

    /// External document-based identifier (hash of external document)
    External(Sha256Hash),
}

/// Represents a SHA-256 hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Hash(pub [u8; SHA256_HASH_LEN]);

// data-structures.md §sidecar-data — base64url-no-pad encoding for hashes.
// Manual impls (NOT derive(Serialize, Deserialize)) because the default derive
// on a tuple struct around [u8; 32] would emit a JSON array of 32 numbers, not
// a base64url string.
impl Serialize for Sha256Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = URL_SAFE_NO_PAD.encode(self.0);
        // Emit a plain JSON string (NOT an array of bytes). serde_jcs uses
        // the same Serialize trait, so JCS-canonical output is identical to
        // serde_json's output for this type — preserves hash integrity per
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Sha256Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| D::Error::custom(format!("invalid base64url-no-pad hash: {e}")))?;
        let arr: [u8; SHA256_HASH_LEN] = bytes.try_into().map_err(|v: Vec<u8>| {
            D::Error::custom(format!(
                "expected {} bytes, got {}",
                SHA256_HASH_LEN,
                v.len()
            ))
        })?;
        Ok(Sha256Hash(arr))
    }
}

impl TryFrom<&DecodedResult> for IdType {
    type Error = Error;

    fn try_from(decoded: &DecodedResult) -> Result<Self, Self::Error> {
        if decoded.dp.is_empty() {
            return Err(Error::InvalidDidFormat(
                "No data in DID identifier".to_string(),
            ));
        }

        // Validate bytes length
        let expected_len = match decoded.hrp.as_str() {
            HRP_KEY => PUBLIC_KEY_SIZE,
            HRP_EXTERNAL => SHA256_HASH_LEN,
            _ => return Err(Error::InvalidHrp(decoded.hrp.clone())),
        };

        let actual_len = decoded.dp[1..].len();
        if actual_len != expected_len {
            return Err(Error::InvalidGenesisLength(actual_len, expected_len));
        }

        // Determine identifier type from HRP
        match decoded.hrp.as_str() {
            HRP_KEY => {
                // Length already checked above (actual_len == PUBLIC_KEY_SIZE).
                let payload: [u8; PUBLIC_KEY_SIZE] = decoded.dp[1..].try_into().expect(
                    "decoded.dp[1..] has length PUBLIC_KEY_SIZE per length check immediately above",
                );
                // Parse, don't validate: reject 33-byte payloads that are not a
                // valid secp256k1 curve point. This makes `Did::public_key_unchecked`
                // a statically-guaranteed success.
                PublicKey::from_slice(&payload).map_err(Error::InvalidPublicKeyPoint)?;
                Ok(IdType::Key(payload))
            }
            HRP_EXTERNAL => {
                let payload: [u8; SHA256_HASH_LEN] = decoded.dp[1..].try_into().expect(
                    "decoded.dp[1..] has length SHA256_HASH_LEN per length check immediately above",
                );
                Ok(IdType::External(Sha256Hash(payload)))
            }
            _ => unreachable!("HRP filtered to HRP_KEY/HRP_EXTERNAL by expected_len match above"),
        }
    }
}

impl From<PublicKey> for IdType {
    fn from(key: PublicKey) -> Self {
        Self::Key(key.serialize())
    }
}

impl IdType {
    /// Create External from byte slice. Slice must be exactly 32 bytes long.
    pub fn from_sha256_hash(hash: &[u8]) -> Result<Self, Error> {
        Ok(IdType::External(Sha256Hash(
            hash.try_into().map_err(|_| Error::InvalidHashLength)?,
        )))
    }

    /// Get the human-readable part for this identifier type
    pub fn hrp(&self) -> &'static str {
        match self {
            IdType::Key(_) => HRP_KEY,
            IdType::External(_) => HRP_EXTERNAL,
        }
    }
}

/// Components of a parsed DID:BTCR2 identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidComponents {
    /// Specification version (1-16)
    version: DidVersion,
    /// Bitcoin network
    network: Network,
    /// Identifier type
    id_type: IdType,
}

impl DidComponents {
    /// Create new DID components with validation
    pub fn new(version: DidVersion, network: Network, id_type: IdType) -> Self {
        Self {
            version,
            network,
            id_type,
        }
    }

    /// The did:btcr2 encoding version.
    pub fn version(&self) -> DidVersion {
        self.version
    }

    /// The Bitcoin network this identifier is anchored to.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The identifier type (key-based or external).
    pub fn id_type(&self) -> IdType {
        self.id_type
    }
}

/// Parse a DID:BTCR2 identifier string into its components
///
/// # Arguments
///
/// * `did` - The DID identifier string to parse
///
/// # Returns
///
/// * `Ok(DidComponents)` - The parsed components
/// * `Err(Error)` - If parsing fails
///
/// # Examples
///
/// ```rust
/// use did_btcr2::identifier::{parse_did_identifier, Network, IdType, Error, DidVersion};
///
/// let did = "did:btcr2:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
/// let components = parse_did_identifier(did)?;
///
/// assert_eq!(components.version(), DidVersion::One);
/// assert_eq!(components.network(), Network::Mainnet);
/// assert!(matches!(components.id_type(), IdType::Key(_)));
/// # Ok::<(), Error>(())
/// ```
pub fn parse_did_identifier(did: &str) -> Result<DidComponents, Error> {
    // Check DID prefix
    if !did.starts_with(DID_BTCR2_PREFIX) {
        return Err(Error::InvalidDidFormat(format!(
            "DID must start with '{DID_BTCR2_PREFIX}'",
        )));
    }

    // Extract the bech32 part
    let bech32_part = &did[DID_BTCR2_PREFIX.len()..];

    // Decode the bech32 string
    let decoded = decode(bech32_part)?;

    // Determine identifier type from HRP
    let id_type = IdType::try_from(&decoded)?;

    // First byte contains version (high nibble) and network (low nibble)
    let version_network_byte = decoded.dp[0];
    let version = ((version_network_byte >> 4) & 0x0F) + 1; // High nibble + 1
    let network_nibble = version_network_byte & 0x0F; // Low nibble
    let network = Network::try_from(network_nibble)?;

    // Create and validate components
    Ok(DidComponents::new(version.try_into()?, network, id_type))
}

/// Encode DID components into a DID:BTCR2 identifier string
///
/// # Arguments
///
/// * `version` - Specification version (1-16)
/// * `network` - Bitcoin network
/// * `id_type` - Identifier type
/// * `genesis_bytes` - Genesis data (public key or hash)
///
/// # Returns
///
/// * `Ok(String)` - The encoded DID identifier
/// * `Err(Error)` - If encoding fails
fn encode_did_identifier(
    version: DidVersion,
    network: Network,
    id_type: IdType,
) -> Result<String, Error> {
    let genesis_bytes = match &id_type {
        IdType::Key(key) => &key[..],
        IdType::External(Sha256Hash(hash)) => &hash[..],
    };

    // Build the data payload
    let mut data = Vec::with_capacity(1 + genesis_bytes.len());

    // First byte: version (high nibble) + network (low nibble)
    let version_nibble = (u8::from(version) - 1) & 0x0F; // Version - 1, mask to 4 bits
    let network_nibble = u8::from(network) & 0x0F; // Mask to 4 bits
    let version_network_byte = (version_nibble << 4) | network_nibble;
    data.push(version_network_byte);

    // Add genesis bytes
    data.extend_from_slice(genesis_bytes);

    // Encode with bech32m
    let bech32_part = encode(id_type.hrp(), &data)?;

    // Construct full DID
    Ok(format!("{DID_BTCR2_PREFIX}{bech32_part}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    impl From<&[u8]> for IdType {
        fn from(bytes: &[u8]) -> Self {
            match bytes.len() {
                PUBLIC_KEY_SIZE => IdType::Key(bytes.try_into().unwrap()),
                SHA256_HASH_LEN => IdType::External(Sha256Hash(bytes.try_into().unwrap())),
                _ => unreachable!(),
            }
        }
    }

    /// Returns a valid 33-byte compressed secp256k1 public key (derived from
    /// secret key = [0x01; 32]). Required because parse-time curve-point
    /// validation rejects the previously-used all-zero placeholder.
    fn valid_secp256k1_pubkey_bytes() -> [u8; PUBLIC_KEY_SIZE] {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32])
            .expect("0x01..0x01 is a valid secp256k1 secret key");
        sk.public_key(&secp).serialize()
    }

    #[test]
    fn test_network_conversion() {
        assert_eq!(Network::try_from(0).unwrap(), Network::Mainnet);
        assert_eq!(Network::try_from(1).unwrap(), Network::Signet);
        assert_eq!(Network::try_from(5).unwrap(), Network::Mutinynet);
        assert_eq!(Network::try_from(12).unwrap(), Network::Custom(12));
        assert!(Network::try_from(16).is_err());

        assert_eq!(u8::from(Network::Mainnet), 0);
        assert_eq!(u8::from(Network::Signet), 1);
        assert_eq!(u8::from(Network::Custom(12)), 12);
    }

    #[test]
    fn test_id_type_hrps() {
        let key = IdType::from(&[0_u8; PUBLIC_KEY_SIZE][..]);
        assert_eq!(key.hrp(), "k");

        let hash = IdType::from(&[0_u8; SHA256_HASH_LEN][..]);
        assert_eq!(hash.hrp(), "x");
    }

    #[test]
    fn test_encode_decode_key_based() {
        // Encode->parse round-trip requires a valid curve point,
        // because parse-time validation now rejects non-curve-point payloads.
        let key = IdType::from(&valid_secp256k1_pubkey_bytes()[..]);

        let did_str = encode_did_identifier(DidVersion::One, Network::Mainnet, key).unwrap();

        assert!(did_str.starts_with("did:btcr2:k1"));

        let components = parse_did_identifier(&did_str).unwrap();
        assert_eq!(u8::from(components.version), 1);
        assert_eq!(components.network, Network::Mainnet);
        assert_eq!(components.id_type, key);
    }

    #[test]
    fn did_with_non_curve_point_payload_is_rejected() {
        // a DID with HRP=`k` and a 33-byte payload that is
        // length-correct but is NOT a valid secp256k1 curve point must be
        // rejected at parse time. Previously, parsing succeeded and the
        // panic happened later in Did::public_key_unchecked() — an
        // attacker-controlled-input panic on the resolve happy path.

        // Construct a payload of 33 zero bytes. The secp256k1 library
        // rejects the all-zero key (it is not on the curve).
        let bad_payload = [0u8; PUBLIC_KEY_SIZE];

        // Build the encoded data: 1 version/network byte + 33 payload bytes.
        let mut data = Vec::with_capacity(1 + bad_payload.len());
        data.push(0u8); // version=1 (high nibble 0), network=Mainnet (low nibble 0)
        data.extend_from_slice(&bad_payload);

        let bech32_part = encode(HRP_KEY, &data).expect("HRP and data are valid bech32m inputs");
        let did_str = format!("{DID_BTCR2_PREFIX}{bech32_part}");

        // Must fail to parse — and specifically with InvalidPublicKeyPoint.
        let err = did_str
            .parse::<Did>()
            .expect_err("non-curve-point payload must be rejected at parse time");
        assert!(
            matches!(err, Error::InvalidPublicKeyPoint(_)),
            "expected InvalidPublicKeyPoint, got: {err:?}"
        );
    }

    #[test]
    fn test_encode_decode_external() {
        let hash = IdType::from(&[255_u8; SHA256_HASH_LEN][..]);

        let did = encode_did_identifier(DidVersion::One, Network::Signet, hash).unwrap();

        assert!(did.starts_with("did:btcr2:x1"));

        let components = parse_did_identifier(&did).unwrap();
        assert_eq!(u8::from(components.version), 1);
        assert_eq!(components.network, Network::Signet);
        assert_eq!(components.id_type, hash);
    }

    #[test]
    fn test_invalid_prefix() {
        let result = parse_did_identifier("did:example:123");
        assert!(matches!(result, Err(Error::InvalidDidFormat(_))));

        // the old on-wire prefix `did:btc1:` is hard-rejected with a typed
        // error (no back-compat acceptance path), never a panic.
        let legacy = parse_did_identifier(
            "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx",
        );
        assert!(matches!(legacy, Err(Error::InvalidDidFormat(_))));
    }

    #[test]
    fn test_invalid_genesis_length() {
        let encoded = bech32_rust::encode(HRP_KEY, b"foo").unwrap();
        let dr: DecodedResult = decode(encoded).unwrap();

        let id_type = IdType::try_from(&dr);
        assert!(matches!(id_type, Err(Error::InvalidGenesisLength(_, _))));
    }

    #[test]
    fn test_custom_network() {
        // Encode->parse round-trip requires a valid curve point.
        let key = IdType::from(&valid_secp256k1_pubkey_bytes()[..]);
        let did = encode_did_identifier(DidVersion::One, Network::Custom(15), key).unwrap();

        let components = parse_did_identifier(&did).unwrap();
        assert_eq!(components.network, Network::Custom(15));
    }
}

#[cfg(test)]
mod sha256_hash_serde_tests {
    use super::*;

    #[test]
    fn sha256_hash_round_trips_as_base64url_no_pad() {
        // Spec: did-btcr2/src/data-structures.md lines 14-15 — base64url-no-pad
        // encoding for all hashes.
        let bytes = [0x42u8; 32];
        let hash = Sha256Hash(bytes);

        // Verified base64url-no-pad of [0x42; 32]: 43 chars, no padding.
        let expected = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";

        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, format!("\"{expected}\""));

        // serde_jcs and serde_json must produce identical bytes for a
        // Sha256Hash.
        let jcs = serde_jcs::to_string(&hash).unwrap();
        assert_eq!(jcs, format!("\"{expected}\""));

        let parsed: Sha256Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, hash);
    }

    #[test]
    fn sha256_hash_rejects_padded_base64url() {
        let padded = "\"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=\"";
        assert!(serde_json::from_str::<Sha256Hash>(padded).is_err());
    }

    #[test]
    fn sha256_hash_rejects_short_input() {
        // 16-byte hash should be rejected (wrong length).
        let short = "\"QkJCQkJCQkJCQkJCQkJCQg\""; // 16 bytes of 0x42
        assert!(serde_json::from_str::<Sha256Hash>(short).is_err());
    }
}
