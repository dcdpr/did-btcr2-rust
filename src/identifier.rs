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
    #[error("invalid did:btcr2 version {0}: only version 1 is defined")]
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
            IdType::Key(key) => Some(key),
            IdType::External(_) => None,
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
    /// Custom test network (values 12 to 14)
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
            // Spec algorithms.md Table 1: only 12..=14 is the custom partition;
            // 6..=11 are reserved and 15 is undefined — reject both.
            12..=14 => Ok(Network::Custom(nibble)),
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
    /// Key-based identifier (validated secp256k1 public key)
    Key(PublicKey),

    /// External document-based identifier (hash of external document)
    External(Sha256Hash),
}

/// Represents a SHA-256 hash.
///
/// The inner bytes are private: a `Sha256Hash` is minted only through
/// [`From<[u8; SHA256_HASH_LEN]>`] (infallible, for compile-time-sized data) or
/// [`TryFrom<Vec<u8>>`] (length-validating, for runtime byte data). Any 32-byte
/// array is a valid hash — there is no value invariant beyond length — so the
/// standard fixed-size-newtype split applies (single `TryFrom<Vec<u8>>` + `From`),
/// unlike `SecretKey` which needs two fallible constructors for its scalar
/// invariant. Raw bytes leave the newtype only via [`Sha256Hash::as_bytes`], at
/// the hex/wire point of use; there are deliberately no hex-conversion
/// convenience methods on the newtype (callers do `hex::encode(h.as_bytes())`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Hash([u8; SHA256_HASH_LEN]);

impl From<[u8; SHA256_HASH_LEN]> for Sha256Hash {
    fn from(bytes: [u8; SHA256_HASH_LEN]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<Vec<u8>> for Sha256Hash {
    type Error = Error;

    fn try_from(v: Vec<u8>) -> Result<Self, Error> {
        let arr: [u8; SHA256_HASH_LEN] = v.try_into().map_err(|_| Error::InvalidHashLength)?;
        Ok(Self(arr))
    }
}

impl Sha256Hash {
    /// The raw 32 hash bytes. Extract only at the hex/wire point of use.
    pub fn as_bytes(&self) -> &[u8; SHA256_HASH_LEN] {
        &self.0
    }
}

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
        let s = String::deserialize(deserializer)?;
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
                // valid secp256k1 curve point, and STORE the parsed key so a
                // non-curve-point key can never enter a `Did`.
                let key = PublicKey::from_slice(&payload).map_err(Error::InvalidPublicKeyPoint)?;
                Ok(IdType::Key(key))
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
        Self::Key(key)
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
    /// Create validated DID components.
    ///
    /// Rejects a [`Network::Custom`] whose nibble is outside the spec's custom
    /// partition `12..=14` with [`Error::InvalidNetwork`], so a hand-built
    /// out-of-range Custom network can never enter a validated identifier. The
    /// other inputs are already type-constrained (`DidVersion` has a single
    /// variant; the named `Network` variants are all valid).
    pub fn new(version: DidVersion, network: Network, id_type: IdType) -> Result<Self, Error> {
        if let Network::Custom(n) = network
            && !(12..=14).contains(&n)
        {
            return Err(Error::InvalidNetwork(n));
        }
        Ok(Self {
            version,
            network,
            id_type,
        })
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
/// Private to match its private inverse [`encode_did_identifier`]; external
/// callers reach it through the public [`Did`] `FromStr` impl. The former
/// public doctest is preserved as the `parse_did_identifier_decodes_key_based`
/// unit test.
fn parse_did_identifier(did: &str) -> Result<DidComponents, Error> {
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
    DidComponents::new(version.try_into()?, network, id_type)
}

/// Encode DID components into a DID:BTCR2 identifier string
///
/// # Arguments
///
/// * `version` - Specification version (only version 1 is defined)
/// * `network` - Bitcoin network
/// * `id_type` - Identifier type (carries the genesis public key or hash)
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
    let key_bytes;
    let genesis_bytes = match &id_type {
        IdType::Key(key) => {
            key_bytes = key.serialize();
            &key_bytes[..]
        }
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
                PUBLIC_KEY_SIZE => IdType::Key(PublicKey::from_slice(bytes).unwrap()),
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
        // `IdType::Key` now stores a validated PublicKey, so the helper needs a
        // real curve point rather than the former all-zero placeholder.
        let key = IdType::from(&valid_secp256k1_pubkey_bytes()[..]);
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
        // rejected at parse time. Previously, parsing stored the raw bytes and
        // a later key access re-parsed them, risking an attacker-controlled
        // panic on the resolve happy path; `IdType::Key` now holds a validated
        // key, so a non-curve-point payload cannot enter a `Did` at all.

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
        // Only the spec's custom partition 12..=14 decodes as Custom.
        // Encode->parse round-trip requires a valid curve point.
        let key = IdType::from(&valid_secp256k1_pubkey_bytes()[..]);
        for n in 12..=14u8 {
            let did = encode_did_identifier(DidVersion::One, Network::Custom(n), key).unwrap();
            let components = parse_did_identifier(&did).unwrap();
            assert_eq!(components.network, Network::Custom(n));
        }

        // Reserved (6..=11) and undefined (15) nibbles are typed-rejected.
        for n in [6u8, 11, 15] {
            assert!(
                matches!(Network::try_from(n), Err(Error::InvalidNetwork(m)) if m == n),
                "network nibble {n} must be rejected as InvalidNetwork"
            );
        }
    }

    /// A hand-built out-of-range `Network::Custom` cannot enter a
    /// validated `DidComponents` — `new` rejects it with `InvalidNetwork`.
    #[test]
    fn did_components_new_rejects_out_of_range_custom_network() {
        let key = IdType::from(&valid_secp256k1_pubkey_bytes()[..]);
        assert!(
            matches!(
                DidComponents::new(DidVersion::One, Network::Custom(200), key),
                Err(Error::InvalidNetwork(200))
            ),
            "Custom(200) must be rejected by DidComponents::new"
        );
        // And an in-range Custom is accepted.
        assert!(DidComponents::new(DidVersion::One, Network::Custom(13), key).is_ok());
    }

    /// Migrated from the former public `parse_did_identifier` doctest
    /// (now private). Pins the same fixed-string decode assertions.
    #[test]
    fn parse_did_identifier_decodes_key_based() {
        let did = "did:btcr2:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
        let components = parse_did_identifier(did).unwrap();

        assert_eq!(components.version(), DidVersion::One);
        assert_eq!(components.network(), Network::Mainnet);
        assert!(matches!(components.id_type(), IdType::Key(_)));
    }

    // ---- parse-edge negative tests -----------------
    //
    // Bech32m identifiers are attacker-supplied strings; malformed inputs must
    // fail closed with a typed error, never a panic. Variants confirmed against
    // source: version-nibble -> InvalidVersion (identifier.rs:200 via
    // parse_did_identifier's `version.try_into()` at :476), malformed bech32 ->
    // Bech32 (decode at :464), from_sha256_hash wrong length -> the UNIT variant
    // InvalidHashLength (identifier.rs:378), distinct from InvalidGenesisLength
    // (the bech32-decode length path at :341).

    /// A first byte with a non-zero high nibble decodes to version >= 2
    /// (`version = (high_nibble) + 1`, identifier.rs:471), which `DidVersion::try_from`
    /// rejects (identifier.rs:200) as `InvalidVersion`. The payload is a VALID
    /// curve point so parsing reaches the version check AFTER `IdType::try_from`
    /// (identifier.rs:467) succeeds.
    #[test]
    fn test_id_type_rejects_invalid_version() {
        let key = valid_secp256k1_pubkey_bytes();
        // High nibble 1 -> version 2; low nibble 0 -> Mainnet.
        let mut data = Vec::with_capacity(1 + key.len());
        data.push(0x10);
        data.extend_from_slice(&key);

        let bech32_part = encode(HRP_KEY, &data).expect("HRP and data are valid bech32m inputs");
        let did_str = format!("{DID_BTCR2_PREFIX}{bech32_part}");

        let result = parse_did_identifier(&did_str);
        assert!(
            matches!(result, Err(Error::InvalidVersion(_))),
            "version >= 2 must be rejected, got {result:?}"
        );
    }

    /// A `did:btcr2:` string whose bech32 body has a corrupted checksum
    /// fails at `decode` (identifier.rs:464) -> `Error::Bech32`. Mirrors
    /// `test_invalid_prefix`'s shape but drives the bech32 decode path, not the
    /// prefix path.
    #[test]
    fn test_from_str_rejects_malformed_bech32() {
        // Valid prefix + valid HRP `k1`, but the payload/checksum is corrupt.
        let result = parse_did_identifier("did:btcr2:k1qqqqqqqqqqqqqqqqqqqqqqqqqqq");
        assert!(
            matches!(result, Err(Error::Bech32(_))),
            "malformed bech32 must be rejected as Bech32, got {result:?}"
        );
    }

    /// `IdType::from_sha256_hash` with a wrong-length slice hits
    /// `hash.try_into().map_err(|_| Error::InvalidHashLength)` (identifier.rs:378),
    /// returning the UNIT variant `InvalidHashLength` — distinct from
    /// `InvalidGenesisLength(_, _)`, which belongs to the bech32-decode path.
    #[test]
    fn test_from_sha256_hash_rejects_wrong_length() {
        assert!(
            matches!(
                IdType::from_sha256_hash(&[0u8; 31]),
                Err(Error::InvalidHashLength)
            ),
            "a 31-byte slice must be rejected as InvalidHashLength"
        );
    }

    /// `Did::public_key` returns `None` for an External (`x1…`) id —
    /// there is no genesis public key for an external identifier. Positive-shape
    /// assertion pinning the discriminated behavior (identifier.rs:161-166).
    #[test]
    fn test_public_key_none_for_external_id() {
        let hash = IdType::from(&[0xAB_u8; SHA256_HASH_LEN][..]);
        let did_str = encode_did_identifier(DidVersion::One, Network::Signet, hash)
            .expect("external id encodes");
        let did: Did = did_str.parse().expect("external DID parses");
        assert!(
            did.public_key().is_none(),
            "an External id must have no genesis public key"
        );
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

    #[test]
    fn sha256_hash_deserializes_escaped_string() {
        // A JSON string carrying an escape sequence cannot be zero-copy-borrowed,
        // so a borrowed-`&str` deserialize impl would error on the *borrow* before ever
        // inspecting the hash content. The owned-`String` impl allocates and then
        // decodes the same valid base64url-no-pad hash. The leading 'Q' (U+0051)
        // of the canonical [0x42; 32] encoding is written as the JSON escape
        // `Q`; the decoded content is identical to the unescaped form.
        let expected = Sha256Hash([0x42u8; 32]);
        let escaped = "\"\\u0051kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI\"";

        let parsed: Sha256Hash = serde_json::from_str(escaped)
            .expect("escaped but valid base64url-no-pad hash must deserialize Ok");
        assert_eq!(parsed, expected);
    }
}

#[cfg(test)]
mod sha256_hash_newtype_tests {
    use super::*;

    // The hardened newtype rejects a wrong-length runtime `Vec<u8>` with the
    // typed `Error::InvalidHashLength` (the same length variant used by
    // `IdType::from_sha256_hash`), while `From<[u8; 32]>` is infallible.

    #[test]
    fn try_from_rejects_short_vec() {
        assert!(matches!(
            Sha256Hash::try_from(vec![0u8; SHA256_HASH_LEN - 1]),
            Err(Error::InvalidHashLength)
        ));
    }

    #[test]
    fn try_from_rejects_long_vec() {
        assert!(matches!(
            Sha256Hash::try_from(vec![0u8; SHA256_HASH_LEN + 1]),
            Err(Error::InvalidHashLength)
        ));
    }

    #[test]
    fn try_from_accepts_exact_len_vec() {
        let v = vec![0x42u8; SHA256_HASH_LEN];
        let hash = Sha256Hash::try_from(v).expect("32-byte vec is a valid hash");
        assert_eq!(hash.as_bytes(), &[0x42u8; SHA256_HASH_LEN]);
    }

    #[test]
    fn from_array_is_infallible_and_round_trips_bytes() {
        let bytes = [0x7fu8; SHA256_HASH_LEN];
        let hash = Sha256Hash::from(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }
}

#[cfg(test)]
mod pinned_mutinynet_vector_tests {
    use super::*;

    // The spec's mutinynet decoding example (did-btcr2/src/algorithms.md
    // lines 99-110), pinned in BOTH directions with externally-sourced bytes.
    //
    // This is the sole NON-self-inverse identifier vector: the genesis bytes are
    // hard-coded from the spec, not derived from the codec under test. A
    // self-consistent-but-wrong codec (e.g. a flipped version/network nibble
    // layout, GAP-1) passes every existing self-inverse round-trip test but must
    // fail this one, settling GAP-1 at the byte level.
    const MUTINYNET_DID: &str =
        "did:btcr2:x1qhjw6jnhwcyu5wau4x0cpwvz74c3g82c3uaehqpaf7lzfgmnwsd7spmmf54";

    // genesis SHA-256 e4ed4a777609ca3bbca99f80b982f571141d588f3b9b803d4fbe24a373741be8,
    // spec algorithms.md decoding example.
    const EXPECTED_GENESIS: [u8; 32] = [
        0xe4, 0xed, 0x4a, 0x77, 0x76, 0x09, 0xca, 0x3b, 0xbc, 0xa9, 0x9f, 0x80, 0xb9, 0x82, 0xf5,
        0x71, 0x14, 0x1d, 0x58, 0x8f, 0x3b, 0x9b, 0x80, 0x3d, 0x4f, 0xbe, 0x24, 0xa3, 0x73, 0x74,
        0x1b, 0xe8,
    ];

    #[test]
    fn decode_matches_spec_version_network_genesis() {
        let components = parse_did_identifier(MUTINYNET_DID).expect("spec mutinynet DID parses");
        assert_eq!(components.version(), DidVersion::One);
        assert_eq!(components.network(), Network::Mutinynet);
        match components.id_type() {
            IdType::External(hash) => assert_eq!(hash.as_bytes(), &EXPECTED_GENESIS),
            IdType::Key(_) => panic!("mutinynet vector must decode to an External id_type"),
        }
    }

    #[test]
    fn encode_reproduces_spec_string() {
        let id_type = IdType::External(Sha256Hash::from(EXPECTED_GENESIS));
        let encoded = encode_did_identifier(DidVersion::One, Network::Mutinynet, id_type)
            .expect("mutinynet components encode");
        assert_eq!(encoded, MUTINYNET_DID);
    }
}
