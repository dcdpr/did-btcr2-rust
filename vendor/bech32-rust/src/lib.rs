//! A Rust implementation of Bech32 encoding and decoding.
//!
//! This crate provides a complete implementation of the Bech32 data encoding format,
//! which is primarily used for Bitcoin addresses as specified in
//! [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) and
//! [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).
//!
//! Bech32 is a checksummed base32 data encoding format that provides error detection
//! capabilities and human-readable prefixes for different data types.
//!
//! # Features
//!
//! - **Complete Bech32 support**: Handles both original Bech32 and improved Bech32m variants
//! - **Automatic format detection**: Decoding automatically detects which variant was used
//! - **Error detection**: Robust checksum validation catches most transmission errors
//! - **Easy to use**: Simple encode/decode functions for most use cases
//! - **Memory efficient**: Optimized for typical usage patterns
//! - **Well tested**: Comprehensive test suite including property-based tests
//!
//! # Quick Start
//!
//! The two main functions you'll need are [`encode`] and [`decode`]:
//!
//! ```rust
//! use bech32_rust::{encode, decode};
//!
//! // Encode some data with a human-readable part
//! let encoded = encode("hello", &[14, 15, 3, 31, 13]).unwrap();
//! assert_eq!(encoded, "hello1pc8sx8cdpvr52n");
//!
//! // Decode it
//! let decoded = decode(&encoded).unwrap();
//! assert_eq!(decoded.hrp, "hello");
//! assert_eq!(decoded.dp, vec![14, 15, 3, 31, 13]);
//! ```
//!
//! # Bech32 Format Overview
//!
//! A Bech32 string has the format: `<human-readable-part>1<data><checksum>`
//!
//! - **Human-readable part (HRP)**: 1-83 characters identifying the data type
//! - **Separator**: Always the character '1'
//! - **Data**: Variable-length encoded payload
//! - **Checksum**: 6 characters providing error detection
//!
//! For example, in `hello1pc8sx8cdpvr52n`:
//! - HRP: `hello`
//! - Separator: `1`
//! - Data: `pc8sx8cd` (encodes `[14, 15, 3, 31, 13]`)
//! - Checksum: `pvr52n`
//!
//! # Encoding Variants
//!
//! This library supports both Bech32 variants:
//!
//! - **Bech32m** (default): Uses improved checksum constant for better error detection
//! - **Original Bech32**: Legacy format for compatibility
//!
//! The [`decode`] function automatically detects which variant was used and reports
//! it in the [`DecodedResult`]. The [`encode`] function defaults to Bech32m.
//!
//! # Error Handling
//!
//! All functions return [`Result`] types with detailed [`Bech32Error`] variants
//! for different failure modes:
//!
//! ```rust
//! use bech32_rust::{decode, Bech32Error};
//!
//! match decode("invalid-string") {
//!     Ok(result) => println!("Decoded: {:?}", result),
//!     Err(Bech32Error::BStringMissingSeparator) => {
//!         println!("Missing '1' separator character");
//!     }
//!     Err(e) => println!("Other error: {}", e),
//! }
//! ```
//!
//! # Advanced Usage
//!
//! For most applications, the basic [`encode`] and [`decode`] functions are
//! sufficient, please see the [`Quick Start`](#quick-start) section above.
//!
//! ```rust
//! use bech32_rust::{encode, decode};
//!
//! // Encode binary data (like a hash)
//! let hash_data = [0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4];
//! let encoded = encode("data", &hash_data).unwrap();
//!
//! // Decode and verify
//! let decoded = decode(&encoded).unwrap();
//! assert_eq!(decoded.dp, hash_data.to_vec());
//! assert_eq!(decoded.hrp, "data");
//! ```

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(unused_extern_crates)]
#![warn(unreachable_pub)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]
// Clippy-specific
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

// Internal modules - these contain implementation details

mod constants;
mod core;
mod data_checksum;
mod data_part;
mod data_part_with_checksum;
mod error;
mod hrp;
mod validation;

use arbitrary_int::u5;

// Re-export public constants that users might need for validation
pub use constants::*;

// Re-export the error type for user error handling
pub use error::Bech32Error;

/// Represents which encoding variant was used for a Bech32 string.
///
/// When decoding, this indicates whether the string was encoded using the
/// original Bech32 algorithm or the improved Bech32m variant. The encoding
/// is detected automatically during decoding by testing both checksum constants.
///
/// # Variants
///
/// - [`Encoding::Bech32`]: Uses the original checksum constant (1) from BIP-173
/// - [`Encoding::Bech32m`]: Uses the improved checksum constant (0x2bc830a3) from BIP-350
/// - [`Encoding::Invalid`]: No valid encoding was detected (checksum failed for both variants)
///
/// # Examples
///
/// ```rust
/// use bech32_rust::{decode, Encoding};
///
/// let result = decode("hello1pc8sx8cdpvr52n").unwrap();
/// match result.encoding {
///     Encoding::Bech32m => println!("Uses improved Bech32m encoding"),
///     Encoding::Bech32 => println!("Uses original Bech32 encoding"),
///     Encoding::Invalid => println!("Invalid encoding detected"),
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub enum Encoding {
    /// No valid encoding was detected during decoding.
    Invalid,
    /// Original Bech32 encoding using checksum constant 1.
    Bech32,
    /// Improved Bech32m encoding using checksum constant 0x2bc830a3.
    Bech32m,
}

/// The result of successfully decoding a Bech32 string.
///
/// Contains the extracted components and metadata about the decoded string.
/// All strings are normalized to lowercase as per the Bech32 specification.
///
/// # Fields
///
/// - [`DecodedResult::encoding`]: Which Bech32 variant was used (original or Bech32m)
/// - [`DecodedResult::hrp`]: The human-readable part (1-83 characters)
/// - [`DecodedResult::dp`]: The decoded data payload as bytes
///
/// # Examples
///
/// ```rust
/// use bech32_rust::{decode, Encoding};
///
/// let result = decode("hello1pc8sx8cdpvr52n").unwrap();
///
/// println!("HRP: {}", result.hrp);           // "hello"
/// println!("Data: {:?}", result.dp);         // [14, 15, 3, 31, 13]
/// println!("Encoding: {:?}", result.encoding); // Encoding::Bech32m
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct DecodedResult {
    /// The encoding variant that was detected during decoding.
    pub encoding: Encoding,
    /// The human-readable part, normalized to lowercase.
    pub hrp: String,
    /// The decoded data payload as a vector of bytes.
    pub dp: Vec<u8>,
}

/// The result of successfully decoding a Bech32 string.
///
/// Contains the extracted components and metadata about the decoded string.
/// All strings are normalized to lowercase as per the Bech32 specification.
///
/// # Fields
///
/// - [`DecodedResult5bit::encoding`]: Which Bech32 variant was used (original or Bech32m)
/// - [`DecodedResult5bit::hrp`]: The human-readable part (1-83 characters)
/// - [`DecodedResult5bit::dp`]: The decoded data payload as "5-bit" values, represented by `arbitrary_int:u5`
///
/// # Examples
///
/// ```rust
/// use bech32_rust::{decode_5bit, Encoding};
///
/// let result = decode_5bit("hello1w0rldjn365x").unwrap();
///
/// println!("HRP: {}", result.hrp);             // "hello"
/// println!("Data: {:?}", result.dp);           // [14, 15, 3, 31, 13]
/// println!("Encoding: {:?}", result.encoding); // Encoding::Bech32m
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct DecodedResult5bit {
    /// The encoding variant that was detected during decoding.
    pub encoding: Encoding,
    /// The human-readable part, normalized to lowercase.
    pub hrp: String,
    /// The decoded data payload as a vector of `arbitrary_int::u5`.
    pub dp: Vec<u5>,
}

/// Encodes binary data as a Bech32 string using the Bech32m variant.
///
/// This is the main encoding function that converts binary data into a Bech32
/// string with the specified human-readable part. It automatically handles
/// bit conversion from 8-bit bytes to 5-bit Bech32 values and computes the
/// checksum using the improved Bech32m algorithm.
///
/// # Arguments
///
/// * `hrp_str` - Human-readable part (1-83 ASCII characters, will be lowercased)
/// * `dp` - Binary data to encode (will be converted from 8-bit to 5-bit representation)
///
/// # Returns
///
/// * `Ok(String)` - The encoded Bech32 string
/// * `Err(Bech32Error)` - If encoding fails due to invalid input
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust
/// use bech32_rust::encode;
///
/// // Encode simple data
/// let encoded = encode("hello", &[14, 15, 3, 31, 13]).unwrap();
/// assert_eq!(encoded, "hello1pc8sx8cdpvr52n");
/// ```
///
/// ## Encoding Binary Data
///
/// ```rust
/// use bech32_rust::encode;
///
/// // Encode a hash or other binary data
/// let hash = [0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4];
/// let encoded = encode("hash", &hash).unwrap();
/// assert_eq!(encoded, "hash1w508d6qejxtdgc0kq4r");
/// ```
pub fn encode(hrp_str: impl AsRef<str>, dp: impl AsRef<[u8]>) -> Result<String, Bech32Error> {
    core::encode(hrp_str, dp)
}

/// Encodes data using 5-bit values directly.
///
/// For use when data is already in 5-bit format.
///
/// # Arguments
///
/// * `hrp_str` - Human-readable part string
/// * `dp` - 5-bit data values
///
/// # Returns
///
/// * `Ok(String)` - The encoded Bech32 string
/// * `Err(Bech32Error)` - If encoding fails
///
pub fn encode_5bit(hrp_str: impl AsRef<str>, dp: impl AsRef<[u5]>) -> Result<String, Bech32Error> {
    core::encode_5bit(hrp_str, dp)
}

/// Decodes a Bech32 string and returns the original data.
///
/// This is the main decoding function that parses a Bech32 string, validates
/// the checksum, and extracts the original binary data. It automatically
/// detects whether the string uses original Bech32 or Bech32m encoding
/// and handles bit conversion from 5-bit Bech32 values back to 8-bit bytes.
///
/// # Arguments
///
/// * `bstring` - The Bech32 string to decode
///
/// # Returns
///
/// * `Ok(DecodedResult)` - The decoded components and metadata
/// * `Err(Bech32Error)` - If decoding fails due to invalid input
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust
/// use bech32_rust::decode;
///
/// let result = decode("hello1pc8sx8cdpvr52n").unwrap();
/// assert_eq!(result.hrp, "hello");
/// assert_eq!(result.dp, vec![14, 15, 3, 31, 13]);
/// ```
///
/// ## Handling Different Encodings
///
/// ```rust
/// use bech32_rust::{decode, Encoding};
///
/// let result = decode("hello1pc8sx8cdpvr52n").unwrap();
/// match result.encoding {
///     Encoding::Bech32m => println!("Modern Bech32m encoding"),
///     Encoding::Bech32 => println!("Legacy Bech32 encoding"),
///     Encoding::Invalid => unreachable!("Would have returned error"),
/// }
/// ```
///
/// ## Error Handling
///
/// ```rust
/// use bech32_rust::{decode, Bech32Error};
///
/// match decode("invalid-string") {
///     Ok(result) => println!("Success: {:?}", result),
///     Err(Bech32Error::BStringMissingSeparator) => {
///         println!("Missing '1' separator");
///     }
///     Err(Bech32Error::InvalidChecksum) => {
///         println!("Checksum validation failed");
///     }
///     Err(e) => println!("Other error: {}", e),
/// }
/// ```
///
/// ## Round-trip Encoding/Decoding
///
/// ```rust
/// use bech32_rust::{encode, decode};
///
/// let original_data = b"test data";
/// let encoded = encode("test", original_data).unwrap();
/// let decoded = decode(&encoded).unwrap();
///
/// assert_eq!(decoded.hrp, "test");
/// assert_eq!(decoded.dp, original_data.to_vec());
/// ```
pub fn decode(bstring: impl AsRef<str>) -> Result<DecodedResult, Bech32Error> {
    core::decode(bstring)
}

/// Decodes a Bech32 string returning 5-bit values directly.
///
/// For internal use when 5-bit output format is needed. Used primarily
/// in testing and specialized decoding scenarios where bit conversion
/// is not needed.
///
/// # Arguments
///
/// * `bstring` - Bech32 string to decode
///
/// # Returns
///
/// * `Ok(DecodedResult)` - The decoded 5-bit values with metadata
/// * `Err(Bech32Error)` - If decoding fails
///
#[cfg_attr(not(test), allow(dead_code))]
pub fn decode_5bit(bstring: impl AsRef<str>) -> Result<DecodedResult5bit, Bech32Error> {
    core::decode_5bit(bstring)
}

#[cfg(test)]
mod tests_8bit {
    use super::*;

    // These tests set the data to be encoded as 8-bit, using the u8
    // type, and use DecodedResult::dp when checking decoded results.

    #[test]
    fn test_small_hrp_empty_data() {
        let result = encode("a", []);
        let expected = "a1lqfn3a";

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);

        let dr: DecodedResult = decode(expected).unwrap();
        assert_eq!(String::from("a"), dr.hrp);
        assert!(dr.dp.is_empty());
    }

    #[test]
    fn test_small_hrp_small_data() {
        let u8_data = [1, 2, 3];
        let result = encode("xyz", u8_data);
        let expected = "xyz1qypqxw3p2kq";

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);

        let dr: DecodedResult = decode(expected).unwrap();
        assert_eq!(String::from("xyz"), dr.hrp);
        assert_eq!(dr.dp, u8_data);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_data_values_0_to_31() {
        let u8_data: [u8; 32] = std::array::from_fn(|i| 31 - i as u8);
        let result = encode("abcdef", u8_data);
        let expected = "abcdef1ru0p68qmrgv3s9ckz52pxys3zq8surgvpv9qjzq8qczsgqczqyqqncvqap";

        assert!(result.is_ok());
        let bstring = result.unwrap();
        assert_eq!(bstring, expected);

        let dr: DecodedResult = decode(bstring).unwrap();
        assert_eq!(String::from("abcdef"), dr.hrp);
        assert_eq!(dr.dp, u8_data);
    }

    #[test]
    fn encode_then_decode_u32() {
        // 0) Here is an example large integer
        let orig_num: u32 = 123_456_789;

        // 1) decompose large integer into vector of u8
        let data = orig_num.to_be_bytes();

        // 2) bech32 encode
        let result = encode("m", data);

        assert!(result.is_ok());

        let bstring = result.unwrap();

        assert_eq!("m1qadu69gndsgn8", bstring);

        // 3) now decode the above bstring

        let dr = decode(bstring).unwrap();

        let decoded_data = dr.dp;

        // 4) show that we have gone round trip back to original
        let num = u32::from_be_bytes(decoded_data.try_into().unwrap());
        assert_eq!(orig_num, num);
    }

    #[test]
    fn encode_then_decode_u64() {
        // 0) Here is an example large integer
        let orig_num: u64 = 8_223_372_036_854_775_807;

        // 1) decompose large integer into vector of u8
        let data = orig_num.to_be_bytes();

        // 2) bech32 encode (8 bit version)
        let result = encode("m", data);

        assert!(result.is_ok());

        let bstring = result.unwrap();

        assert_eq!("m1wg05jnzcn0ll779tx9j", bstring);

        // 3) now decode the above bstring

        let dr = decode(bstring).unwrap();

        let decoded_data = dr.dp;

        // 4) show that we have gone round trip back to original
        let num = u64::from_be_bytes(decoded_data.try_into().unwrap());
        assert_eq!(orig_num, num);
    }

    #[test]
    fn encode_then_decode_hex_string() {
        // 0) Here is an example SHA256 hash
        let orig_str = "502a60dc06f9d1fd7ee8268d16798b82c10cfe61951cc057208f1b4272a3e1ad";

        // 1) decode hex string into vector of u8
        let data_str = hex::decode(orig_str).unwrap();

        // 2) bech32 encode (8 bit version)
        let result = encode("a", &data_str);

        assert!(result.is_ok());

        let bstring = result.unwrap();

        assert_eq!(
            "a12q4xphqxl8gl6lhgy6x3v7vtstqselnpj5wvq4eq3ud5yu4ruxks37q3w4",
            bstring
        );

        // 3) now decode the above bstring

        let dr = decode(bstring).unwrap();

        let decoded_data = dr.dp;

        // 4) show that we have gone round trip back to original SHA256 hash
        assert_eq!(hex::encode(decoded_data), orig_str);
    }
}

#[cfg(test)]
mod tests_5bit {
    use super::*;

    // These tests specifically set the data to be encoded as 5-bit, using the
    // arbitrary_int::u5 type, and use DecodedResult5bit::dp when checking
    // decoded results.

    #[test]
    fn test_small_hrp_empty_data() {
        let result = encode_5bit("a", []);
        let expected = "a1lqfn3a";

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);

        let dr: DecodedResult5bit = decode_5bit(expected).unwrap();
        assert_eq!(String::from("a"), dr.hrp);
        assert!(dr.dp.is_empty());
    }

    #[test]
    fn test_small_hrp_small_data() {
        let u5_data = [u5::new(1), u5::new(2), u5::new(3)];
        let result = encode_5bit("xyz", u5_data);
        let expected = "xyz1pzrs3usye";

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);

        let dr: DecodedResult5bit = decode_5bit(expected).unwrap();
        assert_eq!(String::from("xyz"), dr.hrp);
        assert_eq!(dr.dp, u5_data);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_all_data_values() {
        let u5_data: [u5; 32] = std::array::from_fn(|i| u5::new(31 - i as u8));
        let result = encode_5bit("abcdef", u5_data);
        let expected = "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx";

        assert!(result.is_ok());
        let bstring = result.unwrap();
        assert_eq!(bstring, expected);

        let dr: DecodedResult5bit = decode_5bit(bstring).unwrap();
        assert_eq!(String::from("abcdef"), dr.hrp);
        assert_eq!(dr.dp, u5_data);
    }
}
