//! Error types for Bech32 encoding and decoding operations.
//!
//! This module defines all possible errors that can occur during Bech32 string
//! validation, encoding, and decoding.
//!
//! # Error Categories
//!
//! - **String format errors**: Issues with overall Bech32 string structure
//! - **Component errors**: Problems with specific parts (HRP, data part, checksum)
//! - **Data validation errors**: Invalid characters or values
//! - **Processing errors**: Issues during encoding/decoding operations
//!
//! # Example
//!
//! ```rust
//! use bech32_rust::{decode, Bech32Error};
//!
//! match decode("invalid-bech32") {
//!     Ok(result) => println!("Decoded: {:?}", result),
//!     Err(Bech32Error::BStringMissingSeparator) => {
//!         println!("Missing '1' separator character");
//!     }
//!     Err(e) => println!("Other error: {}", e),
//! }
//! ```

use onlyerror::Error;
use std::io::Error as IoError;

/// Represents errors that may occur when encoding or decoding Bech32 strings.
///
/// This error type is returned by the [`encode`] and [`decode`] functions in this crate.
/// It includes validation failures (like invalid length, characters, or checksums),
/// as well as lower-level issues such as bit conversion errors or I/O failures.
///
/// Bech32 strings must follow strict formatting rules. This enum helps indicate
/// exactly what went wrong if an input string is malformed or cannot be generated
/// correctly.
///
/// [`encode`]: crate::encode
/// [`decode`]: crate::decode
#[derive(Debug, Error)]
pub enum Bech32Error {
    /// Bech32 string is too short.
    ///
    /// Bech32 strings must be at least 8 characters long (minimum 1-character HRP +
    /// '1' separator + 6-character checksum). This error occurs when the input
    /// string has fewer than 8 characters.
    BStringTooShort,

    /// Bech32 string is too long.
    ///
    /// Bech32 strings cannot exceed 90 characters total. This error occurs when
    /// the input string exceeds this limit.
    BStringTooLong,

    /// Bech32 string contains mixed case characters.
    ///
    /// Bech32 strings must be either all uppercase or all lowercase. This error
    /// occurs when the string contains both uppercase and lowercase letters, which
    /// violates the specification.
    BStringMixedCase,

    /// Bech32 string contains characters outside the valid ASCII range.
    ///
    /// All characters in a Bech32 string must have ASCII values between 33 and 126
    /// (printable ASCII characters excluding space). This error occurs when
    /// characters like control characters, spaces, or extended ASCII are found.
    BStringValueOutOfRange,

    /// Bech32 string is missing the required separator character.
    ///
    /// Every Bech32 string must contain at least one '1' character that separates
    /// the human-readable part from the data part. When multiple '1' characters
    /// are present, the rightmost one is treated as the separator.
    BStringMissingSeparator,

    /// Data part contains invalid characters.
    ///
    /// The data part (after the separator) can only contain characters from the
    /// Bech32 alphabet. This error occurs when characters outside this set are
    /// found in the data part.
    BStringInvalidCharacter,

    /// Human-readable part is too short.
    ///
    /// The HRP must contain at least one character. This error occurs when
    /// the string starts with the separator '1', resulting in an empty HRP.
    HrpTooShort,

    /// Human-readable part is too long.
    ///
    /// The HRP cannot exceed 83 characters. This limit ensures the total
    /// Bech32 string stays within the 90-character maximum. This error occurs
    /// when the HRP portion exceeds this limit.
    HrpTooLong,

    /// Data part is too short for decoding.
    ///
    /// The data part must contain at least 6 characters for the checksum.
    /// This error occurs when attempting to decode a string where the portion
    /// after the separator contains fewer than 6 characters.
    DpTooShort,

    /// Combined length of HRP and data part exceeds maximum allowed size.
    ///
    /// The total length of HRP + separator + data part + checksum cannot exceed
    /// 90 characters. This error occurs during encoding when the input would
    /// result in a string that's too long, even if individual parts are valid.
    BothPartsTooLong,

    /// Data value is outside the valid 5-bit range.
    ///
    /// Bech32 data values must be in the range 0-31 (5 bits). This error occurs
    /// when attempting to encode data containing values greater than 31, or when
    /// invalid characters map to out-of-range values during decoding.
    DataValueOutOfRange,

    /// Bech32 string has an invalid checksum.
    ///
    /// The checksum verification failed, indicating either data corruption or
    /// an invalid Bech32 string. This error occurs when the computed checksum
    /// doesn't match the expected value for either Bech32 or Bech32m encoding.
    InvalidChecksum,

    /// IO error occurred during processing.
    ///
    /// This error wraps underlying I/O errors that may occur during bit
    /// conversion operations or other processing steps.
    #[error("IO error: {0}")]
    IOError(#[from] IoError),

    /// Failed to convert between different bit representations.
    ///
    /// This error occurs during the conversion between 8-bit bytes and 5-bit
    /// Bech32 values when the conversion cannot be completed properly due to
    /// invalid padding or incompatible data lengths.
    #[error("failed to convert bits")]
    BitConversionError,
}
