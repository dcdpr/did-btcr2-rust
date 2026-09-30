//! Constants and limits for Bech32 encoding and decoding.
//!
//! This module defines all the constants used throughout the Bech32 implementation,
//! including character set definitions, length limits, and checksum constants.
//! These values are derived from the Bech32 specification in
//! [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) and
//! [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).
//!
//! # Key Components
//!
//! - **Character limits**: Valid ASCII ranges for human-readable parts
//! - **Length constraints**: Minimum and maximum sizes for various string components
//! - **Character sets**: Encoding/decoding lookup tables for the 32-character Bech32 alphabet
//! - **Checksum constants**: Values for both original Bech32 and Bech32m variants
//!
//! # Bech32 String Structure
//!
//! A complete Bech32 string has the format: `<hrp>1<data><checksum>`
//! - Human-readable part (HRP): 1-83 characters
//! - Separator: always '1'
//! - Data part: variable length, 5-bit encoded values
//! - Checksum: exactly 6 characters

/// Minimum allowed ASCII value for characters in the human-readable part.
/// Value is 33 (ASCII '!'). All HRP characters must be in the range
/// [`MIN_HRP_CHAR_VALUE`] to [`MAX_HRP_CHAR_VALUE`] (33-126).
pub const MIN_HRP_CHAR_VALUE: u8 = 33; // ascii '!'

/// Maximum allowed ASCII value for characters in the human-readable part.
/// Value is 126 (ASCII '~'). All HRP characters must be in the range
/// [`MIN_HRP_CHAR_VALUE`] to [`MAX_HRP_CHAR_VALUE`] (33-126).
pub const MAX_HRP_CHAR_VALUE: u8 = 126; // ascii '~'

/// Minimum length of the human-readable part (1 character).
/// The HRP must be between [`MIN_HRP_LENGTH`] and [`MAX_HRP_LENGTH`] characters.
pub const MIN_HRP_LENGTH: usize = 1;

/// Maximum length of the human-readable part (83 characters).
/// The HRP must be between [`MIN_HRP_LENGTH`] and [`MAX_HRP_LENGTH`] characters.
/// This limit ensures the total Bech32 string stays within [`MAX_BECH32_LENGTH`].
pub const MAX_HRP_LENGTH: usize = 83;

/// Length of the separator character in a Bech32 string.
/// The separator is always exactly 1 character ('1').
pub const SEPARATOR_LENGTH: usize = 1;

/// Length of the checksum in a Bech32 string.
pub const CHECKSUM_LENGTH: usize = 6;

/// Minimum allowed length for a complete Bech32 string (8 characters).
/// Calculated as [`MIN_HRP_LENGTH`] + [`SEPARATOR_LENGTH`] + [`CHECKSUM_LENGTH`].
/// This represents the shortest possible valid Bech32 string: 1-char HRP + '1' + 6-char checksum.
pub const MIN_BECH32_LENGTH: usize = MIN_HRP_LENGTH + SEPARATOR_LENGTH + CHECKSUM_LENGTH; // 8

/// Maximum allowed length for a complete Bech32 string (90 characters).
/// Calculated as [`MAX_HRP_LENGTH`] + [`SEPARATOR_LENGTH`] + [`CHECKSUM_LENGTH`].
pub const MAX_BECH32_LENGTH: usize = MAX_HRP_LENGTH + SEPARATOR_LENGTH + CHECKSUM_LENGTH; // 90

/// Minimum length of the data part in a Bech32 string (0 characters).
/// The data part can be empty, containing only the checksum.
pub const MIN_DP_LENGTH: usize = 0;

/// Returns the maximum allowed length for the data part given an HRP length.
///
/// The maximum data part length is dynamic because the total Bech32 string cannot
/// exceed [`MAX_BECH32_LENGTH`] characters. As the HRP gets longer, the available
/// space for the data part decreases.
///
/// When 8-bit data is being used, there is an additional complication since that
/// data needs to be "expanded". This expansion increases the numbers of bytes needed
/// to represent the data by a factor of 8/5, so we need to scale the length returned
/// here by 5/8.
///
/// # Arguments
///
/// * `hrp_length` - The length of the human-readable part
///
/// # Returns
///
/// The maximum number of bytes available for the data part
///
/// # Examples
///
/// ```
/// use bech32_rust::max_dp_length;
///
/// // With a 0-character HRP, we have 51 bytes available for data
/// assert_eq!(max_dp_length(0), 51);
///
/// // With an 8-character HRP, we have 46 bytes available for data
/// assert_eq!(max_dp_length(8), 46);
///
/// // With an 83-character HRP, we have 0 bytes available for data
/// assert_eq!(max_dp_length(83), 0);
/// ```
#[must_use]
pub fn max_dp_length(hrp_length: usize) -> usize {
    (MAX_BECH32_LENGTH - hrp_length - SEPARATOR_LENGTH - CHECKSUM_LENGTH) * 5 / 8
}

/// Returns the maximum allowed length for the data part given an HRP length.
///
/// The maximum data part length is dynamic because the total Bech32 string cannot
/// exceed [`MAX_BECH32_LENGTH`] characters. As the HRP gets longer, the available
/// space for the data part decreases.
///
/// # Arguments
///
/// * `hrp_length` - The length of the human-readable part
///
/// # Returns
///
/// The maximum number of bytes available for the data part
///
/// # Examples
///
/// ```
/// use bech32_rust::max_dp_length_5bit;
///
/// // With a 0-character HRP, we have 83 bytes available for data
/// assert_eq!(max_dp_length_5bit(0), 83);
///
/// // With an 8-character HRP, we have 75 bytes available for data
/// assert_eq!(max_dp_length_5bit(8), 75);
///
/// // With an 83-character HRP, we have 0 bytes available for data
/// assert_eq!(max_dp_length_5bit(83), 0);
/// ```
#[must_use]
pub fn max_dp_length_5bit(hrp_length: usize) -> usize {
    MAX_BECH32_LENGTH - hrp_length - SEPARATOR_LENGTH - CHECKSUM_LENGTH
}

/// The Bech32 separator character ('1').
/// This character separates the human-readable part from the data part.
pub const SEPARATOR: char = '1';

/// Size of the valid Bech32 character set (32 characters).
/// This represents 2^5, allowing each character to encode exactly 5 bits of data.
/// Used for bounds checking during encoding and decoding operations.
pub const VALID_DP_CHARSET_SIZE: usize = 32;

/// Maximum value that can be used to index into the valid Bech32 character
/// set (32 characters).
pub const MAX_DP_CHARSET_INDEX: u8 = 31;

/// The Bech32 character set for encoding data values to characters.
///
/// This array maps 5-bit values (0-31) to their corresponding Bech32 characters.
/// For example: 0 -> 'q', 10 -> '2', 31 -> 'l'.
///
/// This character set excludes '1' (separator), 'b', 'i', and 'o' to avoid
/// visual confusion. The mapping comes from the table in
/// [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
pub(crate) const DP_CHARSET: [u8; VALID_DP_CHARSET_SIZE] = *b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Size of the reverse character mapping table (128 entries).
/// Covers the full 7-bit ASCII range for efficient character-to-value lookups.
pub(crate) const REVERSE_CHARSET_SIZE: usize = 128;

/// Maximum value that can be used to index into the reverse character
/// mapping table (128 entries).
pub const MAX_REVERSE_CHARSET_INDEX: u8 = 127;

/// The Bech32 character set for decoding characters to data values.
///
/// Maps ASCII characters to their corresponding 5-bit values, or -1 for invalid characters.
/// Both uppercase and lowercase letters map to the same values (e.g., 'Q' and 'q' both map to 0).
/// Invalid characters are set to -1 for easy error detection.
///
/// This lookup table enables efficient O(1) character validation and conversion during decoding.
/// The mapping comes from the table in
/// [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
pub(crate) const REVERSE_CHARSET: [i8; REVERSE_CHARSET_SIZE] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

/// Checksum constant used in Bech32m checksum generation (0x2bc830a3).
///
/// This is the improved constant introduced in
/// [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).
/// Exhaustive analysis showed this value provides optimal error detection properties.
/// This is the default constant used by this library for encoding.
///
/// See also [`M0`] for the original Bech32 constant.
pub(crate) const M: u32 = 0x2bc_830a3;

/// Original checksum constant used in early Bech32 checksum generation (1).
///
/// This was the constant used in the original Bech32 specification from
/// [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
/// Later analysis revealed that this value was not optimal for error detection,
/// leading to the development of Bech32m with the improved constant [`M`].
///
/// This constant is maintained for backward compatibility and decoding of
/// legacy Bech32 strings.
pub(crate) const M0: u32 = 1;
